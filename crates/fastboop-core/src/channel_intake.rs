use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use futures_util::stream::{self, StreamExt, TryStreamExt};
use gibblox_core::{BlockReader, ReadContext};
use gibblox_pipeline::{PipelineHints, pipeline_identity_string};

use crate::channel_index::{
    CHANNEL_INDEX_RECORD_FIXED_HEADER_LEN, ChannelIndexEntryV0,
    channel_index_record_header_version, decode_channel_index_payload,
    decode_channel_index_record_fixed_header, validate_channel_index,
};
use crate::channel_pipeline_hints::{
    CHANNEL_PIPELINE_HINTS_RECORD_FIXED_HEADER_LEN, ChannelPipelineHintsRecordHead,
    channel_pipeline_hints_record_header_version, decode_channel_pipeline_hints_record,
    decode_channel_pipeline_hints_record_fixed_header, decode_channel_pipeline_hints_record_prefix,
};
use crate::{
    BootProfile, BootProfileArtifactSource, DeviceProfile, boot_profile_bin_header_version,
    decode_boot_profile_prefix, decode_dev_profile_prefix, dev_profile_bin_header_version,
    validate_boot_profile,
};

pub const CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES: usize = 4 * 1024 * 1024;
pub const CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS: usize = 128;

const CHANNEL_STREAM_RECORD_PROBE_BYTES: usize = 64;
const CHANNEL_STREAM_RECORD_INITIAL_READ_BYTES: usize = 4 * 1024;
const CHANNEL_INDEX_DISPATCH_PROBE_BYTES: usize = 64;
const CHANNEL_INDEX_PARALLEL_FETCH_LIMIT: usize = 16;

#[derive(Clone, Debug, Default)]
pub struct BootProfileStreamHead {
    pub profiles: Vec<BootProfile>,
    pub consumed_bytes: u64,
}

#[derive(Debug)]
pub enum BootProfileStreamHeadError {
    DecodeHeadTruncated { offset: u64, cause: String },
    DecodeFailure { offset: u64, cause: String },
    EmptyRecord { offset: u64 },
    MaxRecordCountExceeded { max_records: usize },
    CursorOverflow,
}

impl core::fmt::Display for BootProfileStreamHeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DecodeHeadTruncated { cause, .. } => write!(f, "{cause}"),
            Self::DecodeFailure { cause, .. } => write!(f, "{cause}"),
            Self::EmptyRecord { offset } => {
                write!(
                    f,
                    "decoded boot profile consumed zero bytes at offset {offset}"
                )
            }
            Self::MaxRecordCountExceeded { max_records } => write!(
                f,
                "channel boot profile stream exceeds max profile count {max_records}"
            ),
            Self::CursorOverflow => write!(f, "channel boot profile cursor overflow"),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ChannelPipelineHintsRecord {
    pub record_offset_bytes: u64,
    pub payload_offset_bytes: u64,
    pub payload_size_bytes: u64,
    pub pipeline_identities: Vec<String>,
}

/// Location (and hoistable metadata) of a single head record inside a
/// concatenated-records channel. Emitted by [`scan_channel_head_record_locations`]
/// so callers like `fastboop channel index` can build a [`ChannelIndexV0`]
/// without re-decoding the records after the scan.
#[derive(Clone, Debug)]
pub enum ChannelHeadRecordLocation {
    BootProfile {
        offset: u64,
        size: u64,
        id: String,
    },
    DeviceProfile {
        offset: u64,
        size: u64,
        id: String,
    },
    PipelineHints {
        offset: u64,
        size: u64,
        /// Payload offset relative to the start of the record (not the channel).
        payload_offset: u64,
        payload_size: u64,
        pipeline_identities: Vec<String>,
    },
}

impl ChannelHeadRecordLocation {
    pub fn offset(&self) -> u64 {
        match self {
            Self::BootProfile { offset, .. }
            | Self::DeviceProfile { offset, .. }
            | Self::PipelineHints { offset, .. } => *offset,
        }
    }

    pub fn size(&self) -> u64 {
        match self {
            Self::BootProfile { size, .. }
            | Self::DeviceProfile { size, .. }
            | Self::PipelineHints { size, .. } => *size,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ChannelStreamHead {
    pub boot_profiles: Vec<BootProfile>,
    pub dev_profiles: Vec<DeviceProfile>,
    pub pipeline_hints: PipelineHints,
    pub pipeline_hint_records: Vec<ChannelPipelineHintsRecord>,
    pub consumed_bytes: u64,
    pub warning_count: usize,
}

impl ChannelStreamHead {
    pub fn pipeline_hint_entry_count(&self) -> usize {
        if !self.pipeline_hints.entries.is_empty() {
            self.pipeline_hints.entries.len()
        } else {
            self.pipeline_hint_records
                .iter()
                .map(|record| record.pipeline_identities.len())
                .sum()
        }
    }
}

#[derive(Debug)]
pub enum ChannelStreamHeadError {
    DecodeFailure {
        record_type: &'static str,
        offset: u64,
        cause: String,
    },
    DecodeHeadTruncated {
        record_type: &'static str,
        offset: u64,
        cause: String,
    },
    EmptyRecord {
        offset: u64,
    },
    MaxRecordCountExceeded {
        max_records: usize,
    },
    DuplicatePipelineHintIdentity {
        pipeline_identity: String,
    },
    CursorOverflow,
}

impl core::fmt::Display for ChannelStreamHeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DecodeFailure {
                record_type,
                offset,
                cause,
            } => write!(f, "decode {record_type} stream at offset {offset}: {cause}"),
            Self::DecodeHeadTruncated {
                record_type,
                offset,
                cause,
            } => write!(f, "decode {record_type} stream at offset {offset}: {cause}"),
            Self::EmptyRecord { offset } => {
                write!(
                    f,
                    "decoded profile record consumed zero bytes at offset {offset}"
                )
            }
            Self::MaxRecordCountExceeded { max_records } => {
                write!(
                    f,
                    "channel profile stream exceeds max record count {max_records}"
                )
            }
            Self::DuplicatePipelineHintIdentity { pipeline_identity } => write!(
                f,
                "duplicate pipeline hint identity '{}' is not allowed in channel stream",
                pipeline_identity
            ),
            Self::CursorOverflow => write!(f, "channel profile stream cursor overflow"),
        }
    }
}

#[derive(Debug)]
pub enum ChannelStreamHeadReadError {
    Decode(ChannelStreamHeadError),
    InvalidReaderBlockSize {
        block_size: u32,
    },
    ReadFailure {
        offset: u64,
        len: usize,
        cause: String,
    },
    ShortRead {
        offset: u64,
        expected_bytes: usize,
        actual_bytes: usize,
    },
    RangeOverflow,
}

impl core::fmt::Display for ChannelStreamHeadReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(err) => write!(f, "{err}"),
            Self::InvalidReaderBlockSize { block_size } => {
                write!(f, "channel reader block size {block_size} is invalid")
            }
            Self::ReadFailure { offset, len, cause } => {
                write!(
                    f,
                    "read channel bytes at offset {offset} (len {len}): {cause}"
                )
            }
            Self::ShortRead {
                offset,
                expected_bytes,
                actual_bytes,
            } => write!(
                f,
                "short channel read at offset {offset}: expected {expected_bytes} bytes, got {actual_bytes}"
            ),
            Self::RangeOverflow => write!(f, "channel read range overflow"),
        }
    }
}

impl From<ChannelStreamHeadError> for ChannelStreamHeadReadError {
    fn from(err: ChannelStreamHeadError) -> Self {
        Self::Decode(err)
    }
}

pub fn read_boot_profile_stream_head(
    bytes: &[u8],
    exact_total_bytes: u64,
) -> Result<BootProfileStreamHead, BootProfileStreamHeadError> {
    let scan_cap = core::cmp::min(
        CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES as u64,
        exact_total_bytes,
    ) as usize;
    let scan_len = core::cmp::min(scan_cap, bytes.len());

    let mut out = BootProfileStreamHead::default();
    let mut cursor = 0usize;

    while cursor < scan_len {
        if out.profiles.len() >= CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS {
            return Err(BootProfileStreamHeadError::MaxRecordCountExceeded {
                max_records: CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS,
            });
        }

        let remaining = &bytes[cursor..scan_len];
        if boot_profile_bin_header_version(remaining).is_none() {
            break;
        }

        let (profile, consumed) = match decode_boot_profile_prefix(remaining) {
            Ok(decoded) => decoded,
            Err(err) if (scan_cap as u64) < exact_total_bytes => {
                return Err(BootProfileStreamHeadError::DecodeHeadTruncated {
                    offset: cursor as u64,
                    cause: format!(
                        "decode boot profile stream at offset {cursor}: {err}; stream head exceeds {CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES} bytes"
                    ),
                });
            }
            Err(err) => {
                return Err(BootProfileStreamHeadError::DecodeFailure {
                    offset: cursor as u64,
                    cause: format!("decode boot profile stream at offset {cursor}: {err}"),
                });
            }
        };

        if consumed == 0 {
            return Err(BootProfileStreamHeadError::EmptyRecord {
                offset: cursor as u64,
            });
        }

        validate_boot_profile(&profile).map_err(|err| {
            BootProfileStreamHeadError::DecodeFailure {
                offset: cursor as u64,
                cause: format!(
                    "validate boot profile '{}' at stream offset {cursor}: {err}",
                    profile.id
                ),
            }
        })?;

        out.profiles.push(profile);

        cursor = cursor
            .checked_add(consumed)
            .ok_or(BootProfileStreamHeadError::CursorOverflow)?;
    }

    out.consumed_bytes = cursor as u64;
    Ok(out)
}

pub fn read_channel_stream_head(
    bytes: &[u8],
    exact_total_bytes: u64,
) -> Result<ChannelStreamHead, ChannelStreamHeadError> {
    if channel_index_record_header_version(bytes).is_some() {
        return read_indexed_channel_stream_head(bytes, exact_total_bytes);
    }
    read_sequential_channel_stream_head(bytes, exact_total_bytes)
}

fn read_sequential_channel_stream_head(
    bytes: &[u8],
    exact_total_bytes: u64,
) -> Result<ChannelStreamHead, ChannelStreamHeadError> {
    let scan_cap = core::cmp::min(
        CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES as u64,
        exact_total_bytes,
    ) as usize;
    let scan_len = core::cmp::min(scan_cap, bytes.len());

    let mut out = ChannelStreamHead::default();
    let mut cursor = 0usize;
    let mut pipeline_hint_identities = BTreeSet::new();
    let mut records_consumed = 0usize;

    while cursor < scan_len {
        if records_consumed >= CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS {
            return Err(ChannelStreamHeadError::MaxRecordCountExceeded {
                max_records: CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS,
            });
        }

        let remaining = &bytes[cursor..scan_len];

        if boot_profile_bin_header_version(remaining).is_some() {
            match decode_boot_profile_prefix(remaining) {
                Ok((profile, consumed)) => {
                    validate_boot_profile(&profile).map_err(|err| {
                        ChannelStreamHeadError::DecodeFailure {
                            record_type: "boot profile",
                            offset: cursor as u64,
                            cause: format!(
                                "validate boot profile '{}' at stream offset {cursor}: {err}",
                                profile.id
                            ),
                        }
                    })?;

                    if consumed == 0 {
                        return Err(ChannelStreamHeadError::EmptyRecord {
                            offset: cursor as u64,
                        });
                    }

                    out.boot_profiles.push(profile);
                    cursor = cursor
                        .checked_add(consumed)
                        .ok_or(ChannelStreamHeadError::CursorOverflow)?;
                    records_consumed = records_consumed.saturating_add(1);
                    continue;
                }
                Err(err) => {
                    if !channel_stream_has_records(&out) {
                        if (scan_cap as u64) < exact_total_bytes {
                            return Err(ChannelStreamHeadError::DecodeHeadTruncated {
                                record_type: "boot profile",
                                offset: cursor as u64,
                                cause: format!(
                                    "decode boot profile stream at offset {cursor}: {err}; stream head exceeds {CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES} bytes"
                                ),
                            });
                        }
                        return Err(ChannelStreamHeadError::DecodeFailure {
                            record_type: "boot profile",
                            offset: cursor as u64,
                            cause: format!("decode boot profile stream at offset {cursor}: {err}"),
                        });
                    }

                    out.warning_count += 1;
                    break;
                }
            }
        }

        if dev_profile_bin_header_version(remaining).is_some() {
            match decode_dev_profile_prefix(remaining) {
                Ok((profile, consumed)) => {
                    if consumed == 0 {
                        return Err(ChannelStreamHeadError::EmptyRecord {
                            offset: cursor as u64,
                        });
                    }

                    out.dev_profiles.push(profile);
                    cursor = cursor
                        .checked_add(consumed)
                        .ok_or(ChannelStreamHeadError::CursorOverflow)?;
                    records_consumed = records_consumed.saturating_add(1);
                    continue;
                }
                Err(err) => {
                    if !channel_stream_has_records(&out) {
                        if (scan_cap as u64) < exact_total_bytes {
                            return Err(ChannelStreamHeadError::DecodeHeadTruncated {
                                record_type: "dev profile",
                                offset: cursor as u64,
                                cause: format!(
                                    "decode dev profile stream at offset {cursor}: {err}; stream head exceeds {CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES} bytes"
                                ),
                            });
                        }
                        return Err(ChannelStreamHeadError::DecodeFailure {
                            record_type: "dev profile",
                            offset: cursor as u64,
                            cause: format!("decode dev profile stream at offset {cursor}: {err}"),
                        });
                    }

                    out.warning_count += 1;
                    break;
                }
            }
        }

        if channel_pipeline_hints_record_header_version(remaining).is_some() {
            let record_head = match decode_channel_pipeline_hints_record_prefix(remaining) {
                Ok(head) => head,
                Err(err) => {
                    if !channel_stream_has_records(&out) {
                        if (scan_cap as u64) < exact_total_bytes {
                            return Err(ChannelStreamHeadError::DecodeHeadTruncated {
                                record_type: "pipeline hints",
                                offset: cursor as u64,
                                cause: format!(
                                    "decode pipeline hints stream at offset {cursor}: {err}; stream head exceeds {CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES} bytes"
                                ),
                            });
                        }
                        return Err(ChannelStreamHeadError::DecodeFailure {
                            record_type: "pipeline hints",
                            offset: cursor as u64,
                            cause: format!(
                                "decode pipeline hints stream at offset {cursor}: {err}"
                            ),
                        });
                    }

                    out.warning_count += 1;
                    break;
                }
            };

            let record_size = usize::try_from(record_head.total_record_size_bytes)
                .map_err(|_| ChannelStreamHeadError::CursorOverflow)?;
            if record_size == 0 {
                return Err(ChannelStreamHeadError::EmptyRecord {
                    offset: cursor as u64,
                });
            }
            if remaining.len() < record_size {
                if !channel_stream_has_records(&out) {
                    if (scan_cap as u64) < exact_total_bytes {
                        return Err(ChannelStreamHeadError::DecodeHeadTruncated {
                            record_type: "pipeline hints",
                            offset: cursor as u64,
                            cause: format!(
                                "decode pipeline hints stream at offset {cursor}: record requires {record_size} bytes, available {}; stream head exceeds {CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES} bytes",
                                remaining.len()
                            ),
                        });
                    }
                    return Err(ChannelStreamHeadError::DecodeFailure {
                        record_type: "pipeline hints",
                        offset: cursor as u64,
                        cause: format!(
                            "decode pipeline hints stream at offset {cursor}: record requires {record_size} bytes, available {}",
                            remaining.len()
                        ),
                    });
                }

                out.warning_count += 1;
                break;
            }

            let record = &remaining[..record_size];
            let (hints, consumed) =
                decode_channel_pipeline_hints_record(record).map_err(|err| {
                    ChannelStreamHeadError::DecodeFailure {
                        record_type: "pipeline hints",
                        offset: cursor as u64,
                        cause: format!("decode pipeline hints stream at offset {cursor}: {err}"),
                    }
                })?;

            if consumed == 0 {
                return Err(ChannelStreamHeadError::EmptyRecord {
                    offset: cursor as u64,
                });
            }

            append_pipeline_hints(
                &mut out.pipeline_hints,
                &mut pipeline_hint_identities,
                hints,
            )?;
            push_pipeline_hint_record(&mut out, cursor as u64, &record_head)?;

            cursor = cursor
                .checked_add(consumed)
                .ok_or(ChannelStreamHeadError::CursorOverflow)?;
            records_consumed = records_consumed.saturating_add(1);
            continue;
        }

        if channel_stream_has_records(&out) {
            out.warning_count += 1;
        }
        break;
    }

    out.pipeline_hints
        .entries
        .sort_unstable_by(|left, right| left.pipeline_identity.cmp(&right.pipeline_identity));
    out.consumed_bytes = cursor as u64;
    Ok(out)
}

/// Walk a concatenated-records channel sequentially and emit per-record
/// locations. Intended as the input to [`encode_channel_head`] when
/// wrapping an existing channel with an index. Refuses to walk a channel
/// that already begins with an `FBCHIDX0` record; indexing an indexed
/// channel is a caller bug.
///
/// Unlike the streaming read paths, this helper does not apply a byte cap:
/// the caller already has the full input in memory, so the
/// `CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES` streaming budget is not
/// relevant. The record count cap (`CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS`)
/// still applies as a DoS guard.
///
/// If the loop exits because `bytes` ran out before a non-head byte was
/// detected and `bytes.len() < exact_total_bytes`, the caller passed a
/// truncated prefix and the scan cannot safely produce a complete index;
/// returns an error in that case.
///
/// Returns `(locations, consumed_bytes)`.
pub fn scan_channel_head_record_locations(
    bytes: &[u8],
    exact_total_bytes: u64,
) -> Result<(Vec<ChannelHeadRecordLocation>, u64), ChannelStreamHeadError> {
    if channel_index_record_header_version(bytes).is_some() {
        return Err(ChannelStreamHeadError::DecodeFailure {
            record_type: "channel index",
            offset: 0,
            cause: String::from("channel already begins with a FBCHIDX0 record; nothing to index"),
        });
    }

    let scan_len = core::cmp::min(bytes.len() as u64, exact_total_bytes) as usize;

    let mut locations: Vec<ChannelHeadRecordLocation> = Vec::new();
    let mut cursor: usize = 0;
    let mut tail_boundary_detected = false;

    while cursor < scan_len {
        if locations.len() >= CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS {
            return Err(ChannelStreamHeadError::MaxRecordCountExceeded {
                max_records: CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS,
            });
        }

        let remaining = &bytes[cursor..scan_len];

        if boot_profile_bin_header_version(remaining).is_some() {
            let (profile, consumed) = decode_boot_profile_prefix(remaining).map_err(|err| {
                ChannelStreamHeadError::DecodeFailure {
                    record_type: "boot profile",
                    offset: cursor as u64,
                    cause: format!("decode boot profile stream at offset {cursor}: {err}"),
                }
            })?;
            if consumed == 0 {
                return Err(ChannelStreamHeadError::EmptyRecord {
                    offset: cursor as u64,
                });
            }
            validate_boot_profile(&profile).map_err(|err| {
                ChannelStreamHeadError::DecodeFailure {
                    record_type: "boot profile",
                    offset: cursor as u64,
                    cause: format!(
                        "validate boot profile '{}' at stream offset {cursor}: {err}",
                        profile.id
                    ),
                }
            })?;
            locations.push(ChannelHeadRecordLocation::BootProfile {
                offset: cursor as u64,
                size: consumed as u64,
                id: profile.id.clone(),
            });
            cursor = cursor
                .checked_add(consumed)
                .ok_or(ChannelStreamHeadError::CursorOverflow)?;
            continue;
        }

        if dev_profile_bin_header_version(remaining).is_some() {
            let (profile, consumed) = decode_dev_profile_prefix(remaining).map_err(|err| {
                ChannelStreamHeadError::DecodeFailure {
                    record_type: "dev profile",
                    offset: cursor as u64,
                    cause: format!("decode dev profile stream at offset {cursor}: {err}"),
                }
            })?;
            if consumed == 0 {
                return Err(ChannelStreamHeadError::EmptyRecord {
                    offset: cursor as u64,
                });
            }
            locations.push(ChannelHeadRecordLocation::DeviceProfile {
                offset: cursor as u64,
                size: consumed as u64,
                id: profile.id.clone(),
            });
            cursor = cursor
                .checked_add(consumed)
                .ok_or(ChannelStreamHeadError::CursorOverflow)?;
            continue;
        }

        if channel_pipeline_hints_record_header_version(remaining).is_some() {
            let record_head =
                decode_channel_pipeline_hints_record_prefix(remaining).map_err(|err| {
                    ChannelStreamHeadError::DecodeFailure {
                        record_type: "pipeline hints",
                        offset: cursor as u64,
                        cause: format!("decode pipeline hints stream at offset {cursor}: {err}"),
                    }
                })?;
            let record_size = usize::try_from(record_head.total_record_size_bytes)
                .map_err(|_| ChannelStreamHeadError::CursorOverflow)?;
            if record_size == 0 {
                return Err(ChannelStreamHeadError::EmptyRecord {
                    offset: cursor as u64,
                });
            }
            if remaining.len() < record_size {
                return Err(ChannelStreamHeadError::DecodeFailure {
                    record_type: "pipeline hints",
                    offset: cursor as u64,
                    cause: format!(
                        "decode pipeline hints stream at offset {cursor}: record requires {record_size} bytes, available {}",
                        remaining.len()
                    ),
                });
            }
            locations.push(ChannelHeadRecordLocation::PipelineHints {
                offset: cursor as u64,
                size: record_size as u64,
                payload_offset: record_head.payload_offset_bytes,
                payload_size: record_head.payload_size_bytes,
                pipeline_identities: record_head.pipeline_identities,
            });
            cursor = cursor
                .checked_add(record_size)
                .ok_or(ChannelStreamHeadError::CursorOverflow)?;
            continue;
        }

        tail_boundary_detected = true;
        break;
    }

    // If the loop terminated without explicitly detecting a non-head byte
    // AND the caller claimed there was more channel than we walked, we
    // cannot safely emit a complete index — caller passed a truncated
    // prefix.
    if !tail_boundary_detected && (scan_len as u64) < exact_total_bytes {
        return Err(ChannelStreamHeadError::DecodeFailure {
            record_type: "channel head scan",
            offset: scan_len as u64,
            cause: format!(
                "scan consumed {scan_len} bytes but exact_total_bytes is {exact_total_bytes}; \
                 caller passed a truncated channel prefix and an index would silently drop the remainder"
            ),
        });
    }

    Ok((locations, cursor as u64))
}

pub async fn read_channel_stream_head_from_reader<R: BlockReader + ?Sized>(
    reader: &R,
    exact_total_bytes: u64,
) -> Result<ChannelStreamHead, ChannelStreamHeadReadError> {
    let block_size = channel_reader_block_size(reader)?;

    if exact_total_bytes >= CHANNEL_INDEX_RECORD_FIXED_HEADER_LEN as u64 {
        let probe_len =
            core::cmp::min(CHANNEL_INDEX_DISPATCH_PROBE_BYTES as u64, exact_total_bytes) as usize;
        let probe = read_channel_reader_bytes(reader, block_size, 0, probe_len).await?;
        if channel_index_record_header_version(probe.as_slice()).is_some() {
            return read_indexed_channel_stream_head_from_reader(
                reader,
                block_size,
                exact_total_bytes,
            )
            .await;
        }
    }

    read_sequential_channel_stream_head_from_reader(reader, block_size, exact_total_bytes).await
}

async fn read_sequential_channel_stream_head_from_reader<R: BlockReader + ?Sized>(
    reader: &R,
    block_size: usize,
    exact_total_bytes: u64,
) -> Result<ChannelStreamHead, ChannelStreamHeadReadError> {
    let mut out = ChannelStreamHead::default();
    let mut cursor = 0u64;
    let mut records_consumed = 0usize;
    let mut pipeline_hint_identities = BTreeSet::new();

    while cursor < exact_total_bytes {
        if records_consumed >= CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS {
            return Err(ChannelStreamHeadReadError::Decode(
                ChannelStreamHeadError::MaxRecordCountExceeded {
                    max_records: CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS,
                },
            ));
        }

        let probe_len = core::cmp::min(
            CHANNEL_STREAM_RECORD_PROBE_BYTES as u64,
            exact_total_bytes - cursor,
        ) as usize;
        let probe = read_channel_reader_bytes(reader, block_size, cursor, probe_len).await?;

        if boot_profile_bin_header_version(probe.as_slice()).is_some() {
            let (profile, consumed) = decode_prefixed_record_from_reader(
                reader,
                block_size,
                cursor,
                exact_total_bytes,
                "boot profile",
                decode_boot_profile_prefix,
            )
            .await?;

            validate_boot_profile(&profile).map_err(|err| {
                ChannelStreamHeadReadError::Decode(ChannelStreamHeadError::DecodeFailure {
                    record_type: "boot profile",
                    offset: cursor,
                    cause: format!(
                        "validate boot profile '{}' at stream offset {cursor}: {err}",
                        profile.id
                    ),
                })
            })?;

            if consumed == 0 {
                return Err(ChannelStreamHeadReadError::Decode(
                    ChannelStreamHeadError::EmptyRecord { offset: cursor },
                ));
            }

            out.boot_profiles.push(profile);
            cursor =
                cursor
                    .checked_add(consumed as u64)
                    .ok_or(ChannelStreamHeadReadError::Decode(
                        ChannelStreamHeadError::CursorOverflow,
                    ))?;
            records_consumed = records_consumed.saturating_add(1);
            continue;
        }

        if dev_profile_bin_header_version(probe.as_slice()).is_some() {
            let (profile, consumed) = decode_prefixed_record_from_reader(
                reader,
                block_size,
                cursor,
                exact_total_bytes,
                "dev profile",
                decode_dev_profile_prefix,
            )
            .await?;

            if consumed == 0 {
                return Err(ChannelStreamHeadReadError::Decode(
                    ChannelStreamHeadError::EmptyRecord { offset: cursor },
                ));
            }

            out.dev_profiles.push(profile);
            cursor =
                cursor
                    .checked_add(consumed as u64)
                    .ok_or(ChannelStreamHeadReadError::Decode(
                        ChannelStreamHeadError::CursorOverflow,
                    ))?;
            records_consumed = records_consumed.saturating_add(1);
            continue;
        }

        if channel_pipeline_hints_record_header_version(probe.as_slice()).is_some() {
            let fixed = read_channel_reader_bytes(
                reader,
                block_size,
                cursor,
                CHANNEL_PIPELINE_HINTS_RECORD_FIXED_HEADER_LEN,
            )
            .await?;
            let fixed_header = decode_channel_pipeline_hints_record_fixed_header(fixed.as_slice())
                .map_err(|err| {
                    ChannelStreamHeadReadError::Decode(ChannelStreamHeadError::DecodeFailure {
                        record_type: "pipeline hints",
                        offset: cursor,
                        cause: format!("decode pipeline hints stream at offset {cursor}: {err}"),
                    })
                })?;

            let metadata_size = usize::try_from(fixed_header.metadata_size_bytes)
                .map_err(|_| ChannelStreamHeadReadError::RangeOverflow)?;
            let record_prefix_len = CHANNEL_PIPELINE_HINTS_RECORD_FIXED_HEADER_LEN
                .checked_add(metadata_size)
                .ok_or(ChannelStreamHeadReadError::RangeOverflow)?;
            let record_prefix =
                read_channel_reader_bytes(reader, block_size, cursor, record_prefix_len).await?;
            let record_head = decode_channel_pipeline_hints_record_prefix(record_prefix.as_slice())
                .map_err(|err| {
                    ChannelStreamHeadReadError::Decode(ChannelStreamHeadError::DecodeFailure {
                        record_type: "pipeline hints",
                        offset: cursor,
                        cause: format!("decode pipeline hints stream at offset {cursor}: {err}"),
                    })
                })?;

            if record_head.total_record_size_bytes == 0 {
                return Err(ChannelStreamHeadReadError::Decode(
                    ChannelStreamHeadError::EmptyRecord { offset: cursor },
                ));
            }
            if record_head.total_record_size_bytes > exact_total_bytes.saturating_sub(cursor) {
                return Err(ChannelStreamHeadReadError::Decode(
                    ChannelStreamHeadError::DecodeFailure {
                        record_type: "pipeline hints",
                        offset: cursor,
                        cause: format!(
                            "decode pipeline hints stream at offset {cursor}: record exceeds channel size"
                        ),
                    },
                ));
            }

            append_pipeline_hint_identities(
                &mut pipeline_hint_identities,
                record_head.pipeline_identities.as_slice(),
            )
            .map_err(ChannelStreamHeadReadError::Decode)?;
            push_pipeline_hint_record(&mut out, cursor, &record_head)
                .map_err(ChannelStreamHeadReadError::Decode)?;

            cursor = cursor
                .checked_add(record_head.total_record_size_bytes)
                .ok_or(ChannelStreamHeadReadError::Decode(
                    ChannelStreamHeadError::CursorOverflow,
                ))?;
            records_consumed = records_consumed.saturating_add(1);
            continue;
        }

        if channel_stream_has_records(&out) {
            out.warning_count += 1;
        }
        break;
    }

    out.consumed_bytes = cursor;
    Ok(out)
}

fn read_indexed_channel_stream_head(
    bytes: &[u8],
    exact_total_bytes: u64,
) -> Result<ChannelStreamHead, ChannelStreamHeadError> {
    let fixed = decode_channel_index_record_fixed_header(bytes).map_err(|err| {
        ChannelStreamHeadError::DecodeFailure {
            record_type: "channel index",
            offset: 0,
            cause: format!("decode channel index header at offset 0: {err}"),
        }
    })?;
    let payload_size = fixed.payload_size_bytes as usize;
    let payload_start = CHANNEL_INDEX_RECORD_FIXED_HEADER_LEN;
    let payload_end = payload_start
        .checked_add(payload_size)
        .ok_or(ChannelStreamHeadError::CursorOverflow)?;
    if bytes.len() < payload_end || (exact_total_bytes as usize) < payload_end {
        return Err(ChannelStreamHeadError::DecodeFailure {
            record_type: "channel index",
            offset: 0,
            cause: format!(
                "channel index payload truncated (required {payload_end} bytes, got {})",
                bytes.len()
            ),
        });
    }
    let payload_bytes = &bytes[payload_start..payload_end];
    let index = decode_channel_index_payload(payload_bytes).map_err(|err| {
        ChannelStreamHeadError::DecodeFailure {
            record_type: "channel index",
            offset: 0,
            cause: format!("decode channel index payload at offset 0: {err}"),
        }
    })?;

    let base_offset = payload_end as u64;
    let records_region_size = exact_total_bytes
        .checked_sub(base_offset)
        .ok_or(ChannelStreamHeadError::CursorOverflow)?;
    validate_channel_index(
        &index,
        records_region_size,
        CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS,
    )
    .map_err(|err| ChannelStreamHeadError::DecodeFailure {
        record_type: "channel index",
        offset: 0,
        cause: format!("validate channel index at offset 0: {err}"),
    })?;

    let mut out = ChannelStreamHead::default();
    let mut last_end: u64 = 0;

    for (idx, entry) in index.entries.iter().enumerate() {
        match entry {
            ChannelIndexEntryV0::BootProfile { offset, size, id } => {
                let absolute = base_offset
                    .checked_add(*offset)
                    .ok_or(ChannelStreamHeadError::CursorOverflow)?;
                let end = absolute
                    .checked_add(*size)
                    .ok_or(ChannelStreamHeadError::CursorOverflow)?;
                let record_bytes =
                    record_slice(bytes, absolute, end, "boot profile", idx, *offset)?;
                if boot_profile_bin_header_version(record_bytes).is_none() {
                    return Err(ChannelStreamHeadError::DecodeFailure {
                        record_type: "boot profile",
                        offset: absolute,
                        cause: format!(
                            "channel index entry {idx} claims boot profile but record has wrong magic"
                        ),
                    });
                }
                let (profile, _) = decode_boot_profile_prefix(record_bytes).map_err(|err| {
                    ChannelStreamHeadError::DecodeFailure {
                        record_type: "boot profile",
                        offset: absolute,
                        cause: format!("decode boot profile stream at offset {absolute}: {err}"),
                    }
                })?;
                if profile.id != *id {
                    return Err(ChannelStreamHeadError::DecodeFailure {
                        record_type: "boot profile",
                        offset: absolute,
                        cause: format!(
                            "channel index entry {idx} id '{id}' does not match decoded profile id '{}'",
                            profile.id
                        ),
                    });
                }
                validate_boot_profile(&profile).map_err(|err| {
                    ChannelStreamHeadError::DecodeFailure {
                        record_type: "boot profile",
                        offset: absolute,
                        cause: format!(
                            "validate boot profile '{}' at stream offset {absolute}: {err}",
                            profile.id
                        ),
                    }
                })?;
                out.boot_profiles.push(profile);
                last_end = end;
            }
            ChannelIndexEntryV0::DeviceProfile { offset, size, id } => {
                let absolute = base_offset
                    .checked_add(*offset)
                    .ok_or(ChannelStreamHeadError::CursorOverflow)?;
                let end = absolute
                    .checked_add(*size)
                    .ok_or(ChannelStreamHeadError::CursorOverflow)?;
                let record_bytes = record_slice(bytes, absolute, end, "dev profile", idx, *offset)?;
                if dev_profile_bin_header_version(record_bytes).is_none() {
                    return Err(ChannelStreamHeadError::DecodeFailure {
                        record_type: "dev profile",
                        offset: absolute,
                        cause: format!(
                            "channel index entry {idx} claims dev profile but record has wrong magic"
                        ),
                    });
                }
                let (profile, _) = decode_dev_profile_prefix(record_bytes).map_err(|err| {
                    ChannelStreamHeadError::DecodeFailure {
                        record_type: "dev profile",
                        offset: absolute,
                        cause: format!("decode dev profile stream at offset {absolute}: {err}"),
                    }
                })?;
                if profile.id != *id {
                    return Err(ChannelStreamHeadError::DecodeFailure {
                        record_type: "dev profile",
                        offset: absolute,
                        cause: format!(
                            "channel index entry {idx} id '{id}' does not match decoded profile id '{}'",
                            profile.id
                        ),
                    });
                }
                out.dev_profiles.push(profile);
                last_end = end;
            }
            ChannelIndexEntryV0::PipelineHints {
                offset,
                size,
                payload_offset,
                payload_size,
                pipeline_identities,
            } => {
                let record_offset = base_offset
                    .checked_add(*offset)
                    .ok_or(ChannelStreamHeadError::CursorOverflow)?;
                let record_end = record_offset
                    .checked_add(*size)
                    .ok_or(ChannelStreamHeadError::CursorOverflow)?;
                let payload_abs_offset = base_offset
                    .checked_add(*payload_offset)
                    .ok_or(ChannelStreamHeadError::CursorOverflow)?;
                out.pipeline_hint_records.push(ChannelPipelineHintsRecord {
                    record_offset_bytes: record_offset,
                    payload_offset_bytes: payload_abs_offset,
                    payload_size_bytes: *payload_size,
                    pipeline_identities: pipeline_identities.clone(),
                });
                last_end = record_end;
            }
        }
    }

    out.consumed_bytes = last_end;
    Ok(out)
}

fn record_slice<'a>(
    bytes: &'a [u8],
    absolute: u64,
    end: u64,
    record_type: &'static str,
    idx: usize,
    _relative_offset: u64,
) -> Result<&'a [u8], ChannelStreamHeadError> {
    let start = usize::try_from(absolute).map_err(|_| ChannelStreamHeadError::CursorOverflow)?;
    let stop = usize::try_from(end).map_err(|_| ChannelStreamHeadError::CursorOverflow)?;
    if bytes.len() < stop {
        return Err(ChannelStreamHeadError::DecodeFailure {
            record_type,
            offset: absolute,
            cause: format!(
                "channel index entry {idx} extends beyond the input byte slice (required {stop} bytes, got {})",
                bytes.len()
            ),
        });
    }
    Ok(&bytes[start..stop])
}

enum DecodedIndexEntry {
    Boot {
        profile: BootProfile,
        end: u64,
    },
    Dev {
        profile: DeviceProfile,
        end: u64,
    },
    Hints {
        record: ChannelPipelineHintsRecord,
        end: u64,
    },
}

async fn read_indexed_channel_stream_head_from_reader<R: BlockReader + ?Sized>(
    reader: &R,
    block_size: usize,
    exact_total_bytes: u64,
) -> Result<ChannelStreamHead, ChannelStreamHeadReadError> {
    let fixed_bytes =
        read_channel_reader_bytes(reader, block_size, 0, CHANNEL_INDEX_RECORD_FIXED_HEADER_LEN)
            .await?;
    let fixed =
        decode_channel_index_record_fixed_header(fixed_bytes.as_slice()).map_err(|err| {
            ChannelStreamHeadReadError::Decode(ChannelStreamHeadError::DecodeFailure {
                record_type: "channel index",
                offset: 0,
                cause: format!("decode channel index header at offset 0: {err}"),
            })
        })?;
    let payload_size = fixed.payload_size_bytes as usize;
    let base_offset = (CHANNEL_INDEX_RECORD_FIXED_HEADER_LEN as u64)
        .checked_add(payload_size as u64)
        .ok_or(ChannelStreamHeadReadError::RangeOverflow)?;
    if base_offset > exact_total_bytes {
        return Err(ChannelStreamHeadReadError::Decode(
            ChannelStreamHeadError::DecodeFailure {
                record_type: "channel index",
                offset: 0,
                cause: format!(
                    "channel index payload (base_offset {base_offset}) exceeds channel size {exact_total_bytes}"
                ),
            },
        ));
    }

    let payload_bytes = read_channel_reader_bytes(
        reader,
        block_size,
        CHANNEL_INDEX_RECORD_FIXED_HEADER_LEN as u64,
        payload_size,
    )
    .await?;
    let index = decode_channel_index_payload(payload_bytes.as_slice()).map_err(|err| {
        ChannelStreamHeadReadError::Decode(ChannelStreamHeadError::DecodeFailure {
            record_type: "channel index",
            offset: 0,
            cause: format!("decode channel index payload at offset 0: {err}"),
        })
    })?;

    let records_region_size = exact_total_bytes
        .checked_sub(base_offset)
        .ok_or(ChannelStreamHeadReadError::RangeOverflow)?;
    validate_channel_index(
        &index,
        records_region_size,
        CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS,
    )
    .map_err(|err| {
        ChannelStreamHeadReadError::Decode(ChannelStreamHeadError::DecodeFailure {
            record_type: "channel index",
            offset: 0,
            cause: format!("validate channel index at offset 0: {err}"),
        })
    })?;

    let entries = &index.entries;
    let results: Vec<DecodedIndexEntry> =
        stream::iter(entries.iter().enumerate().map(|(idx, entry)| async move {
            decode_indexed_entry_from_reader(reader, block_size, base_offset, idx, entry).await
        }))
        .buffered(CHANNEL_INDEX_PARALLEL_FETCH_LIMIT)
        .try_collect()
        .await?;

    let mut out = ChannelStreamHead::default();
    let mut last_end: u64 = base_offset;
    for decoded in results {
        match decoded {
            DecodedIndexEntry::Boot { profile, end } => {
                out.boot_profiles.push(profile);
                last_end = end;
            }
            DecodedIndexEntry::Dev { profile, end } => {
                out.dev_profiles.push(profile);
                last_end = end;
            }
            DecodedIndexEntry::Hints { record, end } => {
                out.pipeline_hint_records.push(record);
                last_end = end;
            }
        }
    }
    out.consumed_bytes = last_end;
    Ok(out)
}

async fn decode_indexed_entry_from_reader<R: BlockReader + ?Sized>(
    reader: &R,
    block_size: usize,
    base_offset: u64,
    idx: usize,
    entry: &ChannelIndexEntryV0,
) -> Result<DecodedIndexEntry, ChannelStreamHeadReadError> {
    match entry {
        ChannelIndexEntryV0::BootProfile { offset, size, id } => {
            let absolute = base_offset
                .checked_add(*offset)
                .ok_or(ChannelStreamHeadReadError::RangeOverflow)?;
            let end = absolute
                .checked_add(*size)
                .ok_or(ChannelStreamHeadReadError::RangeOverflow)?;
            let size_usize =
                usize::try_from(*size).map_err(|_| ChannelStreamHeadReadError::RangeOverflow)?;
            let record_bytes =
                read_channel_reader_bytes(reader, block_size, absolute, size_usize).await?;
            if boot_profile_bin_header_version(record_bytes.as_slice()).is_none() {
                return Err(ChannelStreamHeadReadError::Decode(
                    ChannelStreamHeadError::DecodeFailure {
                        record_type: "boot profile",
                        offset: absolute,
                        cause: format!(
                            "channel index entry {idx} claims boot profile but record has wrong magic"
                        ),
                    },
                ));
            }
            let (profile, _) =
                decode_boot_profile_prefix(record_bytes.as_slice()).map_err(|err| {
                    ChannelStreamHeadReadError::Decode(ChannelStreamHeadError::DecodeFailure {
                        record_type: "boot profile",
                        offset: absolute,
                        cause: format!("decode boot profile stream at offset {absolute}: {err}"),
                    })
                })?;
            if profile.id != *id {
                return Err(ChannelStreamHeadReadError::Decode(
                    ChannelStreamHeadError::DecodeFailure {
                        record_type: "boot profile",
                        offset: absolute,
                        cause: format!(
                            "channel index entry {idx} id '{id}' does not match decoded profile id '{}'",
                            profile.id
                        ),
                    },
                ));
            }
            validate_boot_profile(&profile).map_err(|err| {
                ChannelStreamHeadReadError::Decode(ChannelStreamHeadError::DecodeFailure {
                    record_type: "boot profile",
                    offset: absolute,
                    cause: format!(
                        "validate boot profile '{}' at stream offset {absolute}: {err}",
                        profile.id
                    ),
                })
            })?;
            Ok(DecodedIndexEntry::Boot { profile, end })
        }
        ChannelIndexEntryV0::DeviceProfile { offset, size, id } => {
            let absolute = base_offset
                .checked_add(*offset)
                .ok_or(ChannelStreamHeadReadError::RangeOverflow)?;
            let end = absolute
                .checked_add(*size)
                .ok_or(ChannelStreamHeadReadError::RangeOverflow)?;
            let size_usize =
                usize::try_from(*size).map_err(|_| ChannelStreamHeadReadError::RangeOverflow)?;
            let record_bytes =
                read_channel_reader_bytes(reader, block_size, absolute, size_usize).await?;
            if dev_profile_bin_header_version(record_bytes.as_slice()).is_none() {
                return Err(ChannelStreamHeadReadError::Decode(
                    ChannelStreamHeadError::DecodeFailure {
                        record_type: "dev profile",
                        offset: absolute,
                        cause: format!(
                            "channel index entry {idx} claims dev profile but record has wrong magic"
                        ),
                    },
                ));
            }
            let (profile, _) =
                decode_dev_profile_prefix(record_bytes.as_slice()).map_err(|err| {
                    ChannelStreamHeadReadError::Decode(ChannelStreamHeadError::DecodeFailure {
                        record_type: "dev profile",
                        offset: absolute,
                        cause: format!("decode dev profile stream at offset {absolute}: {err}"),
                    })
                })?;
            if profile.id != *id {
                return Err(ChannelStreamHeadReadError::Decode(
                    ChannelStreamHeadError::DecodeFailure {
                        record_type: "dev profile",
                        offset: absolute,
                        cause: format!(
                            "channel index entry {idx} id '{id}' does not match decoded profile id '{}'",
                            profile.id
                        ),
                    },
                ));
            }
            Ok(DecodedIndexEntry::Dev { profile, end })
        }
        ChannelIndexEntryV0::PipelineHints {
            offset,
            size,
            payload_offset,
            payload_size,
            pipeline_identities,
        } => {
            // No fetch needed: the index already carries all the metadata
            // that ChannelPipelineHintsRecord needs for lazy payload loading.
            let record_offset = base_offset
                .checked_add(*offset)
                .ok_or(ChannelStreamHeadReadError::RangeOverflow)?;
            let end = record_offset
                .checked_add(*size)
                .ok_or(ChannelStreamHeadReadError::RangeOverflow)?;
            let payload_abs_offset = base_offset
                .checked_add(*payload_offset)
                .ok_or(ChannelStreamHeadReadError::RangeOverflow)?;
            Ok(DecodedIndexEntry::Hints {
                record: ChannelPipelineHintsRecord {
                    record_offset_bytes: record_offset,
                    payload_offset_bytes: payload_abs_offset,
                    payload_size_bytes: *payload_size,
                    pipeline_identities: pipeline_identities.clone(),
                },
                end,
            })
        }
    }
}

pub fn boot_profile_pipeline_identities(profile: &BootProfile) -> BTreeSet<String> {
    let mut identities = BTreeSet::new();
    collect_boot_profile_pipeline_identities_from_source(profile.rootfs.source(), &mut identities);
    if let Some(kernel) = profile.kernel.as_ref() {
        collect_boot_profile_pipeline_identities_from_source(
            kernel.artifact_source(),
            &mut identities,
        );
    }
    if let Some(dtbs) = profile.dtbs.as_ref() {
        collect_boot_profile_pipeline_identities_from_source(
            dtbs.artifact_source(),
            &mut identities,
        );
    }
    identities
}

pub async fn read_channel_pipeline_hints_for_boot_profile<R: BlockReader + ?Sized>(
    reader: &R,
    stream_head: &ChannelStreamHead,
    profile: &BootProfile,
) -> Result<PipelineHints, ChannelStreamHeadReadError> {
    let required = boot_profile_pipeline_identities(profile);
    read_channel_pipeline_hints_for_identities(reader, stream_head, &required).await
}

pub async fn read_channel_pipeline_hints_for_identities<R: BlockReader + ?Sized>(
    reader: &R,
    stream_head: &ChannelStreamHead,
    identities: &BTreeSet<String>,
) -> Result<PipelineHints, ChannelStreamHeadReadError> {
    if identities.is_empty() {
        return Ok(PipelineHints::default());
    }

    if stream_head.pipeline_hint_records.is_empty() {
        return Ok(filter_pipeline_hints_by_identity_set(
            &stream_head.pipeline_hints,
            identities,
        ));
    }

    let block_size = channel_reader_block_size(reader)?;

    let mut out = PipelineHints::default();
    let mut seen_identities = BTreeSet::new();

    for record in &stream_head.pipeline_hint_records {
        if !record
            .pipeline_identities
            .iter()
            .any(|identity| identities.contains(identity))
        {
            continue;
        }

        // Fetch the full record (fixed header + metadata section + payload)
        // rather than just the payload, and run the canonical decoder so
        // the metadata-vs-payload identity consistency check runs. The
        // hoisted `record.pipeline_identities` list came from the channel
        // index, which is not independently trustworthy: after the full
        // decode we cross-check decoded identities against the hoisted
        // list so a lying or stale index can't silently let a record
        // through with the wrong contents.
        let record_header_len = record
            .payload_offset_bytes
            .checked_sub(record.record_offset_bytes)
            .ok_or(ChannelStreamHeadReadError::RangeOverflow)?;
        let record_size = record_header_len
            .checked_add(record.payload_size_bytes)
            .ok_or(ChannelStreamHeadReadError::RangeOverflow)?;
        let record_size_usize =
            usize::try_from(record_size).map_err(|_| ChannelStreamHeadReadError::RangeOverflow)?;
        let record_bytes = read_channel_reader_bytes(
            reader,
            block_size,
            record.record_offset_bytes,
            record_size_usize,
        )
        .await?;

        let (hints, _consumed) = decode_channel_pipeline_hints_record(record_bytes.as_slice())
            .map_err(|err| {
                ChannelStreamHeadReadError::Decode(ChannelStreamHeadError::DecodeFailure {
                    record_type: "pipeline hints",
                    offset: record.record_offset_bytes,
                    cause: format!(
                        "decode pipeline hints record at offset {}: {err}",
                        record.record_offset_bytes
                    ),
                })
            })?;

        let decoded_identities: BTreeSet<&str> = hints
            .entries
            .iter()
            .map(|entry| entry.pipeline_identity.as_str())
            .collect();
        let hoisted_identities: BTreeSet<&str> = record
            .pipeline_identities
            .iter()
            .map(|s| s.as_str())
            .collect();
        if decoded_identities != hoisted_identities {
            return Err(ChannelStreamHeadReadError::Decode(
                ChannelStreamHeadError::DecodeFailure {
                    record_type: "pipeline hints",
                    offset: record.record_offset_bytes,
                    cause: format!(
                        "pipeline hints identity mismatch at offset {}: index claims {:?}, record payload has {:?}",
                        record.record_offset_bytes,
                        record.pipeline_identities,
                        hints
                            .entries
                            .iter()
                            .map(|e| e.pipeline_identity.as_str())
                            .collect::<Vec<_>>()
                    ),
                },
            ));
        }

        append_pipeline_hints(&mut out, &mut seen_identities, hints)
            .map_err(ChannelStreamHeadReadError::Decode)?;
    }

    out.entries
        .sort_unstable_by(|left, right| left.pipeline_identity.cmp(&right.pipeline_identity));
    Ok(out)
}

fn filter_pipeline_hints_by_identity_set(
    hints: &PipelineHints,
    identities: &BTreeSet<String>,
) -> PipelineHints {
    PipelineHints {
        entries: hints
            .entries
            .iter()
            .filter(|entry| identities.contains(&entry.pipeline_identity))
            .cloned()
            .collect(),
    }
}

fn collect_boot_profile_pipeline_identities_from_source(
    source: &BootProfileArtifactSource,
    out: &mut BTreeSet<String>,
) {
    out.insert(pipeline_identity_string(source));

    match source {
        BootProfileArtifactSource::Http(_)
        | BootProfileArtifactSource::File(_)
        | BootProfileArtifactSource::Casync(_) => {}
        BootProfileArtifactSource::Xz(source) => {
            collect_boot_profile_pipeline_identities_from_source(source.xz.as_ref(), out);
        }
        BootProfileArtifactSource::AndroidSparseImg(source) => {
            collect_boot_profile_pipeline_identities_from_source(
                source.android_sparseimg.source.as_ref(),
                out,
            );
        }
        BootProfileArtifactSource::Tar(source) => {
            collect_boot_profile_pipeline_identities_from_source(source.tar.source.as_ref(), out);
        }
        BootProfileArtifactSource::Mbr(source) => {
            collect_boot_profile_pipeline_identities_from_source(source.mbr.source.as_ref(), out);
        }
        BootProfileArtifactSource::Gpt(source) => {
            collect_boot_profile_pipeline_identities_from_source(source.gpt.source.as_ref(), out);
        }
    }
}

async fn decode_prefixed_record_from_reader<R, T, E, F>(
    reader: &R,
    block_size: usize,
    cursor: u64,
    exact_total_bytes: u64,
    record_type: &'static str,
    decode: F,
) -> Result<(T, usize), ChannelStreamHeadReadError>
where
    R: BlockReader + ?Sized,
    F: Fn(&[u8]) -> Result<(T, usize), E>,
    E: core::fmt::Display,
{
    let total_remaining = exact_total_bytes.saturating_sub(cursor);
    let max_window = core::cmp::min(
        total_remaining,
        CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES as u64,
    ) as usize;
    if max_window == 0 {
        return Err(ChannelStreamHeadReadError::Decode(
            ChannelStreamHeadError::DecodeFailure {
                record_type,
                offset: cursor,
                cause: format!("decode {record_type} stream at offset {cursor}: empty record"),
            },
        ));
    }

    let mut window = core::cmp::min(max_window, CHANNEL_STREAM_RECORD_INITIAL_READ_BYTES);
    if window == 0 {
        window = max_window;
    }
    loop {
        let bytes = read_channel_reader_bytes(reader, block_size, cursor, window).await?;
        match decode(bytes.as_slice()) {
            Ok(decoded) => return Ok(decoded),
            Err(err) => {
                let last_err = err.to_string();
                if window >= max_window {
                    if (max_window as u64) < total_remaining {
                        return Err(ChannelStreamHeadReadError::Decode(
                            ChannelStreamHeadError::DecodeHeadTruncated {
                                record_type,
                                offset: cursor,
                                cause: format!(
                                    "decode {record_type} stream at offset {cursor}: {last_err}; stream head exceeds {CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES} bytes"
                                ),
                            },
                        ));
                    }

                    return Err(ChannelStreamHeadReadError::Decode(
                        ChannelStreamHeadError::DecodeFailure {
                            record_type,
                            offset: cursor,
                            cause: format!(
                                "decode {record_type} stream at offset {cursor}: {last_err}"
                            ),
                        },
                    ));
                }

                let next_window = core::cmp::min(max_window, window.saturating_mul(2));
                if next_window == window {
                    return Err(ChannelStreamHeadReadError::Decode(
                        ChannelStreamHeadError::DecodeFailure {
                            record_type,
                            offset: cursor,
                            cause: format!(
                                "decode {record_type} stream at offset {cursor}: {last_err}"
                            ),
                        },
                    ));
                }
                window = next_window;
            }
        }
    }
}

fn channel_reader_block_size<R: BlockReader + ?Sized>(
    reader: &R,
) -> Result<usize, ChannelStreamHeadReadError> {
    let block_size = usize::try_from(reader.block_size()).map_err(|_| {
        ChannelStreamHeadReadError::InvalidReaderBlockSize {
            block_size: reader.block_size(),
        }
    })?;
    if block_size == 0 {
        return Err(ChannelStreamHeadReadError::InvalidReaderBlockSize {
            block_size: reader.block_size(),
        });
    }
    Ok(block_size)
}

async fn read_channel_reader_bytes<R: BlockReader + ?Sized>(
    reader: &R,
    block_size: usize,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, ChannelStreamHeadReadError> {
    if len == 0 {
        return Ok(Vec::new());
    }

    let block_size_u64 = block_size as u64;
    let start_block = offset / block_size_u64;
    let offset_in_block = usize::try_from(offset % block_size_u64)
        .map_err(|_| ChannelStreamHeadReadError::RangeOverflow)?;
    let required_bytes = offset_in_block
        .checked_add(len)
        .ok_or(ChannelStreamHeadReadError::RangeOverflow)?;
    let blocks_to_read = required_bytes.div_ceil(block_size);
    let aligned_bytes = blocks_to_read
        .checked_mul(block_size)
        .ok_or(ChannelStreamHeadReadError::RangeOverflow)?;

    let mut scratch = vec![0u8; aligned_bytes];
    let read = reader
        .read_blocks(start_block, &mut scratch, ReadContext::FOREGROUND)
        .await
        .map_err(|err| ChannelStreamHeadReadError::ReadFailure {
            offset,
            len,
            cause: format!("{err}"),
        })?;
    if read < required_bytes {
        return Err(ChannelStreamHeadReadError::ShortRead {
            offset,
            expected_bytes: required_bytes,
            actual_bytes: read,
        });
    }

    let end = offset_in_block
        .checked_add(len)
        .ok_or(ChannelStreamHeadReadError::RangeOverflow)?;
    Ok(scratch[offset_in_block..end].to_vec())
}

fn append_pipeline_hints(
    out: &mut PipelineHints,
    seen_identities: &mut BTreeSet<String>,
    hints: PipelineHints,
) -> Result<(), ChannelStreamHeadError> {
    for entry in hints.entries {
        if !seen_identities.insert(entry.pipeline_identity.clone()) {
            return Err(ChannelStreamHeadError::DuplicatePipelineHintIdentity {
                pipeline_identity: entry.pipeline_identity,
            });
        }
        out.entries.push(entry);
    }
    Ok(())
}

fn append_pipeline_hint_identities(
    seen_identities: &mut BTreeSet<String>,
    identities: &[String],
) -> Result<(), ChannelStreamHeadError> {
    for identity in identities {
        if !seen_identities.insert(identity.clone()) {
            return Err(ChannelStreamHeadError::DuplicatePipelineHintIdentity {
                pipeline_identity: identity.clone(),
            });
        }
    }
    Ok(())
}

fn push_pipeline_hint_record(
    out: &mut ChannelStreamHead,
    record_offset: u64,
    head: &ChannelPipelineHintsRecordHead,
) -> Result<(), ChannelStreamHeadError> {
    let payload_offset_bytes = record_offset
        .checked_add(head.payload_offset_bytes)
        .ok_or(ChannelStreamHeadError::CursorOverflow)?;
    out.pipeline_hint_records.push(ChannelPipelineHintsRecord {
        record_offset_bytes: record_offset,
        payload_offset_bytes,
        payload_size_bytes: head.payload_size_bytes,
        pipeline_identities: head.pipeline_identities.clone(),
    });
    Ok(())
}

fn channel_stream_has_records(stream: &ChannelStreamHead) -> bool {
    !stream.boot_profiles.is_empty()
        || !stream.dev_profiles.is_empty()
        || !stream.pipeline_hint_records.is_empty()
}

#[derive(Debug)]
pub enum BootProfileSelectionError {
    StreamEmpty,
    RequestedNotFound {
        requested: String,
        available: Vec<String>,
    },
    RequestedIncompatible {
        requested: String,
        device_profile_id: String,
    },
    NoCompatible {
        device_profile_id: String,
        available: Vec<String>,
    },
    TooManyCompatible {
        device_profile_id: String,
        available: Vec<String>,
    },
}

impl core::fmt::Display for BootProfileSelectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StreamEmpty => write!(f, "channel boot profile stream is empty"),
            Self::RequestedNotFound {
                requested,
                available,
            } => write!(
                f,
                "requested boot profile '{}' was not found in channel stream (available: {})",
                requested,
                available.join(", ")
            ),
            Self::RequestedIncompatible {
                requested,
                device_profile_id,
            } => write!(
                f,
                "boot profile '{}' is not compatible with device profile '{}'",
                requested, device_profile_id
            ),
            Self::NoCompatible {
                device_profile_id,
                available,
            } => write!(
                f,
                "no compatible boot profile found for device profile '{}' in channel stream (available: {})",
                device_profile_id,
                available.join(", ")
            ),
            Self::TooManyCompatible {
                device_profile_id,
                available,
            } => write!(
                f,
                "multiple compatible boot profiles found for device profile '{}' ({}); pass --boot-profile",
                device_profile_id,
                available.join(", ")
            ),
        }
    }
}

pub fn boot_profile_matches_device(profile: &BootProfile, device_profile_id: &str) -> bool {
    profile.stage0.devices.is_empty() || profile.stage0.devices.contains_key(device_profile_id)
}

pub fn select_boot_profile_for_device(
    profiles: &[BootProfile],
    device_profile_id: &str,
    requested_boot_profile_id: Option<&str>,
) -> Result<BootProfile, BootProfileSelectionError> {
    if profiles.is_empty() {
        return Err(BootProfileSelectionError::StreamEmpty);
    }

    if let Some(requested) = requested_boot_profile_id {
        let Some(profile) = profiles.iter().find(|profile| profile.id == requested) else {
            return Err(BootProfileSelectionError::RequestedNotFound {
                requested: String::from(requested),
                available: profile_ids(profiles),
            });
        };

        if !boot_profile_matches_device(profile, device_profile_id) {
            return Err(BootProfileSelectionError::RequestedIncompatible {
                requested: String::from(requested),
                device_profile_id: String::from(device_profile_id),
            });
        }

        return Ok(profile.clone());
    }

    let compatible: Vec<&BootProfile> = profiles
        .iter()
        .filter(|profile| boot_profile_matches_device(profile, device_profile_id))
        .collect();

    match compatible.as_slice() {
        [] => Err(BootProfileSelectionError::NoCompatible {
            device_profile_id: String::from(device_profile_id),
            available: profile_ids(profiles),
        }),
        [profile] => Ok((*profile).clone()),
        _ => Err(BootProfileSelectionError::TooManyCompatible {
            device_profile_id: String::from(device_profile_id),
            available: compatible
                .iter()
                .map(|profile| profile.id.clone())
                .collect(),
        }),
    }
}

fn profile_ids(profiles: &[BootProfile]) -> Vec<String> {
    profiles
        .iter()
        .map(|profile| profile.id.clone())
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::{ChannelHeadRecordLocation, scan_channel_head_record_locations};
    use gibblox_pipeline::{
        PipelineContentDigestHint, PipelineHint, PipelineHintEntry, PipelineHints,
    };

    use crate::encode_channel_pipeline_hints_record;

    use super::{ChannelStreamHeadError, read_channel_stream_head};

    #[test]
    fn merges_pipeline_hint_records_in_sorted_identity_order() {
        let first = encode_channel_pipeline_hints_record(&PipelineHints {
            entries: vec![pipeline_hint_entry(
                "xz{source=http{url=len:22:https://example.com/a;}}",
                "sha512:11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
            )],
        })
        .expect("encode first pipeline hints record");
        let second = encode_channel_pipeline_hints_record(&PipelineHints {
            entries: vec![pipeline_hint_entry(
                "android_sparseimg{source=xz{source=http{url=len:22:https://example.com/a;}}}",
                "sha512:22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222",
            )],
        })
        .expect("encode second pipeline hints record");

        let mut stream = first;
        stream.extend(second);

        let stream_head = read_channel_stream_head(&stream, stream.len() as u64)
            .expect("read channel stream with merged pipeline hints");

        let identities: Vec<&str> = stream_head
            .pipeline_hints
            .entries
            .iter()
            .map(|entry| entry.pipeline_identity.as_str())
            .collect();
        assert_eq!(
            identities,
            vec![
                "android_sparseimg{source=xz{source=http{url=len:22:https://example.com/a;}}}",
                "xz{source=http{url=len:22:https://example.com/a;}}",
            ]
        );
        assert_eq!(stream_head.pipeline_hint_records.len(), 2);
    }

    #[test]
    fn rejects_duplicate_pipeline_hint_identity_across_records() {
        let first = encode_channel_pipeline_hints_record(&PipelineHints {
            entries: vec![pipeline_hint_entry(
                "xz{source=http{url=len:22:https://example.com/a;}}",
                "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )],
        })
        .expect("encode first pipeline hints record");
        let second = encode_channel_pipeline_hints_record(&PipelineHints {
            entries: vec![pipeline_hint_entry(
                "xz{source=http{url=len:22:https://example.com/a;}}",
                "sha512:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )],
        })
        .expect("encode second pipeline hints record");

        let mut stream = first;
        stream.extend(second);

        let err = read_channel_stream_head(&stream, stream.len() as u64)
            .expect_err("duplicate identity should fail");

        match err {
            ChannelStreamHeadError::DuplicatePipelineHintIdentity { pipeline_identity } => {
                assert_eq!(
                    pipeline_identity,
                    "xz{source=http{url=len:22:https://example.com/a;}}"
                );
            }
            other => panic!("expected duplicate pipeline identity error, got {other:?}"),
        }
    }

    fn pipeline_hint_entry(identity: &str, digest: &str) -> PipelineHintEntry {
        PipelineHintEntry {
            pipeline_identity: String::from(identity),
            hints: vec![PipelineHint::ContentDigest(PipelineContentDigestHint {
                digest: String::from(digest),
                size_bytes: 1,
            })],
        }
    }

    #[test]
    fn indexed_channel_round_trips_pipeline_hints() {
        use crate::ChannelHeadRecord;
        use crate::channel_index::encode_channel_head;

        let hints = PipelineHints {
            entries: vec![pipeline_hint_entry(
                "xz{source=http{url=len:22:https://example.com/a;}}",
                "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )],
        };
        let encoded = encode_channel_head(&[ChannelHeadRecord::PipelineHints(hints.clone())])
            .expect("encode indexed channel head");
        let head = read_channel_stream_head(&encoded, encoded.len() as u64)
            .expect("read indexed channel head");
        assert!(head.boot_profiles.is_empty());
        assert!(head.dev_profiles.is_empty());
        // Lazy-load contract: indexed path populates records but leaves inline hints empty.
        assert!(head.pipeline_hints.entries.is_empty());
        assert_eq!(head.pipeline_hint_records.len(), 1);
        assert_eq!(
            head.pipeline_hint_records[0].pipeline_identities,
            vec![String::from(
                "xz{source=http{url=len:22:https://example.com/a;}}"
            )]
        );
        assert_eq!(head.consumed_bytes, encoded.len() as u64);
        assert_eq!(head.warning_count, 0);
    }

    #[test]
    fn indexed_channel_rejects_invalid_payload() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"FBCHIDX0");
        bytes.extend_from_slice(&0u16.to_le_bytes()); // version
        bytes.extend_from_slice(&16u32.to_le_bytes()); // payload size
        bytes.extend_from_slice(&[0u8; 16]); // garbage payload
        let err = read_channel_stream_head(&bytes, bytes.len() as u64).expect_err("bad payload");
        assert!(matches!(err, ChannelStreamHeadError::DecodeFailure { .. }));
    }

    #[test]
    fn scan_channel_head_record_locations_tracks_pipeline_hints() {
        let hints = PipelineHints {
            entries: vec![pipeline_hint_entry(
                "xz{source=http{url=len:22:https://example.com/a;}}",
                "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )],
        };
        let bytes = encode_channel_pipeline_hints_record(&hints).expect("encode hints");
        let (locations, consumed) =
            scan_channel_head_record_locations(&bytes, bytes.len() as u64).expect("scan");
        assert_eq!(consumed, bytes.len() as u64);
        assert_eq!(locations.len(), 1);
        match &locations[0] {
            ChannelHeadRecordLocation::PipelineHints {
                offset,
                size,
                payload_offset,
                payload_size,
                pipeline_identities,
            } => {
                assert_eq!(*offset, 0);
                assert_eq!(*size, bytes.len() as u64);
                assert!(*payload_offset > 0);
                assert!(*payload_size > 0);
                assert_eq!(
                    pipeline_identities,
                    &vec![String::from(
                        "xz{source=http{url=len:22:https://example.com/a;}}"
                    )]
                );
            }
            other => panic!("expected PipelineHints location, got {other:?}"),
        }
    }

    #[test]
    fn scan_channel_head_record_locations_rejects_truncated_prefix() {
        // Produce a real hint record, then lie to the scanner by passing a
        // truncated prefix with exact_total_bytes pointing past what we
        // actually have. Scan should refuse to produce a partial index.
        let hints = PipelineHints {
            entries: vec![pipeline_hint_entry(
                "xz{source=http{url=len:22:https://example.com/a;}}",
                "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )],
        };
        let bytes = encode_channel_pipeline_hints_record(&hints).expect("encode hints");
        // Claim the channel is 4x larger than the slice we hand over.
        let lying_total = (bytes.len() as u64) * 4;
        let err = scan_channel_head_record_locations(&bytes, lying_total).expect_err("truncated");
        match err {
            ChannelStreamHeadError::DecodeFailure {
                record_type, cause, ..
            } => {
                assert_eq!(record_type, "channel head scan");
                assert!(
                    cause.contains("truncated channel prefix"),
                    "expected truncated prefix diagnostic, got {cause}"
                );
            }
            other => panic!("expected DecodeFailure, got {other:?}"),
        }
    }

    #[test]
    fn scan_channel_head_record_locations_walks_past_legacy_4mb_cap() {
        // Legacy 4MB scan cap used to silently stop the walk. The byte-slice
        // scan helper no longer imposes that cap, so a channel whose head
        // records extend past 4MB should still be walked end-to-end.
        // We don't actually build a 4MB-plus channel here (would be slow);
        // this test documents the lifted cap via a small-but-explicit scan
        // on a channel with two back-to-back records and asserts the helper
        // visits both. The truncation-rejection test above covers the
        // "incomplete caller input" case.
        let first = encode_channel_pipeline_hints_record(&PipelineHints {
            entries: vec![pipeline_hint_entry(
                "xz{source=http{url=len:22:https://example.com/a;}}",
                "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )],
        })
        .expect("encode first");
        let second = encode_channel_pipeline_hints_record(&PipelineHints {
            entries: vec![pipeline_hint_entry(
                "xz{source=http{url=len:22:https://example.com/b;}}",
                "sha512:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )],
        })
        .expect("encode second");
        let mut stream = first;
        stream.extend(second);
        let (locations, consumed) =
            scan_channel_head_record_locations(&stream, stream.len() as u64)
                .expect("scan both records");
        assert_eq!(locations.len(), 2);
        assert_eq!(consumed, stream.len() as u64);
    }

    #[test]
    fn scan_channel_head_record_locations_rejects_already_indexed() {
        use crate::ChannelHeadRecord;
        use crate::channel_index::encode_channel_head;

        let hints = PipelineHints {
            entries: vec![pipeline_hint_entry(
                "xz{source=http{url=len:22:https://example.com/a;}}",
                "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )],
        };
        let encoded = encode_channel_head(&[ChannelHeadRecord::PipelineHints(hints)])
            .expect("encode indexed");
        let err = scan_channel_head_record_locations(&encoded, encoded.len() as u64)
            .expect_err("indexed rejected");
        match err {
            ChannelStreamHeadError::DecodeFailure {
                record_type, cause, ..
            } => {
                assert_eq!(record_type, "channel index");
                assert!(cause.contains("already begins"));
            }
            other => panic!("expected DecodeFailure, got {other:?}"),
        }
    }
}
