use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use gibblox_core::{BlockReader, ReadContext};
use gibblox_pipeline::{PipelineHints, pipeline_identity_string};

use crate::channel_pipeline_hints::{
    CHANNEL_PIPELINE_HINTS_RECORD_FIXED_HEADER_LEN, ChannelPipelineHintsRecordHead,
    channel_pipeline_hints_record_header_version, decode_channel_pipeline_hints_record,
    decode_channel_pipeline_hints_record_fixed_header,
    decode_channel_pipeline_hints_record_payload, decode_channel_pipeline_hints_record_prefix,
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

pub async fn read_channel_stream_head_from_reader<R: BlockReader + ?Sized>(
    reader: &R,
    exact_total_bytes: u64,
) -> Result<ChannelStreamHead, ChannelStreamHeadReadError> {
    let block_size = channel_reader_block_size(reader)?;

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

        let payload_len = usize::try_from(record.payload_size_bytes)
            .map_err(|_| ChannelStreamHeadReadError::RangeOverflow)?;
        let payload =
            read_channel_reader_bytes(reader, block_size, record.payload_offset_bytes, payload_len)
                .await?;
        let hints =
            decode_channel_pipeline_hints_record_payload(payload.as_slice()).map_err(|err| {
                ChannelStreamHeadReadError::Decode(ChannelStreamHeadError::DecodeFailure {
                    record_type: "pipeline hints",
                    offset: record.record_offset_bytes,
                    cause: format!(
                        "decode pipeline hints payload at offset {}: {err}",
                        record.payload_offset_bytes
                    ),
                })
            })?;

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
}
