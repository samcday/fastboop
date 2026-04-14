extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use fastboop_schema::{BootProfile, DeviceProfile};
use gibblox_pipeline::PipelineHints;
use serde::{Deserialize, Serialize};

use crate::bootprofile::encode_boot_profile;
use crate::channel_pipeline_hints::{
    CHANNEL_PIPELINE_HINTS_RECORD_FIXED_HEADER_LEN, ChannelPipelineHintsRecordCodecError,
    decode_channel_pipeline_hints_record_prefix, encode_channel_pipeline_hints_record,
};
use crate::devpro::encode_dev_profile;
use crate::validate_boot_profile;

pub const CHANNEL_INDEX_RECORD_MAGIC: [u8; 8] = *b"FBCHIDX0";
pub const CHANNEL_INDEX_RECORD_FORMAT_VERSION: u16 = 0;
pub const CHANNEL_INDEX_RECORD_FIXED_HEADER_LEN: usize = CHANNEL_INDEX_RECORD_MAGIC.len() + 2 + 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelIndexRecordFixedHeader {
    pub payload_size_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ChannelIndexV0 {
    pub entries: Vec<ChannelIndexEntryV0>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ChannelIndexEntryV0 {
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
        payload_offset: u64,
        payload_size: u64,
        pipeline_identities: Vec<String>,
    },
}

impl ChannelIndexEntryV0 {
    pub(crate) fn offset(&self) -> u64 {
        match self {
            Self::BootProfile { offset, .. }
            | Self::DeviceProfile { offset, .. }
            | Self::PipelineHints { offset, .. } => *offset,
        }
    }

    pub(crate) fn size(&self) -> u64 {
        match self {
            Self::BootProfile { size, .. }
            | Self::DeviceProfile { size, .. }
            | Self::PipelineHints { size, .. } => *size,
        }
    }
}

pub enum ChannelHeadRecord {
    BootProfile(BootProfile),
    DeviceProfile(DeviceProfile),
    PipelineHints(PipelineHints),
}

#[derive(Debug)]
pub enum ChannelIndexCodecError {
    Decode(postcard::Error),
    InvalidMagic,
    UnsupportedFormatVersion(u16),
    LengthOverflow,
    TruncatedRecord {
        required_bytes: usize,
        available_bytes: usize,
    },
    Empty,
    TooManyRecords {
        max_records: usize,
    },
    EntryEmptySize {
        index: usize,
    },
    EntryOutOfOrder {
        index: usize,
    },
    EntryOutOfBounds {
        index: usize,
    },
    PipelineHintsPayloadOutOfBounds {
        index: usize,
    },
    RecordCodec {
        cause: String,
    },
}

impl core::fmt::Display for ChannelIndexCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(err) => write!(f, "decode channel index record: {err}"),
            Self::InvalidMagic => write!(
                f,
                "invalid channel index record magic (expected {CHANNEL_INDEX_RECORD_MAGIC:?})"
            ),
            Self::UnsupportedFormatVersion(version) => write!(
                f,
                "unsupported channel index record format version {version} (expected {CHANNEL_INDEX_RECORD_FORMAT_VERSION})"
            ),
            Self::LengthOverflow => write!(f, "channel index record length overflow"),
            Self::TruncatedRecord {
                required_bytes,
                available_bytes,
            } => write!(
                f,
                "channel index record is truncated (required {required_bytes} bytes, got {available_bytes})"
            ),
            Self::Empty => write!(f, "channel index must contain at least one entry"),
            Self::TooManyRecords { max_records } => {
                write!(f, "channel index exceeds max record count {max_records}")
            }
            Self::EntryEmptySize { index } => {
                write!(f, "channel index entry {index} has zero size")
            }
            Self::EntryOutOfOrder { index } => write!(
                f,
                "channel index entry {index} is not strictly increasing by offset"
            ),
            Self::EntryOutOfBounds { index } => {
                write!(f, "channel index entry {index} points past end of channel")
            }
            Self::PipelineHintsPayloadOutOfBounds { index } => write!(
                f,
                "channel index pipeline hints entry {index} has payload outside record bounds"
            ),
            Self::RecordCodec { cause } => write!(f, "{cause}"),
        }
    }
}

impl From<postcard::Error> for ChannelIndexCodecError {
    fn from(err: postcard::Error) -> Self {
        Self::Decode(err)
    }
}

impl From<ChannelPipelineHintsRecordCodecError> for ChannelIndexCodecError {
    fn from(err: ChannelPipelineHintsRecordCodecError) -> Self {
        Self::RecordCodec {
            cause: err.to_string(),
        }
    }
}

/// Encode a channel head as a single indexed byte stream.
///
/// Layout: `[FBCHIDX0 header | postcard ChannelIndexV0 | record0 | record1 | ...]`.
///
/// All per-entry offsets are relative to the byte immediately following the
/// index record (i.e. offset 0 == first record byte). This keeps the writer
/// from needing to know the encoded index size in advance — offsets depend
/// only on the per-record byte sizes.
pub fn encode_channel_head(
    records: &[ChannelHeadRecord],
) -> Result<Vec<u8>, ChannelIndexCodecError> {
    if records.is_empty() {
        return Err(ChannelIndexCodecError::Empty);
    }

    let mut encoded_records: Vec<Vec<u8>> = Vec::with_capacity(records.len());
    let mut entries: Vec<ChannelIndexEntryV0> = Vec::with_capacity(records.len());
    let mut running_offset: u64 = 0;

    for record in records {
        let (entry, bytes) = encode_record_for_index(record, running_offset)?;
        let size = entry.size();
        running_offset = running_offset
            .checked_add(size)
            .ok_or(ChannelIndexCodecError::LengthOverflow)?;
        entries.push(entry);
        encoded_records.push(bytes);
    }

    let index_record = encode_channel_index_record_bytes(entries)?;
    let total_records_bytes: usize = encoded_records.iter().map(|b| b.len()).sum();
    let capacity = index_record
        .len()
        .checked_add(total_records_bytes)
        .ok_or(ChannelIndexCodecError::LengthOverflow)?;

    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(index_record.as_slice());
    for record in encoded_records {
        out.extend_from_slice(record.as_slice());
    }
    Ok(out)
}

/// Encode a standalone `FBCHIDX0` index record (header + payload, no trailing
/// records). Used by `fastboop channel index` to wrap an already-concatenated
/// channel byte stream with an index prefix — the original records live
/// immediately after this record and their relative offsets (from
/// end-of-index) stay valid without rewriting.
pub fn encode_channel_index_record_from_locations(
    locations: &[crate::channel_intake::ChannelHeadRecordLocation],
) -> Result<Vec<u8>, ChannelIndexCodecError> {
    use crate::channel_intake::ChannelHeadRecordLocation;
    if locations.is_empty() {
        return Err(ChannelIndexCodecError::Empty);
    }
    let mut entries: Vec<ChannelIndexEntryV0> = Vec::with_capacity(locations.len());
    for location in locations {
        let entry = match location {
            ChannelHeadRecordLocation::BootProfile { offset, size, id } => {
                ChannelIndexEntryV0::BootProfile {
                    offset: *offset,
                    size: *size,
                    id: id.clone(),
                }
            }
            ChannelHeadRecordLocation::DeviceProfile { offset, size, id } => {
                ChannelIndexEntryV0::DeviceProfile {
                    offset: *offset,
                    size: *size,
                    id: id.clone(),
                }
            }
            ChannelHeadRecordLocation::PipelineHints {
                offset,
                size,
                payload_offset,
                payload_size,
                pipeline_identities,
            } => {
                let absolute_payload_offset = offset
                    .checked_add(*payload_offset)
                    .ok_or(ChannelIndexCodecError::LengthOverflow)?;
                ChannelIndexEntryV0::PipelineHints {
                    offset: *offset,
                    size: *size,
                    payload_offset: absolute_payload_offset,
                    payload_size: *payload_size,
                    pipeline_identities: pipeline_identities.clone(),
                }
            }
        };
        entries.push(entry);
    }
    encode_channel_index_record_bytes(entries)
}

fn encode_channel_index_record_bytes(
    entries: Vec<ChannelIndexEntryV0>,
) -> Result<Vec<u8>, ChannelIndexCodecError> {
    let index_payload = postcard::to_allocvec(&ChannelIndexV0 { entries })?;
    let payload_len =
        u32::try_from(index_payload.len()).map_err(|_| ChannelIndexCodecError::LengthOverflow)?;
    let capacity = CHANNEL_INDEX_RECORD_FIXED_HEADER_LEN
        .checked_add(index_payload.len())
        .ok_or(ChannelIndexCodecError::LengthOverflow)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(&CHANNEL_INDEX_RECORD_MAGIC);
    out.extend_from_slice(&CHANNEL_INDEX_RECORD_FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(index_payload.as_slice());
    Ok(out)
}

fn encode_record_for_index(
    record: &ChannelHeadRecord,
    offset: u64,
) -> Result<(ChannelIndexEntryV0, Vec<u8>), ChannelIndexCodecError> {
    match record {
        ChannelHeadRecord::BootProfile(profile) => {
            validate_boot_profile(profile).map_err(|err| ChannelIndexCodecError::RecordCodec {
                cause: format!("validate boot profile '{}': {err}", profile.id),
            })?;
            let bytes = encode_boot_profile(profile).map_err(|err| {
                ChannelIndexCodecError::RecordCodec {
                    cause: format!("encode boot profile '{}': {err}", profile.id),
                }
            })?;
            let size = bytes.len() as u64;
            Ok((
                ChannelIndexEntryV0::BootProfile {
                    offset,
                    size,
                    id: profile.id.clone(),
                },
                bytes,
            ))
        }
        ChannelHeadRecord::DeviceProfile(profile) => {
            let bytes =
                encode_dev_profile(profile).map_err(|err| ChannelIndexCodecError::RecordCodec {
                    cause: format!("encode dev profile '{}': {err}", profile.id),
                })?;
            let size = bytes.len() as u64;
            Ok((
                ChannelIndexEntryV0::DeviceProfile {
                    offset,
                    size,
                    id: profile.id.clone(),
                },
                bytes,
            ))
        }
        ChannelHeadRecord::PipelineHints(hints) => {
            let bytes = encode_channel_pipeline_hints_record(hints)?;
            let head = decode_channel_pipeline_hints_record_prefix(bytes.as_slice())?;
            let size = bytes.len() as u64;
            let payload_offset = offset
                .checked_add(head.payload_offset_bytes)
                .ok_or(ChannelIndexCodecError::LengthOverflow)?;
            Ok((
                ChannelIndexEntryV0::PipelineHints {
                    offset,
                    size,
                    payload_offset,
                    payload_size: head.payload_size_bytes,
                    pipeline_identities: head.pipeline_identities,
                },
                bytes,
            ))
        }
    }
}

/// Decode the 14-byte fixed header of an `FBCHIDX0` record.
pub fn decode_channel_index_record_fixed_header(
    bytes: &[u8],
) -> Result<ChannelIndexRecordFixedHeader, ChannelIndexCodecError> {
    let Some(format_version) = channel_index_record_header_version(bytes) else {
        return Err(ChannelIndexCodecError::InvalidMagic);
    };
    if format_version != CHANNEL_INDEX_RECORD_FORMAT_VERSION {
        return Err(ChannelIndexCodecError::UnsupportedFormatVersion(
            format_version,
        ));
    }

    let payload_len_start = CHANNEL_INDEX_RECORD_MAGIC.len() + 2;
    let payload_size_bytes = u32::from_le_bytes([
        bytes[payload_len_start],
        bytes[payload_len_start + 1],
        bytes[payload_len_start + 2],
        bytes[payload_len_start + 3],
    ]);

    Ok(ChannelIndexRecordFixedHeader { payload_size_bytes })
}

/// Decode the postcard-serialized index payload from a slice sized exactly
/// to `payload_size_bytes` (from the fixed header).
pub(crate) fn decode_channel_index_payload(
    bytes: &[u8],
) -> Result<ChannelIndexV0, ChannelIndexCodecError> {
    let index: ChannelIndexV0 = postcard::from_bytes(bytes)?;
    Ok(index)
}

pub fn channel_index_record_header_version(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < CHANNEL_INDEX_RECORD_FIXED_HEADER_LEN {
        return None;
    }
    if bytes[..CHANNEL_INDEX_RECORD_MAGIC.len()] != CHANNEL_INDEX_RECORD_MAGIC {
        return None;
    }
    Some(u16::from_le_bytes([
        bytes[CHANNEL_INDEX_RECORD_MAGIC.len()],
        bytes[CHANNEL_INDEX_RECORD_MAGIC.len() + 1],
    ]))
}

pub(crate) fn validate_channel_index(
    index: &ChannelIndexV0,
    records_region_size: u64,
    max_records: usize,
) -> Result<(), ChannelIndexCodecError> {
    if index.entries.is_empty() {
        return Err(ChannelIndexCodecError::Empty);
    }
    if index.entries.len() > max_records {
        return Err(ChannelIndexCodecError::TooManyRecords { max_records });
    }

    let mut expected_next_offset: u64 = 0;
    for (idx, entry) in index.entries.iter().enumerate() {
        let offset = entry.offset();
        let size = entry.size();
        if size == 0 {
            return Err(ChannelIndexCodecError::EntryEmptySize { index: idx });
        }
        if offset < expected_next_offset {
            return Err(ChannelIndexCodecError::EntryOutOfOrder { index: idx });
        }
        let end = offset
            .checked_add(size)
            .ok_or(ChannelIndexCodecError::LengthOverflow)?;
        if end > records_region_size {
            return Err(ChannelIndexCodecError::EntryOutOfBounds { index: idx });
        }
        if let ChannelIndexEntryV0::PipelineHints {
            payload_offset,
            payload_size,
            ..
        } = entry
        {
            let header_boundary = offset
                .checked_add(CHANNEL_PIPELINE_HINTS_RECORD_FIXED_HEADER_LEN as u64)
                .ok_or(ChannelIndexCodecError::LengthOverflow)?;
            if *payload_offset < header_boundary {
                return Err(ChannelIndexCodecError::PipelineHintsPayloadOutOfBounds { index: idx });
            }
            let payload_end = payload_offset
                .checked_add(*payload_size)
                .ok_or(ChannelIndexCodecError::LengthOverflow)?;
            if payload_end > end {
                return Err(ChannelIndexCodecError::PipelineHintsPayloadOutOfBounds { index: idx });
            }
        }
        expected_next_offset = end;
    }

    // Sanity-check identity set is non-duplicated within each hints entry.
    for (idx, entry) in index.entries.iter().enumerate() {
        if let ChannelIndexEntryV0::PipelineHints {
            pipeline_identities,
            ..
        } = entry
        {
            let mut set: BTreeSet<&str> = BTreeSet::new();
            for identity in pipeline_identities {
                if !set.insert(identity.as_str()) {
                    return Err(ChannelIndexCodecError::RecordCodec {
                        cause: format!(
                            "channel index pipeline hints entry {idx} duplicate identity '{identity}'"
                        ),
                    });
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec;

    use fastboop_schema::{
        AndroidBootImage, AndroidKernel, Boot, BootPayload, BootProfile, BootProfileArtifactSource,
        BootProfileArtifactSourceHttpSource, BootProfileRootfs, BootProfileRootfsErofsSource,
        BootProfileStage0, DeviceProfile, FastbootMatch, KernelEncoding, MatchRule, Stage0,
    };
    use gibblox_pipeline::{
        PipelineContentDigestHint, PipelineHint, PipelineHintEntry, PipelineHints,
        PipelineSourceContent,
    };

    use super::*;
    use crate::channel_pipeline_hints::decode_channel_pipeline_hints_record_prefix;

    fn sample_boot_profile(id: &str) -> BootProfile {
        let digest = alloc::format!("sha512:{}", "0".repeat(128));
        BootProfile {
            id: String::from(id),
            display_name: None,
            rootfs: BootProfileRootfs::Erofs(BootProfileRootfsErofsSource {
                erofs: BootProfileArtifactSource::Http(BootProfileArtifactSourceHttpSource {
                    http: String::from("https://example.com/rootfs.ero"),
                    cors_safelisted_mode: false,
                    content: Some(PipelineSourceContent {
                        digest,
                        size_bytes: 1024,
                    }),
                }),
            }),
            kernel: None,
            dtbs: None,
            dt_overlays: vec![],
            extra_cmdline: None,
            stage0: BootProfileStage0::default(),
        }
    }

    fn sample_dev_profile(id: &str) -> DeviceProfile {
        DeviceProfile {
            id: String::from(id),
            display_name: None,
            devicetree_name: String::from("test-device-tree"),
            r#match: vec![MatchRule {
                fastboot: FastbootMatch {
                    vid: 0x1234,
                    pid: 0x5678,
                },
            }],
            probe: vec![],
            boot: Boot {
                fastboot_boot: BootPayload {
                    android_bootimg: AndroidBootImage {
                        header_version: 2,
                        page_size: 4096,
                        base: None,
                        kernel_offset: None,
                        dtb_offset: None,
                        limits: None,
                        kernel: AndroidKernel {
                            encoding: KernelEncoding::Image,
                        },
                        initrd: None,
                        cmdline_append: None,
                    },
                },
            },
            stage0: Stage0 {
                kernel_modules: vec![],
                inject_mac: None,
            },
        }
    }

    fn sample_pipeline_hints() -> PipelineHints {
        PipelineHints {
            entries: vec![
                PipelineHintEntry {
                    pipeline_identity: String::from(
                        "android_sparseimg{source=http{url=len:9:https://a;}}",
                    ),
                    hints: vec![PipelineHint::ContentDigest(PipelineContentDigestHint {
                        digest: String::from(
                            "sha512:11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
                        ),
                        size_bytes: 1,
                    })],
                },
                PipelineHintEntry {
                    pipeline_identity: String::from("xz{source=http{url=len:9:https://b;}}"),
                    hints: vec![PipelineHint::ContentDigest(PipelineContentDigestHint {
                        digest: String::from(
                            "sha512:22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222",
                        ),
                        size_bytes: 2,
                    })],
                },
            ],
        }
    }

    #[test]
    fn encode_channel_head_roundtrips_mixed_records() {
        let records = vec![
            ChannelHeadRecord::DeviceProfile(sample_dev_profile("dev-one")),
            ChannelHeadRecord::BootProfile(sample_boot_profile("boot-one")),
            ChannelHeadRecord::PipelineHints(sample_pipeline_hints()),
        ];
        let encoded = encode_channel_head(&records).expect("encode channel head");

        assert_eq!(&encoded[..8], &CHANNEL_INDEX_RECORD_MAGIC);
        let header = decode_channel_index_record_fixed_header(&encoded).expect("fixed header");
        let payload_start = CHANNEL_INDEX_RECORD_FIXED_HEADER_LEN;
        let payload_end = payload_start + header.payload_size_bytes as usize;
        let payload = &encoded[payload_start..payload_end];
        let index = decode_channel_index_payload(payload).expect("decode payload");

        assert_eq!(index.entries.len(), 3);

        let region_size = (encoded.len() - payload_end) as u64;
        validate_channel_index(&index, region_size, 128).expect("validate");

        match &index.entries[0] {
            ChannelIndexEntryV0::DeviceProfile { offset, id, .. } => {
                assert_eq!(*offset, 0);
                assert_eq!(id, "dev-one");
            }
            other => panic!("entry 0 should be DeviceProfile, got {other:?}"),
        }
        match &index.entries[1] {
            ChannelIndexEntryV0::BootProfile { id, .. } => {
                assert_eq!(id, "boot-one");
            }
            other => panic!("entry 1 should be BootProfile, got {other:?}"),
        }
        match &index.entries[2] {
            ChannelIndexEntryV0::PipelineHints {
                offset,
                size,
                payload_offset,
                payload_size,
                pipeline_identities,
            } => {
                assert_eq!(pipeline_identities.len(), 2);
                // Hoisted identities must match what the hint record's own prefix exposes.
                let record_start = payload_end as u64 + *offset;
                let record_end = record_start + *size;
                let record_bytes = &encoded[record_start as usize..record_end as usize];
                let head = decode_channel_pipeline_hints_record_prefix(record_bytes)
                    .expect("prefix decode");
                assert_eq!(head.pipeline_identities, *pipeline_identities);
                assert_eq!(
                    *payload_offset - *offset,
                    head.payload_offset_bytes,
                    "hoisted payload_offset must match record's internal offset",
                );
                assert_eq!(*payload_size, head.payload_size_bytes);
            }
            other => panic!("entry 2 should be PipelineHints, got {other:?}"),
        }
    }

    #[test]
    fn encode_channel_head_is_deterministic() {
        let records = vec![
            ChannelHeadRecord::DeviceProfile(sample_dev_profile("dev-one")),
            ChannelHeadRecord::BootProfile(sample_boot_profile("boot-one")),
        ];
        let first = encode_channel_head(&records).expect("encode 1");
        let second = encode_channel_head(&records).expect("encode 2");
        assert_eq!(first, second);
    }

    #[test]
    fn encode_channel_head_rejects_empty() {
        let err = encode_channel_head(&[]).expect_err("empty rejected");
        assert!(matches!(err, ChannelIndexCodecError::Empty));
    }

    #[test]
    fn decode_fixed_header_rejects_bad_magic() {
        let mut bytes = [0u8; CHANNEL_INDEX_RECORD_FIXED_HEADER_LEN];
        bytes[..4].copy_from_slice(b"XXXX");
        let err = decode_channel_index_record_fixed_header(&bytes).expect_err("bad magic");
        assert!(matches!(err, ChannelIndexCodecError::InvalidMagic));
    }

    #[test]
    fn decode_fixed_header_rejects_unsupported_version() {
        let mut bytes = [0u8; CHANNEL_INDEX_RECORD_FIXED_HEADER_LEN];
        bytes[..CHANNEL_INDEX_RECORD_MAGIC.len()].copy_from_slice(&CHANNEL_INDEX_RECORD_MAGIC);
        bytes[CHANNEL_INDEX_RECORD_MAGIC.len()] = 0x99;
        let err =
            decode_channel_index_record_fixed_header(&bytes).expect_err("unsupported version");
        match err {
            ChannelIndexCodecError::UnsupportedFormatVersion(v) => assert_eq!(v, 0x0099),
            other => panic!("expected UnsupportedFormatVersion, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_out_of_order_entries() {
        let mut index = ChannelIndexV0 {
            entries: vec![
                ChannelIndexEntryV0::DeviceProfile {
                    offset: 0,
                    size: 100,
                    id: String::from("a"),
                },
                ChannelIndexEntryV0::BootProfile {
                    offset: 50,
                    size: 100,
                    id: String::from("b"),
                },
            ],
        };
        let err = validate_channel_index(&index, 1024, 128).expect_err("out of order rejected");
        assert!(matches!(
            err,
            ChannelIndexCodecError::EntryOutOfOrder { index: 1 }
        ));

        index.entries[1] = ChannelIndexEntryV0::BootProfile {
            offset: 100,
            size: 100,
            id: String::from("b"),
        };
        validate_channel_index(&index, 1024, 128).expect("valid after fix");
    }

    #[test]
    fn validate_rejects_out_of_bounds_entry() {
        let index = ChannelIndexV0 {
            entries: vec![ChannelIndexEntryV0::BootProfile {
                offset: 900,
                size: 200,
                id: String::from("a"),
            }],
        };
        let err = validate_channel_index(&index, 1024, 128).expect_err("oob rejected");
        assert!(matches!(
            err,
            ChannelIndexCodecError::EntryOutOfBounds { index: 0 }
        ));
    }

    #[test]
    fn validate_rejects_zero_size_entry() {
        let index = ChannelIndexV0 {
            entries: vec![ChannelIndexEntryV0::BootProfile {
                offset: 0,
                size: 0,
                id: String::from("a"),
            }],
        };
        let err = validate_channel_index(&index, 1024, 128).expect_err("empty size rejected");
        assert!(matches!(
            err,
            ChannelIndexCodecError::EntryEmptySize { index: 0 }
        ));
    }

    #[test]
    fn validate_rejects_pipeline_hints_payload_outside_record() {
        let index = ChannelIndexV0 {
            entries: vec![ChannelIndexEntryV0::PipelineHints {
                offset: 0,
                size: 200,
                payload_offset: 500,
                payload_size: 50,
                pipeline_identities: vec![],
            }],
        };
        let err = validate_channel_index(&index, 1024, 128).expect_err("oob payload rejected");
        assert!(matches!(
            err,
            ChannelIndexCodecError::PipelineHintsPayloadOutOfBounds { index: 0 }
        ));
    }
}
