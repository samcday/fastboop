use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gibblox_pipeline::{PipelineHints, decode_pipeline_hints, encode_pipeline_hints};
use serde::{Deserialize, Serialize};

pub const CHANNEL_PIPELINE_HINTS_RECORD_MAGIC: [u8; 8] = *b"FBPHINT0";
pub const CHANNEL_PIPELINE_HINTS_RECORD_FORMAT_VERSION: u16 = 0;
pub const CHANNEL_PIPELINE_HINTS_RECORD_FIXED_HEADER_LEN: usize =
    CHANNEL_PIPELINE_HINTS_RECORD_MAGIC.len() + 2 + 4 + 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelPipelineHintsRecordFixedHeader {
    pub metadata_size_bytes: u32,
    pub payload_size_bytes: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChannelPipelineHintsRecordHead {
    pub pipeline_identities: Vec<String>,
    pub payload_offset_bytes: u64,
    pub payload_size_bytes: u64,
    pub total_record_size_bytes: u64,
}

#[derive(Debug)]
pub enum ChannelPipelineHintsRecordCodecError {
    Decode(postcard::Error),
    InvalidMagic,
    UnsupportedFormatVersion(u16),
    LengthOverflow,
    TruncatedRecord {
        required_bytes: usize,
        available_bytes: usize,
    },
    DuplicateIdentity {
        pipeline_identity: String,
    },
    UnsortedIdentity {
        previous_identity: String,
        pipeline_identity: String,
    },
    IdentityIndexMismatch {
        expected: Vec<String>,
        actual: Vec<String>,
    },
    HintsCodec {
        cause: String,
    },
}

impl core::fmt::Display for ChannelPipelineHintsRecordCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(err) => write!(f, "decode channel pipeline hints record: {err}"),
            Self::InvalidMagic => {
                write!(
                    f,
                    "invalid channel pipeline hints record magic (expected {CHANNEL_PIPELINE_HINTS_RECORD_MAGIC:?})"
                )
            }
            Self::UnsupportedFormatVersion(version) => write!(
                f,
                "unsupported channel pipeline hints record format version {version} (expected {CHANNEL_PIPELINE_HINTS_RECORD_FORMAT_VERSION})"
            ),
            Self::LengthOverflow => write!(f, "channel pipeline hints record length overflow"),
            Self::TruncatedRecord {
                required_bytes,
                available_bytes,
            } => write!(
                f,
                "channel pipeline hints record is truncated (required {required_bytes} bytes, got {available_bytes})"
            ),
            Self::DuplicateIdentity { pipeline_identity } => write!(
                f,
                "duplicate channel pipeline hint identity '{}' is not allowed",
                pipeline_identity
            ),
            Self::UnsortedIdentity {
                previous_identity,
                pipeline_identity,
            } => write!(
                f,
                "channel pipeline hint identity index must be sorted; '{}' appears after '{}'",
                pipeline_identity, previous_identity
            ),
            Self::IdentityIndexMismatch { expected, actual } => write!(
                f,
                "channel pipeline hint identity index mismatch (expected: {}; actual: {})",
                expected.join(", "),
                actual.join(", ")
            ),
            Self::HintsCodec { cause } => write!(f, "{cause}"),
        }
    }
}

impl From<postcard::Error> for ChannelPipelineHintsRecordCodecError {
    fn from(err: postcard::Error) -> Self {
        Self::Decode(err)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ChannelPipelineHintsRecordMetadataV0 {
    pipeline_identities: Vec<String>,
}

pub fn encode_channel_pipeline_hints_record(
    hints: &PipelineHints,
) -> Result<Vec<u8>, ChannelPipelineHintsRecordCodecError> {
    let payload = encode_pipeline_hints(hints).map_err(|err| {
        ChannelPipelineHintsRecordCodecError::HintsCodec {
            cause: err.to_string(),
        }
    })?;

    let mut identity_set = BTreeSet::new();
    for entry in &hints.entries {
        identity_set.insert(entry.pipeline_identity.clone());
    }
    let metadata = ChannelPipelineHintsRecordMetadataV0 {
        pipeline_identities: identity_set.into_iter().collect(),
    };
    let metadata_bytes = postcard::to_allocvec(&metadata)?;

    let metadata_len = u32::try_from(metadata_bytes.len())
        .map_err(|_| ChannelPipelineHintsRecordCodecError::LengthOverflow)?;
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| ChannelPipelineHintsRecordCodecError::LengthOverflow)?;

    let mut out = Vec::with_capacity(
        CHANNEL_PIPELINE_HINTS_RECORD_FIXED_HEADER_LEN
            .checked_add(metadata_bytes.len())
            .and_then(|v| v.checked_add(payload.len()))
            .ok_or(ChannelPipelineHintsRecordCodecError::LengthOverflow)?,
    );
    out.extend_from_slice(&CHANNEL_PIPELINE_HINTS_RECORD_MAGIC);
    out.extend_from_slice(&CHANNEL_PIPELINE_HINTS_RECORD_FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&metadata_len.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(metadata_bytes.as_slice());
    out.extend_from_slice(payload.as_slice());
    Ok(out)
}

pub fn decode_channel_pipeline_hints_record_prefix(
    bytes: &[u8],
) -> Result<ChannelPipelineHintsRecordHead, ChannelPipelineHintsRecordCodecError> {
    let fixed_header = decode_channel_pipeline_hints_record_fixed_header(bytes)?;
    let metadata_len = fixed_header.metadata_size_bytes;
    let payload_len = fixed_header.payload_size_bytes;

    let payload_offset = CHANNEL_PIPELINE_HINTS_RECORD_FIXED_HEADER_LEN
        .checked_add(
            usize::try_from(metadata_len)
                .map_err(|_| ChannelPipelineHintsRecordCodecError::LengthOverflow)?,
        )
        .ok_or(ChannelPipelineHintsRecordCodecError::LengthOverflow)?;
    if bytes.len() < payload_offset {
        return Err(ChannelPipelineHintsRecordCodecError::TruncatedRecord {
            required_bytes: payload_offset,
            available_bytes: bytes.len(),
        });
    }

    let metadata_bytes = &bytes[CHANNEL_PIPELINE_HINTS_RECORD_FIXED_HEADER_LEN..payload_offset];
    let metadata: ChannelPipelineHintsRecordMetadataV0 = postcard::from_bytes(metadata_bytes)?;
    validate_identity_index(metadata.pipeline_identities.as_slice())?;

    let total_record_size = payload_offset
        .checked_add(
            usize::try_from(payload_len)
                .map_err(|_| ChannelPipelineHintsRecordCodecError::LengthOverflow)?,
        )
        .ok_or(ChannelPipelineHintsRecordCodecError::LengthOverflow)?;

    Ok(ChannelPipelineHintsRecordHead {
        pipeline_identities: metadata.pipeline_identities,
        payload_offset_bytes: payload_offset as u64,
        payload_size_bytes: payload_len as u64,
        total_record_size_bytes: total_record_size as u64,
    })
}

pub fn decode_channel_pipeline_hints_record_fixed_header(
    bytes: &[u8],
) -> Result<ChannelPipelineHintsRecordFixedHeader, ChannelPipelineHintsRecordCodecError> {
    let Some(format_version) = channel_pipeline_hints_record_header_version(bytes) else {
        return Err(ChannelPipelineHintsRecordCodecError::InvalidMagic);
    };
    if format_version != CHANNEL_PIPELINE_HINTS_RECORD_FORMAT_VERSION {
        return Err(ChannelPipelineHintsRecordCodecError::UnsupportedFormatVersion(format_version));
    }

    let metadata_len_start = CHANNEL_PIPELINE_HINTS_RECORD_MAGIC.len() + 2;
    let metadata_len = u32::from_le_bytes([
        bytes[metadata_len_start],
        bytes[metadata_len_start + 1],
        bytes[metadata_len_start + 2],
        bytes[metadata_len_start + 3],
    ]);
    let payload_len_start = metadata_len_start + 4;
    let payload_len = u32::from_le_bytes([
        bytes[payload_len_start],
        bytes[payload_len_start + 1],
        bytes[payload_len_start + 2],
        bytes[payload_len_start + 3],
    ]);

    Ok(ChannelPipelineHintsRecordFixedHeader {
        metadata_size_bytes: metadata_len,
        payload_size_bytes: payload_len,
    })
}

pub fn decode_channel_pipeline_hints_record(
    bytes: &[u8],
) -> Result<(PipelineHints, usize), ChannelPipelineHintsRecordCodecError> {
    let head = decode_channel_pipeline_hints_record_prefix(bytes)?;
    let total_record_size = usize::try_from(head.total_record_size_bytes)
        .map_err(|_| ChannelPipelineHintsRecordCodecError::LengthOverflow)?;
    if bytes.len() < total_record_size {
        return Err(ChannelPipelineHintsRecordCodecError::TruncatedRecord {
            required_bytes: total_record_size,
            available_bytes: bytes.len(),
        });
    }

    let payload_offset = usize::try_from(head.payload_offset_bytes)
        .map_err(|_| ChannelPipelineHintsRecordCodecError::LengthOverflow)?;
    let payload_size = usize::try_from(head.payload_size_bytes)
        .map_err(|_| ChannelPipelineHintsRecordCodecError::LengthOverflow)?;
    let payload_end = payload_offset
        .checked_add(payload_size)
        .ok_or(ChannelPipelineHintsRecordCodecError::LengthOverflow)?;
    let payload = &bytes[payload_offset..payload_end];
    let hints = decode_pipeline_hints(payload).map_err(|err| {
        ChannelPipelineHintsRecordCodecError::HintsCodec {
            cause: err.to_string(),
        }
    })?;

    let actual: Vec<String> = hints
        .entries
        .iter()
        .map(|entry| entry.pipeline_identity.clone())
        .collect();
    if actual != head.pipeline_identities {
        return Err(
            ChannelPipelineHintsRecordCodecError::IdentityIndexMismatch {
                expected: head.pipeline_identities,
                actual,
            },
        );
    }

    Ok((hints, total_record_size))
}

pub fn channel_pipeline_hints_record_header_version(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < CHANNEL_PIPELINE_HINTS_RECORD_FIXED_HEADER_LEN {
        return None;
    }
    if bytes[..CHANNEL_PIPELINE_HINTS_RECORD_MAGIC.len()] != CHANNEL_PIPELINE_HINTS_RECORD_MAGIC {
        return None;
    }

    Some(u16::from_le_bytes([
        bytes[CHANNEL_PIPELINE_HINTS_RECORD_MAGIC.len()],
        bytes[CHANNEL_PIPELINE_HINTS_RECORD_MAGIC.len() + 1],
    ]))
}

fn validate_identity_index(
    identities: &[String],
) -> Result<(), ChannelPipelineHintsRecordCodecError> {
    let mut previous_identity: Option<&str> = None;
    for identity in identities {
        let identity = identity.as_str();
        if let Some(previous) = previous_identity {
            if previous == identity {
                return Err(ChannelPipelineHintsRecordCodecError::DuplicateIdentity {
                    pipeline_identity: identity.to_string(),
                });
            }
            if previous > identity {
                return Err(ChannelPipelineHintsRecordCodecError::UnsortedIdentity {
                    previous_identity: previous.to_string(),
                    pipeline_identity: identity.to_string(),
                });
            }
        }
        previous_identity = Some(identity);
    }
    Ok(())
}

pub fn decode_channel_pipeline_hints_record_payload(
    payload: &[u8],
) -> Result<PipelineHints, ChannelPipelineHintsRecordCodecError> {
    decode_pipeline_hints(payload).map_err(|err| ChannelPipelineHintsRecordCodecError::HintsCodec {
        cause: format!("decode pipeline hints payload: {err}"),
    })
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec;

    use gibblox_pipeline::{
        PipelineContentDigestHint, PipelineHint, PipelineHintEntry, PipelineHints,
    };

    use super::{
        ChannelPipelineHintsRecordCodecError, decode_channel_pipeline_hints_record,
        decode_channel_pipeline_hints_record_prefix, encode_channel_pipeline_hints_record,
    };

    #[test]
    fn encode_decode_roundtrip() {
        let hints = sample_hints();
        let encoded = encode_channel_pipeline_hints_record(&hints).expect("encode record");
        let (decoded, consumed) =
            decode_channel_pipeline_hints_record(encoded.as_slice()).expect("decode record");
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, hints);
    }

    #[test]
    fn prefix_exposes_identity_index_and_payload_offsets() {
        let hints = sample_hints();
        let encoded = encode_channel_pipeline_hints_record(&hints).expect("encode record");
        let head = decode_channel_pipeline_hints_record_prefix(encoded.as_slice())
            .expect("decode record prefix");

        assert_eq!(
            head.pipeline_identities,
            vec![
                String::from("android_sparseimg{source=http{url=len:9:https://a;}}"),
                String::from("xz{source=http{url=len:9:https://b;}}"),
            ]
        );
        assert!(head.payload_offset_bytes > 0);
        assert!(head.payload_size_bytes > 0);
        assert_eq!(head.total_record_size_bytes as usize, encoded.len());
    }

    #[test]
    fn decode_rejects_identity_index_mismatch() {
        let hints = sample_hints();
        let mut encoded = encode_channel_pipeline_hints_record(&hints).expect("encode record");

        let prefix_head =
            decode_channel_pipeline_hints_record_prefix(encoded.as_slice()).expect("decode prefix");
        let metadata_start = super::CHANNEL_PIPELINE_HINTS_RECORD_FIXED_HEADER_LEN;
        let metadata_end =
            usize::try_from(prefix_head.payload_offset_bytes).expect("payload offset");

        let mut metadata: super::ChannelPipelineHintsRecordMetadataV0 =
            postcard::from_bytes(&encoded[metadata_start..metadata_end]).expect("decode metadata");
        metadata.pipeline_identities[0] =
            String::from("android_sparseimg{source=http{url=len:9:https://z;}}");
        let metadata_bytes = postcard::to_allocvec(&metadata).expect("re-encode metadata");
        assert_eq!(metadata_bytes.len(), metadata_end - metadata_start);
        encoded[metadata_start..metadata_end].copy_from_slice(metadata_bytes.as_slice());

        let err = decode_channel_pipeline_hints_record(encoded.as_slice())
            .expect_err("identity mismatch should fail");
        match err {
            ChannelPipelineHintsRecordCodecError::IdentityIndexMismatch { .. } => {}
            other => panic!("expected identity mismatch error, got {other:?}"),
        }
    }

    fn sample_hints() -> PipelineHints {
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
}
