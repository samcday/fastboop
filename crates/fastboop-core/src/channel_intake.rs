use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use gibblox_pipeline::{
    PipelineHints, decode_pipeline_hints_prefix, pipeline_hints_bin_header_version,
};

use crate::{
    BootProfile, DeviceProfile, boot_profile_bin_header_version, decode_boot_profile_prefix,
    decode_dev_profile_prefix, dev_profile_bin_header_version, validate_boot_profile,
};

pub const CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES: usize = 4 * 1024 * 1024;
pub const CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS: usize = 128;

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
pub struct ChannelStreamHead {
    pub boot_profiles: Vec<BootProfile>,
    pub dev_profiles: Vec<DeviceProfile>,
    pub pipeline_hints: PipelineHints,
    pub consumed_bytes: u64,
    pub warning_count: usize,
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
                    if out.boot_profiles.is_empty() && out.dev_profiles.is_empty() {
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
                    if out.boot_profiles.is_empty() && out.dev_profiles.is_empty() {
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

        if pipeline_hints_bin_header_version(remaining).is_some() {
            match decode_pipeline_hints_prefix(remaining) {
                Ok((hints, consumed)) => {
                    if consumed == 0 {
                        return Err(ChannelStreamHeadError::EmptyRecord {
                            offset: cursor as u64,
                        });
                    }

                    for entry in hints.entries {
                        if !pipeline_hint_identities.insert(entry.pipeline_identity.clone()) {
                            return Err(ChannelStreamHeadError::DuplicatePipelineHintIdentity {
                                pipeline_identity: entry.pipeline_identity,
                            });
                        }
                        out.pipeline_hints.entries.push(entry);
                    }

                    cursor = cursor
                        .checked_add(consumed)
                        .ok_or(ChannelStreamHeadError::CursorOverflow)?;
                    records_consumed = records_consumed.saturating_add(1);
                    continue;
                }
                Err(err) => {
                    if out.boot_profiles.is_empty()
                        && out.dev_profiles.is_empty()
                        && out.pipeline_hints.entries.is_empty()
                    {
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
            }
        }

        if !out.boot_profiles.is_empty()
            || !out.dev_profiles.is_empty()
            || !out.pipeline_hints.entries.is_empty()
        {
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
        encode_pipeline_hints,
    };

    use super::{ChannelStreamHeadError, read_channel_stream_head};

    #[test]
    fn merges_pipeline_hint_records_in_sorted_identity_order() {
        let first = encode_pipeline_hints(&PipelineHints {
            entries: vec![pipeline_hint_entry(
                "xz{source=http{url=len:22:https://example.com/a;}}",
                "sha512:11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
            )],
        })
        .expect("encode first pipeline hints");
        let second = encode_pipeline_hints(&PipelineHints {
            entries: vec![pipeline_hint_entry(
                "android_sparseimg{source=xz{source=http{url=len:22:https://example.com/a;}}}",
                "sha512:22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222",
            )],
        })
        .expect("encode second pipeline hints");

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
    }

    #[test]
    fn rejects_duplicate_pipeline_hint_identity_across_records() {
        let first = encode_pipeline_hints(&PipelineHints {
            entries: vec![pipeline_hint_entry(
                "xz{source=http{url=len:22:https://example.com/a;}}",
                "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )],
        })
        .expect("encode first pipeline hints");
        let second = encode_pipeline_hints(&PipelineHints {
            entries: vec![pipeline_hint_entry(
                "xz{source=http{url=len:22:https://example.com/a;}}",
                "sha512:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )],
        })
        .expect("encode second pipeline hints");

        let mut stream = first;
        stream.extend(second);

        let err = read_channel_stream_head(&stream, stream.len() as u64)
            .expect_err("duplicate pipeline identity should fail");

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
