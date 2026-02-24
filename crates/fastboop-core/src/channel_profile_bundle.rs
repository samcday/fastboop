extern crate alloc;

use alloc::vec::Vec;

use fastboop_schema::{BootProfile, DeviceProfile};
use serde::{Deserialize, Serialize};

use crate::channel_stream::{CHANNEL_PROFILE_BUNDLE_FORMAT_V1, CHANNEL_PROFILE_BUNDLE_MAGIC};

pub const CHANNEL_PROFILE_BUNDLE_HEADER_LEN: usize = 6;

#[derive(Clone, Debug, Default)]
pub struct ChannelProfileBundle {
    pub devprofiles: Vec<DeviceProfile>,
    pub bootprofiles: Vec<BootProfile>,
}

#[derive(Debug)]
pub enum ChannelProfileBundleCodecError {
    Decode(postcard::Error),
    InvalidMagic,
    UnsupportedFormatVersion(u16),
}

impl core::fmt::Display for ChannelProfileBundleCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(err) => write!(f, "decode channel profile bundle: {err}"),
            Self::InvalidMagic => {
                write!(f, "invalid channel profile bundle magic")
            }
            Self::UnsupportedFormatVersion(version) => write!(
                f,
                "unsupported channel profile bundle format version {version} (expected {CHANNEL_PROFILE_BUNDLE_FORMAT_V1})"
            ),
        }
    }
}

impl From<postcard::Error> for ChannelProfileBundleCodecError {
    fn from(err: postcard::Error) -> Self {
        Self::Decode(err)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ChannelProfileBundleV1Bin {
    devprofiles: Vec<DeviceProfile>,
    bootprofiles: Vec<BootProfile>,
}

pub fn decode_channel_profile_bundle(
    bytes: &[u8],
) -> Result<ChannelProfileBundle, ChannelProfileBundleCodecError> {
    let Some(format_version) = channel_profile_bundle_header_version(bytes) else {
        return Err(ChannelProfileBundleCodecError::InvalidMagic);
    };
    if format_version != CHANNEL_PROFILE_BUNDLE_FORMAT_V1 {
        return Err(ChannelProfileBundleCodecError::UnsupportedFormatVersion(
            format_version,
        ));
    }

    let payload = &bytes[CHANNEL_PROFILE_BUNDLE_HEADER_LEN..];
    let payload: ChannelProfileBundleV1Bin = postcard::from_bytes(payload)?;
    Ok(ChannelProfileBundle {
        devprofiles: payload.devprofiles,
        bootprofiles: payload.bootprofiles,
    })
}

pub fn encode_channel_profile_bundle(
    bundle: &ChannelProfileBundle,
) -> Result<Vec<u8>, postcard::Error> {
    let payload = postcard::to_allocvec(&ChannelProfileBundleV1Bin {
        devprofiles: bundle.devprofiles.clone(),
        bootprofiles: bundle.bootprofiles.clone(),
    })?;
    let mut out = Vec::with_capacity(CHANNEL_PROFILE_BUNDLE_HEADER_LEN + payload.len());
    out.extend_from_slice(&CHANNEL_PROFILE_BUNDLE_MAGIC);
    out.extend_from_slice(&CHANNEL_PROFILE_BUNDLE_FORMAT_V1.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn channel_profile_bundle_header_version(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < CHANNEL_PROFILE_BUNDLE_HEADER_LEN {
        return None;
    }
    if bytes[..CHANNEL_PROFILE_BUNDLE_MAGIC.len()] != CHANNEL_PROFILE_BUNDLE_MAGIC {
        return None;
    }
    Some(u16::from_le_bytes([
        bytes[CHANNEL_PROFILE_BUNDLE_MAGIC.len()],
        bytes[CHANNEL_PROFILE_BUNDLE_MAGIC.len() + 1],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_empty_bundle() {
        let bundle = ChannelProfileBundle::default();
        let encoded = encode_channel_profile_bundle(&bundle).unwrap();
        let decoded = decode_channel_profile_bundle(&encoded).unwrap();
        assert!(decoded.devprofiles.is_empty());
        assert!(decoded.bootprofiles.is_empty());
    }

    #[test]
    fn rejects_invalid_magic() {
        let err = decode_channel_profile_bundle(b"xxxx\x01\x00payload").unwrap_err();
        matches!(err, ChannelProfileBundleCodecError::InvalidMagic);
    }
}
