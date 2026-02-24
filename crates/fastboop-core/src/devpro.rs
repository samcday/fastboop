use alloc::vec::Vec;

use fastboop_schema::bin::{
    DEV_PROFILE_BIN_FORMAT_VERSION, DEV_PROFILE_BIN_HEADER_LEN, DEV_PROFILE_BIN_MAGIC,
    DeviceProfileBin,
};

pub use fastboop_schema::*;

#[derive(Debug)]
pub enum DevProfileCodecError {
    Decode(postcard::Error),
    InvalidMagic,
    UnsupportedFormatVersion(u16),
}

impl core::fmt::Display for DevProfileCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(err) => write!(f, "decode dev profile: {err}"),
            Self::InvalidMagic => {
                write!(
                    f,
                    "invalid dev profile magic (expected {DEV_PROFILE_BIN_MAGIC:?})"
                )
            }
            Self::UnsupportedFormatVersion(version) => {
                write!(
                    f,
                    "unsupported dev profile format version {version} (expected {DEV_PROFILE_BIN_FORMAT_VERSION})"
                )
            }
        }
    }
}

impl From<postcard::Error> for DevProfileCodecError {
    fn from(err: postcard::Error) -> Self {
        Self::Decode(err)
    }
}

pub fn decode_dev_profile(bytes: &[u8]) -> Result<DeviceProfile, DevProfileCodecError> {
    let Some(format_version) = dev_profile_bin_header_version(bytes) else {
        return Err(DevProfileCodecError::InvalidMagic);
    };
    if format_version != DEV_PROFILE_BIN_FORMAT_VERSION {
        return Err(DevProfileCodecError::UnsupportedFormatVersion(
            format_version,
        ));
    }

    let payload = &bytes[DEV_PROFILE_BIN_HEADER_LEN..];
    let profile: DeviceProfileBin = postcard::from_bytes(payload)?;
    Ok(DeviceProfile::from(profile))
}

pub fn decode_dev_profile_prefix(
    bytes: &[u8],
) -> Result<(DeviceProfile, usize), DevProfileCodecError> {
    let Some(format_version) = dev_profile_bin_header_version(bytes) else {
        return Err(DevProfileCodecError::InvalidMagic);
    };
    if format_version != DEV_PROFILE_BIN_FORMAT_VERSION {
        return Err(DevProfileCodecError::UnsupportedFormatVersion(
            format_version,
        ));
    }

    let payload = &bytes[DEV_PROFILE_BIN_HEADER_LEN..];
    let (profile, remaining): (DeviceProfileBin, &[u8]) = postcard::take_from_bytes(payload)?;
    let consumed = DEV_PROFILE_BIN_HEADER_LEN
        .checked_add(payload.len() - remaining.len())
        .expect("dev profile consumed length overflow");
    Ok((DeviceProfile::from(profile), consumed))
}

pub fn encode_dev_profile(profile: &DeviceProfile) -> Result<Vec<u8>, postcard::Error> {
    let payload = postcard::to_allocvec(&DeviceProfileBin::from(profile.clone()))?;
    let mut out = Vec::with_capacity(DEV_PROFILE_BIN_HEADER_LEN + payload.len());
    out.extend_from_slice(&DEV_PROFILE_BIN_MAGIC);
    out.extend_from_slice(&DEV_PROFILE_BIN_FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn dev_profile_bin_header_version(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < DEV_PROFILE_BIN_HEADER_LEN {
        return None;
    }
    if bytes[..DEV_PROFILE_BIN_MAGIC.len()] != DEV_PROFILE_BIN_MAGIC {
        return None;
    }
    Some(u16::from_le_bytes([
        bytes[DEV_PROFILE_BIN_MAGIC.len()],
        bytes[DEV_PROFILE_BIN_MAGIC.len() + 1],
    ]))
}
