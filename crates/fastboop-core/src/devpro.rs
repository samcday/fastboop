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
    /// The record was written for a format version other than
    /// [`DEV_PROFILE_BIN_FORMAT_VERSION`], typically by another fastboop
    /// version. Carries the version found in the record header.
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
                    "unsupported dev profile format version {version} (this fastboop supports version {DEV_PROFILE_BIN_FORMAT_VERSION}); recompile the device profile with this fastboop version (`fastboop devprofile create`) and rebuild any channel that embeds it"
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
    let payload = dev_profile_bin_payload(bytes)?;
    let profile: DeviceProfileBin = postcard::from_bytes(payload)?;
    Ok(DeviceProfile::from(profile))
}

pub fn decode_dev_profile_prefix(
    bytes: &[u8],
) -> Result<(DeviceProfile, usize), DevProfileCodecError> {
    let payload = dev_profile_bin_payload(bytes)?;
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

/// Returns the header format version when `bytes` starts with a device
/// profile record, whatever that version is. Decoding rejects every version
/// other than [`DEV_PROFILE_BIN_FORMAT_VERSION`].
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

/// Checks a device profile record header without decoding its payload.
pub fn check_dev_profile_bin_header(bytes: &[u8]) -> Result<(), DevProfileCodecError> {
    dev_profile_bin_payload(bytes).map(|_| ())
}

fn dev_profile_bin_payload(bytes: &[u8]) -> Result<&[u8], DevProfileCodecError> {
    let Some(format_version) = dev_profile_bin_header_version(bytes) else {
        return Err(DevProfileCodecError::InvalidMagic);
    };
    if format_version != DEV_PROFILE_BIN_FORMAT_VERSION {
        return Err(DevProfileCodecError::UnsupportedFormatVersion(
            format_version,
        ));
    }
    Ok(&bytes[DEV_PROFILE_BIN_HEADER_LEN..])
}
