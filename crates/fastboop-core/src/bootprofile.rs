use alloc::string::{String, ToString};
use alloc::vec::Vec;

use fastboop_schema::BootProfile;
use fastboop_schema::bin::{
    BOOT_PROFILE_BIN_FORMAT_VERSION, BootProfileBin, BootProfileEnvelopeBin,
};

#[derive(Debug)]
pub enum BootProfileCodecError {
    Decode(postcard::Error),
    UnsupportedFormatVersion(u16),
}

impl core::fmt::Display for BootProfileCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(err) => write!(f, "decode boot profile: {err}"),
            Self::UnsupportedFormatVersion(version) => {
                write!(
                    f,
                    "unsupported boot profile format version {version} (expected {})",
                    BOOT_PROFILE_BIN_FORMAT_VERSION
                )
            }
        }
    }
}

impl From<postcard::Error> for BootProfileCodecError {
    fn from(err: postcard::Error) -> Self {
        Self::Decode(err)
    }
}

pub fn decode_boot_profile(bytes: &[u8]) -> Result<BootProfile, BootProfileCodecError> {
    let envelope: BootProfileEnvelopeBin = postcard::from_bytes(bytes)?;
    if envelope.format_version != BOOT_PROFILE_BIN_FORMAT_VERSION {
        return Err(BootProfileCodecError::UnsupportedFormatVersion(
            envelope.format_version,
        ));
    }
    Ok(BootProfile::from(envelope.profile))
}

pub fn encode_boot_profile(profile: &BootProfile) -> Result<Vec<u8>, postcard::Error> {
    let envelope = BootProfileEnvelopeBin {
        format_version: BOOT_PROFILE_BIN_FORMAT_VERSION,
        profile: BootProfileBin::from(profile.clone()),
    };
    postcard::to_allocvec(&envelope)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EffectiveBootProfileStage0 {
    pub dt_overlays: Vec<Vec<u8>>,
    pub extra_cmdline: Option<String>,
    pub extra_modules: Vec<String>,
}

pub fn resolve_effective_boot_profile_stage0(
    profile: &BootProfile,
    device_profile_id: &str,
) -> EffectiveBootProfileStage0 {
    let mut dt_overlays = profile.dt_overlays.clone();
    let mut extra_modules = profile.stage0.extra_modules.clone();
    let mut extra_cmdline = profile.extra_cmdline.clone();

    if let Some(device) = profile.stage0.devices.get(device_profile_id) {
        dt_overlays.extend(device.dt_overlays.iter().cloned());
        extra_modules.extend(device.stage0.extra_modules.iter().cloned());
        extra_cmdline =
            join_cmdline_parts(extra_cmdline.as_deref(), device.extra_cmdline.as_deref());
    }

    EffectiveBootProfileStage0 {
        dt_overlays,
        extra_cmdline,
        extra_modules,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootProfileValidationError {
    UnsupportedCasyncArchiveIndex { index: String },
}

impl core::fmt::Display for BootProfileValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedCasyncArchiveIndex { index } => write!(
                f,
                "unsupported casync archive index (.caidx) in boot profile: {index}; expected casync blob index (.caibx)"
            ),
        }
    }
}

pub fn validate_boot_profile(profile: &BootProfile) -> Result<(), BootProfileValidationError> {
    if let Some(casync) = profile.rootfs.casync() {
        let index_path = strip_query_and_fragment(casync.index.as_str());
        if index_path.ends_with(".caidx") {
            return Err(BootProfileValidationError::UnsupportedCasyncArchiveIndex {
                index: casync.index.clone(),
            });
        }
    }
    Ok(())
}

fn join_cmdline_parts(primary: Option<&str>, secondary: Option<&str>) -> Option<String> {
    let first = primary.map(str::trim).filter(|value| !value.is_empty());
    let second = secondary.map(str::trim).filter(|value| !value.is_empty());
    match (first, second) {
        (Some(a), Some(b)) => Some([a, b].join(" ")),
        (Some(a), None) => Some(a.to_string()),
        (None, Some(b)) => Some(b.to_string()),
        (None, None) => None,
    }
}

fn strip_query_and_fragment(value: &str) -> &str {
    let mut end = value.len();
    if let Some(pos) = value.find('?') {
        end = end.min(pos);
    }
    if let Some(pos) = value.find('#') {
        end = end.min(pos);
    }
    &value[..end]
}
