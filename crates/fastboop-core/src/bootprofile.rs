use alloc::string::{String, ToString};
use alloc::vec::Vec;

use fastboop_schema::bin::{
    BOOT_PROFILE_BIN_FORMAT_VERSION, BOOT_PROFILE_BIN_HEADER_LEN, BOOT_PROFILE_BIN_MAGIC,
    BootProfileBin,
};
use fastboop_schema::{
    BootProfile, BootProfileArtifactPathSource, BootProfileRootfs,
    BootProfileRootfsFilesystemSource,
};
use gibblox_pipeline::{PipelineValidationError, validate_pipeline};

#[derive(Debug)]
pub enum BootProfileCodecError {
    Decode(postcard::Error),
    InvalidMagic,
    UnsupportedFormatVersion(u16),
}

impl core::fmt::Display for BootProfileCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(err) => write!(f, "decode boot profile: {err}"),
            Self::InvalidMagic => {
                write!(
                    f,
                    "invalid boot profile magic (expected {BOOT_PROFILE_BIN_MAGIC:?})"
                )
            }
            Self::UnsupportedFormatVersion(version) => {
                write!(
                    f,
                    "unsupported boot profile format version {version} (expected {BOOT_PROFILE_BIN_FORMAT_VERSION})"
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
    let Some(format_version) = boot_profile_bin_header_version(bytes) else {
        return Err(BootProfileCodecError::InvalidMagic);
    };
    if format_version != BOOT_PROFILE_BIN_FORMAT_VERSION {
        return Err(BootProfileCodecError::UnsupportedFormatVersion(
            format_version,
        ));
    }

    let payload = &bytes[BOOT_PROFILE_BIN_HEADER_LEN..];
    let profile: BootProfileBin = postcard::from_bytes(payload)?;
    Ok(BootProfile::from(profile))
}

pub fn decode_boot_profile_prefix(
    bytes: &[u8],
) -> Result<(BootProfile, usize), BootProfileCodecError> {
    let Some(format_version) = boot_profile_bin_header_version(bytes) else {
        return Err(BootProfileCodecError::InvalidMagic);
    };
    if format_version != BOOT_PROFILE_BIN_FORMAT_VERSION {
        return Err(BootProfileCodecError::UnsupportedFormatVersion(
            format_version,
        ));
    }

    let payload = &bytes[BOOT_PROFILE_BIN_HEADER_LEN..];
    let (profile, remaining): (BootProfileBin, &[u8]) = postcard::take_from_bytes(payload)?;
    let consumed = BOOT_PROFILE_BIN_HEADER_LEN
        .checked_add(payload.len() - remaining.len())
        .expect("boot profile consumed length overflow");
    Ok((BootProfile::from(profile), consumed))
}

pub fn encode_boot_profile(profile: &BootProfile) -> Result<Vec<u8>, postcard::Error> {
    let payload = postcard::to_allocvec(&BootProfileBin::from(profile.clone()))?;
    let mut out = Vec::with_capacity(BOOT_PROFILE_BIN_HEADER_LEN + payload.len());
    out.extend_from_slice(&BOOT_PROFILE_BIN_MAGIC);
    out.extend_from_slice(&BOOT_PROFILE_BIN_FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn boot_profile_bin_header_version(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < BOOT_PROFILE_BIN_HEADER_LEN {
        return None;
    }
    if bytes[..BOOT_PROFILE_BIN_MAGIC.len()] != BOOT_PROFILE_BIN_MAGIC {
        return None;
    }
    Some(u16::from_le_bytes([
        bytes[BOOT_PROFILE_BIN_MAGIC.len()],
        bytes[BOOT_PROFILE_BIN_MAGIC.len() + 1],
    ]))
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
    UnsupportedRootfsFilesystem { filesystem: &'static str },
    Pipeline(PipelineValidationError),
    EmptyKernelPath,
    EmptyDtbsPath,
}

impl core::fmt::Display for BootProfileValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedRootfsFilesystem { filesystem } => write!(
                f,
                "boot profile rootfs filesystem '{filesystem}' is not supported for stage0 switchroot (supported: erofs, ext4)"
            ),
            Self::Pipeline(err) => write!(f, "{err}"),
            Self::EmptyKernelPath => {
                write!(f, "boot profile kernel path must not be empty")
            }
            Self::EmptyDtbsPath => {
                write!(f, "boot profile dtbs path must not be empty")
            }
        }
    }
}

pub fn validate_boot_profile(profile: &BootProfile) -> Result<(), BootProfileValidationError> {
    if !rootfs_supports_stage0_switchroot(&profile.rootfs) {
        return Err(BootProfileValidationError::UnsupportedRootfsFilesystem { filesystem: "fat" });
    }
    validate_pipeline(profile.rootfs.source()).map_err(BootProfileValidationError::Pipeline)?;
    if let Some(kernel) = profile.kernel.as_ref() {
        validate_profile_artifact_path_source(kernel, BootProfileValidationError::EmptyKernelPath)?;
    }
    if let Some(dtbs) = profile.dtbs.as_ref() {
        validate_profile_artifact_path_source(dtbs, BootProfileValidationError::EmptyDtbsPath)?;
    }
    Ok(())
}

fn rootfs_supports_stage0_switchroot(rootfs: &BootProfileRootfs) -> bool {
    match rootfs {
        BootProfileRootfs::Erofs(_) | BootProfileRootfs::Ext4(_) => true,
        BootProfileRootfs::Fat(_) => false,
        BootProfileRootfs::Ostree(source) => matches!(
            &source.ostree,
            BootProfileRootfsFilesystemSource::Erofs(_)
                | BootProfileRootfsFilesystemSource::Ext4(_)
        ),
    }
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

fn validate_profile_artifact_path_source(
    source: &BootProfileArtifactPathSource,
    empty_path_err: BootProfileValidationError,
) -> Result<(), BootProfileValidationError> {
    if source.path.trim().is_empty() {
        return Err(empty_path_err);
    }
    validate_pipeline(source.artifact_source()).map_err(BootProfileValidationError::Pipeline)
}
