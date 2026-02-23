use alloc::string::{String, ToString};
use alloc::vec::Vec;

use fastboop_schema::bin::{
    BOOT_PROFILE_BIN_FORMAT_VERSION, BOOT_PROFILE_BIN_HEADER_LEN, BOOT_PROFILE_BIN_MAGIC,
    BootProfileBin,
};
use fastboop_schema::{BootProfile, BootProfileArtifactPathSource, BootProfileArtifactSource};

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
    UnsupportedCasyncArchiveIndex { index: String },
    PipelineDepthExceeded { max_depth: usize },
    InvalidMbrSelectorCount { selectors: usize },
    EmptyMbrPartuuid,
    InvalidGptSelectorCount { selectors: usize },
    EmptyGptPartlabel,
    EmptyGptPartuuid,
    EmptyKernelPath,
    EmptyDtbsPath,
}

impl core::fmt::Display for BootProfileValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedCasyncArchiveIndex { index } => write!(
                f,
                "unsupported casync archive index (.caidx) in boot profile: {index}; expected casync blob index (.caibx)"
            ),
            Self::PipelineDepthExceeded { max_depth } => {
                write!(
                    f,
                    "boot profile rootfs pipeline exceeds max depth {max_depth}"
                )
            }
            Self::InvalidMbrSelectorCount { selectors } => write!(
                f,
                "boot profile mbr step must specify exactly one selector (partuuid or index); found {selectors}"
            ),
            Self::EmptyMbrPartuuid => {
                write!(f, "boot profile mbr partuuid must not be empty")
            }
            Self::InvalidGptSelectorCount { selectors } => write!(
                f,
                "boot profile gpt step must specify exactly one selector (partlabel, partuuid, or index); found {selectors}"
            ),
            Self::EmptyGptPartlabel => {
                write!(f, "boot profile gpt partlabel must not be empty")
            }
            Self::EmptyGptPartuuid => {
                write!(f, "boot profile gpt partuuid must not be empty")
            }
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
    validate_artifact_source(profile.rootfs.source(), 0)?;
    if let Some(kernel) = profile.kernel.as_ref() {
        validate_profile_artifact_path_source(kernel, BootProfileValidationError::EmptyKernelPath)?;
    }
    if let Some(dtbs) = profile.dtbs.as_ref() {
        validate_profile_artifact_path_source(dtbs, BootProfileValidationError::EmptyDtbsPath)?;
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

const MAX_ROOTFS_PIPELINE_DEPTH: usize = 16;

fn validate_artifact_source(
    source: &BootProfileArtifactSource,
    depth: usize,
) -> Result<(), BootProfileValidationError> {
    if depth > MAX_ROOTFS_PIPELINE_DEPTH {
        return Err(BootProfileValidationError::PipelineDepthExceeded {
            max_depth: MAX_ROOTFS_PIPELINE_DEPTH,
        });
    }

    match source {
        BootProfileArtifactSource::Casync(source) => {
            let index_path = strip_query_and_fragment(source.casync.index.as_str());
            if index_path.ends_with(".caidx") {
                return Err(BootProfileValidationError::UnsupportedCasyncArchiveIndex {
                    index: source.casync.index.clone(),
                });
            }
            Ok(())
        }
        BootProfileArtifactSource::Http(_) => Ok(()),
        BootProfileArtifactSource::File(_) => Ok(()),
        BootProfileArtifactSource::Xz(source) => {
            validate_artifact_source(source.xz.as_ref(), depth + 1)
        }
        BootProfileArtifactSource::AndroidSparseImg(source) => {
            validate_artifact_source(source.android_sparseimg.as_ref(), depth + 1)
        }
        BootProfileArtifactSource::Mbr(source) => {
            let mut selectors = 0usize;

            if let Some(partuuid) = source.mbr.partuuid.as_deref() {
                if partuuid.trim().is_empty() {
                    return Err(BootProfileValidationError::EmptyMbrPartuuid);
                }
                selectors += 1;
            }
            if source.mbr.index.is_some() {
                selectors += 1;
            }

            if selectors != 1 {
                return Err(BootProfileValidationError::InvalidMbrSelectorCount { selectors });
            }

            validate_artifact_source(source.mbr.source.as_ref(), depth + 1)
        }
        BootProfileArtifactSource::Gpt(source) => {
            let mut selectors = 0usize;

            if let Some(partlabel) = source.gpt.partlabel.as_deref() {
                if partlabel.trim().is_empty() {
                    return Err(BootProfileValidationError::EmptyGptPartlabel);
                }
                selectors += 1;
            }
            if let Some(partuuid) = source.gpt.partuuid.as_deref() {
                if partuuid.trim().is_empty() {
                    return Err(BootProfileValidationError::EmptyGptPartuuid);
                }
                selectors += 1;
            }
            if source.gpt.index.is_some() {
                selectors += 1;
            }

            if selectors != 1 {
                return Err(BootProfileValidationError::InvalidGptSelectorCount { selectors });
            }

            validate_artifact_source(source.gpt.source.as_ref(), depth + 1)
        }
    }
}

fn validate_profile_artifact_path_source(
    source: &BootProfileArtifactPathSource,
    empty_path_err: BootProfileValidationError,
) -> Result<(), BootProfileValidationError> {
    if source.path.trim().is_empty() {
        return Err(empty_path_err);
    }
    validate_artifact_source(source.artifact_source(), 0)
}
