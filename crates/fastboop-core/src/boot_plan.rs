use alloc::string::{String, ToString};
use core::fmt;

use gibblox_pipeline::PipelineHints;

use crate::fastboot::{FastbootProtocolError, FastbootWire, boot, download};
use crate::{
    BootProfile, BootProfileArtifactSource, BootProfileSelectionError, ChannelStreamHead,
    DeviceProfile, EffectiveBootProfileStage0, resolve_effective_boot_profile_stage0,
    select_boot_profile_for_device,
};

#[derive(Clone, Debug)]
pub struct Channel {
    source: Option<String>,
    head: ChannelStreamHead,
}

impl Channel {
    pub fn new(source: Option<String>, head: ChannelStreamHead) -> Self {
        Self { source, head }
    }

    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    pub fn stream_head(&self) -> &ChannelStreamHead {
        &self.head
    }

    pub fn devprofiles(&self) -> &[DeviceProfile] {
        &self.head.dev_profiles
    }

    pub fn bootprofiles(&self) -> &[BootProfile] {
        &self.head.boot_profiles
    }

    pub fn pipeline_hints(&self) -> &PipelineHints {
        &self.head.pipeline_hints
    }

    pub fn select_boot_profile(
        &self,
        device_profile_id: &str,
        requested_boot_profile_id: Option<&str>,
    ) -> Result<BootProfile, BootProfileSelectionError> {
        select_boot_profile_for_device(
            self.bootprofiles(),
            device_profile_id,
            requested_boot_profile_id,
        )
    }

    pub fn boot_spec(&self, request: BootSpecRequest) -> Result<BootSpec, BootSpecError> {
        let boot_profile = self.resolve_boot_profile(
            request.device_profile.id.as_str(),
            request.requested_boot_profile_id.as_deref(),
        )?;
        Ok(BootSpec::new(request.device_profile, boot_profile))
    }

    pub fn resolve_boot_profile(
        &self,
        device_profile_id: &str,
        requested_boot_profile_id: Option<&str>,
    ) -> Result<Option<BootProfile>, BootSpecError> {
        if self.bootprofiles().is_empty() {
            if let Some(requested) = requested_boot_profile_id {
                return Err(BootSpecError::RequestedBootProfileWithoutStream {
                    requested: requested.to_string(),
                });
            }
            return Ok(None);
        }

        self.select_boot_profile(device_profile_id, requested_boot_profile_id)
            .map(Some)
            .map_err(BootSpecError::BootProfileSelection)
    }
}

#[derive(Clone, Debug)]
pub struct BootSpecRequest {
    device_profile: DeviceProfile,
    requested_boot_profile_id: Option<String>,
}

impl BootSpecRequest {
    pub fn new(device_profile: DeviceProfile) -> Self {
        Self {
            device_profile,
            requested_boot_profile_id: None,
        }
    }

    pub fn with_requested_boot_profile_id(mut self, requested: impl Into<String>) -> Self {
        self.requested_boot_profile_id = Some(requested.into());
        self
    }

    pub fn with_optional_requested_boot_profile_id(mut self, requested: Option<String>) -> Self {
        self.requested_boot_profile_id = requested;
        self
    }

    pub fn device_profile(&self) -> &DeviceProfile {
        &self.device_profile
    }

    pub fn requested_boot_profile_id(&self) -> Option<&str> {
        self.requested_boot_profile_id.as_deref()
    }
}

#[derive(Debug)]
pub enum BootSpecError {
    RequestedBootProfileWithoutStream { requested: String },
    BootProfileSelection(BootProfileSelectionError),
}

impl fmt::Display for BootSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestedBootProfileWithoutStream { requested } => write!(
                f,
                "boot profile '{requested}' was requested, but channel does not start with a boot profile stream"
            ),
            Self::BootProfileSelection(err) => write!(f, "{err}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BootSpec {
    device_profile: DeviceProfile,
    boot_profile: Option<BootProfile>,
    stage0: EffectiveBootProfileStage0,
}

impl BootSpec {
    pub fn new(device_profile: DeviceProfile, boot_profile: Option<BootProfile>) -> Self {
        let stage0 = boot_profile
            .as_ref()
            .map(|profile| resolve_effective_boot_profile_stage0(profile, &device_profile.id))
            .unwrap_or_default();
        Self {
            device_profile,
            boot_profile,
            stage0,
        }
    }

    pub fn device_profile(&self) -> &DeviceProfile {
        &self.device_profile
    }

    pub fn boot_profile(&self) -> Option<&BootProfile> {
        self.boot_profile.as_ref()
    }

    pub fn stage0(&self) -> &EffectiveBootProfileStage0 {
        &self.stage0
    }

    pub fn pipelines(&self) -> BootSpecPipelines<'_> {
        BootSpecPipelines {
            rootfs: self
                .boot_profile
                .as_ref()
                .map(|profile| profile.rootfs.source()),
            kernel: self
                .boot_profile
                .as_ref()
                .and_then(|profile| profile.kernel.as_ref())
                .map(|source| source.artifact_source()),
            dtbs: self
                .boot_profile
                .as_ref()
                .and_then(|profile| profile.dtbs.as_ref())
                .map(|source| source.artifact_source()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BootSpecPipelines<'a> {
    pub rootfs: Option<&'a BootProfileArtifactSource>,
    pub kernel: Option<&'a BootProfileArtifactSource>,
    pub dtbs: Option<&'a BootProfileArtifactSource>,
}

pub struct FastbootBoot<'a> {
    boot_image: &'a [u8],
}

impl<'a> FastbootBoot<'a> {
    pub fn new(boot_image: &'a [u8]) -> Self {
        Self { boot_image }
    }

    pub fn boot_image(&self) -> &'a [u8] {
        self.boot_image
    }

    pub async fn download<F>(&self, fastboot: &mut F) -> Result<(), FastbootProtocolError<F::Error>>
    where
        F: FastbootWire,
    {
        download(fastboot, self.boot_image).await
    }

    pub async fn boot<F>(&self, fastboot: &mut F) -> Result<(), FastbootProtocolError<F::Error>>
    where
        F: FastbootWire,
    {
        boot(fastboot).await
    }

    pub async fn run<F>(&self, fastboot: &mut F) -> Result<(), FastbootProtocolError<F::Error>>
    where
        F: FastbootWire,
    {
        self.download(fastboot).await?;
        self.boot(fastboot).await
    }
}
