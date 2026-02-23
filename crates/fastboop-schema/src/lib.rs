#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// DevPro v0 schema root.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct DeviceProfile {
    pub id: String,
    pub display_name: Option<String>,
    pub devicetree_name: String,
    pub r#match: Vec<MatchRule>,
    pub probe: Vec<ProbeStep>,
    pub boot: Boot,
    pub stage0: Stage0,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct MatchRule {
    pub fastboot: FastbootMatch,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct FastbootMatch {
    pub vid: u16,
    pub pid: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum ProbeStep {
    #[serde(untagged)]
    FastbootGetvarEq(FastbootGetvarEq),
    #[serde(untagged)]
    FastbootGetvarNotEq(FastbootGetvarNotEq),
    #[serde(untagged)]
    FastbootGetvarExists(FastbootGetvarExists),
    #[serde(untagged)]
    FastbootGetvarNotExists(FastbootGetvarNotExists),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct FastbootGetvarEq {
    #[serde(rename = "fastboot.getvar")]
    pub name: String,
    pub equals: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct FastbootGetvarNotEq {
    #[serde(rename = "fastboot.getvar")]
    pub name: String,
    pub not_equals: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct FastbootGetvarExists {
    #[serde(rename = "fastboot.getvar")]
    pub name: String,
    /// presence of the key means "exists" check
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exists: Option<ExistsFlag>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct FastbootGetvarNotExists {
    #[serde(rename = "fastboot.getvar")]
    pub name: String,
    /// presence of the key means "not_exists" check
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_exists: Option<NotExistsFlag>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ExistsFlag;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct NotExistsFlag;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Boot {
    pub fastboot_boot: BootPayload,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BootPayload {
    #[serde(alias = "bootimg")]
    pub android_bootimg: AndroidBootImage,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Stage0 {
    #[serde(default)]
    pub kernel_modules: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject_mac: Option<InjectMac>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct InjectMac {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wifi: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bluetooth: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct AndroidBootImage {
    pub header_version: u32,
    pub page_size: u32,
    #[serde(default)]
    pub base: Option<u64>,
    #[serde(default)]
    pub kernel_offset: Option<u64>,
    #[serde(default)]
    pub dtb_offset: Option<u64>,
    #[serde(default)]
    pub limits: Option<BootLimits>,
    pub kernel: AndroidKernel,
    #[serde(default)]
    pub initrd: Option<AndroidInitrd>,
    #[serde(default)]
    pub cmdline_append: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BootLimits {
    pub max_kernel_bytes: Option<u64>,
    pub max_initrd_bytes: Option<u64>,
    pub max_total_bytes: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct AndroidKernel {
    pub encoding: KernelEncoding,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum KernelEncoding {
    #[serde(rename = "image")]
    Image,
    #[serde(rename = "image+dtb")]
    ImageDtb,
    #[serde(rename = "image.gz")]
    ImageGzip,
    #[serde(rename = "image.gz+dtb")]
    ImageGzipDtb,
    #[serde(rename = "image.lz4")]
    ImageLz4,
    #[serde(rename = "image.lz4+dtb")]
    ImageLz4Dtb,
    #[serde(rename = "image.zst")]
    ImageZstd,
    #[serde(rename = "image.zst+dtb")]
    ImageZstdDtb,
}

impl KernelEncoding {
    pub fn compression(&self) -> Compression {
        match self {
            KernelEncoding::Image | KernelEncoding::ImageDtb => Compression::None,
            KernelEncoding::ImageGzip | KernelEncoding::ImageGzipDtb => Compression::Gzip,
            KernelEncoding::ImageLz4 | KernelEncoding::ImageLz4Dtb => Compression::Lz4,
            KernelEncoding::ImageZstd | KernelEncoding::ImageZstdDtb => Compression::Zstd,
        }
    }

    pub fn append_dtb(&self) -> bool {
        matches!(
            self,
            KernelEncoding::ImageDtb
                | KernelEncoding::ImageGzipDtb
                | KernelEncoding::ImageLz4Dtb
                | KernelEncoding::ImageZstdDtb
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Compression {
    None,
    Gzip,
    Lz4,
    Zstd,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct AndroidInitrd {
    #[serde(default)]
    pub compress: Option<Compression>,
}

/// Authoring schema for boot profiles (YAML/JSON).
///
/// This shape keeps DT overlays as inline DTS/DTSO text. Runtime code should consume
/// [`BootProfile`], where overlays are compiled DTB/DTBO blobs.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileManifest {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub rootfs: BootProfileRootfs,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<BootProfileArtifactPathSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtbs: Option<BootProfileArtifactPathSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dt_overlays: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_cmdline: Option<String>,
    #[serde(default, skip_serializing_if = "BootProfileManifestStage0::is_empty")]
    pub stage0: BootProfileManifestStage0,
}

impl BootProfileManifest {
    pub fn compile_dt_overlays<E, F>(&self, mut compile: F) -> Result<BootProfile, E>
    where
        F: FnMut(&str) -> Result<Vec<u8>, E>,
    {
        let mut dt_overlays = Vec::with_capacity(self.dt_overlays.len());
        for overlay in &self.dt_overlays {
            dt_overlays.push(compile(overlay)?);
        }

        let mut devices = BTreeMap::new();
        for (device_id, device) in &self.stage0.devices {
            let mut device_overlays = Vec::with_capacity(device.dt_overlays.len());
            for overlay in &device.dt_overlays {
                device_overlays.push(compile(overlay)?);
            }
            devices.insert(
                device_id.clone(),
                BootProfileDevice {
                    dt_overlays: device_overlays,
                    extra_cmdline: device.extra_cmdline.clone(),
                    stage0: BootProfileDeviceStage0 {
                        extra_modules: device.stage0.extra_modules.clone(),
                    },
                },
            );
        }

        Ok(BootProfile {
            id: self.id.clone(),
            display_name: self.display_name.clone(),
            rootfs: self.rootfs.clone(),
            kernel: self.kernel.clone(),
            dtbs: self.dtbs.clone(),
            dt_overlays,
            extra_cmdline: self.extra_cmdline.clone(),
            stage0: BootProfileStage0 {
                extra_modules: self.stage0.extra_modules.clone(),
                devices,
            },
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileManifestStage0 {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_modules: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub devices: BTreeMap<String, BootProfileManifestDevice>,
}

impl BootProfileManifestStage0 {
    pub fn is_empty(&self) -> bool {
        self.extra_modules.is_empty() && self.devices.is_empty()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileManifestDevice {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dt_overlays: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_cmdline: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "BootProfileManifestDeviceStage0::is_empty"
    )]
    pub stage0: BootProfileManifestDeviceStage0,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileManifestDeviceStage0 {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_modules: Vec<String>,
}

impl BootProfileManifestDeviceStage0 {
    pub fn is_empty(&self) -> bool {
        self.extra_modules.is_empty()
    }
}

/// Runtime boot profile with precompiled DT overlays.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfile {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub rootfs: BootProfileRootfs,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<BootProfileArtifactPathSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtbs: Option<BootProfileArtifactPathSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dt_overlays: Vec<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_cmdline: Option<String>,
    #[serde(default, skip_serializing_if = "BootProfileStage0::is_empty")]
    pub stage0: BootProfileStage0,
}

impl BootProfile {
    pub fn decompile_dt_overlays<E, F>(&self, mut decompile: F) -> Result<BootProfileManifest, E>
    where
        F: FnMut(&[u8]) -> Result<String, E>,
    {
        let mut dt_overlays = Vec::with_capacity(self.dt_overlays.len());
        for overlay in &self.dt_overlays {
            dt_overlays.push(decompile(overlay)?);
        }

        let mut devices = BTreeMap::new();
        for (device_id, device) in &self.stage0.devices {
            let mut device_overlays = Vec::with_capacity(device.dt_overlays.len());
            for overlay in &device.dt_overlays {
                device_overlays.push(decompile(overlay)?);
            }
            devices.insert(
                device_id.clone(),
                BootProfileManifestDevice {
                    dt_overlays: device_overlays,
                    extra_cmdline: device.extra_cmdline.clone(),
                    stage0: BootProfileManifestDeviceStage0 {
                        extra_modules: device.stage0.extra_modules.clone(),
                    },
                },
            );
        }

        Ok(BootProfileManifest {
            id: self.id.clone(),
            display_name: self.display_name.clone(),
            rootfs: self.rootfs.clone(),
            kernel: self.kernel.clone(),
            dtbs: self.dtbs.clone(),
            dt_overlays,
            extra_cmdline: self.extra_cmdline.clone(),
            stage0: BootProfileManifestStage0 {
                extra_modules: self.stage0.extra_modules.clone(),
                devices,
            },
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileStage0 {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_modules: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub devices: BTreeMap<String, BootProfileDevice>,
}

impl BootProfileStage0 {
    pub fn is_empty(&self) -> bool {
        self.extra_modules.is_empty() && self.devices.is_empty()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileDevice {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dt_overlays: Vec<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_cmdline: Option<String>,
    #[serde(default, skip_serializing_if = "BootProfileDeviceStage0::is_empty")]
    pub stage0: BootProfileDeviceStage0,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileDeviceStage0 {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_modules: Vec<String>,
}

impl BootProfileDeviceStage0 {
    pub fn is_empty(&self) -> bool {
        self.extra_modules.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(untagged)]
pub enum BootProfileRootfs {
    Erofs(BootProfileRootfsErofsSource),
    Ext4(BootProfileRootfsExt4Source),
}

impl BootProfileRootfs {
    pub fn source(&self) -> &BootProfileArtifactSource {
        match self {
            Self::Erofs(source) => &source.erofs,
            Self::Ext4(source) => &source.ext4,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BootProfileArtifactPathSource {
    pub path: String,
    #[serde(flatten)]
    pub source: BootProfileRootfs,
}

impl BootProfileArtifactPathSource {
    pub fn artifact_source(&self) -> &BootProfileArtifactSource {
        self.source.source()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileRootfsErofsSource {
    pub erofs: BootProfileArtifactSource,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileRootfsExt4Source {
    pub ext4: BootProfileArtifactSource,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(untagged)]
pub enum BootProfileArtifactSource {
    Casync(BootProfileArtifactSourceCasyncSource),
    Http(BootProfileArtifactSourceHttpSource),
    File(BootProfileArtifactSourceFileSource),
    Xz(BootProfileArtifactSourceXzSource),
    AndroidSparseImg(BootProfileArtifactSourceAndroidSparseImgSource),
    Gpt(BootProfileArtifactSourceGptSource),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileArtifactSourceCasyncSource {
    pub casync: BootProfileArtifactSourceCasync,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileArtifactSourceHttpSource {
    pub http: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileArtifactSourceFileSource {
    pub file: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileArtifactSourceXzSource {
    pub xz: Box<BootProfileArtifactSource>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileArtifactSourceAndroidSparseImgSource {
    pub android_sparseimg: Box<BootProfileArtifactSource>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileArtifactSourceGptSource {
    pub gpt: BootProfileArtifactSourceGpt,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BootProfileArtifactSourceGpt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partlabel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partuuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    #[serde(flatten)]
    pub source: Box<BootProfileArtifactSource>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BootProfileArtifactSourceCasync {
    pub index: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_store: Option<String>,
}

pub mod bin;
