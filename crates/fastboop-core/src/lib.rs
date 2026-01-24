#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod bootimg;
pub mod fastboot;

use alloc::{string::String, vec::Vec};
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
    FastbootGetvarExists(FastbootGetvarExists),
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
pub struct FastbootGetvarExists {
    #[serde(rename = "fastboot.getvar")]
    pub name: String,
    /// presence of the key means "exists" check
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exists: Option<ExistsFlag>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ExistsFlag;

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
    pub limits: BootLimits,
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
pub struct KernelEncoding {
    #[serde(rename = "type")]
    pub kind: KernelEncodingKind,
    #[serde(default)]
    pub compress: Option<Compression>,
    #[serde(default)]
    pub append_dtb: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum KernelEncodingKind {
    Image,
    ImageDtb,
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

/// Newline-separated list of modules to load, in deterministic order.
pub type ModuleLoadList = Vec<String>;

/// Minimal VFS-like access to a rootfs.
pub trait RootfsProvider {
    type Error;

    /// Read the full contents of a file at `path` (absolute or relative to rootfs).
    fn read_all(&self, path: &str) -> Result<alloc::vec::Vec<u8>, Self::Error>;

    /// Read a range of bytes from a file at `path`.
    fn read_range(
        &self,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<alloc::vec::Vec<u8>, Self::Error>;

    /// List entries (file/dir names) in a directory at `path`.
    fn read_dir(&self, path: &str) -> Result<alloc::vec::Vec<String>, Self::Error>;

    /// Check if a path exists.
    fn exists(&self, path: &str) -> Result<bool, Self::Error>;
}
