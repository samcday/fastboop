#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt;

use async_trait::async_trait;
use fastboop_core::bootimg::{BootImageError, build_android_bootimg};
use fastboop_core::builtin::builtin_profiles;
use fastboop_core::fastboot::{FastbootProtocolError, FastbootWire, ProbeError, boot, download};
use fastboop_core::{
    BootProfile, BootProfileArtifactSource, BootProfileRootfs, BootProfileRootfsFilesystemSource,
    CHANNEL_SNIFF_PREFIX_LEN, ChannelStreamKind, DeviceProfile, classify_channel_prefix,
};
use fastboop_stage0_generator::{
    Stage0Build, Stage0Error, Stage0KernelOverride, Stage0Options, Stage0SwitchrootFs,
    build_stage0, stage0_binary_ready,
};
use gibblox_core::{
    AlignedByteReader, BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext,
};
use gibblox_ext4::{Ext4EntryType, Ext4Fs};
use gobblytes_core::{Filesystem, FilesystemEntryType, normalize_ostree_deployment_path};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const SESSION_STATE_VERSION: u32 = 0;
pub const SESSION_STATE_MAGIC: &[u8; 8] = b"FBSESS0\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OstreeArg {
    Disabled,
    AutoDetect,
    Explicit(String),
}

#[derive(Debug)]
pub enum OstreeArgError {
    Normalize(gobblytes_core::OstreeError),
}

impl fmt::Display for OstreeArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normalize(err) => write!(f, "normalize ostree deployment path: {err}"),
        }
    }
}

pub fn parse_ostree_arg(raw: Option<&Option<String>>) -> Result<OstreeArg, OstreeArgError> {
    match raw {
        None => Ok(OstreeArg::Disabled),
        Some(None) => Ok(OstreeArg::AutoDetect),
        Some(Some(path)) => normalize_ostree_deployment_path(path)
            .map(OstreeArg::Explicit)
            .map_err(OstreeArgError::Normalize),
    }
}

pub fn resolve_effective_ostree_arg(
    requested: &OstreeArg,
    boot_profile: Option<&BootProfile>,
) -> OstreeArg {
    if matches!(requested, OstreeArg::Disabled)
        && boot_profile.is_some_and(|profile| profile.rootfs.is_ostree())
    {
        OstreeArg::AutoDetect
    } else {
        requested.clone()
    }
}

#[derive(Debug)]
pub enum OstreeDetectError {
    Filesystem {
        operation: &'static str,
        path: String,
        source: String,
    },
    NotDirectory {
        path: &'static str,
    },
    MissingDeploymentSymlink,
}

impl fmt::Display for OstreeDetectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Filesystem {
                operation,
                path,
                source,
            } => write!(f, "{operation} {path}: {source}"),
            Self::NotDirectory { path } => {
                write!(
                    f,
                    "auto-detect ostree deployment failed: {path} is not a directory"
                )
            }
            Self::MissingDeploymentSymlink => write!(
                f,
                "auto-detect ostree deployment failed: no deployment symlink found under /ostree/boot.*"
            ),
        }
    }
}

pub async fn auto_detect_ostree_deployment_path<P>(rootfs: &P) -> Result<String, OstreeDetectError>
where
    P: Filesystem,
    P::Error: fmt::Display,
{
    const OSTREE_ROOT: &str = "/ostree";

    if !is_directory(rootfs, OSTREE_ROOT).await? {
        return Err(OstreeDetectError::NotDirectory { path: OSTREE_ROOT });
    }

    for boot_dir in sorted_dir_entries(rootfs, OSTREE_ROOT).await? {
        if !boot_dir.starts_with("boot.") {
            continue;
        }
        let boot_path = format!("{OSTREE_ROOT}/{boot_dir}");
        if !is_directory(rootfs, &boot_path).await? {
            continue;
        }

        for stateroot in sorted_dir_entries(rootfs, &boot_path).await? {
            let stateroot_path = format!("{boot_path}/{stateroot}");
            if !is_directory(rootfs, &stateroot_path).await? {
                continue;
            }

            for checksum in sorted_dir_entries(rootfs, &stateroot_path).await? {
                let checksum_path = format!("{stateroot_path}/{checksum}");
                if !is_directory(rootfs, &checksum_path).await? {
                    continue;
                }

                for deploy_index in sorted_dir_entries(rootfs, &checksum_path).await? {
                    let candidate_path = format!("{checksum_path}/{deploy_index}");
                    if is_symlink(rootfs, &candidate_path).await? {
                        return Ok(candidate_path.trim_start_matches('/').to_string());
                    }
                }
            }
        }
    }

    Err(OstreeDetectError::MissingDeploymentSymlink)
}

async fn sorted_dir_entries<P>(rootfs: &P, path: &str) -> Result<Vec<String>, OstreeDetectError>
where
    P: Filesystem,
    P::Error: fmt::Display,
{
    let mut entries = rootfs
        .read_dir(path)
        .await
        .map_err(|err| ostree_fs_error("read directory", path, err))?;
    entries.sort();
    Ok(entries)
}

async fn is_directory<P>(rootfs: &P, path: &str) -> Result<bool, OstreeDetectError>
where
    P: Filesystem,
    P::Error: fmt::Display,
{
    let ty = rootfs
        .entry_type(path)
        .await
        .map_err(|err| ostree_fs_error("read entry type", path, err))?;
    Ok(matches!(ty, Some(FilesystemEntryType::Directory)))
}

async fn is_symlink<P>(rootfs: &P, path: &str) -> Result<bool, OstreeDetectError>
where
    P: Filesystem,
    P::Error: fmt::Display,
{
    let ty = rootfs
        .entry_type(path)
        .await
        .map_err(|err| ostree_fs_error("read entry type", path, err))?;
    Ok(matches!(ty, Some(FilesystemEntryType::Symlink)))
}

fn ostree_fs_error<E>(operation: &'static str, path: &str, source: E) -> OstreeDetectError
where
    E: fmt::Display,
{
    OstreeDetectError::Filesystem {
        operation,
        path: path.to_string(),
        source: source.to_string(),
    }
}

#[derive(Debug)]
pub enum DeviceProfilePoolError {
    Builtin(postcard::Error),
    NotFound {
        requested: String,
        available: Vec<String>,
    },
}

impl fmt::Display for DeviceProfilePoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Builtin(err) => write!(f, "loading builtin device profiles: {err}"),
            Self::NotFound {
                requested,
                available,
            } => write!(
                f,
                "device profile '{requested}' not found; available ids: [{}]",
                available.join(", ")
            ),
        }
    }
}

/// Returns the device profile matching pool: the union of built-in,
/// channel-carried, and externally-loaded DevPros. Precedence on id collision
/// is `external > channel > built-in`.
pub fn build_device_profile_pool(
    channel_dev_profiles: &[DeviceProfile],
    external_profiles: impl IntoIterator<Item = DeviceProfile>,
) -> Result<Vec<DeviceProfile>, DeviceProfilePoolError> {
    let mut profiles = BTreeMap::<String, DeviceProfile>::new();
    for profile in builtin_profiles().map_err(DeviceProfilePoolError::Builtin)? {
        profiles.insert(profile.id.clone(), profile);
    }
    for profile in channel_dev_profiles {
        profiles.insert(profile.id.clone(), profile.clone());
    }
    for profile in external_profiles {
        profiles.insert(profile.id.clone(), profile);
    }
    Ok(profiles.into_values().collect())
}

pub fn resolve_profile_in_pool(
    pool: &[DeviceProfile],
    requested: &str,
) -> Result<DeviceProfile, DeviceProfilePoolError> {
    if let Some(profile) = pool.iter().find(|profile| profile.id == requested) {
        return Ok(profile.clone());
    }

    let mut available: Vec<_> = pool.iter().map(|profile| profile.id.clone()).collect();
    available.sort();
    Err(DeviceProfilePoolError::NotFound {
        requested: requested.to_string(),
        available,
    })
}

pub fn format_probe_error<E>(err: ProbeError<FastbootProtocolError<E>>) -> String
where
    E: fmt::Display,
{
    match err {
        ProbeError::Transport(err) => err.to_string(),
        ProbeError::MissingVar(name) => format!("missing getvar {name}"),
        ProbeError::Mismatch {
            name,
            expected,
            actual,
        } => format!("getvar {name} mismatch: expected '{expected}', got '{actual}'"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage0RootfsKind {
    Erofs,
    Ext4,
    Fat,
}

#[derive(Clone, Debug)]
pub enum BlockReaderHelperError {
    BlockReader(GibbloxError),
    BlockSizeZero,
    SizeOverflow(&'static str),
    OffsetExceedsSize { offset_bytes: u64, size_bytes: u64 },
    OffsetOverflow(&'static str),
}

impl fmt::Display for BlockReaderHelperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlockReader(err) => write!(f, "block reader error: {err}"),
            Self::BlockSizeZero => write!(f, "block reader block size is zero"),
            Self::SizeOverflow(context) => write!(f, "block reader size overflow: {context}"),
            Self::OffsetExceedsSize {
                offset_bytes,
                size_bytes,
            } => write!(
                f,
                "block reader offset {offset_bytes} exceeds source size {size_bytes}"
            ),
            Self::OffsetOverflow(context) => {
                write!(f, "block reader offset overflow: {context}")
            }
        }
    }
}

impl From<GibbloxError> for BlockReaderHelperError {
    fn from(value: GibbloxError) -> Self {
        Self::BlockReader(value)
    }
}

pub async fn block_reader_size_bytes<R>(reader: &R) -> Result<u64, BlockReaderHelperError>
where
    R: BlockReader + ?Sized,
{
    reader
        .total_blocks()
        .await?
        .checked_mul(reader.block_size() as u64)
        .ok_or(BlockReaderHelperError::SizeOverflow(
            "total blocks * block size",
        ))
}

pub async fn read_block_reader_prefix<R>(
    reader: &R,
    cap: usize,
) -> Result<Vec<u8>, BlockReaderHelperError>
where
    R: BlockReader + ?Sized,
{
    let block_size = reader.block_size() as usize;
    if block_size == 0 {
        return Err(BlockReaderHelperError::BlockSizeZero);
    }

    let total_bytes = block_reader_size_bytes(reader).await?;
    let prefix_len = core::cmp::min(cap as u64, total_bytes) as usize;
    if prefix_len == 0 {
        return Ok(Vec::new());
    }

    let blocks_to_read = prefix_len.div_ceil(block_size);
    let mut scratch = vec![0u8; blocks_to_read * block_size];
    let read = reader
        .read_blocks(0, &mut scratch, ReadContext::FOREGROUND)
        .await?;
    scratch.truncate(core::cmp::min(read, prefix_len));
    Ok(scratch)
}

pub async fn classify_channel_reader<R>(
    reader: &R,
) -> Result<ChannelStreamKind, BlockReaderHelperError>
where
    R: BlockReader + ?Sized,
{
    let prefix = read_block_reader_prefix(reader, CHANNEL_SNIFF_PREFIX_LEN).await?;
    Ok(classify_channel_prefix(&prefix))
}

pub async fn detect_rootfs_kind<R>(
    reader: &R,
) -> Result<Option<Stage0RootfsKind>, BlockReaderHelperError>
where
    R: BlockReader + ?Sized,
{
    if reader_has_erofs_magic(reader).await? {
        return Ok(Some(Stage0RootfsKind::Erofs));
    }
    if reader_has_ext4_magic(reader).await? {
        return Ok(Some(Stage0RootfsKind::Ext4));
    }
    if reader_has_fat_magic(reader).await? {
        return Ok(Some(Stage0RootfsKind::Fat));
    }
    Ok(None)
}

pub async fn reader_has_erofs_magic<R>(reader: &R) -> Result<bool, BlockReaderHelperError>
where
    R: BlockReader + ?Sized,
{
    const EROFS_SUPER_OFFSET: u64 = 1024;
    const EROFS_SUPER_MAGIC: u32 = 0xe0f5_e1e2;

    let Some(bytes) = read_magic_bytes(reader, EROFS_SUPER_OFFSET, 4).await? else {
        return Ok(false);
    };
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    Ok(magic == EROFS_SUPER_MAGIC)
}

pub async fn reader_has_ext4_magic<R>(reader: &R) -> Result<bool, BlockReaderHelperError>
where
    R: BlockReader + ?Sized,
{
    const EXT4_MAGIC_OFFSET: u64 = 1024 + 0x38;
    const EXT4_MAGIC: u16 = 0xef53;

    let Some(bytes) = read_magic_bytes(reader, EXT4_MAGIC_OFFSET, 2).await? else {
        return Ok(false);
    };
    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    Ok(magic == EXT4_MAGIC)
}

pub async fn reader_has_fat_magic<R>(reader: &R) -> Result<bool, BlockReaderHelperError>
where
    R: BlockReader + ?Sized,
{
    let Some(boot_signature) = read_magic_bytes(reader, 510, 2).await? else {
        return Ok(false);
    };
    if boot_signature.as_slice() != [0x55, 0xAA] {
        return Ok(false);
    }

    let fat12 = read_magic_bytes(reader, 54, 5).await?;
    if fat12.as_deref() == Some(b"FAT12") {
        return Ok(true);
    }

    let fat16 = read_magic_bytes(reader, 54, 5).await?;
    if fat16.as_deref() == Some(b"FAT16") {
        return Ok(true);
    }

    let fat32 = read_magic_bytes(reader, 82, 5).await?;
    Ok(fat32.as_deref() == Some(b"FAT32"))
}

async fn read_magic_bytes<R>(
    reader: &R,
    offset: u64,
    len: usize,
) -> Result<Option<Vec<u8>>, BlockReaderHelperError>
where
    R: BlockReader + ?Sized,
{
    if len == 0 {
        return Ok(Some(Vec::new()));
    }

    let block_size = reader.block_size() as u64;
    if block_size == 0 {
        return Err(BlockReaderHelperError::BlockSizeZero);
    }
    let total_bytes = block_reader_size_bytes(reader).await?;
    let required_end = offset
        .checked_add(len as u64)
        .ok_or(BlockReaderHelperError::OffsetOverflow("magic end offset"))?;
    if total_bytes < required_end {
        return Ok(None);
    }

    let super_lba = offset / block_size;
    let within_block = (offset % block_size) as usize;
    let block_size_usize = block_size as usize;
    let required = within_block + len;
    let blocks_to_read = required.div_ceil(block_size_usize);
    let mut scratch = vec![0u8; blocks_to_read * block_size_usize];
    reader
        .read_blocks(super_lba, &mut scratch, ReadContext::FOREGROUND)
        .await?;
    Ok(Some(scratch[within_block..within_block + len].to_vec()))
}

#[derive(Clone)]
pub struct OffsetBlockReader {
    inner: Arc<dyn BlockReader>,
    offset_bytes: u64,
    size_bytes: u64,
    block_size: u32,
}

impl OffsetBlockReader {
    pub fn new(
        inner: Arc<dyn BlockReader>,
        offset_bytes: u64,
        inner_size_bytes: u64,
    ) -> Result<Self, BlockReaderHelperError> {
        let block_size = inner.block_size();
        if block_size == 0 {
            return Err(BlockReaderHelperError::BlockSizeZero);
        }
        if offset_bytes > inner_size_bytes {
            return Err(BlockReaderHelperError::OffsetExceedsSize {
                offset_bytes,
                size_bytes: inner_size_bytes,
            });
        }

        Ok(Self {
            inner,
            offset_bytes,
            size_bytes: inner_size_bytes - offset_bytes,
            block_size,
        })
    }
}

#[async_trait]
impl BlockReader for OffsetBlockReader {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        let block_size = self.block_size as u64;
        if block_size == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "block size must be non-zero",
            ));
        }
        Ok(self.size_bytes.div_ceil(block_size))
    }

    fn write_identity(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.inner.write_identity(out)?;
        write!(out, "|offset:{}", self.offset_bytes)
    }

    async fn read_blocks(
        &self,
        lba: u64,
        buf: &mut [u8],
        ctx: ReadContext,
    ) -> GibbloxResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let block_size = self.block_size as u64;
        let local_offset = lba.checked_mul(block_size).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "channel read offset overflow")
        })?;
        if local_offset >= self.size_bytes {
            return Ok(0);
        }

        let remaining = self.size_bytes - local_offset;
        let max_read = core::cmp::min(buf.len() as u64, remaining) as usize;
        let global_offset = self.offset_bytes.checked_add(local_offset).ok_or_else(|| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "channel global read offset overflow",
            )
        })?;

        let byte_reader = AlignedByteReader::new(self.inner.clone()).await?;
        byte_reader
            .read_exact_at(global_offset, &mut buf[..max_read], ctx)
            .await?;
        Ok(max_read)
    }
}

pub async fn maybe_offset_block_reader(
    reader: Arc<dyn BlockReader>,
    offset_bytes: u64,
) -> Result<Arc<dyn BlockReader>, BlockReaderHelperError> {
    if offset_bytes == 0 {
        return Ok(reader);
    }

    let size_bytes = block_reader_size_bytes(reader.as_ref()).await?;
    Ok(Arc::new(OffsetBlockReader::new(
        reader,
        offset_bytes,
        size_bytes,
    )?))
}

#[derive(Clone, Debug)]
pub enum RootfsAdapterError {
    Ext4 {
        operation: &'static str,
        path: Option<String>,
        source: String,
    },
}

impl fmt::Display for RootfsAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ext4 {
                operation,
                path,
                source,
            } => match path {
                Some(path) => write!(f, "{operation} {path}: {source}"),
                None => write!(f, "{operation}: {source}"),
            },
        }
    }
}

#[derive(Clone)]
pub struct Ext4Rootfs {
    fs: Ext4Fs,
}

impl Ext4Rootfs {
    pub async fn open(reader: Arc<dyn BlockReader>) -> Result<Self, RootfsAdapterError> {
        let fs = Ext4Fs::open(reader)
            .await
            .map_err(|err| RootfsAdapterError::Ext4 {
                operation: "open ext4 rootfs",
                path: None,
                source: err.to_string(),
            })?;
        Ok(Self { fs })
    }
}

impl Filesystem for Ext4Rootfs {
    type Error = RootfsAdapterError;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>, Self::Error> {
        self.fs
            .read_all(path)
            .await
            .map_err(|err| RootfsAdapterError::Ext4 {
                operation: "read ext4 path",
                path: Some(path.to_string()),
                source: err.to_string(),
            })
    }

    async fn read_range(
        &self,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        self.fs
            .read_range(path, offset, len)
            .await
            .map_err(|err| RootfsAdapterError::Ext4 {
                operation: "read ext4 path range",
                path: Some(format!("{path}@{offset}+{len}")),
                source: err.to_string(),
            })
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>, Self::Error> {
        self.fs
            .read_dir(path)
            .await
            .map_err(|err| RootfsAdapterError::Ext4 {
                operation: "read ext4 directory",
                path: Some(path.to_string()),
                source: err.to_string(),
            })
    }

    async fn entry_type(&self, path: &str) -> Result<Option<FilesystemEntryType>, Self::Error> {
        let ty = self
            .fs
            .entry_type(path)
            .await
            .map_err(|err| RootfsAdapterError::Ext4 {
                operation: "read ext4 entry type",
                path: Some(path.to_string()),
                source: err.to_string(),
            })?;
        Ok(ty.map(|entry| match entry {
            Ext4EntryType::File => FilesystemEntryType::File,
            Ext4EntryType::Directory => FilesystemEntryType::Directory,
            Ext4EntryType::Symlink => FilesystemEntryType::Symlink,
            Ext4EntryType::Other => FilesystemEntryType::Other,
        }))
    }

    async fn read_link(&self, path: &str) -> Result<String, Self::Error> {
        self.fs
            .read_link(path)
            .await
            .map_err(|err| RootfsAdapterError::Ext4 {
                operation: "read ext4 symlink target",
                path: Some(path.to_string()),
                source: err.to_string(),
            })
    }

    async fn exists(&self, path: &str) -> Result<bool, Self::Error> {
        self.fs
            .exists(path)
            .await
            .map_err(|err| RootfsAdapterError::Ext4 {
                operation: "check ext4 path",
                path: Some(path.to_string()),
                source: err.to_string(),
            })
    }
}

pub trait Stage0RootfsFactory {
    type Erofs: Filesystem;
    type Fat: Filesystem;
    type Error;

    async fn open_erofs(
        &mut self,
        reader: Arc<dyn BlockReader>,
        image_size_bytes: u64,
    ) -> Result<Self::Erofs, Self::Error>;

    async fn open_fat(&mut self, reader: Arc<dyn BlockReader>) -> Result<Self::Fat, Self::Error>;
}

#[derive(Debug)]
pub enum Stage0RootfsProviderError<OpenError, ErofsError, FatError> {
    OpenErofs {
        source: OpenError,
    },
    OpenExt4 {
        source: RootfsAdapterError,
    },
    OpenFat {
        source: OpenError,
    },
    Erofs {
        operation: &'static str,
        path: String,
        source: ErofsError,
    },
    Ext4 {
        source: RootfsAdapterError,
    },
    Fat {
        operation: &'static str,
        path: String,
        source: FatError,
    },
    BlockReader {
        source: BlockReaderHelperError,
    },
    UnsupportedFatSwitchroot,
    EmptyProviderList,
    NoSupportedProvider,
    NoBootableProvider,
    MissingPath {
        path: String,
    },
    MissingSymlink {
        path: String,
    },
}

impl<OpenError, ErofsError, FatError> fmt::Display
    for Stage0RootfsProviderError<OpenError, ErofsError, FatError>
where
    OpenError: fmt::Display,
    ErofsError: fmt::Display,
    FatError: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenErofs { source } => write!(f, "open erofs rootfs: {source}"),
            Self::OpenExt4 { source } | Self::Ext4 { source } => write!(f, "{source}"),
            Self::OpenFat { source } => write!(f, "open fat rootfs: {source}"),
            Self::Erofs {
                operation,
                path,
                source,
            } => write!(f, "{operation} {path}: {source}"),
            Self::Fat {
                operation,
                path,
                source,
            } => write!(f, "{operation} {path}: {source}"),
            Self::BlockReader { source } => write!(f, "{source}"),
            Self::UnsupportedFatSwitchroot => {
                write!(f, "stage0 build does not support FAT rootfs providers")
            }
            Self::EmptyProviderList => write!(f, "channel filesystem provider list is empty"),
            Self::NoSupportedProvider => {
                write!(
                    f,
                    "channel did not contain a supported filesystem (erofs/ext4/fat)"
                )
            }
            Self::NoBootableProvider => write!(
                f,
                "channel did not contain a bootable root filesystem (erofs/ext4)"
            ),
            Self::MissingPath { path } => write!(f, "missing path {path}"),
            Self::MissingSymlink { path } => write!(f, "missing symlink {path}"),
        }
    }
}

pub type Stage0RootfsProviderErrorFor<F> = Stage0RootfsProviderError<
    <F as Stage0RootfsFactory>::Error,
    <<F as Stage0RootfsFactory>::Erofs as Filesystem>::Error,
    <<F as Stage0RootfsFactory>::Fat as Filesystem>::Error,
>;

pub enum Stage0RootfsProvider<F>
where
    F: Stage0RootfsFactory,
{
    Erofs(F::Erofs),
    Ext4(Ext4Rootfs),
    Fat(F::Fat),
}

impl<F> Stage0RootfsProvider<F>
where
    F: Stage0RootfsFactory,
{
    pub async fn open(
        kind: Stage0RootfsKind,
        reader: Arc<dyn BlockReader>,
        image_size_bytes: u64,
    ) -> Result<Self, Stage0RootfsProviderErrorFor<F>>
    where
        F: Default,
    {
        let mut factory = F::default();
        Self::open_with(&mut factory, kind, reader, image_size_bytes).await
    }

    pub async fn open_with(
        factory: &mut F,
        kind: Stage0RootfsKind,
        reader: Arc<dyn BlockReader>,
        image_size_bytes: u64,
    ) -> Result<Self, Stage0RootfsProviderErrorFor<F>> {
        match kind {
            Stage0RootfsKind::Erofs => factory
                .open_erofs(reader, image_size_bytes)
                .await
                .map(Self::Erofs)
                .map_err(|source| Stage0RootfsProviderError::OpenErofs { source }),
            Stage0RootfsKind::Ext4 => Ext4Rootfs::open(reader)
                .await
                .map(Self::Ext4)
                .map_err(|source| Stage0RootfsProviderError::OpenExt4 { source }),
            Stage0RootfsKind::Fat => factory
                .open_fat(reader)
                .await
                .map(Self::Fat)
                .map_err(|source| Stage0RootfsProviderError::OpenFat { source }),
        }
    }

    pub fn switchroot_fs(&self) -> Option<Stage0SwitchrootFs> {
        match self {
            Self::Erofs(_) => Some(Stage0SwitchrootFs::Erofs),
            Self::Ext4(_) => Some(Stage0SwitchrootFs::Ext4),
            Self::Fat(_) => None,
        }
    }

    pub fn require_switchroot_fs(
        &self,
    ) -> Result<Stage0SwitchrootFs, Stage0RootfsProviderErrorFor<F>> {
        self.switchroot_fs()
            .ok_or(Stage0RootfsProviderError::UnsupportedFatSwitchroot)
    }
}

impl<F> Filesystem for Stage0RootfsProvider<F>
where
    F: Stage0RootfsFactory,
{
    type Error = Stage0RootfsProviderErrorFor<F>;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::Erofs(rootfs) => {
                rootfs
                    .read_all(path)
                    .await
                    .map_err(|source| Stage0RootfsProviderError::Erofs {
                        operation: "read erofs path",
                        path: path.to_string(),
                        source,
                    })
            }
            Self::Ext4(rootfs) => rootfs
                .read_all(path)
                .await
                .map_err(|source| Stage0RootfsProviderError::Ext4 { source }),
            Self::Fat(rootfs) => {
                rootfs
                    .read_all(path)
                    .await
                    .map_err(|source| Stage0RootfsProviderError::Fat {
                        operation: "read fat path",
                        path: path.to_string(),
                        source,
                    })
            }
        }
    }

    async fn read_range(
        &self,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::Erofs(rootfs) => rootfs
                .read_range(path, offset, len)
                .await
                .map_err(|source| Stage0RootfsProviderError::Erofs {
                    operation: "read erofs path range",
                    path: format!("{path}@{offset}+{len}"),
                    source,
                }),
            Self::Ext4(rootfs) => rootfs
                .read_range(path, offset, len)
                .await
                .map_err(|source| Stage0RootfsProviderError::Ext4 { source }),
            Self::Fat(rootfs) => rootfs
                .read_range(path, offset, len)
                .await
                .map_err(|source| Stage0RootfsProviderError::Fat {
                    operation: "read fat path range",
                    path: format!("{path}@{offset}+{len}"),
                    source,
                }),
        }
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>, Self::Error> {
        match self {
            Self::Erofs(rootfs) => {
                rootfs
                    .read_dir(path)
                    .await
                    .map_err(|source| Stage0RootfsProviderError::Erofs {
                        operation: "read erofs directory",
                        path: path.to_string(),
                        source,
                    })
            }
            Self::Ext4(rootfs) => rootfs
                .read_dir(path)
                .await
                .map_err(|source| Stage0RootfsProviderError::Ext4 { source }),
            Self::Fat(rootfs) => {
                rootfs
                    .read_dir(path)
                    .await
                    .map_err(|source| Stage0RootfsProviderError::Fat {
                        operation: "read fat directory",
                        path: path.to_string(),
                        source,
                    })
            }
        }
    }

    async fn entry_type(&self, path: &str) -> Result<Option<FilesystemEntryType>, Self::Error> {
        match self {
            Self::Erofs(rootfs) => {
                rootfs
                    .entry_type(path)
                    .await
                    .map_err(|source| Stage0RootfsProviderError::Erofs {
                        operation: "read erofs entry type",
                        path: path.to_string(),
                        source,
                    })
            }
            Self::Ext4(rootfs) => rootfs
                .entry_type(path)
                .await
                .map_err(|source| Stage0RootfsProviderError::Ext4 { source }),
            Self::Fat(rootfs) => {
                rootfs
                    .entry_type(path)
                    .await
                    .map_err(|source| Stage0RootfsProviderError::Fat {
                        operation: "read fat entry type",
                        path: path.to_string(),
                        source,
                    })
            }
        }
    }

    async fn read_link(&self, path: &str) -> Result<String, Self::Error> {
        match self {
            Self::Erofs(rootfs) => {
                rootfs
                    .read_link(path)
                    .await
                    .map_err(|source| Stage0RootfsProviderError::Erofs {
                        operation: "read erofs symlink target",
                        path: path.to_string(),
                        source,
                    })
            }
            Self::Ext4(rootfs) => rootfs
                .read_link(path)
                .await
                .map_err(|source| Stage0RootfsProviderError::Ext4 { source }),
            Self::Fat(rootfs) => {
                rootfs
                    .read_link(path)
                    .await
                    .map_err(|source| Stage0RootfsProviderError::Fat {
                        operation: "read fat symlink target",
                        path: path.to_string(),
                        source,
                    })
            }
        }
    }

    async fn exists(&self, path: &str) -> Result<bool, Self::Error> {
        match self {
            Self::Erofs(rootfs) => {
                rootfs
                    .exists(path)
                    .await
                    .map_err(|source| Stage0RootfsProviderError::Erofs {
                        operation: "check erofs path",
                        path: path.to_string(),
                        source,
                    })
            }
            Self::Ext4(rootfs) => rootfs
                .exists(path)
                .await
                .map_err(|source| Stage0RootfsProviderError::Ext4 { source }),
            Self::Fat(rootfs) => {
                rootfs
                    .exists(path)
                    .await
                    .map_err(|source| Stage0RootfsProviderError::Fat {
                        operation: "check fat path",
                        path: path.to_string(),
                        source,
                    })
            }
        }
    }
}

impl<F> BootProfileSourceRootfs for Stage0RootfsProvider<F>
where
    F: Stage0RootfsFactory + Default,
{
    async fn open_boot_profile_source(
        source: &BootProfileRootfs,
        reader: Arc<dyn BlockReader>,
    ) -> Result<Self, Self::Error> {
        let kind = boot_profile_rootfs_kind(source);
        let image_size_bytes = block_reader_size_bytes(reader.as_ref())
            .await
            .map_err(|source| Stage0RootfsProviderError::BlockReader { source })?;
        Self::open(kind, reader, image_size_bytes).await
    }
}

pub struct Stage0CoalescingFilesystem<F>
where
    F: Stage0RootfsFactory,
{
    providers: Vec<Stage0RootfsProvider<F>>,
    switchroot_fs: Stage0SwitchrootFs,
}

impl<F> Stage0CoalescingFilesystem<F>
where
    F: Stage0RootfsFactory + Default,
{
    pub async fn open(
        readers: Vec<Arc<dyn BlockReader>>,
    ) -> Result<Self, Stage0RootfsProviderErrorFor<F>> {
        if readers.is_empty() {
            return Err(Stage0RootfsProviderError::EmptyProviderList);
        }

        let mut providers = Vec::new();
        for reader in readers {
            let image_size_bytes = block_reader_size_bytes(reader.as_ref())
                .await
                .map_err(|source| Stage0RootfsProviderError::BlockReader { source })?;
            let Some(kind) = detect_rootfs_kind(reader.as_ref())
                .await
                .map_err(|source| Stage0RootfsProviderError::BlockReader { source })?
            else {
                continue;
            };
            let provider = Stage0RootfsProvider::<F>::open(kind, reader, image_size_bytes).await?;
            providers.push(provider);
        }

        if providers.is_empty() {
            return Err(Stage0RootfsProviderError::NoSupportedProvider);
        }

        let switchroot_fs = providers
            .iter()
            .find_map(Stage0RootfsProvider::switchroot_fs)
            .ok_or(Stage0RootfsProviderError::NoBootableProvider)?;

        Ok(Self {
            providers,
            switchroot_fs,
        })
    }

    pub fn switchroot_fs(&self) -> Stage0SwitchrootFs {
        self.switchroot_fs
    }
}

impl<F> Filesystem for Stage0CoalescingFilesystem<F>
where
    F: Stage0RootfsFactory,
{
    type Error = Stage0RootfsProviderErrorFor<F>;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>, Self::Error> {
        let mut last_err = None;
        for provider in &self.providers {
            match provider.read_all(path).await {
                Ok(data) => return Ok(data),
                Err(err) => last_err = Some(err),
            }
        }
        Err(
            last_err.unwrap_or_else(|| Stage0RootfsProviderError::MissingPath {
                path: path.to_string(),
            }),
        )
    }

    async fn read_range(
        &self,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut last_err = None;
        for provider in &self.providers {
            match provider.read_range(path, offset, len).await {
                Ok(data) => return Ok(data),
                Err(err) => last_err = Some(err),
            }
        }
        Err(
            last_err.unwrap_or_else(|| Stage0RootfsProviderError::MissingPath {
                path: path.to_string(),
            }),
        )
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>, Self::Error> {
        let Some(first) = self.providers.first() else {
            return Err(Stage0RootfsProviderError::EmptyProviderList);
        };
        first.read_dir(path).await
    }

    async fn entry_type(&self, path: &str) -> Result<Option<FilesystemEntryType>, Self::Error> {
        let mut last_err = None;
        for provider in &self.providers {
            match provider.entry_type(path).await {
                Ok(Some(ty)) => return Ok(Some(ty)),
                Ok(None) => {}
                Err(err) => last_err = Some(err),
            }
        }

        if let Some(err) = last_err {
            Err(err)
        } else {
            Ok(None)
        }
    }

    async fn read_link(&self, path: &str) -> Result<String, Self::Error> {
        let mut last_err = None;
        for provider in &self.providers {
            match provider.read_link(path).await {
                Ok(target) => return Ok(target),
                Err(err) => last_err = Some(err),
            }
        }
        Err(
            last_err.unwrap_or_else(|| Stage0RootfsProviderError::MissingSymlink {
                path: path.to_string(),
            }),
        )
    }

    async fn exists(&self, path: &str) -> Result<bool, Self::Error> {
        let mut last_err = None;
        for provider in &self.providers {
            match provider.exists(path).await {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(err) => last_err = Some(err),
            }
        }

        if let Some(err) = last_err {
            Err(err)
        } else {
            Ok(false)
        }
    }
}

pub struct BootProfileSourceOverrides {
    pub kernel_override: Option<Stage0KernelOverride>,
    pub dtb_override: Option<Vec<u8>>,
}

impl BootProfileSourceOverrides {
    pub const fn empty() -> Self {
        Self {
            kernel_override: None,
            dtb_override: None,
        }
    }
}

pub trait BootProfileArtifactSourceOpener {
    type Error;

    async fn open_boot_profile_artifact_source(
        &mut self,
        source: &BootProfileArtifactSource,
    ) -> Result<Arc<dyn BlockReader>, Self::Error>;
}

pub trait BootProfileSourceRootfs: Filesystem + Sized {
    async fn open_boot_profile_source(
        source: &BootProfileRootfs,
        reader: Arc<dyn BlockReader>,
    ) -> Result<Self, Self::Error>;
}

#[derive(Debug)]
pub enum ProfileSourceOverrideError<ArtifactError, RootfsError> {
    OpenArtifactSource {
        source: ArtifactError,
    },
    OpenRootfs {
        source: RootfsError,
    },
    ReadPath {
        path: String,
        source: RootfsError,
    },
    ProbePath {
        path: String,
        source: RootfsError,
    },
    EmptyProfilePath {
        field: &'static str,
    },
    EmptyDeviceTreeName,
    MissingDtb {
        dtbs_base: String,
        devicetree_name: String,
    },
}

impl<ArtifactError, RootfsError> fmt::Display
    for ProfileSourceOverrideError<ArtifactError, RootfsError>
where
    ArtifactError: fmt::Display,
    RootfsError: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenArtifactSource { source } => {
                write!(f, "open boot profile artifact source: {source}")
            }
            Self::OpenRootfs { source } => write!(f, "open boot profile source rootfs: {source}"),
            Self::ReadPath { path, source } => {
                write!(f, "read boot profile source path {path}: {source}")
            }
            Self::ProbePath { path, source } => {
                write!(f, "probe boot profile source path {path}: {source}")
            }
            Self::EmptyProfilePath { field } => write!(f, "boot profile {field} must not be empty"),
            Self::EmptyDeviceTreeName => write!(f, "device profile devicetree_name is empty"),
            Self::MissingDtb {
                dtbs_base,
                devicetree_name,
            } => write!(
                f,
                "boot profile dtbs path {dtbs_base} does not contain dtb for {devicetree_name}"
            ),
        }
    }
}

pub async fn resolve_boot_profile_source_overrides_with<Opener, SourceRootfs>(
    boot_profile: Option<&BootProfile>,
    device_profile: &DeviceProfile,
    opener: &mut Opener,
) -> Result<
    BootProfileSourceOverrides,
    ProfileSourceOverrideError<Opener::Error, SourceRootfs::Error>,
>
where
    Opener: BootProfileArtifactSourceOpener,
    SourceRootfs: BootProfileSourceRootfs,
{
    let Some(boot_profile) = boot_profile else {
        return Ok(BootProfileSourceOverrides::empty());
    };

    let kernel_override = if let Some(kernel_source) = boot_profile.kernel.as_ref() {
        let kernel_path = non_empty_profile_path(kernel_source.path.as_str(), "kernel.path")?;
        let source_reader = opener
            .open_boot_profile_artifact_source(kernel_source.artifact_source())
            .await
            .map_err(|source| ProfileSourceOverrideError::OpenArtifactSource { source })?;
        let source_rootfs =
            SourceRootfs::open_boot_profile_source(&kernel_source.source, source_reader)
                .await
                .map_err(|source| ProfileSourceOverrideError::OpenRootfs { source })?;
        let kernel_image = source_rootfs
            .read_all(kernel_path)
            .await
            .map_err(|source| ProfileSourceOverrideError::ReadPath {
                path: kernel_path.to_string(),
                source,
            })?;
        Some(Stage0KernelOverride {
            path: kernel_path.to_string(),
            image: kernel_image,
        })
    } else {
        None
    };

    let dtb_override = if let Some(dtbs_source) = boot_profile.dtbs.as_ref() {
        let dtbs_base = non_empty_profile_path(dtbs_source.path.as_str(), "dtbs.path")?;
        let source_reader = opener
            .open_boot_profile_artifact_source(dtbs_source.artifact_source())
            .await
            .map_err(|source| ProfileSourceOverrideError::OpenArtifactSource { source })?;
        let source_rootfs =
            SourceRootfs::open_boot_profile_source(&dtbs_source.source, source_reader)
                .await
                .map_err(|source| ProfileSourceOverrideError::OpenRootfs { source })?;
        let dtb_path = resolve_dtb_path_candidate(
            &source_rootfs,
            dtbs_base,
            device_profile.devicetree_name.as_str(),
        )
        .await?;
        Some(
            source_rootfs
                .read_all(dtb_path.as_str())
                .await
                .map_err(|source| ProfileSourceOverrideError::ReadPath {
                    path: dtb_path,
                    source,
                })?,
        )
    } else {
        None
    };

    Ok(BootProfileSourceOverrides {
        kernel_override,
        dtb_override,
    })
}

fn non_empty_profile_path<'a, ArtifactError, RootfsError>(
    path: &'a str,
    field: &'static str,
) -> Result<&'a str, ProfileSourceOverrideError<ArtifactError, RootfsError>> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(ProfileSourceOverrideError::EmptyProfilePath { field });
    }
    Ok(trimmed)
}

async fn resolve_dtb_path_candidate<ArtifactError, SourceRootfs>(
    source_rootfs: &SourceRootfs,
    dtbs_base: &str,
    devicetree_name: &str,
) -> Result<String, ProfileSourceOverrideError<ArtifactError, SourceRootfs::Error>>
where
    SourceRootfs: BootProfileSourceRootfs,
{
    let devicetree_name = devicetree_name.trim().trim_start_matches('/');
    if devicetree_name.is_empty() {
        return Err(ProfileSourceOverrideError::EmptyDeviceTreeName);
    }

    let mut candidates = Vec::new();
    if dtbs_base.ends_with(".dtb") {
        candidates.push(dtbs_base.to_string());
    } else {
        let dtb_file = format!("{devicetree_name}.dtb");
        candidates.push(join_profile_path(dtbs_base, dtb_file.as_str()));
        candidates.push(join_profile_path(dtbs_base, devicetree_name));
        candidates.push(dtbs_base.to_string());
    }

    for candidate in candidates {
        if source_rootfs
            .exists(candidate.as_str())
            .await
            .map_err(|source| ProfileSourceOverrideError::ProbePath {
                path: candidate.clone(),
                source,
            })?
        {
            return Ok(candidate);
        }
    }

    Err(ProfileSourceOverrideError::MissingDtb {
        dtbs_base: dtbs_base.to_string(),
        devicetree_name: devicetree_name.to_string(),
    })
}

pub fn join_profile_path(base: &str, suffix: &str) -> String {
    let base = base.trim_end_matches('/');
    let suffix = suffix.trim_start_matches('/');
    if base.is_empty() {
        format!("/{suffix}")
    } else {
        format!("{base}/{suffix}")
    }
}

pub fn boot_profile_rootfs_kind(rootfs: &BootProfileRootfs) -> Stage0RootfsKind {
    match rootfs {
        BootProfileRootfs::Ostree(source) => match &source.ostree {
            BootProfileRootfsFilesystemSource::Erofs(_) => Stage0RootfsKind::Erofs,
            BootProfileRootfsFilesystemSource::Ext4(_) => Stage0RootfsKind::Ext4,
            BootProfileRootfsFilesystemSource::Fat(_) => Stage0RootfsKind::Fat,
        },
        BootProfileRootfs::Erofs(_) => Stage0RootfsKind::Erofs,
        BootProfileRootfs::Ext4(_) => Stage0RootfsKind::Ext4,
        BootProfileRootfs::Fat(_) => Stage0RootfsKind::Fat,
    }
}

pub struct Stage0ExtraCmdline<'a> {
    pub selected_ostree: Option<&'a str>,
    pub profile_cmdline: Option<&'a str>,
    pub requested_cmdline: Option<&'a str>,
    pub system_time: Option<&'a str>,
    pub smoo_queue_count: Option<u16>,
    pub smoo_queue_depth: Option<u16>,
    pub smoo_max_io: Option<usize>,
    pub default_smoo_max_io: usize,
}

pub fn build_stage0_extra_cmdline(parts: Stage0ExtraCmdline<'_>) -> Option<String> {
    let merged_profile_cmdline = join_cmdline(parts.profile_cmdline, parts.requested_cmdline);
    let mut extra_parts = Vec::new();
    if let Some(ostree) = parts.selected_ostree {
        extra_parts.push(format!("ostree=/{ostree}"));
    }
    if !merged_profile_cmdline.is_empty() {
        extra_parts.push(merged_profile_cmdline);
    }
    if let Some(system_time) = parts.system_time {
        extra_parts.push(system_time.to_string());
    }
    if let Some(queue_count) = parts.smoo_queue_count {
        extra_parts.push(format!("smoo.queue_count={queue_count}"));
    }
    if let Some(queue_depth) = parts.smoo_queue_depth {
        extra_parts.push(format!("smoo.queue_depth={queue_depth}"));
    }
    extra_parts.push(format!(
        "smoo.max_io_bytes={}",
        parts.smoo_max_io.unwrap_or(parts.default_smoo_max_io)
    ));

    if extra_parts.is_empty() {
        None
    } else {
        Some(extra_parts.join(" "))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    Phase {
        phase: SessionEventPhase,
        detail: String,
    },
    Log(String),
    SmooStatus {
        active: bool,
        export_count: u32,
        session_id: u64,
        ios_up: u64,
        ios_down: u64,
        bytes_up: u64,
        bytes_down: u64,
        inflight_requests: u64,
        max_inflight_requests: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEventPhase {
    Preparing,
    WaitingForDevice,
    DeviceDetected,
    BuildingStage0,
    BuildingBootImage,
    Downloading,
    Booting,
    WaitingForSmoo,
    Serving,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BootRequest {
    pub seed: u64,
    pub source: Option<String>,
    pub requested_device_profile: Option<String>,
    pub requested_boot_profile: Option<String>,
}

impl BootRequest {
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            source: None,
            requested_device_profile: None,
            requested_boot_profile: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionSnapshot {
    pub version: u32,
    pub request: BootRequest,
    pub status: SessionStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SessionStatus {
    New,
    Preparing,
    BootImageReady {
        profile_id: String,
        boot_image_size: u64,
        export_identity: String,
        export_size_bytes: u64,
    },
    Downloading {
        profile_id: String,
        boot_image_size: u64,
    },
    BootHandoffStarted {
        profile_id: String,
        boot_image_size: u64,
    },
    BootIssued {
        profile_id: String,
    },
    Serving {
        profile_id: String,
        export_identity: String,
        export_size_bytes: u64,
    },
    Completed,
    Failed {
        message: String,
    },
}

impl SessionStatus {
    pub const fn phase(&self) -> SessionPhase {
        match self {
            Self::New => SessionPhase::New,
            Self::Preparing => SessionPhase::Preparing,
            Self::BootImageReady { .. } => SessionPhase::Ready,
            Self::Downloading { .. }
            | Self::BootHandoffStarted { .. }
            | Self::BootIssued { .. } => SessionPhase::Booting,
            Self::Serving { .. } => SessionPhase::Serving,
            Self::Completed => SessionPhase::Completed,
            Self::Failed { .. } => SessionPhase::Failed,
        }
    }

    pub const fn is_post_handoff(&self) -> bool {
        matches!(
            self,
            Self::BootHandoffStarted { .. } | Self::BootIssued { .. } | Self::Serving { .. }
        )
    }

    pub fn profile_id(&self) -> Option<&str> {
        match self {
            Self::BootImageReady { profile_id, .. }
            | Self::Downloading { profile_id, .. }
            | Self::BootHandoffStarted { profile_id, .. }
            | Self::BootIssued { profile_id }
            | Self::Serving { profile_id, .. } => Some(profile_id),
            Self::New | Self::Preparing | Self::Completed | Self::Failed { .. } => None,
        }
    }
}

pub fn session_status_event(status: &SessionStatus) -> Option<SessionEvent> {
    match status {
        SessionStatus::BootImageReady {
            boot_image_size, ..
        } => Some(SessionEvent::Phase {
            phase: SessionEventPhase::BuildingBootImage,
            detail: format!("boot image built ({boot_image_size} bytes)"),
        }),
        SessionStatus::Downloading {
            boot_image_size, ..
        } => Some(SessionEvent::Phase {
            phase: SessionEventPhase::Downloading,
            detail: format!("sending {boot_image_size} bytes"),
        }),
        SessionStatus::BootHandoffStarted { .. } => Some(SessionEvent::Phase {
            phase: SessionEventPhase::Booting,
            detail: "issuing fastboot boot".to_string(),
        }),
        SessionStatus::BootIssued { .. } => Some(SessionEvent::Log(
            "fastboot boot command accepted".to_string(),
        )),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SessionPhase {
    New,
    Preparing,
    Ready,
    Booting,
    Serving,
    Completed,
    Failed,
}

#[derive(Clone)]
pub struct FastboopSession {
    inner: Rc<RefCell<SessionSnapshot>>,
}

impl FastboopSession {
    pub fn new(request: BootRequest) -> Self {
        Self::from_snapshot(SessionSnapshot {
            version: SESSION_STATE_VERSION,
            request,
            status: SessionStatus::New,
        })
    }

    pub fn from_snapshot(snapshot: SessionSnapshot) -> Self {
        Self {
            inner: Rc::new(RefCell::new(snapshot)),
        }
    }

    pub async fn request(&self) -> BootRequest {
        self.snapshot_sync().request
    }

    pub async fn status(&self) -> SessionStatus {
        self.snapshot_sync().status
    }

    pub async fn phase(&self) -> SessionPhase {
        self.snapshot_sync().status.phase()
    }

    pub async fn snapshot(&self) -> SessionSnapshot {
        self.snapshot_sync()
    }

    pub async fn prepare<E>(&self, env: &mut E) -> Result<PreparedBoot, E::Error>
    where
        E: SessionEnvironment,
        E::Error: fmt::Display,
    {
        let resume_status = self.status().await;
        let preserve_handoff_state = resume_status.is_post_handoff();
        if !preserve_handoff_state {
            self.transition(env, SessionStatus::Preparing).await?;
        }

        let prepared = match env.prepare_boot(self).await {
            Ok(prepared) => prepared,
            Err(err) => {
                let message = err.to_string();
                let _ = self.mark_failed(env, message).await;
                return Err(err);
            }
        };

        if !preserve_handoff_state {
            self.transition(env, prepared.ready_status()).await?;
        }
        Ok(prepared)
    }

    pub async fn run<E>(
        &self,
        env: &mut E,
    ) -> Result<(), SessionRunError<E::Error, <E::Fastboot as FastbootWire>::Error>>
    where
        E: BootSessionEnvironment,
        E::Error: fmt::Display,
        <E::Fastboot as FastbootWire>::Error: fmt::Display,
    {
        let resume_status = self.status().await;
        let post_handoff_resume = resume_status.is_post_handoff();
        let prepared = self
            .prepare(env)
            .await
            .map_err(SessionRunError::Environment)?;

        if !post_handoff_resume {
            let mut fastboot = match env.connect_fastboot(self, &prepared.info()).await {
                Ok(fastboot) => fastboot,
                Err(err) => {
                    let message = err.to_string();
                    let _ = self.mark_failed(env, message).await;
                    return Err(SessionRunError::Environment(err));
                }
            };

            self.transition(env, prepared.downloading_status())
                .await
                .map_err(SessionRunError::Environment)?;
            if let Err(err) = download(&mut fastboot, &prepared.boot_image).await {
                let message = err.to_string();
                let _ = self.mark_failed(env, message).await;
                return Err(SessionRunError::Fastboot(err));
            }

            self.transition(env, prepared.handoff_started_status())
                .await
                .map_err(SessionRunError::Environment)?;
            if let Err(err) = boot(&mut fastboot).await {
                let message = err.to_string();
                let _ = self.mark_failed(env, message).await;
                return Err(SessionRunError::Fastboot(err));
            }

            self.transition(env, prepared.boot_issued_status())
                .await
                .map_err(SessionRunError::Environment)?;
        }

        self.transition(env, prepared.serving_status())
            .await
            .map_err(SessionRunError::Environment)?;
        let export = prepared.export;
        if let Err(err) = env.serve_runtime(self, export).await {
            let message = err.to_string();
            let _ = self.mark_failed(env, message).await;
            return Err(SessionRunError::Environment(err));
        }
        self.transition(env, SessionStatus::Completed)
            .await
            .map_err(SessionRunError::Environment)
    }

    async fn transition<E>(&self, env: &mut E, status: SessionStatus) -> Result<(), E::Error>
    where
        E: SessionEnvironment,
    {
        let snapshot = self.replace_status(status);
        let encoded =
            encode_session_snapshot(&snapshot).map_err(|err| env.session_codec_error(err))?;
        tracing::debug!(phase = ?snapshot.status.phase(), "fastboop session transition");
        env.persist_session(&snapshot, &encoded).await
    }

    async fn mark_failed<E>(&self, env: &mut E, message: String) -> Result<(), E::Error>
    where
        E: SessionEnvironment,
    {
        self.transition(env, SessionStatus::Failed { message })
            .await
    }

    fn replace_status(&self, status: SessionStatus) -> SessionSnapshot {
        let mut snapshot = self.inner.borrow_mut();
        snapshot.status = status;
        snapshot.clone()
    }

    pub fn snapshot_sync(&self) -> SessionSnapshot {
        self.inner.borrow().clone()
    }
}

impl Serialize for FastboopSession {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.snapshot_sync().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FastboopSession {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let snapshot = SessionSnapshot::deserialize(deserializer)?;
        Ok(Self::from_snapshot(snapshot))
    }
}

#[derive(Clone)]
pub struct RuntimeExport {
    pub reader: Arc<dyn BlockReader>,
    pub size_bytes: u64,
    pub identity: String,
}

pub struct PreparedBoot {
    pub profile_id: String,
    pub boot_image: Vec<u8>,
    pub export: RuntimeExport,
}

impl PreparedBoot {
    pub fn info(&self) -> PreparedBootInfo {
        PreparedBootInfo {
            profile_id: self.profile_id.clone(),
            boot_image_size: self.boot_image.len() as u64,
            export_identity: self.export.identity.clone(),
            export_size_bytes: self.export.size_bytes,
        }
    }

    fn ready_status(&self) -> SessionStatus {
        let info = self.info();
        SessionStatus::BootImageReady {
            profile_id: info.profile_id,
            boot_image_size: info.boot_image_size,
            export_identity: info.export_identity,
            export_size_bytes: info.export_size_bytes,
        }
    }

    fn downloading_status(&self) -> SessionStatus {
        SessionStatus::Downloading {
            profile_id: self.profile_id.clone(),
            boot_image_size: self.boot_image.len() as u64,
        }
    }

    fn handoff_started_status(&self) -> SessionStatus {
        SessionStatus::BootHandoffStarted {
            profile_id: self.profile_id.clone(),
            boot_image_size: self.boot_image.len() as u64,
        }
    }

    fn boot_issued_status(&self) -> SessionStatus {
        SessionStatus::BootIssued {
            profile_id: self.profile_id.clone(),
        }
    }

    fn serving_status(&self) -> SessionStatus {
        SessionStatus::Serving {
            profile_id: self.profile_id.clone(),
            export_identity: self.export.identity.clone(),
            export_size_bytes: self.export.size_bytes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedBootInfo {
    pub profile_id: String,
    pub boot_image_size: u64,
    pub export_identity: String,
    pub export_size_bytes: u64,
}

pub trait SessionEnvironment {
    type Error;

    fn session_codec_error(&mut self, err: SessionCodecError) -> Self::Error;

    async fn persist_session(
        &mut self,
        snapshot: &SessionSnapshot,
        encoded: &[u8],
    ) -> Result<(), Self::Error>;

    async fn prepare_boot(
        &mut self,
        session: &FastboopSession,
    ) -> Result<PreparedBoot, Self::Error>;
}

pub trait BootSessionEnvironment: SessionEnvironment {
    type Fastboot: FastbootWire;

    async fn connect_fastboot(
        &mut self,
        session: &FastboopSession,
        prepared: &PreparedBootInfo,
    ) -> Result<Self::Fastboot, Self::Error>;

    async fn serve_runtime(
        &mut self,
        session: &FastboopSession,
        export: RuntimeExport,
    ) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub enum SessionRunError<E, F> {
    Environment(E),
    Fastboot(FastbootProtocolError<F>),
}

impl<E, F> fmt::Display for SessionRunError<E, F>
where
    E: fmt::Display,
    F: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Environment(err) => write!(f, "session environment error: {err}"),
            Self::Fastboot(err) => write!(f, "fastboot handoff error: {err}"),
        }
    }
}

pub struct Stage0Assembly {
    pub options: Stage0Options,
    pub stage0_binary: Option<Vec<u8>>,
    pub extra_cmdline: Option<String>,
    pub existing_cpio: Option<Vec<u8>>,
}

impl Stage0Assembly {
    pub fn new(options: Stage0Options, stage0_binary: Option<Vec<u8>>) -> Self {
        Self {
            options,
            stage0_binary,
            extra_cmdline: None,
            existing_cpio: None,
        }
    }

    pub fn with_extra_cmdline(mut self, extra_cmdline: Option<String>) -> Self {
        self.extra_cmdline = extra_cmdline;
        self
    }

    pub fn with_existing_cpio(mut self, existing_cpio: Option<Vec<u8>>) -> Self {
        self.existing_cpio = existing_cpio;
        self
    }

    pub async fn build<P>(
        &self,
        profile: &DeviceProfile,
        rootfs: &P,
    ) -> Result<Stage0Build, Stage0Error>
    where
        P: Filesystem,
    {
        build_stage0(
            profile,
            rootfs,
            &self.options,
            stage0_binary_ready(self.stage0_binary.clone()),
            self.extra_cmdline.as_deref(),
            self.existing_cpio.as_deref(),
        )
        .await
    }
}

pub fn build_android_boot_payload(
    profile: &DeviceProfile,
    build: Stage0Build,
) -> Result<Vec<u8>, BootImageError> {
    let cmdline = join_cmdline(
        profile
            .boot
            .fastboot_boot
            .android_bootimg
            .cmdline_append
            .as_deref(),
        Some(build.kernel_cmdline_append.as_str()),
    );

    let mut kernel_image = build.kernel_image;
    if profile
        .boot
        .fastboot_boot
        .android_bootimg
        .kernel
        .encoding
        .append_dtb()
    {
        kernel_image.extend_from_slice(&build.dtb);
    }

    build_android_bootimg(
        profile,
        &kernel_image,
        &build.initrd,
        Some(&build.dtb),
        &cmdline,
    )
}

pub fn join_cmdline(left: Option<&str>, right: Option<&str>) -> String {
    let mut out = String::new();
    if let Some(left) = left.map(str::trim).filter(|value| !value.is_empty()) {
        out.push_str(left);
    }
    if let Some(right) = right.map(str::trim).filter(|value| !value.is_empty()) {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(right);
    }
    out
}

#[derive(Debug)]
pub enum SessionCodecError {
    BadMagic,
    Encode(postcard::Error),
    Decode(postcard::Error),
}

impl fmt::Display for SessionCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(f, "session state has an invalid magic header"),
            Self::Encode(err) => write!(f, "encode session state: {err}"),
            Self::Decode(err) => write!(f, "decode session state: {err}"),
        }
    }
}

pub fn encode_session_snapshot(snapshot: &SessionSnapshot) -> Result<Vec<u8>, SessionCodecError> {
    let payload = postcard::to_allocvec(snapshot).map_err(SessionCodecError::Encode)?;
    let mut out = Vec::with_capacity(SESSION_STATE_MAGIC.len() + payload.len());
    out.extend_from_slice(SESSION_STATE_MAGIC);
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_session_snapshot(bytes: &[u8]) -> Result<SessionSnapshot, SessionCodecError> {
    let payload = bytes
        .strip_prefix(SESSION_STATE_MAGIC)
        .ok_or(SessionCodecError::BadMagic)?;
    postcard::from_bytes(payload).map_err(SessionCodecError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_snapshot_round_trips_postcard_envelope() {
        let snapshot = SessionSnapshot {
            version: SESSION_STATE_VERSION,
            request: BootRequest {
                seed: 42,
                source: Some("rootfs.ero".to_string()),
                requested_device_profile: Some("oneplus-fajita".to_string()),
                requested_boot_profile: Some("pmos".to_string()),
            },
            status: SessionStatus::BootHandoffStarted {
                profile_id: "oneplus-fajita".to_string(),
                boot_image_size: 1024,
            },
        };

        let encoded = encode_session_snapshot(&snapshot).unwrap();
        assert!(encoded.starts_with(SESSION_STATE_MAGIC));
        let decoded = decode_session_snapshot(&encoded).unwrap();
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn fastboop_session_serializes_as_snapshot() {
        let session = FastboopSession::from_snapshot(SessionSnapshot {
            version: SESSION_STATE_VERSION,
            request: BootRequest::new(7),
            status: SessionStatus::Serving {
                profile_id: "oneplus-fajita".to_string(),
                export_identity: "test-export".to_string(),
                export_size_bytes: 4096,
            },
        });

        let encoded = postcard::to_allocvec(&session).unwrap();
        let decoded: FastboopSession = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.snapshot_sync(), session.snapshot_sync());
    }

    #[test]
    fn ostree_arg_normalizes_explicit_paths() {
        let raw = Some(Some(" /ostree//boot.1/./fedora/abc/0/ ".to_string()));
        let parsed = parse_ostree_arg(raw.as_ref()).unwrap();
        assert_eq!(
            parsed,
            OstreeArg::Explicit("ostree/boot.1/fedora/abc/0".to_string())
        );
    }

    #[test]
    fn device_profile_pool_reports_available_ids() {
        let pool = build_device_profile_pool(&[], []).unwrap();
        let err = resolve_profile_in_pool(&pool, "does-not-exist").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("does-not-exist"));
        assert!(message.contains("available ids"));
    }
}
