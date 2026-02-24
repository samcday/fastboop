use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use fastboop_core::fastboot::{FastbootProtocolError, ProbeError};
use fastboop_core::{
    BootProfile, BootProfileArtifactSource, BootProfileRootfs, CHANNEL_SNIFF_PREFIX_LEN,
    ChannelStreamKind, DeviceProfile, boot_profile_bin_header_version, classify_channel_prefix,
    decode_boot_profile_prefix, validate_boot_profile,
};
use fastboop_stage0_generator::{Stage0KernelOverride, Stage0SwitchrootFs};
use gibblox_android_sparse::AndroidSparseBlockReader;
use gibblox_cache::CachedBlockReader;
use gibblox_cache_store_std::StdCacheOps;
use gibblox_casync::{CasyncBlockReader, CasyncReaderConfig};
use gibblox_casync_std::{
    StdCasyncChunkStore, StdCasyncChunkStoreConfig, StdCasyncChunkStoreLocator,
    StdCasyncIndexLocator, StdCasyncIndexSource,
};
use gibblox_core::{
    BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, GptBlockReader,
    GptPartitionSelector, ReadContext,
};
use gibblox_ext4::{Ext4EntryType, Ext4Fs};
use gibblox_file::StdFileBlockReader;
use gibblox_http::HttpBlockReader;
use gibblox_mbr::{MbrBlockReader, MbrPartitionSelector};
use gibblox_xz::XzBlockReader;
use gibblox_zip::ZipEntryBlockReader;
use gobblytes_core::{Filesystem, FilesystemEntryType, normalize_ostree_deployment_path};
use gobblytes_erofs::{DEFAULT_IMAGE_BLOCK_SIZE, ErofsRootfs};
use gobblytes_fat::FatFs;
use tracing::info;
use url::Url;

mod boot;
mod bootprofile;
mod detect;
mod stage0;

pub use boot::{BootArgs, run_boot};
pub use bootprofile::{BootProfileArgs, run_bootprofile};
pub use detect::{DetectArgs, run_detect};
pub use stage0::{Stage0Args, run_stage0};

pub(crate) struct ChannelInput {
    pub(crate) reader: Arc<dyn BlockReader>,
    pub(crate) stage0_readers: Vec<Arc<dyn BlockReader>>,
    pub(crate) boot_profile: Option<fastboop_core::BootProfile>,
}

struct ChannelSourceReader {
    reader: Arc<dyn BlockReader>,
    exact_size_bytes: u64,
}

#[derive(Clone, Debug, Default)]
struct BootProfileStreamHead {
    profiles: Vec<BootProfile>,
    consumed_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootfsKind {
    Erofs,
    Ext4,
    Fat,
}

#[derive(Clone)]
pub(crate) struct Ext4Rootfs {
    fs: Ext4Fs,
}

impl Ext4Rootfs {
    async fn open(reader: Arc<dyn BlockReader>) -> Result<Self> {
        let fs = Ext4Fs::open(reader)
            .await
            .map_err(|err| anyhow!("open ext4 rootfs: {err}"))?;
        Ok(Self { fs })
    }
}

impl Filesystem for Ext4Rootfs {
    type Error = anyhow::Error;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        self.fs
            .read_all(path)
            .await
            .map_err(|err| anyhow!("read ext4 path {path}: {err}"))
    }

    async fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.fs
            .read_range(path, offset, len)
            .await
            .map_err(|err| anyhow!("read ext4 path range {path}@{offset}+{len}: {err}"))
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>> {
        self.fs
            .read_dir(path)
            .await
            .map_err(|err| anyhow!("read ext4 directory {path}: {err}"))
    }

    async fn entry_type(&self, path: &str) -> Result<Option<FilesystemEntryType>> {
        let ty = self
            .fs
            .entry_type(path)
            .await
            .map_err(|err| anyhow!("read ext4 entry type {path}: {err}"))?;
        Ok(ty.map(|entry| match entry {
            Ext4EntryType::File => FilesystemEntryType::File,
            Ext4EntryType::Directory => FilesystemEntryType::Directory,
            Ext4EntryType::Symlink => FilesystemEntryType::Symlink,
            Ext4EntryType::Other => FilesystemEntryType::Other,
        }))
    }

    async fn read_link(&self, path: &str) -> Result<String> {
        self.fs
            .read_link(path)
            .await
            .map_err(|err| anyhow!("read ext4 symlink target {path}: {err}"))
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        self.fs
            .exists(path)
            .await
            .map_err(|err| anyhow!("check ext4 path {path}: {err}"))
    }
}

pub(crate) enum Stage0RootfsProvider {
    Erofs(ErofsRootfs),
    Ext4(Ext4Rootfs),
    Fat(FatFs),
}

impl Stage0RootfsProvider {
    pub(crate) async fn open(
        kind: RootfsKind,
        reader: Arc<dyn BlockReader>,
        image_size_bytes: u64,
    ) -> Result<Self> {
        match kind {
            RootfsKind::Erofs => {
                let rootfs = ErofsRootfs::new(reader, image_size_bytes)
                    .await
                    .map_err(|err| anyhow!("open erofs rootfs: {err}"))?;
                Ok(Self::Erofs(rootfs))
            }
            RootfsKind::Ext4 => {
                let rootfs = Ext4Rootfs::open(reader).await?;
                Ok(Self::Ext4(rootfs))
            }
            RootfsKind::Fat => {
                let rootfs = FatFs::open(reader)
                    .await
                    .map_err(|err| anyhow!("open fat rootfs: {err}"))?;
                Ok(Self::Fat(rootfs))
            }
        }
    }

    pub(crate) fn switchroot_fs(&self) -> Option<Stage0SwitchrootFs> {
        match self {
            Self::Erofs(_) => Some(Stage0SwitchrootFs::Erofs),
            Self::Ext4(_) => Some(Stage0SwitchrootFs::Ext4),
            Self::Fat(_) => None,
        }
    }
}

impl Filesystem for Stage0RootfsProvider {
    type Error = anyhow::Error;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_all(path).await,
            Self::Ext4(rootfs) => rootfs.read_all(path).await,
            Self::Fat(rootfs) => rootfs
                .read_all(path)
                .await
                .map_err(|err| anyhow!("read fat path {path}: {err}")),
        }
    }

    async fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_range(path, offset, len).await,
            Self::Ext4(rootfs) => rootfs.read_range(path, offset, len).await,
            Self::Fat(rootfs) => rootfs
                .read_range(path, offset, len)
                .await
                .map_err(|err| anyhow!("read fat path range {path}@{offset}+{len}: {err}")),
        }
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_dir(path).await,
            Self::Ext4(rootfs) => rootfs.read_dir(path).await,
            Self::Fat(rootfs) => rootfs
                .read_dir(path)
                .await
                .map_err(|err| anyhow!("read fat directory {path}: {err}")),
        }
    }

    async fn entry_type(&self, path: &str) -> Result<Option<FilesystemEntryType>> {
        match self {
            Self::Erofs(rootfs) => rootfs.entry_type(path).await,
            Self::Ext4(rootfs) => rootfs.entry_type(path).await,
            Self::Fat(rootfs) => <FatFs as Filesystem>::entry_type(rootfs, path)
                .await
                .map_err(|err| anyhow!("read fat entry type {path}: {err}")),
        }
    }

    async fn read_link(&self, path: &str) -> Result<String> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_link(path).await,
            Self::Ext4(rootfs) => rootfs.read_link(path).await,
            Self::Fat(rootfs) => rootfs
                .read_link(path)
                .await
                .map_err(|err| anyhow!("read fat symlink target {path}: {err}")),
        }
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        match self {
            Self::Erofs(rootfs) => rootfs.exists(path).await,
            Self::Ext4(rootfs) => rootfs.exists(path).await,
            Self::Fat(rootfs) => rootfs
                .exists(path)
                .await
                .map_err(|err| anyhow!("check fat path {path}: {err}")),
        }
    }
}

pub(crate) struct Stage0CoalescingFilesystem {
    providers: Vec<Stage0RootfsProvider>,
    switchroot_fs: Stage0SwitchrootFs,
}

impl Stage0CoalescingFilesystem {
    pub(crate) async fn open(readers: Vec<Arc<dyn BlockReader>>) -> Result<Self> {
        if readers.is_empty() {
            bail!("channel did not resolve any filesystem providers")
        }

        let mut providers = Vec::new();
        for reader in readers {
            let total_blocks = reader.total_blocks().await?;
            let image_size_bytes = total_blocks
                .checked_mul(reader.block_size() as u64)
                .ok_or_else(|| anyhow!("channel image size overflow"))?;
            let Some(kind) = detect_rootfs_kind(reader.as_ref()).await? else {
                continue;
            };
            let provider = Stage0RootfsProvider::open(kind, reader, image_size_bytes).await?;
            providers.push(provider);
        }

        if providers.is_empty() {
            bail!("channel did not contain a supported filesystem (erofs/ext4/fat)")
        }

        let switchroot_fs = providers
            .iter()
            .find_map(Stage0RootfsProvider::switchroot_fs)
            .ok_or_else(|| {
                anyhow!("channel did not contain a bootable root filesystem (erofs/ext4)")
            })?;

        Ok(Self {
            providers,
            switchroot_fs,
        })
    }

    pub(crate) fn switchroot_fs(&self) -> Stage0SwitchrootFs {
        self.switchroot_fs
    }
}

impl Filesystem for Stage0CoalescingFilesystem {
    type Error = anyhow::Error;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        let mut last_err = None;
        for provider in &self.providers {
            match provider.read_all(path).await {
                Ok(data) => return Ok(data),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("missing path {path}")))
    }

    async fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut last_err = None;
        for provider in &self.providers {
            match provider.read_range(path, offset, len).await {
                Ok(data) => return Ok(data),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("missing path {path}")))
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>> {
        let Some(first) = self.providers.first() else {
            bail!("channel filesystem provider list is empty")
        };
        first.read_dir(path).await
    }

    async fn entry_type(&self, path: &str) -> Result<Option<FilesystemEntryType>> {
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

    async fn read_link(&self, path: &str) -> Result<String> {
        let mut last_err = None;
        for provider in &self.providers {
            match provider.read_link(path).await {
                Ok(target) => return Ok(target),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("missing symlink {path}")))
    }

    async fn exists(&self, path: &str) -> Result<bool> {
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

#[derive(Clone)]
struct OffsetChannelBlockReader {
    inner: Arc<dyn BlockReader>,
    offset_bytes: u64,
    size_bytes: u64,
    inner_size_bytes: u64,
    block_size: u32,
}

impl OffsetChannelBlockReader {
    fn new(inner: Arc<dyn BlockReader>, offset_bytes: u64, inner_size_bytes: u64) -> Result<Self> {
        let block_size = inner.block_size();
        if block_size == 0 {
            bail!("channel reader block size is zero");
        }
        if offset_bytes > inner_size_bytes {
            bail!(
                "channel stream offset {} exceeds source size {}",
                offset_bytes,
                inner_size_bytes
            );
        }

        Ok(Self {
            inner,
            offset_bytes,
            size_bytes: inner_size_bytes - offset_bytes,
            inner_size_bytes,
            block_size,
        })
    }
}

#[async_trait]
impl BlockReader for OffsetChannelBlockReader {
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

        let byte_reader = gibblox_core::ByteRangeReader::new(
            self.inner.clone(),
            self.block_size as usize,
            self.inner_size_bytes,
        );
        byte_reader
            .read_exact_at(global_offset, &mut buf[..max_read], ctx)
            .await?;
        Ok(max_read)
    }
}

#[derive(Default)]
pub(crate) struct ArtifactReaderResolver {
    cache: HashMap<String, Arc<dyn BlockReader>>,
}

type OpenArtifactFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Arc<dyn BlockReader>>> + Send + 'a>>;

impl ArtifactReaderResolver {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) async fn open_channel_input(
        &mut self,
        channel: &Path,
        device_profile_id: &str,
        requested_boot_profile_id: Option<&str>,
    ) -> Result<ChannelInput> {
        let source = open_channel_source_reader(channel).await?;
        let source_total_bytes = source.exact_size_bytes;
        let stream_head =
            read_boot_profile_stream_head(source.reader.as_ref(), source_total_bytes).await?;

        if stream_head.profiles.is_empty() {
            if let Some(requested) = requested_boot_profile_id {
                bail!(
                    "boot profile '{}' was requested, but channel does not start with a boot profile stream",
                    requested
                );
            }

            let reader = unwrap_channel_reader(source.reader, Some(channel)).await?;
            let stage0_readers = derive_stage0_readers(reader.clone()).await?;
            return Ok(ChannelInput {
                reader,
                stage0_readers,
                boot_profile: None,
            });
        }

        let boot_profile = select_boot_profile_for_device(
            stream_head.profiles.as_slice(),
            device_profile_id,
            requested_boot_profile_id,
        )?;

        let reader = if stream_head.consumed_bytes < source_total_bytes {
            let trailing = OffsetChannelBlockReader::new(
                source.reader,
                stream_head.consumed_bytes,
                source_total_bytes,
            )?;
            let trailing: Arc<dyn BlockReader> = Arc::new(trailing);
            unwrap_channel_reader(trailing, Some(channel)).await?
        } else {
            self.open_artifact_source(boot_profile.rootfs.source())
                .await?
        };

        let stage0_readers = derive_stage0_readers(reader.clone()).await?;
        Ok(ChannelInput {
            reader,
            stage0_readers,
            boot_profile: Some(boot_profile),
        })
    }

    pub(crate) fn open_artifact_source<'a>(
        &'a mut self,
        source: &'a BootProfileArtifactSource,
    ) -> OpenArtifactFuture<'a> {
        Box::pin(async move {
            let cache_key = artifact_source_cache_key(source)?;
            if let Some(reader) = self.cache.get(&cache_key).cloned() {
                return Ok(reader);
            }

            let reader: Arc<dyn BlockReader> = match source {
                BootProfileArtifactSource::Http(source) => {
                    let url = Url::parse(source.http.as_str())
                        .with_context(|| format!("parse HTTP artifact URL {}", source.http))?;
                    open_cached_http_reader(url).await?.reader
                }
                BootProfileArtifactSource::File(source) => {
                    let path = Path::new(source.file.as_str());
                    let canonical = fs::canonicalize(path).with_context(|| {
                        format!("canonicalize file artifact path {}", path.display())
                    })?;
                    let file_reader =
                        StdFileBlockReader::open(&canonical, DEFAULT_IMAGE_BLOCK_SIZE).map_err(
                            |err| anyhow!("open file artifact {}: {err}", canonical.display()),
                        )?;
                    Arc::new(file_reader)
                }
                BootProfileArtifactSource::Casync(source) => {
                    let index_url =
                        Url::parse(source.casync.index.as_str()).with_context(|| {
                            format!("parse casync index URL {}", source.casync.index)
                        })?;
                    let chunk_store = source
                        .casync
                        .chunk_store
                        .as_deref()
                        .map(Url::parse)
                        .transpose()
                        .with_context(|| {
                            format!(
                                "parse casync chunk store URL {}",
                                source.casync.chunk_store.as_deref().unwrap_or_default()
                            )
                        })?;
                    open_casync_reader(index_url, chunk_store, false)
                        .await?
                        .reader
                }
                BootProfileArtifactSource::Xz(source) => {
                    let upstream = self.open_artifact_source(source.xz.as_ref()).await?;
                    let reader = XzBlockReader::new(upstream)
                        .await
                        .map_err(|err| anyhow!("open xz block reader: {err}"))?;
                    Arc::new(reader)
                }
                BootProfileArtifactSource::AndroidSparseImg(source) => {
                    let upstream = self
                        .open_artifact_source(source.android_sparseimg.as_ref())
                        .await?;
                    let reader = AndroidSparseBlockReader::new(upstream)
                        .await
                        .map_err(|err| anyhow!("open android sparse reader: {err}"))?;
                    Arc::new(reader)
                }
                BootProfileArtifactSource::Mbr(source) => {
                    let selector = if let Some(partuuid) = source.mbr.partuuid.as_deref() {
                        MbrPartitionSelector::part_uuid(partuuid)
                    } else if let Some(index) = source.mbr.index {
                        MbrPartitionSelector::index(index)
                    } else {
                        bail!("boot profile MBR source missing selector")
                    };

                    let upstream = self
                        .open_artifact_source(source.mbr.source.as_ref())
                        .await?;
                    let reader = MbrBlockReader::new(upstream, selector, DEFAULT_IMAGE_BLOCK_SIZE)
                        .await
                        .map_err(|err| anyhow!("open MBR partition reader: {err}"))?;
                    Arc::new(reader)
                }
                BootProfileArtifactSource::Gpt(source) => {
                    let selector = if let Some(partlabel) = source.gpt.partlabel.as_deref() {
                        GptPartitionSelector::part_label(partlabel)
                    } else if let Some(partuuid) = source.gpt.partuuid.as_deref() {
                        GptPartitionSelector::part_uuid(partuuid)
                    } else if let Some(index) = source.gpt.index {
                        GptPartitionSelector::index(index)
                    } else {
                        bail!("boot profile GPT source missing selector")
                    };

                    let upstream = self
                        .open_artifact_source(source.gpt.source.as_ref())
                        .await?;
                    let reader = GptBlockReader::new(upstream, selector, DEFAULT_IMAGE_BLOCK_SIZE)
                        .await
                        .map_err(|err| anyhow!("open GPT partition reader: {err}"))?;
                    Arc::new(reader)
                }
            };

            self.cache.insert(cache_key, reader.clone());
            Ok(reader)
        })
    }
}

fn artifact_source_cache_key(source: &BootProfileArtifactSource) -> Result<String> {
    match source {
        BootProfileArtifactSource::Http(source) => Ok(format!("http:{}", source.http)),
        BootProfileArtifactSource::File(source) => {
            let path = Path::new(source.file.as_str());
            let canonical = fs::canonicalize(path)
                .with_context(|| format!("canonicalize file artifact path {}", path.display()))?;
            Ok(format!("file:{}", canonical.display()))
        }
        BootProfileArtifactSource::Casync(source) => {
            let chunk_store = source.casync.chunk_store.as_deref().unwrap_or_default();
            Ok(format!("casync:{}:{}", source.casync.index, chunk_store))
        }
        BootProfileArtifactSource::Xz(source) => Ok(format!(
            "xz:{}",
            artifact_source_cache_key(source.xz.as_ref())?
        )),
        BootProfileArtifactSource::AndroidSparseImg(source) => Ok(format!(
            "android_sparseimg:{}",
            artifact_source_cache_key(source.android_sparseimg.as_ref())?
        )),
        BootProfileArtifactSource::Mbr(source) => {
            let selector = if let Some(partuuid) = source.mbr.partuuid.as_deref() {
                format!("partuuid={partuuid}")
            } else if let Some(index) = source.mbr.index {
                format!("index={index}")
            } else {
                bail!("boot profile MBR source missing selector")
            };
            Ok(format!(
                "mbr:{}:{}",
                selector,
                artifact_source_cache_key(source.mbr.source.as_ref())?
            ))
        }
        BootProfileArtifactSource::Gpt(source) => {
            let selector = if let Some(partlabel) = source.gpt.partlabel.as_deref() {
                format!("partlabel={partlabel}")
            } else if let Some(partuuid) = source.gpt.partuuid.as_deref() {
                format!("partuuid={partuuid}")
            } else if let Some(index) = source.gpt.index {
                format!("index={index}")
            } else {
                bail!("boot profile GPT source missing selector")
            };
            Ok(format!(
                "gpt:{}:{}",
                selector,
                artifact_source_cache_key(source.gpt.source.as_ref())?
            ))
        }
    }
}

const CHANNEL_UNWRAP_MAX_DEPTH: usize = 16;
const CHANNEL_PARTITION_PROBE_LIMIT: u32 = 16;
const CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES: usize = 4 * 1024 * 1024;
const CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS: usize = 128;

async fn read_boot_profile_stream_head<R: BlockReader + ?Sized>(
    reader: &R,
    exact_total_bytes: u64,
) -> Result<BootProfileStreamHead> {
    let total_bytes = exact_total_bytes;
    if total_bytes == 0 {
        return Ok(BootProfileStreamHead::default());
    }

    let scan_cap = core::cmp::min(
        CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES as u64,
        total_bytes,
    );
    let prefix = read_channel_prefix(reader, scan_cap as usize).await?;

    let mut out = BootProfileStreamHead::default();
    let mut cursor = 0usize;
    while cursor < prefix.len() {
        if out.profiles.len() >= CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS {
            bail!(
                "channel boot profile stream exceeds max profile count {}",
                CHANNEL_BOOT_PROFILE_STREAM_MAX_RECORDS
            );
        }

        let remaining = &prefix[cursor..];
        if boot_profile_bin_header_version(remaining).is_none() {
            break;
        }

        let (profile, consumed) = match decode_boot_profile_prefix(remaining) {
            Ok(decoded) => decoded,
            Err(err) if scan_cap < total_bytes => {
                bail!(
                    "decode boot profile stream at offset {}: {}; stream head exceeds {} bytes",
                    cursor,
                    err,
                    CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES
                )
            }
            Err(err) => {
                bail!("decode boot profile stream at offset {}: {}", cursor, err)
            }
        };
        if consumed == 0 {
            bail!("decoded boot profile consumed zero bytes at offset {cursor}");
        }
        validate_boot_profile(&profile).map_err(|err| {
            anyhow!(
                "validate boot profile '{}' at stream offset {}: {}",
                profile.id,
                cursor,
                err
            )
        })?;

        out.profiles.push(profile);
        cursor = cursor
            .checked_add(consumed)
            .ok_or_else(|| anyhow!("channel boot profile cursor overflow"))?;
    }

    out.consumed_bytes = cursor as u64;
    Ok(out)
}

fn select_boot_profile_for_device(
    profiles: &[BootProfile],
    device_profile_id: &str,
    requested_boot_profile_id: Option<&str>,
) -> Result<BootProfile> {
    if profiles.is_empty() {
        bail!("channel boot profile stream is empty");
    }

    if let Some(requested) = requested_boot_profile_id {
        let Some(profile) = profiles.iter().find(|profile| profile.id == requested) else {
            let ids = profiles
                .iter()
                .map(|profile| profile.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "requested boot profile '{}' was not found in channel stream (available: {})",
                requested,
                ids
            );
        };
        if !boot_profile_matches_device(profile, device_profile_id) {
            bail!(
                "boot profile '{}' is not compatible with device profile '{}'",
                profile.id,
                device_profile_id
            );
        }
        return Ok(profile.clone());
    }

    let compatible = profiles
        .iter()
        .filter(|profile| boot_profile_matches_device(profile, device_profile_id))
        .collect::<Vec<_>>();
    match compatible.as_slice() {
        [] => {
            let ids = profiles
                .iter()
                .map(|profile| profile.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "no compatible boot profile found for device profile '{}' in channel stream (available: {})",
                device_profile_id,
                ids
            );
        }
        [profile] => Ok((*profile).clone()),
        many => {
            let ids = many
                .iter()
                .map(|profile| profile.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "multiple compatible boot profiles found for device profile '{}' ({}); pass --boot-profile",
                device_profile_id,
                ids
            );
        }
    }
}

fn boot_profile_matches_device(profile: &BootProfile, device_profile_id: &str) -> bool {
    profile.stage0.devices.is_empty() || profile.stage0.devices.contains_key(device_profile_id)
}

async fn open_channel_source_reader(channel: &Path) -> Result<ChannelSourceReader> {
    let channel_str = channel.to_string_lossy();
    if channel_str.ends_with(".caidx") {
        bail!(
            "casync archive indexes (.caidx) are not supported for channel block reads; provide a casync blob index (.caibx)"
        );
    }

    if channel_str.starts_with("http://") || channel_str.starts_with("https://") {
        let url =
            Url::parse(&channel_str).with_context(|| format!("parse channel URL {channel_str}"))?;

        if url.path().ends_with(".caibx") {
            info!(index_url = %url, "using casync blob-index channel reader pipeline");
            return open_casync_reader(url, None, true).await;
        }

        return open_cached_http_reader(url).await;
    }

    let canonical =
        fs::canonicalize(channel).with_context(|| format!("canonicalize {}", channel.display()))?;
    let metadata = fs::metadata(&canonical)
        .with_context(|| format!("stat channel file {}", canonical.display()))?;
    let file_reader = StdFileBlockReader::open(&canonical, DEFAULT_IMAGE_BLOCK_SIZE)
        .map_err(|err| anyhow!("open file {}: {err}", canonical.display()))?;
    Ok(ChannelSourceReader {
        reader: Arc::new(file_reader),
        exact_size_bytes: metadata.len(),
    })
}

async fn unwrap_channel_reader(
    mut reader: Arc<dyn BlockReader>,
    channel_hint: Option<&Path>,
) -> Result<Arc<dyn BlockReader>> {
    for _depth in 0..CHANNEL_UNWRAP_MAX_DEPTH {
        let kind = classify_channel_reader(reader.as_ref()).await?;
        match kind {
            ChannelStreamKind::ProfileBundleV1 => {
                bail!(
                    "channel is a profile bundle; boot/stage0 commands require an artifact channel"
                )
            }
            ChannelStreamKind::Xz => {
                let wrapped = XzBlockReader::new(reader)
                    .await
                    .map_err(|err| anyhow!("open xz block reader: {err}"))?;
                reader = Arc::new(wrapped);
            }
            ChannelStreamKind::AndroidSparse => {
                let wrapped = AndroidSparseBlockReader::new(reader)
                    .await
                    .map_err(|err| anyhow!("open android sparse reader: {err}"))?;
                reader = Arc::new(wrapped);
            }
            ChannelStreamKind::Zip => {
                let Some(entry_name) = zip_entry_name_from_channel_hint(channel_hint)? else {
                    bail!(
                        "channel ZIP input requires a .zip filename stem so fastboop can infer the entry name"
                    )
                };
                let wrapped = ZipEntryBlockReader::new(&entry_name, reader)
                    .await
                    .map_err(|err| anyhow!("open ZIP entry {entry_name}: {err}"))?;
                reader = Arc::new(wrapped);
            }
            ChannelStreamKind::Unknown => {
                bail!("unsupported or unrecognized channel format")
            }
            ChannelStreamKind::Gpt
            | ChannelStreamKind::Iso9660
            | ChannelStreamKind::Erofs
            | ChannelStreamKind::Ext4
            | ChannelStreamKind::Fat
            | ChannelStreamKind::Mbr => {
                return Ok(reader);
            }
        }
    }

    bail!("channel unwrap depth exceeded {CHANNEL_UNWRAP_MAX_DEPTH}")
}

async fn derive_stage0_readers(reader: Arc<dyn BlockReader>) -> Result<Vec<Arc<dyn BlockReader>>> {
    let kind = classify_channel_reader(reader.as_ref()).await?;
    match kind {
        ChannelStreamKind::Gpt => discover_gpt_partition_readers(reader).await,
        ChannelStreamKind::Mbr => discover_mbr_partition_readers(reader).await,
        _ => Ok(vec![reader]),
    }
}

async fn discover_gpt_partition_readers(
    source: Arc<dyn BlockReader>,
) -> Result<Vec<Arc<dyn BlockReader>>> {
    let mut out = Vec::new();
    for index in 0..CHANNEL_PARTITION_PROBE_LIMIT {
        let partition = match GptBlockReader::new(
            source.clone(),
            GptPartitionSelector::index(index),
            DEFAULT_IMAGE_BLOCK_SIZE,
        )
        .await
        {
            Ok(reader) => Arc::new(reader) as Arc<dyn BlockReader>,
            Err(_) => continue,
        };

        let partition = match unwrap_channel_reader(partition, None).await {
            Ok(reader) => reader,
            Err(_) => continue,
        };
        let partition_kind = match classify_channel_reader(partition.as_ref()).await {
            Ok(kind) => kind,
            Err(_) => continue,
        };
        if matches!(
            partition_kind,
            ChannelStreamKind::Erofs | ChannelStreamKind::Ext4 | ChannelStreamKind::Fat
        ) {
            out.push(partition);
        }
    }

    if out.is_empty() {
        bail!("channel GPT input did not expose any EROFS/ext4/FAT partitions")
    }
    Ok(out)
}

async fn discover_mbr_partition_readers(
    source: Arc<dyn BlockReader>,
) -> Result<Vec<Arc<dyn BlockReader>>> {
    let mut out = Vec::new();
    for index in 0..CHANNEL_PARTITION_PROBE_LIMIT {
        let partition = match MbrBlockReader::new(
            source.clone(),
            MbrPartitionSelector::index(index),
            DEFAULT_IMAGE_BLOCK_SIZE,
        )
        .await
        {
            Ok(reader) => Arc::new(reader) as Arc<dyn BlockReader>,
            Err(_) => continue,
        };

        let partition = match unwrap_channel_reader(partition, None).await {
            Ok(reader) => reader,
            Err(_) => continue,
        };
        let partition_kind = match classify_channel_reader(partition.as_ref()).await {
            Ok(kind) => kind,
            Err(_) => continue,
        };
        if matches!(
            partition_kind,
            ChannelStreamKind::Erofs | ChannelStreamKind::Ext4 | ChannelStreamKind::Fat
        ) {
            out.push(partition);
        }
    }

    if out.is_empty() {
        bail!("channel MBR input did not expose any EROFS/ext4/FAT partitions")
    }
    Ok(out)
}

async fn classify_channel_reader<R: BlockReader + ?Sized>(reader: &R) -> Result<ChannelStreamKind> {
    let prefix = read_channel_prefix(reader, CHANNEL_SNIFF_PREFIX_LEN).await?;
    Ok(classify_channel_prefix(&prefix))
}

async fn read_channel_prefix<R: BlockReader + ?Sized>(reader: &R, cap: usize) -> Result<Vec<u8>> {
    let block_size = reader.block_size() as usize;
    if block_size == 0 {
        bail!("channel reader block size is zero")
    }

    let total_bytes = total_reader_bytes(reader).await?;
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

async fn total_reader_bytes<R: BlockReader + ?Sized>(reader: &R) -> Result<u64> {
    let total_blocks = reader.total_blocks().await?;
    total_blocks
        .checked_mul(reader.block_size() as u64)
        .ok_or_else(|| anyhow!("channel size overflow"))
}

fn zip_entry_name_from_channel_hint(channel_hint: Option<&Path>) -> Result<Option<String>> {
    let Some(channel) = channel_hint else {
        return Ok(None);
    };

    let raw = channel.to_string_lossy();
    let trimmed = raw.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let url = Url::parse(trimmed).with_context(|| format!("parse channel URL {trimmed}"))?;
        let file_name = url
            .path_segments()
            .and_then(|segments| segments.filter(|segment| !segment.is_empty()).next_back());
        return zip_entry_name_from_file_name(file_name);
    }

    let file_name = Path::new(trimmed)
        .file_name()
        .and_then(|name| name.to_str());
    zip_entry_name_from_file_name(file_name)
}

fn zip_entry_name_from_file_name(file_name: Option<&str>) -> Result<Option<String>> {
    let Some(file_name) = file_name else {
        return Ok(None);
    };
    if !file_name.to_ascii_lowercase().ends_with(".zip") {
        return Ok(None);
    }

    let stem = &file_name[..file_name.len() - 4];
    if stem.is_empty() {
        bail!("zip channel filename must include a non-empty stem")
    }
    Ok(Some(format!("{stem}.ero")))
}

async fn detect_rootfs_kind<R: BlockReader + ?Sized>(reader: &R) -> Result<Option<RootfsKind>> {
    if reader_has_erofs_magic(reader).await? {
        return Ok(Some(RootfsKind::Erofs));
    }
    if reader_has_ext4_magic(reader).await? {
        return Ok(Some(RootfsKind::Ext4));
    }
    if reader_has_fat_magic(reader).await? {
        return Ok(Some(RootfsKind::Fat));
    }
    Ok(None)
}

async fn open_cached_http_reader(url: Url) -> Result<ChannelSourceReader> {
    let http_reader = HttpBlockReader::new(url.clone(), DEFAULT_IMAGE_BLOCK_SIZE)
        .await
        .map_err(|err| anyhow!("open HTTP reader {url}: {err}"))?;
    let exact_size_bytes = http_reader.size_bytes();
    let cache = StdCacheOps::open_default_for_reader(&http_reader)
        .await
        .map_err(|err| anyhow!("open std cache: {err}"))?;
    let cached = CachedBlockReader::new(http_reader, cache)
        .await
        .map_err(|err| anyhow!("initialize std cache: {err}"))?;
    Ok(ChannelSourceReader {
        reader: Arc::new(cached),
        exact_size_bytes,
    })
}

async fn open_casync_reader(
    index_url: Url,
    chunk_store_url: Option<Url>,
    require_supported_rootfs_magic: bool,
) -> Result<ChannelSourceReader> {
    let index_source = StdCasyncIndexSource::new(StdCasyncIndexLocator::url(index_url.clone()))
        .map_err(|err| anyhow!("open casync index source {index_url}: {err}"))?;

    let chunk_store_url = match chunk_store_url {
        Some(chunk_store_url) => chunk_store_url,
        None => derive_casync_chunk_store_url(&index_url)?,
    };
    info!(
        index_url = %index_url,
        chunk_store_url = %chunk_store_url,
        "resolved casync chunk store URL"
    );

    let chunk_locator = StdCasyncChunkStoreLocator::url_prefix(chunk_store_url.clone())
        .map_err(|err| anyhow!("configure casync chunk store URL {chunk_store_url}: {err}"))?;
    let mut chunk_store_config = StdCasyncChunkStoreConfig::new(chunk_locator);
    chunk_store_config.cache_dir = Some(default_casync_cache_dir());
    let chunk_store = StdCasyncChunkStore::new(chunk_store_config)
        .map_err(|err| anyhow!("build casync chunk store: {err}"))?;

    let reader = CasyncBlockReader::open(
        index_source,
        chunk_store,
        CasyncReaderConfig {
            block_size: DEFAULT_IMAGE_BLOCK_SIZE,
            strict_verify: false,
        },
    )
    .await
    .map_err(|err| anyhow!("open casync reader {index_url}: {err}"))?;
    let exact_size_bytes = reader.index().blob_size();

    if require_supported_rootfs_magic && !casync_blob_looks_like_supported_rootfs(&reader).await? {
        bail!(
            "casync blob index does not reference a supported raw rootfs image: {index_url}; expected EROFS or ext4 superblock magic"
        );
    }
    Ok(ChannelSourceReader {
        reader: Arc::new(reader),
        exact_size_bytes,
    })
}

async fn casync_blob_looks_like_supported_rootfs<R: BlockReader + ?Sized>(
    reader: &R,
) -> Result<bool> {
    Ok(reader_has_erofs_magic(reader).await? || reader_has_ext4_magic(reader).await?)
}

async fn reader_has_erofs_magic<R: BlockReader + ?Sized>(reader: &R) -> Result<bool> {
    const EROFS_SUPER_OFFSET: u64 = 1024;
    const EROFS_SUPER_MAGIC: u32 = 0xe0f5_e1e2;

    let Some(bytes) = read_magic_bytes(reader, EROFS_SUPER_OFFSET, 4).await? else {
        return Ok(false);
    };
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    Ok(magic == EROFS_SUPER_MAGIC)
}

async fn reader_has_ext4_magic<R: BlockReader + ?Sized>(reader: &R) -> Result<bool> {
    const EXT4_MAGIC_OFFSET: u64 = 1024 + 0x38;
    const EXT4_MAGIC: u16 = 0xef53;

    let Some(bytes) = read_magic_bytes(reader, EXT4_MAGIC_OFFSET, 2).await? else {
        return Ok(false);
    };
    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    Ok(magic == EXT4_MAGIC)
}

async fn reader_has_fat_magic<R: BlockReader + ?Sized>(reader: &R) -> Result<bool> {
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

async fn read_magic_bytes<R: BlockReader + ?Sized>(
    reader: &R,
    offset: u64,
    len: usize,
) -> Result<Option<Vec<u8>>> {
    if len == 0 {
        return Ok(Some(Vec::new()));
    }

    let block_size = reader.block_size() as u64;
    if block_size == 0 {
        bail!("channel reader block size is zero");
    }
    let total_blocks = reader.total_blocks().await?;
    let total_bytes = total_blocks
        .checked_mul(block_size)
        .ok_or_else(|| anyhow!("channel blob size overflow"))?;
    let required_end = offset
        .checked_add(len as u64)
        .ok_or_else(|| anyhow!("channel magic offset overflow"))?;
    if total_bytes < required_end {
        return Ok(None);
    }

    let super_lba = offset / block_size;
    let within_block = (offset % block_size) as usize;
    let block_size_usize = block_size as usize;
    let required = within_block + len;
    let blocks_to_read = required.div_ceil(block_size_usize);
    let mut scratch = vec![0u8; blocks_to_read * block_size_usize];
    let read = reader
        .read_blocks(super_lba, &mut scratch, ReadContext::FOREGROUND)
        .await?;
    if read < required {
        return Ok(None);
    }

    Ok(Some(scratch[within_block..within_block + len].to_vec()))
}

fn derive_casync_chunk_store_url(index_url: &Url) -> Result<Url> {
    if let Some(segments) = index_url.path_segments() {
        let segments: Vec<&str> = segments.collect();
        if let Some(index_pos) = segments.iter().rposition(|segment| *segment == "indexes") {
            let mut base_segments = segments[..=index_pos].to_vec();
            base_segments[index_pos] = "chunks";
            let mut url = index_url.clone();
            let mut path = String::from("/");
            path.push_str(&base_segments.join("/"));
            if !path.ends_with('/') {
                path.push('/');
            }
            url.set_path(&path);
            url.set_query(None);
            url.set_fragment(None);
            return Ok(url);
        }
    }

    index_url
        .join("./")
        .with_context(|| format!("derive casync chunk store URL from {index_url}"))
}

fn default_casync_cache_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME") {
        if !path.is_empty() {
            return PathBuf::from(path).join("gibblox").join("casync");
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(path) = std::env::var_os("LOCALAPPDATA") {
            if !path.is_empty() {
                return PathBuf::from(path).join("gibblox").join("casync");
            }
        }
    }

    if let Some(path) = std::env::var_os("HOME") {
        if !path.is_empty() {
            return PathBuf::from(path)
                .join(".cache")
                .join("gibblox")
                .join("casync");
        }
    }

    std::env::temp_dir().join("gibblox").join("casync")
}

#[derive(Default)]
pub(crate) struct BootProfileSourceOverrides {
    pub(crate) kernel_override: Option<Stage0KernelOverride>,
    pub(crate) dtb_override: Option<Vec<u8>>,
}

pub(crate) async fn resolve_boot_profile_source_overrides(
    boot_profile: Option<&fastboop_core::BootProfile>,
    device_profile: &DeviceProfile,
    resolver: &mut ArtifactReaderResolver,
) -> Result<BootProfileSourceOverrides> {
    let Some(boot_profile) = boot_profile else {
        return Ok(BootProfileSourceOverrides::default());
    };

    let kernel_override = if let Some(kernel_source) = boot_profile.kernel.as_ref() {
        let kernel_path = non_empty_profile_path(kernel_source.path.as_str(), "kernel.path")?;
        let source_reader = resolver
            .open_artifact_source(kernel_source.artifact_source())
            .await?;
        let source_rootfs = ProfileSourceRootfs::open(&kernel_source.source, source_reader).await?;
        let kernel_image = source_rootfs.read_all(kernel_path).await?;
        Some(Stage0KernelOverride {
            path: kernel_path.to_string(),
            image: kernel_image,
        })
    } else {
        None
    };

    let dtb_override = if let Some(dtbs_source) = boot_profile.dtbs.as_ref() {
        let dtbs_base = non_empty_profile_path(dtbs_source.path.as_str(), "dtbs.path")?;
        let source_reader = resolver
            .open_artifact_source(dtbs_source.artifact_source())
            .await?;
        let source_rootfs = ProfileSourceRootfs::open(&dtbs_source.source, source_reader).await?;
        let dtb_path = resolve_dtb_path_candidate(
            &source_rootfs,
            dtbs_base,
            device_profile.devicetree_name.as_str(),
        )
        .await?;
        Some(source_rootfs.read_all(dtb_path.as_str()).await?)
    } else {
        None
    };

    Ok(BootProfileSourceOverrides {
        kernel_override,
        dtb_override,
    })
}

enum ProfileSourceRootfs {
    Erofs(ErofsRootfs),
    Ext4(Ext4Rootfs),
    Fat(FatFs),
}

impl ProfileSourceRootfs {
    async fn open(source: &BootProfileRootfs, reader: Arc<dyn BlockReader>) -> Result<Self> {
        match source {
            BootProfileRootfs::Erofs(_) => {
                let total_blocks = reader.total_blocks().await?;
                let image_size_bytes = total_blocks
                    .checked_mul(reader.block_size() as u64)
                    .ok_or_else(|| anyhow!("boot profile source image size overflow"))?;
                let rootfs = ErofsRootfs::new(reader, image_size_bytes)
                    .await
                    .map_err(|err| anyhow!("open boot profile erofs source: {err}"))?;
                Ok(Self::Erofs(rootfs))
            }
            BootProfileRootfs::Ext4(_) => {
                let rootfs = Ext4Rootfs::open(reader)
                    .await
                    .map_err(|err| anyhow!("open boot profile ext4 source: {err}"))?;
                Ok(Self::Ext4(rootfs))
            }
            BootProfileRootfs::Fat(_) => {
                let rootfs = FatFs::open(reader)
                    .await
                    .map_err(|err| anyhow!("open boot profile fat source: {err}"))?;
                Ok(Self::Fat(rootfs))
            }
        }
    }

    async fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        match self {
            Self::Erofs(rootfs) => rootfs
                .read_all(path)
                .await
                .map_err(|err| anyhow!("read boot profile erofs path {path}: {err}")),
            Self::Ext4(rootfs) => rootfs
                .read_all(path)
                .await
                .map_err(|err| anyhow!("read boot profile ext4 path {path}: {err}")),
            Self::Fat(rootfs) => rootfs
                .read_all(path)
                .await
                .map_err(|err| anyhow!("read boot profile fat path {path}: {err}")),
        }
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        match self {
            Self::Erofs(rootfs) => rootfs
                .exists(path)
                .await
                .map_err(|err| anyhow!("check boot profile erofs path {path}: {err}")),
            Self::Ext4(rootfs) => rootfs
                .exists(path)
                .await
                .map_err(|err| anyhow!("check boot profile ext4 path {path}: {err}")),
            Self::Fat(rootfs) => rootfs
                .exists(path)
                .await
                .map_err(|err| anyhow!("check boot profile fat path {path}: {err}")),
        }
    }
}

fn non_empty_profile_path<'a>(path: &'a str, field: &str) -> Result<&'a str> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        bail!("boot profile {field} must not be empty");
    }
    Ok(trimmed)
}

async fn resolve_dtb_path_candidate(
    source_rootfs: &ProfileSourceRootfs,
    dtbs_base: &str,
    devicetree_name: &str,
) -> Result<String> {
    let devicetree_name = devicetree_name.trim().trim_start_matches('/');
    if devicetree_name.is_empty() {
        bail!("device profile devicetree_name is empty");
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
        if source_rootfs.exists(candidate.as_str()).await? {
            return Ok(candidate);
        }
    }

    bail!("boot profile dtbs path {dtbs_base} does not contain dtb for {devicetree_name}")
}

fn join_profile_path(base: &str, suffix: &str) -> String {
    let base = base.trim_end_matches('/');
    let suffix = suffix.trim_start_matches('/');
    if base.is_empty() {
        format!("/{suffix}")
    } else {
        format!("{base}/{suffix}")
    }
}

#[derive(Clone, Debug)]
pub(crate) enum OstreeArg {
    Disabled,
    AutoDetect,
    Explicit(String),
}

pub(crate) fn parse_ostree_arg(raw: Option<&Option<String>>) -> Result<OstreeArg> {
    match raw {
        None => Ok(OstreeArg::Disabled),
        Some(None) => Ok(OstreeArg::AutoDetect),
        Some(Some(path)) => Ok(OstreeArg::Explicit(
            normalize_ostree_deployment_path(path)
                .map_err(|err| anyhow!("normalize ostree deployment path: {err}"))?,
        )),
    }
}

pub(crate) async fn auto_detect_ostree_deployment_path<P>(rootfs: &P) -> Result<String>
where
    P: Filesystem,
    P::Error: core::fmt::Display,
{
    const OSTREE_ROOT: &str = "/ostree";

    if !is_directory(rootfs, OSTREE_ROOT).await? {
        bail!("auto-detect ostree deployment failed: {OSTREE_ROOT} is not a directory");
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

    bail!("auto-detect ostree deployment failed: no deployment symlink found under /ostree/boot.*")
}

async fn sorted_dir_entries<P>(rootfs: &P, path: &str) -> Result<Vec<String>>
where
    P: Filesystem,
    P::Error: core::fmt::Display,
{
    let mut entries = rootfs
        .read_dir(path)
        .await
        .map_err(|err| anyhow!("read directory {path}: {err}"))?;
    entries.sort();
    Ok(entries)
}

async fn is_directory<P>(rootfs: &P, path: &str) -> Result<bool>
where
    P: Filesystem,
    P::Error: core::fmt::Display,
{
    let ty = rootfs
        .entry_type(path)
        .await
        .map_err(|err| anyhow!("read entry type {path}: {err}"))?;
    Ok(matches!(ty, Some(FilesystemEntryType::Directory)))
}

async fn is_symlink<P>(rootfs: &P, path: &str) -> Result<bool>
where
    P: Filesystem,
    P::Error: core::fmt::Display,
{
    let ty = rootfs
        .entry_type(path)
        .await
        .map_err(|err| anyhow!("read entry type {path}: {err}"))?;
    Ok(matches!(ty, Some(FilesystemEntryType::Symlink)))
}

pub(crate) fn format_probe_error(
    err: ProbeError<FastbootProtocolError<fastboop_fastboot_rusb::FastbootRusbError>>,
) -> String {
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

#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct DirectoryRootfs {
    pub(crate) root: PathBuf,
}

#[allow(dead_code)]
impl Filesystem for DirectoryRootfs {
    type Error = anyhow::Error;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        let path = resolve_rooted(&self.root, path)?;
        fs::read(&path).with_context(|| format!("reading {}", path.display()))
    }

    async fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        let path = resolve_rooted(&self.root, path)?;
        let mut f = fs::File::open(&path)
            .with_context(|| format!("opening {} for range read", path.display()))?;
        f.seek(SeekFrom::Start(offset))
            .with_context(|| format!("seeking {} to {}", path.display(), offset))?;
        let mut buf = vec![0u8; len];
        let n = f
            .read(&mut buf)
            .with_context(|| format!("reading range from {}", path.display()))?;
        buf.truncate(n);
        Ok(buf)
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>> {
        let path = resolve_rooted(&self.root, path)?;
        let entries =
            fs::read_dir(&path).with_context(|| format!("reading directory {}", path.display()))?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        Ok(names)
    }

    async fn entry_type(&self, path: &str) -> Result<Option<FilesystemEntryType>> {
        let path = resolve_rooted(&self.root, path)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("reading metadata for {}", path.display()));
            }
        };
        let ty = metadata.file_type();
        let entry_type = if ty.is_file() {
            FilesystemEntryType::File
        } else if ty.is_dir() {
            FilesystemEntryType::Directory
        } else if ty.is_symlink() {
            FilesystemEntryType::Symlink
        } else {
            FilesystemEntryType::Other
        };
        Ok(Some(entry_type))
    }

    async fn read_link(&self, path: &str) -> Result<String> {
        let path = resolve_rooted(&self.root, path)?;
        let target = fs::read_link(&path)
            .with_context(|| format!("reading symlink target {}", path.display()))?;
        Ok(target.to_string_lossy().into_owned())
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let path = resolve_rooted(&self.root, path)?;
        Ok(path.exists())
    }
}

pub(crate) fn read_existing_initrd(path: &Option<PathBuf>) -> Result<Option<Vec<u8>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    Ok(Some(fs::read(path).with_context(|| {
        format!("reading initrd {}", path.display())
    })?))
}

pub(crate) fn read_dtbo_overlays(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for path in paths {
        let data = fs::read(path).with_context(|| format!("reading dtbo {}", path.display()))?;
        out.push(data);
    }
    Ok(out)
}

#[allow(dead_code)]
fn resolve_rooted(root: &Path, path: &str) -> Result<PathBuf> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        bail!("empty path");
    }
    Ok(root.join(trimmed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastboop_core::{BootProfileManifest, encode_boot_profile};
    use gobblytes_core::MockFilesystem;

    #[tokio::test]
    async fn auto_detect_ostree_picks_first_sorted_candidate() {
        let mut rootfs = MockFilesystem::default();
        rootfs.add_dir("/ostree", &["boot.1", "boot.0"]);
        rootfs.add_dir("/ostree/boot.0", &["fedora"]);
        rootfs.add_dir("/ostree/boot.0/fedora", &["aaa"]);
        rootfs.add_dir("/ostree/boot.0/fedora/aaa", &["1"]);
        rootfs.add_symlink("/ostree/boot.0/fedora/aaa/1");

        rootfs.add_dir("/ostree/boot.1", &["fedora"]);
        rootfs.add_dir("/ostree/boot.1/fedora", &["bbb"]);
        rootfs.add_dir("/ostree/boot.1/fedora/bbb", &["0"]);
        rootfs.add_symlink("/ostree/boot.1/fedora/bbb/0");

        let detected = auto_detect_ostree_deployment_path(&rootfs).await.unwrap();
        assert_eq!(detected, "ostree/boot.0/fedora/aaa/1");
    }

    #[tokio::test]
    async fn auto_detect_ostree_errors_when_no_symlink_candidates_exist() {
        let mut rootfs = MockFilesystem::default();
        rootfs.add_dir("/ostree", &["boot.1"]);
        rootfs.add_dir("/ostree/boot.1", &["fedora"]);
        rootfs.add_dir("/ostree/boot.1/fedora", &["aaa"]);
        rootfs.add_dir("/ostree/boot.1/fedora/aaa", &["0"]);

        let err = auto_detect_ostree_deployment_path(&rootfs)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no deployment symlink found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn empty_stage0_device_map_matches_any_device_profile() {
        let profile = compile_boot_profile(
            r#"
id: wildcard
rootfs:
  erofs:
    file: ./rootfs.ero
"#,
        );
        assert!(boot_profile_matches_device(&profile, "oneplus-fajita"));
        assert!(boot_profile_matches_device(&profile, "pine64-pinephone"));
    }

    #[test]
    fn select_boot_profile_requires_explicit_choice_when_multiple_match() {
        let wildcard = compile_boot_profile(
            r#"
id: wildcard
rootfs:
  erofs:
    file: ./rootfs.ero
"#,
        );
        let specific = compile_boot_profile(
            r#"
id: specific
rootfs:
  erofs:
    file: ./rootfs.ero
stage0:
  devices:
    oneplus-fajita: {}
"#,
        );

        let err = select_boot_profile_for_device(&[wildcard, specific], "oneplus-fajita", None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("pass --boot-profile"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn select_boot_profile_honors_requested_id() {
        let wildcard = compile_boot_profile(
            r#"
id: wildcard
rootfs:
  erofs:
    file: ./rootfs.ero
"#,
        );
        let specific = compile_boot_profile(
            r#"
id: specific
rootfs:
  erofs:
    file: ./rootfs.ero
stage0:
  devices:
    oneplus-fajita: {}
"#,
        );

        let selected = select_boot_profile_for_device(
            &[wildcard, specific],
            "oneplus-fajita",
            Some("specific"),
        )
        .unwrap();
        assert_eq!(selected.id, "specific");
    }

    #[tokio::test]
    async fn bootprofile_stream_head_consumes_profiles_then_trailing_artifact() {
        let first = compile_boot_profile(
            r#"
id: first
rootfs:
  erofs:
    file: ./rootfs.ero
"#,
        );
        let second = compile_boot_profile(
            r#"
id: second
rootfs:
  erofs:
    file: ./rootfs.ero
stage0:
  devices:
    oneplus-fajita: {}
"#,
        );

        let first_encoded = encode_boot_profile(&first).unwrap();
        let second_encoded = encode_boot_profile(&second).unwrap();
        let mut trailing = vec![0u8; 2048];
        trailing[1024..1028].copy_from_slice(&0xE0F5_E1E2u32.to_le_bytes());

        let mut stream = Vec::new();
        stream.extend_from_slice(first_encoded.as_slice());
        stream.extend_from_slice(second_encoded.as_slice());
        stream.extend_from_slice(trailing.as_slice());
        let stream_len = stream.len() as u64;

        let source: Arc<dyn BlockReader> = Arc::new(TestBytesBlockReader::new(stream, 512));
        let head = read_boot_profile_stream_head(source.as_ref(), stream_len)
            .await
            .unwrap();
        assert_eq!(head.profiles.len(), 2);
        assert_eq!(head.profiles[0].id, "first");
        assert_eq!(head.profiles[1].id, "second");
        assert_eq!(
            head.consumed_bytes,
            (first_encoded.len() + second_encoded.len()) as u64
        );

        let trailing_reader =
            OffsetChannelBlockReader::new(source, head.consumed_bytes, stream_len).unwrap();
        let trailing_reader: Arc<dyn BlockReader> = Arc::new(trailing_reader);
        let unwrapped = unwrap_channel_reader(trailing_reader, None).await.unwrap();
        let kind = classify_channel_reader(unwrapped.as_ref()).await.unwrap();
        assert_eq!(kind, ChannelStreamKind::Erofs);
    }

    #[tokio::test]
    async fn bootprofile_stream_head_uses_exact_size_not_padded_blocks() {
        let profile = compile_boot_profile(
            r#"
id: tiny
rootfs:
  erofs:
    file: ./rootfs.ero
"#,
        );

        let encoded = encode_boot_profile(&profile).unwrap();
        let exact_len = encoded.len() as u64;
        let source: Arc<dyn BlockReader> = Arc::new(TestBytesBlockReader::new(encoded, 512));

        let head = read_boot_profile_stream_head(source.as_ref(), exact_len)
            .await
            .unwrap();
        assert_eq!(head.profiles.len(), 1);
        assert_eq!(head.consumed_bytes, exact_len);
    }

    fn compile_boot_profile(yaml: &str) -> BootProfile {
        let manifest: BootProfileManifest = serde_yaml::from_str(yaml).expect("parse manifest");
        manifest
            .compile_dt_overlays(|_| Ok::<Vec<u8>, anyhow::Error>(Vec::new()))
            .expect("compile manifest")
    }

    struct TestBytesBlockReader {
        bytes: Vec<u8>,
        block_size: u32,
    }

    impl TestBytesBlockReader {
        fn new(bytes: Vec<u8>, block_size: u32) -> Self {
            Self { bytes, block_size }
        }
    }

    #[async_trait]
    impl BlockReader for TestBytesBlockReader {
        fn block_size(&self) -> u32 {
            self.block_size
        }

        async fn total_blocks(&self) -> GibbloxResult<u64> {
            let block_size = self.block_size as usize;
            if block_size == 0 {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "block size must be non-zero",
                ));
            }
            Ok(self.bytes.len().div_ceil(block_size) as u64)
        }

        fn write_identity(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
            out.write_str("test-bytes")
        }

        async fn read_blocks(
            &self,
            lba: u64,
            buf: &mut [u8],
            _ctx: ReadContext,
        ) -> GibbloxResult<usize> {
            let block_size = self.block_size as usize;
            if block_size == 0 {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "block size must be non-zero",
                ));
            }
            let padded_size = self.bytes.len().div_ceil(block_size) * block_size;

            let offset = lba.checked_mul(self.block_size as u64).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "offset overflow")
            })? as usize;
            if offset >= padded_size {
                return Ok(0);
            }

            let read = core::cmp::min(offset + buf.len(), padded_size) - offset;
            for (index, byte) in buf[..read].iter_mut().enumerate() {
                let source_index = offset + index;
                *byte = self.bytes.get(source_index).copied().unwrap_or(0);
            }
            Ok(read)
        }
    }
}
