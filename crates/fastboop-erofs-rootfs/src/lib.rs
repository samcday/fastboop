#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use fastboop_core::RootfsProvider;
use gibblox_cache::CachedBlockReader;
#[cfg(target_arch = "wasm32")]
use gibblox_cache_store_opfs::OpfsCacheOps;
#[cfg(not(target_arch = "wasm32"))]
use gibblox_cache_store_std::StdCacheOps;
use gibblox_core::{BlockReader, GibbloxErrorKind, ReadContext};
#[cfg(not(target_arch = "wasm32"))]
use gibblox_file::StdFileBlockReader;
use gibblox_http::HttpBlockReader;
use url::Url;

const DIRENT_SIZE: usize = 12;
pub const DEFAULT_IMAGE_BLOCK_SIZE: u32 = 512;

#[derive(Clone)]
pub struct ErofsRootfs {
    fs: gibblox_core::erofs_rs::EroFS<GibbloxReadAtAdapter>,
}

pub struct OpenedRootfs {
    pub provider: ErofsRootfs,
    pub reader: Arc<dyn BlockReader>,
    pub size_bytes: u64,
    pub identity: String,
}

impl ErofsRootfs {
    async fn new(reader: Arc<dyn BlockReader>, image_size_bytes: u64) -> Result<Self> {
        let source_block_size = reader.block_size();
        if source_block_size == 0 || !source_block_size.is_power_of_two() {
            bail!("source block size must be non-zero power of two");
        }
        let adapter = GibbloxReadAtAdapter {
            inner: reader,
            block_size: source_block_size as usize,
        };
        let fs = gibblox_core::erofs_rs::EroFS::from_image(adapter, image_size_bytes)
            .await
            .map_err(|err| anyhow!("open erofs image: {err}"))?;
        Ok(Self { fs })
    }

    fn normalize(path: &str) -> String {
        let trimmed = path.trim();
        let inner = trimmed.trim_start_matches('/');
        if inner.is_empty() {
            "/".to_string()
        } else {
            format!("/{inner}")
        }
    }

    async fn resolve_inode(
        &self,
        path: &str,
    ) -> Result<Option<gibblox_core::erofs_rs::types::Inode>> {
        self.fs
            .get_path_inode_str(path)
            .await
            .map_err(|err| anyhow!("resolve EROFS path {path}: {err}"))
    }
}

pub async fn open_erofs_rootfs(rootfs: &str) -> Result<OpenedRootfs> {
    if rootfs.starts_with("http://") || rootfs.starts_with("https://") {
        return open_http_erofs(rootfs).await;
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        return open_local_erofs(Path::new(rootfs)).await;
    }
    #[cfg(target_arch = "wasm32")]
    {
        bail!("local filesystem rootfs paths are unsupported on wasm targets");
    }
}

async fn open_http_erofs(rootfs_url: &str) -> Result<OpenedRootfs> {
    let url = Url::parse(rootfs_url).with_context(|| format!("parse rootfs URL {rootfs_url}"))?;
    let http_reader = HttpBlockReader::new(url.clone(), DEFAULT_IMAGE_BLOCK_SIZE)
        .await
        .map_err(|err| anyhow!("open HTTP EROFS image {url}: {err}"))?;
    let size_bytes = http_reader.size_bytes();
    let identity = url.to_string();

    #[cfg(not(target_arch = "wasm32"))]
    let reader: Arc<dyn BlockReader> = {
        let cache = StdCacheOps::open_default_for_reader(&http_reader)
            .await
            .map_err(|err| anyhow!("open std cache for HTTP rootfs: {err}"))?;
        let cached = CachedBlockReader::new(http_reader, cache)
            .await
            .map_err(|err| anyhow!("initialize std cache for HTTP rootfs: {err}"))?;
        Arc::new(cached)
    };

    #[cfg(target_arch = "wasm32")]
    let reader: Arc<dyn BlockReader> = {
        let cache = OpfsCacheOps::open_for_reader(&http_reader)
            .await
            .map_err(|err| anyhow!("open OPFS cache for HTTP rootfs: {err}"))?;
        let cached = CachedBlockReader::new(http_reader, cache)
            .await
            .map_err(|err| anyhow!("initialize OPFS cache for HTTP rootfs: {err}"))?;
        Arc::new(cached)
    };

    let provider = ErofsRootfs::new(reader.clone(), size_bytes).await?;
    Ok(OpenedRootfs {
        provider,
        reader,
        size_bytes,
        identity,
    })
}

#[cfg(not(target_arch = "wasm32"))]
async fn open_local_erofs(image_path: &Path) -> Result<OpenedRootfs> {
    let canonical = std::fs::canonicalize(image_path)
        .with_context(|| format!("canonicalize {}", image_path.display()))?;
    let file_reader = StdFileBlockReader::open(&canonical, DEFAULT_IMAGE_BLOCK_SIZE)
        .map_err(|err| anyhow!("open EROFS image {}: {err}", canonical.display()))?;
    let size_bytes = file_reader.size_bytes();
    let identity = format!("file:{}", canonical.display());
    let reader: Arc<dyn BlockReader> = Arc::new(file_reader);
    let provider = ErofsRootfs::new(reader.clone(), size_bytes).await?;
    Ok(OpenedRootfs {
        provider,
        reader,
        size_bytes,
        identity,
    })
}

impl RootfsProvider for ErofsRootfs {
    type Error = anyhow::Error;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        let normalized = Self::normalize(path);
        let inode = self
            .resolve_inode(&normalized)
            .await?
            .ok_or_else(|| anyhow!("missing path {normalized}"))?;
        if !inode.is_file() {
            bail!("path is not a regular file: {normalized}");
        }

        let mut out = vec![0u8; inode.data_size()];
        let mut offset = 0usize;
        while offset < out.len() {
            let read = self
                .fs
                .read_inode_range(&inode, offset, &mut out[offset..])
                .await
                .map_err(|err| anyhow!("read EROFS file {normalized}: {err}"))?;
            if read == 0 {
                break;
            }
            offset += read;
        }
        out.truncate(offset);
        Ok(out)
    }

    async fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let normalized = Self::normalize(path);
        let inode = self
            .resolve_inode(&normalized)
            .await?
            .ok_or_else(|| anyhow!("missing path {normalized}"))?;
        if !inode.is_file() {
            bail!("path is not a regular file: {normalized}");
        }
        let file_size = inode.data_size();
        let offset = usize::try_from(offset).context("range offset exceeds usize")?;
        if offset >= file_size {
            return Ok(Vec::new());
        }
        let read_len = len.min(file_size - offset);
        let mut out = vec![0u8; read_len];
        let read = self
            .fs
            .read_inode_range(&inode, offset, &mut out)
            .await
            .map_err(|err| anyhow!("read range in EROFS file {normalized}: {err}"))?;
        out.truncate(read);
        Ok(out)
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>> {
        let normalized = Self::normalize(path);
        let inode = self
            .resolve_inode(&normalized)
            .await?
            .ok_or_else(|| anyhow!("missing path {normalized}"))?;
        if !inode.is_dir() {
            bail!("path is not a directory: {normalized}");
        }

        let block_size = self.fs.block_size();
        let data_size = inode.data_size();
        let mut names = Vec::new();
        let mut offset = 0usize;
        while offset < data_size {
            let mut block = vec![0u8; (data_size - offset).min(block_size)];
            let read = self
                .fs
                .read_inode_range(&inode, offset, &mut block)
                .await
                .map_err(|err| anyhow!("read EROFS directory {normalized}: {err}"))?;
            block.truncate(read);
            parse_dir_block(&block, &mut names)
                .with_context(|| format!("parse EROFS directory block for {normalized}"))?;
            offset = offset.saturating_add(block_size);
        }

        Ok(names)
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let normalized = Self::normalize(path);
        Ok(self.resolve_inode(&normalized).await?.is_some())
    }
}

#[derive(Clone)]
struct GibbloxReadAtAdapter {
    inner: Arc<dyn BlockReader>,
    block_size: usize,
}

#[async_trait]
impl gibblox_core::erofs_rs::ReadAt for GibbloxReadAtAdapter {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> gibblox_core::erofs_rs::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let bs = self.block_size as u64;
        let start = (offset / bs) * bs;
        let end = offset.checked_add(buf.len() as u64).ok_or_else(|| {
            gibblox_core::erofs_rs::Error::OutOfBounds("range overflow".to_string())
        })?;
        let aligned_end = end.div_ceil(bs) * bs;
        let aligned_len = (aligned_end - start) as usize;

        let mut scratch = vec![0u8; aligned_len];
        let mut filled = 0usize;
        while filled < scratch.len() {
            let lba = (start as usize + filled) / self.block_size;
            let read = self
                .inner
                .read_blocks(lba as u64, &mut scratch[filled..], ReadContext::FOREGROUND)
                .await
                .map_err(map_gibblox_err)?;
            if read == 0 {
                return Err(gibblox_core::erofs_rs::Error::OutOfBounds(
                    "unexpected EOF while servicing aligned read".to_string(),
                ));
            }
            if read % self.block_size != 0 && filled + read < scratch.len() {
                return Err(gibblox_core::erofs_rs::Error::OutOfBounds(
                    "unaligned short read from block source".to_string(),
                ));
            }
            filled += read;
        }

        let head = (offset - start) as usize;
        buf.copy_from_slice(&scratch[head..head + buf.len()]);
        Ok(buf.len())
    }
}

fn parse_dir_block(block: &[u8], out: &mut Vec<String>) -> Result<()> {
    if block.len() < DIRENT_SIZE {
        return Ok(());
    }

    let entry_count = u16::from_le_bytes([block[8], block[9]]) as usize / DIRENT_SIZE;
    if entry_count == 0 {
        return Ok(());
    }

    for index in 0..entry_count {
        let entry_start = index * DIRENT_SIZE;
        let name_off_start = entry_start + 8;
        if name_off_start + 2 > block.len() {
            break;
        }
        let name_start =
            u16::from_le_bytes([block[name_off_start], block[name_off_start + 1]]) as usize;
        let name_end = if index + 1 < entry_count {
            let next_start = (index + 1) * DIRENT_SIZE + 8;
            if next_start + 2 > block.len() {
                block.len()
            } else {
                u16::from_le_bytes([block[next_start], block[next_start + 1]]) as usize
            }
        } else {
            block.len()
        };
        if name_end < name_start || name_end > block.len() {
            bail!("invalid directory name range");
        }
        let name = String::from_utf8_lossy(&block[name_start..name_end])
            .trim_end_matches('\0')
            .to_string();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        out.push(name);
    }

    Ok(())
}

fn map_gibblox_err(err: gibblox_core::GibbloxError) -> gibblox_core::erofs_rs::Error {
    match err.kind() {
        GibbloxErrorKind::InvalidInput => {
            gibblox_core::erofs_rs::Error::CorruptedData(format!("invalid input: {err}"))
        }
        GibbloxErrorKind::OutOfRange => gibblox_core::erofs_rs::Error::OutOfBounds(err.to_string()),
        GibbloxErrorKind::Io => gibblox_core::erofs_rs::Error::OutOfBounds(err.to_string()),
        GibbloxErrorKind::Unsupported => {
            gibblox_core::erofs_rs::Error::NotSupported(err.to_string())
        }
        GibbloxErrorKind::Other => gibblox_core::erofs_rs::Error::OutOfBounds(err.to_string()),
    }
}
