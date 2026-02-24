use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use gibblox_core::{
    BlockReader, ByteRangeReader, GibbloxErrorKind, LruBlockReader, PagedBlockReader, ReadContext,
};
use gobblytes_core::{Filesystem, FilesystemEntryType};

const DIRENT_SIZE: usize = 12;
pub const DEFAULT_IMAGE_BLOCK_SIZE: u32 = 512;

#[derive(Clone)]
pub struct ErofsRootfs {
    fs: gibblox_core::erofs_rs::EroFS<GibbloxReadAtAdapter>,
}

impl ErofsRootfs {
    pub async fn new(reader: Arc<dyn BlockReader>, image_size_bytes: u64) -> Result<Self> {
        let lru = LruBlockReader::new(reader, Default::default())
            .await
            .map_err(|err| anyhow!("initialize LRU for rootfs reader: {err}"))?;
        let paged = PagedBlockReader::new(lru, Default::default())
            .await
            .map_err(|err| anyhow!("initialize paged reader for rootfs reader: {err}"))?;

        let source_block_size = paged.block_size();
        if source_block_size == 0 || !source_block_size.is_power_of_two() {
            bail!("source block size must be non-zero power of two");
        }
        let adapter = GibbloxReadAtAdapter {
            byte_reader: ByteRangeReader::new(
                Arc::new(paged),
                source_block_size as usize,
                image_size_bytes,
            ),
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

    async fn read_symlink_target(
        &self,
        inode: &gibblox_core::erofs_rs::types::Inode,
        path: &str,
    ) -> Result<String> {
        let mut out = vec![0u8; inode.data_size()];
        let read = self
            .fs
            .read_inode_range(inode, 0, &mut out)
            .await
            .map_err(|err| anyhow!("read EROFS symlink {path}: {err}"))?;
        out.truncate(read);

        let target = core::str::from_utf8(&out)
            .map_err(|_| anyhow!("symlink target is not UTF-8 for {path}"))?
            .trim_end_matches('\0')
            .trim();
        if target.is_empty() {
            bail!("symlink target is empty for {path}");
        }
        Ok(target.to_string())
    }
}

impl Filesystem for ErofsRootfs {
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

    async fn entry_type(&self, path: &str) -> Result<Option<FilesystemEntryType>> {
        let normalized = Self::normalize(path);
        let inode = match self.resolve_inode(&normalized).await? {
            Some(inode) => inode,
            None => return Ok(None),
        };
        let ty = if inode.is_file() {
            FilesystemEntryType::File
        } else if inode.is_dir() {
            FilesystemEntryType::Directory
        } else if inode.is_symlink() {
            FilesystemEntryType::Symlink
        } else {
            FilesystemEntryType::Other
        };
        Ok(Some(ty))
    }

    async fn read_link(&self, path: &str) -> Result<String> {
        let normalized = Self::normalize(path);
        let inode = self
            .resolve_inode(&normalized)
            .await?
            .ok_or_else(|| anyhow!("missing path {normalized}"))?;
        if !inode.is_symlink() {
            bail!("path is not a symlink: {normalized}");
        }
        self.read_symlink_target(&inode, &normalized).await
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let normalized = Self::normalize(path);
        Ok(self.resolve_inode(&normalized).await?.is_some())
    }
}

#[derive(Clone)]
struct GibbloxReadAtAdapter {
    byte_reader: ByteRangeReader,
}

#[async_trait]
impl gibblox_core::erofs_rs::ReadAt for GibbloxReadAtAdapter {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> gibblox_core::erofs_rs::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        self.byte_reader
            .read_exact_at(offset, buf, ReadContext::FOREGROUND)
            .await
            .map_err(map_gibblox_err)?;
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
