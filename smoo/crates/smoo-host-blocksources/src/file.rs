use crate::BlockFile;
use anyhow::{Context, ensure};
use async_trait::async_trait;
use smoo_host_core::{
    BlockSource, BlockSourceError, BlockSourceErrorKind, BlockSourceResult, ExportIdentity,
};
use std::hash::Hasher;
use std::path::Path;

/// Block source backed by a regular file.
pub struct FileBlockSource {
    inner: BlockFile,
    block_size: u32,
    identity: String,
}

impl FileBlockSource {
    /// Open a file-backed block source.
    pub async fn open(path: impl AsRef<Path>, block_size: u32) -> anyhow::Result<Self> {
        ensure!(
            block_size.is_power_of_two(),
            "block size must be a power of two"
        );
        ensure!(block_size > 0, "block size must be non-zero");
        let opened = crate::open_block_file(path.as_ref()).await?;
        let canonical = tokio::fs::canonicalize(path.as_ref())
            .await
            .with_context(|| format!("canonicalize {}", path.as_ref().display()))?;
        Ok(Self {
            inner: BlockFile::new(opened.file, opened.len, opened.writable),
            block_size,
            identity: format!("file:{}", canonical.to_string_lossy()),
        })
    }

    fn ensure_aligned(&self, len: usize) -> BlockSourceResult<()> {
        if !len.is_multiple_of(self.block_size as usize) {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "buffer length must align to block size",
            ));
        }
        Ok(())
    }

    fn offset(&self, lba: u64) -> BlockSourceResult<u64> {
        lba.checked_mul(self.block_size as u64).ok_or_else(|| {
            BlockSourceError::with_message(BlockSourceErrorKind::OutOfRange, "lba overflow")
        })
    }

    fn write_identity<H: Hasher + ?Sized>(&self, state: &mut H) {
        state.write(self.identity.as_bytes());
    }
}

#[async_trait]
impl BlockSource for FileBlockSource {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> BlockSourceResult<u64> {
        self.inner
            .size()
            .await
            .map(|bytes| bytes / self.block_size as u64)
            .map_err(crate::io_error)
    }

    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        self.ensure_aligned(buf.len())?;
        if buf.is_empty() {
            return Ok(0);
        }
        let offset = self.offset(lba)?;
        self.inner
            .read_at(offset, buf)
            .await
            .map_err(crate::io_error)?;
        Ok(buf.len())
    }

    async fn write_blocks(&self, lba: u64, buf: &[u8]) -> BlockSourceResult<usize> {
        self.ensure_aligned(buf.len())?;
        if buf.is_empty() {
            return Ok(0);
        }
        let offset = self.offset(lba)?;
        self.inner
            .write_at(offset, buf)
            .await
            .map_err(crate::io_error)?;
        Ok(buf.len())
    }

    async fn flush(&self) -> BlockSourceResult<()> {
        self.inner.flush().await.map_err(crate::io_error)
    }
}

impl ExportIdentity for FileBlockSource {
    fn write_export_id(&self, state: &mut dyn Hasher) {
        self.write_identity(state);
    }
}
