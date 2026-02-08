extern crate alloc;

use alloc::{
    borrow::ToOwned,
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec,
};
use async_trait::async_trait;
use tracing::{info, trace};

use crate::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};

/// File-backed block reader sourced from a file inside an EROFS image.
pub struct EroBlockReader {
    block_size: u32,
    file_size_bytes: u64,
    file_path: String,
    source_identity: String,
    inode: erofs_rs::types::Inode,
    fs: erofs_rs::EroFS<CoreBlockAdapter>,
}

impl EroBlockReader {
    /// Build a block reader for `path` from an EROFS image exposed through `BlockReader`.
    pub async fn new<S: BlockReader + 'static>(
        source: S,
        path: &str,
        block_size: u32,
    ) -> GibbloxResult<Self> {
        info!(path, block_size, "constructing EROFS-backed reader");
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "block size must be non-zero power of two",
            ));
        }

        let source_block_size = source.block_size();
        if source_block_size == 0 || !source_block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "source block size must be non-zero power of two",
            ));
        }

        let total_blocks = source.total_blocks().await?;
        let source_identity = crate::block_identity_string(&source);
        let image_size_bytes = total_blocks
            .checked_mul(source_block_size as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "image size overflow")
            })?;

        let adapter = CoreBlockAdapter {
            inner: Arc::new(source),
            block_size: source_block_size as usize,
        };

        let fs = erofs_rs::EroFS::from_image(adapter, image_size_bytes)
            .await
            .map_err(map_erofs_err("open erofs image"))?;
        let inode = fs
            .get_path_inode_str(path)
            .await
            .map_err(map_erofs_err("resolve erofs path"))?
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::InvalidInput, "path not found")
            })?;
        if !inode.is_file() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "path is not a regular file",
            ));
        }
        let file_size_bytes = inode.data_size() as u64;
        info!(path, file_size_bytes, "resolved file inode from EROFS");

        Ok(Self {
            block_size,
            file_size_bytes,
            file_path: path.to_owned(),
            source_identity,
            inode,
            fs,
        })
    }

    pub fn file_size_bytes(&self) -> u64 {
        self.file_size_bytes
    }
}

#[async_trait]
impl BlockReader for EroBlockReader {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        Ok(self.file_size_bytes.div_ceil(self.block_size as u64))
    }

    fn write_identity(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
        write!(
            out,
            "erofs-file:({}):{}",
            self.source_identity, self.file_path
        )
    }

    async fn read_blocks(
        &self,
        lba: u64,
        buf: &mut [u8],
        _ctx: ReadContext,
    ) -> GibbloxResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !buf.len().is_multiple_of(self.block_size as usize) {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "buffer length must align to block size",
            ));
        }

        let offset = lba.checked_mul(self.block_size as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
        })?;
        if offset >= self.file_size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "requested block out of range",
            ));
        }

        trace!(
            lba,
            offset,
            requested = buf.len(),
            "reading file blocks from EROFS"
        );
        let read = self
            .fs
            .read_inode_range(&self.inode, offset as usize, buf)
            .await
            .map_err(map_erofs_err("read erofs file range"))?;
        if read < buf.len() {
            buf[read..].fill(0);
        }
        Ok(buf.len())
    }
}

#[derive(Clone)]
struct CoreBlockAdapter {
    inner: Arc<dyn BlockReader>,
    block_size: usize,
}

#[async_trait]
impl erofs_rs::ReadAt for CoreBlockAdapter {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> erofs_rs::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let bs = self.block_size as u64;
        let start = (offset / bs) * bs;
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| erofs_rs::Error::OutOfBounds("range overflow".to_string()))?;
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
                .map_err(|err| erofs_rs::Error::OutOfBounds(err.to_string()))?;
            if read == 0 {
                return Err(erofs_rs::Error::OutOfBounds(
                    "unexpected EOF while servicing aligned read".to_string(),
                ));
            }
            if read % self.block_size != 0 && filled + read < scratch.len() {
                return Err(erofs_rs::Error::OutOfBounds(
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

fn map_erofs_err(op: &'static str) -> impl FnOnce(erofs_rs::Error) -> GibbloxError {
    move |err| {
        GibbloxError::with_message(GibbloxErrorKind::Io, [op, ": ", &err.to_string()].concat())
    }
}
