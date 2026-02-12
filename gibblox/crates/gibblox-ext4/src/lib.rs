#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;
use core::error::Error;
use core::fmt;
use ext4_view::{Ext4, Ext4Read};
use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};

/// Simple error wrapper that implements core::error::Error
#[derive(Debug)]
struct SimpleError(&'static str);

impl fmt::Display for SimpleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for SimpleError {}

/// Adapter to bridge gibblox BlockReader to ext4-view's Ext4Read trait.
struct BlockReaderAdapter {
    reader: Arc<dyn BlockReader>,
    source_block_size: u32,
}

impl Ext4Read for BlockReaderAdapter {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if dst.is_empty() {
            return Ok(());
        }

        let block_size = self.source_block_size as u64;
        let start_block = start_byte / block_size;
        let block_offset = (start_byte % block_size) as usize;
        let end_byte = start_byte.checked_add(dst.len() as u64).ok_or_else(|| {
            Box::new(SimpleError("offset overflow")) as Box<dyn Error + Send + Sync>
        })?;
        let end_block = end_byte.saturating_sub(1) / block_size;
        let block_count = (end_block - start_block + 1) as usize;

        // Aligned read - common case
        if block_offset == 0 && dst.len() == block_size as usize * block_count {
            return pollster::block_on(
                self.reader
                    .read_blocks(start_block, dst, ReadContext::FOREGROUND),
            )
            .map(|_| ())
            .map_err(|_| Box::new(SimpleError("read_blocks failed")) as Box<dyn Error + Send + Sync>);
        }

        // Misaligned read - need scratch buffer
        let total_bytes = block_count * self.source_block_size as usize;
        let mut scratch = alloc::vec![0u8; total_bytes];

        pollster::block_on(
            self.reader
                .read_blocks(start_block, &mut scratch, ReadContext::FOREGROUND),
        )
        .map_err(|_| Box::new(SimpleError("read_blocks failed")) as Box<dyn Error + Send + Sync>)?;

        let copy_len = dst.len().min(total_bytes - block_offset);
        dst[..copy_len].copy_from_slice(&scratch[block_offset..block_offset + copy_len]);

        Ok(())
    }
}

/// BlockReader that extracts a single file from an ext4 filesystem.
///
/// Note: This implementation caches the full file contents in memory on construction.
/// ext4-view uses Rc internally which prevents thread-safe access, so we work around
/// this by reading the entire file once and serving from the cached copy.
pub struct Ext4FileBlockReader {
    block_size: u32,
    file_path: String,
    source_identity: String,
    file_data: Vec<u8>,
}

impl Ext4FileBlockReader {
    /// Create a new Ext4FileBlockReader for a specific file within an ext4 filesystem.
    ///
    /// # Arguments
    /// * `source` - Underlying block reader providing ext4 filesystem data
    /// * `path` - Path to file within ext4 filesystem (e.g., "/lib/modules/6.8.0/kernel/...")
    /// * `desired_block_size` - Block size for reads from this file
    pub async fn new(
        source: Arc<dyn BlockReader>,
        path: &str,
        desired_block_size: u32,
    ) -> GibbloxResult<Self> {
        let source_block_size = source.block_size();
        let mut source_identity = String::new();
        source.write_identity(&mut source_identity).map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::Other,
                "failed to write source identity",
            )
        })?;

        let adapter = BlockReaderAdapter {
            reader: source,
            source_block_size,
        };

        // ext4-view is synchronous and uses Rc internally (not thread-safe)
        // Read the entire file once during construction
        let ext4 = Ext4::load(Box::new(adapter)).map_err(|e| {
            GibbloxError::with_message(GibbloxErrorKind::Other, format!("ext4 init failed: {:?}", e))
        })?;

        let file_data = ext4.read(path).map_err(|e| {
            GibbloxError::with_message(
                GibbloxErrorKind::Other,
                format!("ext4 read {} failed: {:?}", path, e),
            )
        })?;

        Ok(Self {
            block_size: desired_block_size,
            file_path: path.to_string(),
            source_identity,
            file_data,
        })
    }
}

#[async_trait]
impl BlockReader for Ext4FileBlockReader {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        let blocks = (self.file_data.len() as u64).div_ceil(self.block_size as u64);
        Ok(blocks)
    }

    fn write_identity(&self, out: &mut dyn fmt::Write) -> fmt::Result {
        write!(
            out,
            "ext4-file:({}):{}", 
            self.source_identity, 
            self.file_path
        )
    }

    async fn read_blocks(
        &self,
        lba: u64,
        buf: &mut [u8],
        _ctx: ReadContext,
    ) -> GibbloxResult<usize> {
        let total_blocks = self.total_blocks().await?;
        if lba >= total_blocks {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                format!("lba {} >= total_blocks {}", lba, total_blocks),
            ));
        }

        let byte_offset = (lba * self.block_size as u64) as usize;
        let remaining_bytes = self.file_data.len().saturating_sub(byte_offset);
        let read_len = buf.len().min(remaining_bytes);

        if read_len == 0 {
            return Ok(0);
        }

        // Copy from cached file data
        buf[..read_len].copy_from_slice(&self.file_data[byte_offset..byte_offset + read_len]);

        // Zero-pad remainder if needed
        if read_len < buf.len() {
            buf[read_len..].fill(0);
        }

        Ok(read_len)
    }
}
