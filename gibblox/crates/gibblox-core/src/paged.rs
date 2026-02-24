use alloc::{boxed::Box, vec};
use core::fmt;

use tracing::{debug, trace};

use crate::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};

#[derive(Clone, Copy, Debug)]
pub struct PagedBlockConfig {
    pub page_blocks: u64,
}

impl Default for PagedBlockConfig {
    fn default() -> Self {
        Self { page_blocks: 1024 }
    }
}

pub struct PagedBlockReader<S> {
    inner: S,
    block_size: u32,
    total_blocks: u64,
    config: PagedBlockConfig,
}

impl<S> PagedBlockReader<S>
where
    S: BlockReader,
{
    pub async fn new(inner: S, config: PagedBlockConfig) -> GibbloxResult<Self> {
        if config.page_blocks == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "page_blocks must be non-zero",
            ));
        }
        let block_size = inner.block_size();
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "block size must be non-zero power of two",
            ));
        }
        let total_blocks = inner.total_blocks().await?;
        debug!(
            page_blocks = config.page_blocks,
            page_bytes = config.page_blocks.saturating_mul(block_size as u64),
            total_blocks,
            "paged block reader initialized"
        );
        Ok(Self {
            inner,
            block_size,
            total_blocks,
            config,
        })
    }

    fn blocks_from_len(&self, len: usize) -> GibbloxResult<u64> {
        if len == 0 {
            return Ok(0);
        }
        let block_size = self.block_size as usize;
        if !len.is_multiple_of(block_size) {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "buffer length must align to block size",
            ));
        }
        Ok((len / block_size) as u64)
    }

    fn validate_range(&self, lba: u64, blocks: u64) -> GibbloxResult<()> {
        let end = lba.checked_add(blocks).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
        })?;
        if end > self.total_blocks {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "requested range exceeds total blocks",
            ));
        }
        Ok(())
    }

    fn page_for_block(&self, block: u64) -> u64 {
        block / self.config.page_blocks
    }

    fn page_bounds(&self, page_idx: u64) -> GibbloxResult<(u64, u64)> {
        let start = page_idx
            .checked_mul(self.config.page_blocks)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "page overflow")
            })?;
        if start >= self.total_blocks {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "page starts past end of image",
            ));
        }
        let remaining = self.total_blocks - start;
        Ok((start, self.config.page_blocks.min(remaining)))
    }
}

#[async_trait::async_trait]
impl<S> BlockReader for PagedBlockReader<S>
where
    S: BlockReader,
{
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        Ok(self.total_blocks)
    }

    fn write_identity(&self, out: &mut dyn fmt::Write) -> fmt::Result {
        out.write_str("paged:(")?;
        self.inner.write_identity(out)?;
        out.write_str(")")
    }

    async fn read_blocks(
        &self,
        lba: u64,
        buf: &mut [u8],
        ctx: ReadContext,
    ) -> GibbloxResult<usize> {
        let blocks = self.blocks_from_len(buf.len())?;
        if blocks == 0 {
            return Ok(0);
        }
        self.validate_range(lba, blocks)?;

        let req_start = lba;
        let req_end = lba + blocks;
        let first_page = self.page_for_block(req_start);
        let last_page = self.page_for_block(req_end - 1);

        let block_size = self.block_size as usize;
        for page_idx in first_page..=last_page {
            let (page_start, page_blocks) = self.page_bounds(page_idx)?;
            let page_bytes = (page_blocks as usize)
                .checked_mul(block_size)
                .ok_or_else(|| {
                    GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "page too large")
                })?;

            let mut page_data = vec![0u8; page_bytes];
            let read = self
                .inner
                .read_blocks(page_start, &mut page_data, ctx)
                .await?;
            if read != page_data.len() {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    "inner source returned short read",
                ));
            }

            let page_end = page_start + page_blocks;
            let copy_start = req_start.max(page_start);
            let copy_end = req_end.min(page_end);
            if copy_start >= copy_end {
                continue;
            }

            let src_block_offset = (copy_start - page_start) as usize;
            let src_byte_start = src_block_offset.checked_mul(block_size).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "source offset overflow")
            })?;
            let copy_blocks = (copy_end - copy_start) as usize;
            let copy_bytes = copy_blocks.checked_mul(block_size).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "copy size overflow")
            })?;
            let src_byte_end = src_byte_start.checked_add(copy_bytes).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "source end overflow")
            })?;

            let dst_block_offset = (copy_start - req_start) as usize;
            let dst_byte_start = dst_block_offset.checked_mul(block_size).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "dest offset overflow")
            })?;
            let dst_byte_end = dst_byte_start.checked_add(copy_bytes).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "dest end overflow")
            })?;

            buf[dst_byte_start..dst_byte_end]
                .copy_from_slice(&page_data[src_byte_start..src_byte_end]);

            trace!(
                page_idx,
                page_start,
                page_blocks,
                request_start = req_start,
                request_blocks = blocks,
                copied_blocks = copy_blocks,
                "paged block reader copied request slice from page"
            );
        }

        Ok(buf.len())
    }
}
