extern crate alloc;

use alloc::{format, sync::Arc, vec, vec::Vec};
use gibblox_core::{BlockReader, ReadContext};

use super::{ZipError, ZipResult};

#[derive(Clone)]
pub(crate) struct ByteReader {
    inner: Arc<dyn BlockReader>,
    block_size: usize,
    size_bytes: u64,
}

impl ByteReader {
    pub(crate) fn new(inner: Arc<dyn BlockReader>, block_size: usize, size_bytes: u64) -> Self {
        Self {
            inner,
            block_size,
            size_bytes,
        }
    }

    pub(crate) async fn read_vec_at(
        &self,
        offset: u64,
        len: usize,
        ctx: ReadContext,
    ) -> ZipResult<Vec<u8>> {
        let mut out = vec![0u8; len];
        self.read_exact_at(offset, &mut out, ctx).await?;
        Ok(out)
    }

    pub(crate) async fn read_exact_at(
        &self,
        offset: u64,
        out: &mut [u8],
        ctx: ReadContext,
    ) -> ZipResult<()> {
        if out.is_empty() {
            return Ok(());
        }

        let end = offset
            .checked_add(out.len() as u64)
            .ok_or_else(|| ZipError::out_of_range("zip byte read range overflow"))?;
        if end > self.size_bytes {
            return Err(ZipError::out_of_range("zip byte read exceeds source size"));
        }

        let bs = self.block_size as u64;
        if (offset % bs) == 0 && out.len().is_multiple_of(self.block_size) {
            self.read_full_blocks(offset / bs, out, ctx).await?;
            return Ok(());
        }

        let start_lba = offset / bs;
        let start_skip = (offset % bs) as usize;
        let aligned_end = end.div_ceil(bs);
        let aligned_blocks = aligned_end.saturating_sub(start_lba);
        let aligned_blocks_usize = usize::try_from(aligned_blocks)
            .map_err(|_| ZipError::out_of_range("zip aligned read too large"))?;
        let aligned_len = aligned_blocks_usize
            .checked_mul(self.block_size)
            .ok_or_else(|| ZipError::out_of_range("zip aligned read size overflow"))?;

        let mut scratch = vec![0u8; aligned_len];
        self.read_full_blocks(start_lba, &mut scratch, ctx).await?;
        let end_skip = start_skip
            .checked_add(out.len())
            .ok_or_else(|| ZipError::out_of_range("zip aligned slice overflow"))?;
        out.copy_from_slice(&scratch[start_skip..end_skip]);

        Ok(())
    }

    async fn read_full_blocks(&self, lba: u64, out: &mut [u8], ctx: ReadContext) -> ZipResult<()> {
        if out.is_empty() {
            return Ok(());
        }
        if !out.len().is_multiple_of(self.block_size) {
            return Err(ZipError::invalid_input(
                "internal zip read requested unaligned buffer",
            ));
        }

        let read =
            self.inner.read_blocks(lba, out, ctx).await.map_err(|err| {
                ZipError::new(err.kind(), format!("zip source read failed: {err}"))
            })?;
        if read != out.len() {
            return Err(ZipError::io(format!(
                "zip source returned short read: expected {}, got {read}",
                out.len()
            )));
        }
        Ok(())
    }
}
