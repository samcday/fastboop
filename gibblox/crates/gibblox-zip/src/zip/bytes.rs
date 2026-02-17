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
        let mut abs = offset;
        let mut out_offset = 0usize;
        let mut scratch: Option<Vec<u8>> = None;

        let head_skip = (abs % bs) as usize;
        if head_skip != 0 {
            let take = (self.block_size - head_skip).min(out.len());
            let tmp = scratch.get_or_insert_with(|| vec![0u8; self.block_size]);
            self.read_full_blocks(abs / bs, tmp, ctx).await?;
            out[..take].copy_from_slice(&tmp[head_skip..head_skip + take]);
            abs += take as u64;
            out_offset += take;
        }

        let remaining = out.len() - out_offset;
        let middle_len = remaining - (remaining % self.block_size);
        if middle_len > 0 {
            self.read_full_blocks(abs / bs, &mut out[out_offset..out_offset + middle_len], ctx)
                .await?;
            abs += middle_len as u64;
            out_offset += middle_len;
        }

        if out_offset < out.len() {
            let tail_len = out.len() - out_offset;
            let tmp = scratch.get_or_insert_with(|| vec![0u8; self.block_size]);
            self.read_full_blocks(abs / bs, tmp, ctx).await?;
            out[out_offset..].copy_from_slice(&tmp[..tail_len]);
        }

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
