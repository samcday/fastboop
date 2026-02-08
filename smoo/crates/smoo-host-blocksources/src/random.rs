use anyhow::ensure;
use async_trait::async_trait;
use smoo_host_core::{
    BlockSource, BlockSourceError, BlockSourceErrorKind, BlockSourceResult, ExportIdentity,
};
use std::hash::Hasher;

/// Block source that produces deterministic pseudo-random data based on a seed.
///
/// Writes are unsupported; callers can use this to exercise read paths without
/// provisioning backing storage.
pub struct RandomBlockSource {
    block_size: u32,
    blocks: u64,
    seed: u64,
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

impl RandomBlockSource {
    /// Construct a random block source.
    pub fn new(block_size: u32, total_blocks: u64, seed: u64) -> anyhow::Result<Self> {
        ensure!(
            block_size.is_power_of_two(),
            "block size must be a power of two"
        );
        ensure!(block_size > 0, "block size must be non-zero");
        ensure!(total_blocks > 0, "total_blocks must be non-zero");
        Ok(Self {
            block_size,
            blocks: total_blocks,
            seed,
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

    fn ensure_in_range(&self, lba: u64, blocks: u64) -> BlockSourceResult<()> {
        let end = lba.checked_add(blocks).ok_or_else(|| {
            BlockSourceError::with_message(BlockSourceErrorKind::OutOfRange, "lba overflow")
        })?;
        if end > self.blocks {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::OutOfRange,
                "request past end of device",
            ));
        }
        Ok(())
    }

    fn fill_block(&self, block_id: u64, buf: &mut [u8]) {
        let mut state = self.seed ^ block_id;
        for chunk in buf.chunks_mut(8) {
            state = splitmix64(state);
            let bytes = state.to_le_bytes();
            let copy_len = chunk.len();
            chunk.copy_from_slice(&bytes[..copy_len]);
        }
    }

    fn write_identity<H: Hasher + ?Sized>(&self, state: &mut H) {
        state.write_u64(self.seed);
        state.write_u64(self.blocks);
    }
}

#[async_trait]
impl BlockSource for RandomBlockSource {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> BlockSourceResult<u64> {
        Ok(self.blocks)
    }

    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        self.ensure_aligned(buf.len())?;
        if buf.is_empty() {
            return Ok(0);
        }
        let blocks = buf.len() / self.block_size as usize;
        self.ensure_in_range(lba, blocks as u64)?;

        for (idx, chunk) in buf.chunks_mut(self.block_size as usize).enumerate() {
            let block_id = lba + idx as u64;
            self.fill_block(block_id, chunk);
        }

        Ok(buf.len())
    }

    async fn write_blocks(&self, _lba: u64, _buf: &[u8]) -> BlockSourceResult<usize> {
        Err(BlockSourceError::with_message(
            BlockSourceErrorKind::Unsupported,
            "random block source is read-only",
        ))
    }
}

impl ExportIdentity for RandomBlockSource {
    fn write_export_id(&self, state: &mut dyn Hasher) {
        self.write_identity(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::RandomBlockSource;

    fn read_block(source: &RandomBlockSource, lba: u64) -> Vec<u8> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut buf = vec![0u8; source.block_size as usize];
        rt.block_on(source.read_blocks(lba, &mut buf)).unwrap();
        buf
    }

    #[test]
    fn random_source_deterministic() {
        let source = RandomBlockSource::new(512, 8, 0xdead_beef).unwrap();
        let a = read_block(&source, 0);
        let b = read_block(&source, 0);
        assert_eq!(a, b);
    }

    #[test]
    fn random_source_changes_per_block() {
        let source = RandomBlockSource::new(512, 8, 0xdead_beef).unwrap();
        let a = read_block(&source, 1);
        let b = read_block(&source, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn random_source_rejects_writes() {
        let source = RandomBlockSource::new(512, 4, 1).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(source.write_blocks(0, &[0u8; 512]))
            .unwrap_err();
        assert_eq!(err.kind(), BlockSourceErrorKind::Unsupported);
    }
}
