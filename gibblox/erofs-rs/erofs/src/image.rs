use alloc::boxed::Box;
use alloc::sync::Arc;

use async_trait::async_trait;

use crate::Result;

#[async_trait]
pub trait ReadAt: Send + Sync {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;
}

#[async_trait]
impl ReadAt for Arc<[u8]> {
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let offset = offset as usize;
        if offset >= self.len() {
            return Ok(0);
        }
        let available = self.len() - offset;
        let read = available.min(buf.len());
        buf[..read].copy_from_slice(&self[offset..offset + read]);
        Ok(read)
    }
}
