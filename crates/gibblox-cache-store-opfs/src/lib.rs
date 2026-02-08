#[cfg(not(target_arch = "wasm32"))]
use async_trait::async_trait;
#[cfg(not(target_arch = "wasm32"))]
use gibblox_cache::{CacheOps, derive_cached_reader_identity_id};
#[cfg(not(target_arch = "wasm32"))]
use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult};

#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(target_arch = "wasm32")]
pub use wasm::OpfsCacheOps;

#[cfg(not(target_arch = "wasm32"))]
pub struct OpfsCacheOps;

#[cfg(not(target_arch = "wasm32"))]
impl OpfsCacheOps {
    pub async fn open(_cache_id: u32) -> GibbloxResult<Self> {
        Err(GibbloxError::with_message(
            GibbloxErrorKind::Unsupported,
            "OpfsCacheOps is only available on wasm32",
        ))
    }

    pub async fn open_for_reader<R: BlockReader + ?Sized>(reader: &R) -> GibbloxResult<Self> {
        let total_blocks = reader.total_blocks().await?;
        let cache_id = derive_cached_reader_identity_id(reader, total_blocks);
        Self::open(cache_id).await
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl CacheOps for OpfsCacheOps {
    async fn read_at(&self, _offset: u64, _out: &mut [u8]) -> GibbloxResult<usize> {
        Err(GibbloxError::with_message(
            GibbloxErrorKind::Unsupported,
            "OpfsCacheOps is only available on wasm32",
        ))
    }

    async fn write_at(&self, _offset: u64, _data: &[u8]) -> GibbloxResult<()> {
        Err(GibbloxError::with_message(
            GibbloxErrorKind::Unsupported,
            "OpfsCacheOps is only available on wasm32",
        ))
    }

    async fn set_len(&self, _len: u64) -> GibbloxResult<()> {
        Err(GibbloxError::with_message(
            GibbloxErrorKind::Unsupported,
            "OpfsCacheOps is only available on wasm32",
        ))
    }

    async fn flush(&self) -> GibbloxResult<()> {
        Err(GibbloxError::with_message(
            GibbloxErrorKind::Unsupported,
            "OpfsCacheOps is only available on wasm32",
        ))
    }
}
