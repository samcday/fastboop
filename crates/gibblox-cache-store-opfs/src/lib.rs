#[cfg(not(target_arch = "wasm32"))]
use async_trait::async_trait;
#[cfg(not(target_arch = "wasm32"))]
use gibblox_cache::CacheOps;
#[cfg(not(target_arch = "wasm32"))]
use gibblox_core::{GibbloxError, GibbloxErrorKind, GibbloxResult};

#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(target_arch = "wasm32")]
pub use wasm::OpfsCacheOps;

#[cfg(not(target_arch = "wasm32"))]
pub struct OpfsCacheOps;

#[cfg(not(target_arch = "wasm32"))]
impl OpfsCacheOps {
    pub async fn open(_identity: &str) -> GibbloxResult<Self> {
        Err(GibbloxError::with_message(
            GibbloxErrorKind::Unsupported,
            "OpfsCacheOps is only available on wasm32",
        ))
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
