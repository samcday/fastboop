//! HTTP-backed block source for smoo-host.
//!
//! Reads are serviced via HTTP range requests. Writes/discard are unsupported (data source is
//! treated as read-only). Designed to work on native (reqwest) and wasm32 (gloo-net/fetch).

use async_trait::async_trait;
use core::hash::Hasher;
use smoo_host_core::{
    BlockSource, BlockSourceError, BlockSourceErrorKind, BlockSourceResult, ExportIdentity,
};
use std::ops::RangeInclusive;
use tracing::debug;
use url::Url;

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(target_arch = "wasm32")]
mod wasm;

/// HTTP-backed read-only block source.
pub struct HttpBlockSource {
    url: Url,
    block_size: u32,
    size_bytes: u64,
    inner: HttpClient,
}

impl HttpBlockSource {
    /// Construct a new HTTP block source. `url` must be absolute and point to the backing object.
    pub async fn new(url: Url, block_size: u32) -> BlockSourceResult<Self> {
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "block size must be non-zero power of two",
            ));
        }
        let client = HttpClient::new()?;
        tracing::debug!(url = %url, "http block source probe");
        let size_bytes = client
            .probe_size(&url)
            .await
            .map_err(map_http_err("probe size"))?;
        Ok(Self {
            url,
            block_size,
            size_bytes,
            inner: client,
        })
    }

    /// Construct with an explicit size (skips remote probe).
    pub async fn new_with_size(
        url: Url,
        block_size: u32,
        size_bytes: u64,
    ) -> BlockSourceResult<Self> {
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "block size must be non-zero power of two",
            ));
        }
        Ok(Self {
            url,
            block_size,
            size_bytes,
            inner: HttpClient::new()?,
        })
    }

    /// Total size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    fn offset_range(&self, lba: u64, len: usize) -> BlockSourceResult<RangeInclusive<u64>> {
        if !len.is_multiple_of(self.block_size as usize) {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "buffer length must align to block size",
            ));
        }
        let start = lba.checked_mul(self.block_size as u64).ok_or_else(|| {
            BlockSourceError::with_message(BlockSourceErrorKind::OutOfRange, "lba overflow")
        })?;
        let end = start
            .checked_add(len as u64)
            .and_then(|x| x.checked_sub(1))
            .ok_or_else(|| {
                BlockSourceError::with_message(BlockSourceErrorKind::OutOfRange, "range overflow")
            })?;
        Ok(start..=end)
    }
}

#[async_trait]
impl BlockSource for HttpBlockSource {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> BlockSourceResult<u64> {
        Ok(self.size_bytes / self.block_size as u64)
    }

    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let range = self.offset_range(lba, buf.len())?;
        tracing::trace!(
            url = %self.url,
            start = *range.start(),
            end = *range.end(),
            len = buf.len(),
            "http read range"
        );
        let read = self
            .inner
            .read_range(&self.url, range.clone(), buf)
            .await
            .map_err(map_http_err("read range"))?;
        if read != buf.len() {
            debug!(
                expected = buf.len(),
                read,
                start = *range.start(),
                end = *range.end(),
                "partial HTTP read"
            );
        }
        Ok(read)
    }

    async fn write_blocks(&self, _lba: u64, _buf: &[u8]) -> BlockSourceResult<usize> {
        Err(BlockSourceError::with_message(
            BlockSourceErrorKind::Unsupported,
            "HTTP block source is read-only",
        ))
    }

    async fn flush(&self) -> BlockSourceResult<()> {
        tracing::trace!(url = %self.url, "http block source flush");
        Ok(())
    }

    async fn discard(&self, _lba: u64, _num_blocks: u32) -> BlockSourceResult<()> {
        Err(BlockSourceError::with_message(
            BlockSourceErrorKind::Unsupported,
            "HTTP block source does not support discard",
        ))
    }
}

impl ExportIdentity for HttpBlockSource {
    fn write_export_id(&self, state: &mut dyn Hasher) {
        state.write(self.url.as_str().as_bytes());
    }
}

#[derive(Clone)]
enum HttpClient {
    #[cfg(not(target_arch = "wasm32"))]
    Native(native::Client),
    #[cfg(target_arch = "wasm32")]
    Wasm(wasm::Client),
}

impl HttpClient {
    fn new() -> BlockSourceResult<Self> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(HttpClient::Native(native::Client::new()?))
        }
        #[cfg(target_arch = "wasm32")]
        {
            return Ok(HttpClient::Wasm(wasm::Client::new()?));
        }
    }

    async fn probe_size(&self, url: &Url) -> Result<u64, HttpError> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            HttpClient::Native(c) => c.probe_size(url).await,
            #[cfg(target_arch = "wasm32")]
            HttpClient::Wasm(c) => c.probe_size(url).await,
        }
    }

    async fn read_range(
        &self,
        url: &Url,
        range: RangeInclusive<u64>,
        buf: &mut [u8],
    ) -> Result<usize, HttpError> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            HttpClient::Native(c) => c.read_range(url, range, buf).await,
            #[cfg(target_arch = "wasm32")]
            HttpClient::Wasm(c) => c.read_range(url, range, buf).await,
        }
    }
}

fn map_http_err(op: &'static str) -> impl FnOnce(HttpError) -> BlockSourceError {
    move |err| BlockSourceError::with_message(BlockSourceErrorKind::Io, format!("{op}: {err}"))
}

#[derive(Debug, thiserror::Error)]
enum HttpError {
    #[error("{0}")]
    Msg(String),
}
