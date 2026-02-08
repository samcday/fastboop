//! HTTP-backed read-only gibblox source.
//!
//! Reads are serviced via HTTP range requests. Designed to work on native (reqwest)
//! and wasm32 (fetch) targets.

use async_trait::async_trait;
use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
use std::ops::RangeInclusive;
use tracing::debug;
use url::Url;

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(target_arch = "wasm32")]
mod wasm;

/// HTTP-backed read-only gibblox source.
pub struct HttpBlockReader {
    url: Url,
    block_size: u32,
    size_bytes: u64,
    inner: HttpClient,
}

impl HttpBlockReader {
    /// Construct a new HTTP source. `url` must be absolute and point to the backing object.
    pub async fn new(url: Url, block_size: u32) -> GibbloxResult<Self> {
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "block size must be non-zero power of two",
            ));
        }
        let client = HttpClient::new()?;
        tracing::debug!(url = %url, "http read source probe");
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
    pub async fn new_with_size(url: Url, block_size: u32, size_bytes: u64) -> GibbloxResult<Self> {
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
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

    /// Logical block size in bytes.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    fn offset_range(&self, offset: u64, len: usize) -> GibbloxResult<RangeInclusive<u64>> {
        if len == 0 {
            return Ok(offset..=offset);
        }
        let end = offset
            .checked_add(len as u64)
            .and_then(|x| x.checked_sub(1))
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "range overflow")
            })?;
        Ok(offset..=end)
    }
}

#[async_trait]
impl BlockReader for HttpBlockReader {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        if self.block_size == 0 || !self.block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "block size must be non-zero power of two",
            ));
        }
        if !self.size_bytes.is_multiple_of(self.block_size as u64) {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "size must align to block size",
            ));
        }
        Ok(self.size_bytes / self.block_size as u64)
    }

    fn write_identity(&self, out: &mut dyn std::fmt::Write) -> std::fmt::Result {
        write!(out, "http:{}", self.url.as_str())
    }

    async fn read_blocks(
        &self,
        lba: u64,
        buf: &mut [u8],
        ctx: ReadContext,
    ) -> GibbloxResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let offset = lba.checked_mul(self.block_size as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
        })?;
        let range = self.offset_range(offset, buf.len())?;
        tracing::trace!(
            url = %self.url,
            start = *range.start(),
            end = *range.end(),
            len = buf.len(),
            "http read range"
        );
        let read = self
            .inner
            .read_range(&self.url, range.clone(), buf, ctx)
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
}

#[derive(Clone)]
enum HttpClient {
    #[cfg(not(target_arch = "wasm32"))]
    Native(native::Client),
    #[cfg(target_arch = "wasm32")]
    Wasm(wasm::Client),
}

impl HttpClient {
    fn new() -> GibbloxResult<Self> {
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
        ctx: ReadContext,
    ) -> Result<usize, HttpError> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            HttpClient::Native(c) => c.read_range(url, range, buf, ctx).await,
            #[cfg(target_arch = "wasm32")]
            HttpClient::Wasm(c) => c.read_range(url, range, buf, ctx).await,
        }
    }
}

fn map_http_err(op: &'static str) -> impl FnOnce(HttpError) -> GibbloxError {
    move |err| GibbloxError::with_message(GibbloxErrorKind::Io, format!("{op}: {err}"))
}

#[derive(Debug, thiserror::Error)]
enum HttpError {
    #[error("{0}")]
    Msg(String),
}
