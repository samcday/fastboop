#[cfg(target_arch = "wasm32")]
mod wasm {
    use anyhow::{anyhow, Result};
    use async_trait::async_trait;
    use gibblox_cache::CachedBlockReader;
    use gibblox_cache_store_opfs::OpfsCacheOps;
    use gibblox_core::{
        AsyncRead, BlockReader, ByteRangeReader, GibbloxError, GibbloxErrorKind, GibbloxResult,
        ReadContext,
    };
    use gibblox_http::HttpBlockReader;
    use gibblox_zip::ZipEntryBlockReader;
    use std::sync::Arc;
    use ui::DEFAULT_CHANNEL;
    use url::Url;

    const DEFAULT_IMAGE_BLOCK_SIZE: u32 = 512;

    pub async fn build_channel_reader_pipeline(
        channel: &str,
        channel_offset_bytes: u64,
    ) -> Result<Arc<dyn BlockReader>> {
        let channel = channel.trim();
        let channel = if channel.is_empty() {
            DEFAULT_CHANNEL
        } else {
            channel
        };
        let url =
            Url::parse(channel).map_err(|err| anyhow!("parse channel URL {channel}: {err}"))?;
        let http_reader = HttpBlockReader::new(url.clone(), DEFAULT_IMAGE_BLOCK_SIZE)
            .await
            .map_err(|err| anyhow!("open HTTP reader {url}: {err}"))?;
        let cache = OpfsCacheOps::open_for_reader(&http_reader)
            .await
            .map_err(|err| anyhow!("open OPFS cache: {err}"))?;
        let cached = CachedBlockReader::new(http_reader, cache)
            .await
            .map_err(|err| anyhow!("initialize OPFS cache: {err}"))?;
        let reader: Arc<dyn BlockReader> = Arc::new(cached);
        let reader = maybe_offset_reader(reader, channel_offset_bytes).await?;
        let reader: Arc<dyn BlockReader> = match zip_entry_name_from_url(&url)? {
            Some(entry_name) => {
                let zip_reader = ZipEntryBlockReader::new(&entry_name, reader)
                    .await
                    .map_err(|err| anyhow!("open ZIP entry {entry_name}: {err}"))?;
                Arc::new(zip_reader)
            }
            None => reader,
        };
        Ok(reader)
    }

    fn zip_entry_name_from_url(url: &Url) -> Result<Option<String>> {
        let file_name = url
            .path_segments()
            .and_then(|segments| segments.filter(|segment| !segment.is_empty()).next_back());
        zip_entry_name_from_file_name(file_name)
    }

    fn zip_entry_name_from_file_name(file_name: Option<&str>) -> Result<Option<String>> {
        let Some(file_name) = file_name else {
            return Ok(None);
        };
        if !file_name.to_ascii_lowercase().ends_with(".zip") {
            return Ok(None);
        }

        let stem = &file_name[..file_name.len() - 4];
        if stem.is_empty() {
            return Err(anyhow!("zip artifact name must include a filename stem"));
        }
        Ok(Some(format!("{stem}.ero")))
    }
}

#[cfg(target_arch = "wasm32")]
async fn maybe_offset_reader(
    reader: Arc<dyn gibblox_core::BlockReader>,
    offset_bytes: u64,
) -> anyhow::Result<Arc<dyn gibblox_core::BlockReader>> {
    if offset_bytes == 0 {
        return Ok(reader);
    }

    let total_size_bytes = reader
        .total_blocks()
        .await
        .map_err(|err| anyhow::anyhow!("read channel total blocks for offset reader: {err}"))?
        .checked_mul(reader.block_size() as u64)
        .ok_or_else(|| anyhow::anyhow!("channel total size overflow"))?;

    Ok(Arc::new(OffsetChannelBlockReader::new(
        reader,
        offset_bytes,
        total_size_bytes,
    )?))
}

#[cfg(target_arch = "wasm32")]
struct OffsetChannelBlockReader {
    inner: Arc<dyn gibblox_core::BlockReader>,
    offset_bytes: u64,
    size_bytes: u64,
    inner_size_bytes: u64,
    block_size: u32,
}

#[cfg(target_arch = "wasm32")]
impl OffsetChannelBlockReader {
    fn new(
        inner: Arc<dyn gibblox_core::BlockReader>,
        offset_bytes: u64,
        inner_size_bytes: u64,
    ) -> anyhow::Result<Self> {
        let block_size = inner.block_size();
        if block_size == 0 {
            anyhow::bail!("channel reader block size is zero");
        }
        if offset_bytes > inner_size_bytes {
            anyhow::bail!(
                "channel reader stream offset {} exceeds source size {}",
                offset_bytes,
                inner_size_bytes
            );
        }

        Ok(Self {
            inner,
            offset_bytes,
            size_bytes: inner_size_bytes
                .checked_sub(offset_bytes)
                .ok_or_else(|| anyhow::anyhow!("channel stream offset underflow"))?,
            inner_size_bytes,
            block_size,
        })
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait]
impl gibblox_core::BlockReader for OffsetChannelBlockReader {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        let block_size = u64::from(self.block_size);
        if block_size == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "channel reader block size is zero",
            ));
        }
        Ok(self.size_bytes.div_ceil(block_size))
    }

    fn write_identity(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.inner.write_identity(out)?;
        write!(out, "|offset:{}", self.offset_bytes)
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

        let local_offset = lba.checked_mul(u64::from(self.block_size)).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "channel read offset overflow")
        })?;
        if local_offset >= self.size_bytes {
            return Ok(0);
        }

        let remaining = self.size_bytes.checked_sub(local_offset).ok_or_else(|| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "channel read offset underflow",
            )
        })?;
        let max_read = core::cmp::min(buf.len() as u64, remaining) as usize;
        let global_offset = self.offset_bytes.checked_add(local_offset).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "channel read offset overflow")
        })?;

        let byte_reader = ByteRangeReader::new(
            self.inner.clone(),
            self.block_size as usize,
            self.inner_size_bytes,
        );
        byte_reader
            .read_exact_at(global_offset, &mut buf[..max_read], ctx)
            .await?;
        Ok(max_read)
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm::*;

#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
pub fn build_channel_reader_pipeline(
    _channel: &str,
) -> anyhow::Result<std::sync::Arc<dyn gibblox_core::BlockReader>> {
    anyhow::bail!("channel reader pipeline is only available on wasm32 targets")
}
