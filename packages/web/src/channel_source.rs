#[cfg(target_arch = "wasm32")]
mod wasm {
    use anyhow::{anyhow, Result};
    use gibblox_cache::CachedBlockReader;
    use gibblox_cache_store_opfs::OpfsCacheOps;
    use gibblox_casync::{CasyncBlockReader, CasyncReaderConfig};
    use gibblox_casync_web::{
        WebCasyncChunkStore, WebCasyncChunkStoreConfig, WebCasyncIndexSource,
    };
    use gibblox_core::BlockReader;
    use gibblox_http::HttpBlockReader;
    use gibblox_zip::ZipEntryBlockReader;
    use std::sync::Arc;
    use tracing::info;
    use url::Url;

    const DEFAULT_IMAGE_BLOCK_SIZE: u32 = 512;

    pub async fn build_channel_reader_pipeline(
        channel: &str,
        channel_offset_bytes: u64,
        channel_chunk_store_url: Option<&str>,
    ) -> Result<Arc<dyn BlockReader>> {
        let channel = channel.trim();
        if channel.is_empty() {
            return Err(anyhow!(
                "missing required channel URL for gibblox worker pipeline"
            ));
        }
        let url =
            Url::parse(channel).map_err(|err| anyhow!("parse channel URL {channel}: {err}"))?;

        if is_casync_archive_index_url(&url) {
            return Err(anyhow!(
                "casync archive indexes (.caidx) are not supported for channel block reads; provide a casync blob index (.caibx)"
            ));
        }

        let chunk_store_url = parse_optional_chunk_store_url(channel_chunk_store_url)?;
        if is_casync_blob_index_url(&url) {
            let reader = open_casync_reader(url, chunk_store_url).await?;
            return super::maybe_offset_reader(reader, channel_offset_bytes).await;
        }
        if chunk_store_url.is_some() {
            return Err(anyhow!(
                "channel chunk store override is only supported with casync blob-index channels (.caibx)"
            ));
        }

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
        let reader = super::maybe_offset_reader(reader, channel_offset_bytes).await?;
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

    async fn open_casync_reader(
        index_url: Url,
        chunk_store_url: Option<Url>,
    ) -> Result<Arc<dyn BlockReader>> {
        let chunk_store_url = match chunk_store_url {
            Some(chunk_store_url) => chunk_store_url,
            None => derive_casync_chunk_store_url(&index_url)?,
        };
        info!(
            index_url = %index_url,
            chunk_store_url = %chunk_store_url,
            "resolved casync chunk store URL"
        );

        let chunk_store_config = WebCasyncChunkStoreConfig::new(chunk_store_url.clone())
            .map_err(|err| anyhow!("configure casync chunk store URL {chunk_store_url}: {err}"))?;
        let chunk_store = WebCasyncChunkStore::new(chunk_store_config)
            .await
            .map_err(|err| anyhow!("open casync chunk store {chunk_store_url}: {err}"))?;

        let reader = CasyncBlockReader::open(
            WebCasyncIndexSource::new(index_url.clone()),
            chunk_store,
            CasyncReaderConfig {
                block_size: DEFAULT_IMAGE_BLOCK_SIZE,
                strict_verify: false,
            },
        )
        .await
        .map_err(|err| anyhow!("open casync reader {index_url}: {err}"))?;
        Ok(Arc::new(reader))
    }

    fn parse_optional_chunk_store_url(value: Option<&str>) -> Result<Option<Url>> {
        let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        let url = Url::parse(value)
            .map_err(|err| anyhow!("parse casync chunk_store URL {value}: {err}"))?;
        Ok(Some(url))
    }

    fn is_casync_blob_index_url(url: &Url) -> bool {
        url.path().to_ascii_lowercase().ends_with(".caibx")
    }

    fn is_casync_archive_index_url(url: &Url) -> bool {
        url.path().to_ascii_lowercase().ends_with(".caidx")
    }

    fn derive_casync_chunk_store_url(index_url: &Url) -> Result<Url> {
        if let Some(segments) = index_url.path_segments() {
            let segments: Vec<&str> = segments.collect();
            if let Some(index_pos) = segments.iter().rposition(|segment| *segment == "indexes") {
                let mut base_segments = segments[..=index_pos].to_vec();
                base_segments[index_pos] = "chunks";
                let mut url = index_url.clone();
                let mut path = String::from("/");
                path.push_str(&base_segments.join("/"));
                if !path.ends_with('/') {
                    path.push('/');
                }
                url.set_path(&path);
                url.set_query(None);
                url.set_fragment(None);
                return Ok(url);
            }
        }

        index_url
            .join("./")
            .map_err(|err| anyhow!("derive casync chunk store URL from {index_url}: {err}"))
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
use gibblox_core::{ByteRangeReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
#[cfg(target_arch = "wasm32")]
use std::sync::Arc;

#[cfg(target_arch = "wasm32")]
pub(crate) async fn maybe_offset_reader(
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
#[async_trait::async_trait]
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
    _channel_offset_bytes: u64,
    _channel_chunk_store_url: Option<&str>,
) -> anyhow::Result<std::sync::Arc<dyn gibblox_core::BlockReader>> {
    anyhow::bail!("channel reader pipeline is only available on wasm32 targets")
}
