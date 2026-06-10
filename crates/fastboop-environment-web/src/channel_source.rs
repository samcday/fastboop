#[cfg(target_arch = "wasm32")]
mod wasm {
    use anyhow::{Result, anyhow};
    use gibblox_cache::CachedBlockReader;
    use gibblox_cache_store_opfs::OpfsCacheOps;
    use gibblox_casync::{CasyncBlockReader, CasyncReaderConfig};
    use gibblox_casync_web::{
        WebCasyncChunkStore, WebCasyncChunkStoreConfig, WebCasyncIndexSource,
    };
    use gibblox_core::{BlockByteReader, BlockReader};
    use gibblox_http::{HttpReader, HttpReaderConfig};
    use gibblox_zip::ZipEntryBlockReader;
    use std::sync::Arc;
    use tracing::{info, warn};
    use url::Url;

    const DEFAULT_IMAGE_BLOCK_SIZE: u32 = 512;

    pub async fn build_channel_reader_pipeline(
        channel: &str,
        channel_offset_bytes: u64,
        channel_chunk_store_url: Option<&str>,
        known_size_bytes: Option<u64>,
        cors_safelisted_mode: bool,
        cache_remote_sources: bool,
    ) -> Result<Arc<dyn BlockReader>> {
        build_channel_reader_pipeline_impl(
            channel,
            channel_offset_bytes,
            channel_chunk_store_url,
            known_size_bytes,
            cors_safelisted_mode,
            cache_remote_sources,
        )
        .await
    }

    async fn build_channel_reader_pipeline_impl(
        channel: &str,
        channel_offset_bytes: u64,
        channel_chunk_store_url: Option<&str>,
        known_size_bytes: Option<u64>,
        cors_safelisted_mode: bool,
        cache_remote_sources: bool,
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
            let reader = open_casync_reader(url, chunk_store_url, cache_remote_sources).await?;
            return super::maybe_offset_reader(reader, channel_offset_bytes).await;
        }
        if chunk_store_url.is_some() {
            return Err(anyhow!(
                "channel chunk store override is only supported with casync blob-index channels (.caibx)"
            ));
        }

        let config = if let Some(size_bytes) = known_size_bytes {
            HttpReaderConfig::with_size(url.clone(), DEFAULT_IMAGE_BLOCK_SIZE, size_bytes)
        } else {
            HttpReaderConfig::new(url.clone(), DEFAULT_IMAGE_BLOCK_SIZE)
        }
        .with_cors_safelisted_mode(cors_safelisted_mode);
        let http_reader = HttpReader::open(config)
            .await
            .map_err(|err| anyhow!("open HTTP reader {url}: {err}"))?;
        let block_reader = BlockByteReader::new(http_reader, DEFAULT_IMAGE_BLOCK_SIZE)
            .map_err(|err| anyhow!("open HTTP block view {url}: {err}"))?;
        let reader: Arc<dyn BlockReader> = Arc::new(block_reader);
        let reader = maybe_cache_remote_reader(reader, cache_remote_sources, "http").await;
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
        cache_remote_sources: bool,
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
                identity: None,
            },
        )
        .await
        .map_err(|err| anyhow!("open casync reader {index_url}: {err}"))?;
        let reader: Arc<dyn BlockReader> = Arc::new(reader);
        Ok(maybe_cache_remote_reader(reader, cache_remote_sources, "casync").await)
    }

    async fn maybe_cache_remote_reader(
        reader: Arc<dyn BlockReader>,
        cache_remote_sources: bool,
        source_kind: &str,
    ) -> Arc<dyn BlockReader> {
        if !cache_remote_sources {
            return reader;
        }

        let cache = match OpfsCacheOps::open_for_reader(&reader).await {
            Ok(cache) => cache,
            Err(err) => {
                warn!(
                    source_kind,
                    error = %err,
                    "failed to open OPFS cache for remote source; using uncached reader"
                );
                return reader;
            }
        };

        match CachedBlockReader::new(Arc::clone(&reader), cache).await {
            Ok(cached) => Arc::new(cached),
            Err(err) => {
                warn!(
                    source_kind,
                    error = %err,
                    "failed to initialize cached remote source; using uncached reader"
                );
                reader
            }
        }
    }

    pub(crate) fn parse_optional_chunk_store_url(value: Option<&str>) -> Result<Option<Url>> {
        let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        let url = Url::parse(value)
            .map_err(|err| anyhow!("parse casync chunk_store URL {value}: {err}"))?;
        Ok(Some(url))
    }

    pub(crate) fn is_casync_blob_index_url(url: &Url) -> bool {
        url.path().to_ascii_lowercase().ends_with(".caibx")
    }

    pub(crate) fn is_casync_archive_index_url(url: &Url) -> bool {
        url.path().to_ascii_lowercase().ends_with(".caidx")
    }

    pub(crate) fn derive_casync_chunk_store_url(index_url: &Url) -> Result<Url> {
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

    pub(crate) fn zip_entry_name_from_url(url: &Url) -> Result<Option<String>> {
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
use std::sync::Arc;

#[cfg(target_arch = "wasm32")]
pub(crate) async fn maybe_offset_reader(
    reader: Arc<dyn gibblox_core::BlockReader>,
    offset_bytes: u64,
) -> anyhow::Result<Arc<dyn gibblox_core::BlockReader>> {
    fastboop_core::maybe_offset_block_reader(reader, offset_bytes)
        .await
        .map_err(|err| anyhow::anyhow!(err.to_string()))
}

#[cfg(target_arch = "wasm32")]
pub use wasm::*;

#[cfg(not(target_arch = "wasm32"))]
pub async fn build_channel_reader_pipeline(
    _channel: &str,
    _channel_offset_bytes: u64,
    _channel_chunk_store_url: Option<&str>,
    _known_size_bytes: Option<u64>,
    _cors_safelisted_mode: bool,
    _cache_remote_sources: bool,
) -> anyhow::Result<std::sync::Arc<dyn gibblox_core::BlockReader>> {
    anyhow::bail!("channel reader pipeline is only available on wasm32 targets")
}
