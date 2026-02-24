#[cfg(target_arch = "wasm32")]
mod wasm {
    use anyhow::{anyhow, Result};
    use gibblox_cache::CachedBlockReader;
    use gibblox_cache_store_opfs::OpfsCacheOps;
    use gibblox_core::BlockReader;
    use gibblox_http::HttpBlockReader;
    use gibblox_zip::ZipEntryBlockReader;
    use std::sync::Arc;
    use ui::DEFAULT_CHANNEL;
    use url::Url;

    const DEFAULT_IMAGE_BLOCK_SIZE: u32 = 512;

    pub async fn build_channel_reader_pipeline(channel: &str) -> Result<Arc<dyn BlockReader>> {
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
pub use wasm::*;

#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
pub fn build_channel_reader_pipeline(
    _channel: &str,
) -> anyhow::Result<std::sync::Arc<dyn gibblox_core::BlockReader>> {
    anyhow::bail!("channel reader pipeline is only available on wasm32 targets")
}
