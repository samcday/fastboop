#[cfg(target_arch = "wasm32")]
mod wasm {
    use anyhow::{anyhow, Result};
    use gibblox_cache::CachedBlockReader;
    use gibblox_cache_store_opfs::OpfsCacheOps;
    use gibblox_core::BlockReader;
    use gibblox_http::HttpBlockReader;
    use std::sync::Arc;
    use url::Url;

    const DEFAULT_IMAGE_BLOCK_SIZE: u32 = 512;
    pub const ROOTFS_URL: &str = "https://bleeding.fastboop.win/sdm845-live-fedora/20260208.ero";

    pub async fn build_rootfs_reader_pipeline() -> Result<Arc<dyn BlockReader>> {
        let url = Url::parse(ROOTFS_URL)
            .map_err(|err| anyhow!("parse rootfs URL {ROOTFS_URL}: {err}"))?;
        let http_reader = HttpBlockReader::new(url.clone(), DEFAULT_IMAGE_BLOCK_SIZE)
            .await
            .map_err(|err| anyhow!("open HTTP reader {url}: {err}"))?;
        let cache = OpfsCacheOps::open_for_reader(&http_reader)
            .await
            .map_err(|err| anyhow!("open OPFS cache: {err}"))?;
        let cached = CachedBlockReader::new(http_reader, cache)
            .await
            .map_err(|err| anyhow!("initialize OPFS cache: {err}"))?;
        Ok(Arc::new(cached))
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm::*;

#[cfg(not(target_arch = "wasm32"))]
pub const ROOTFS_URL: &str = "https://bleeding.fastboop.win/sdm845-live-fedora/20260208.ero";
