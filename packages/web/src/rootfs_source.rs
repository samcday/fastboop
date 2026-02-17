#[cfg(target_arch = "wasm32")]
mod wasm {
    use anyhow::{anyhow, Result};
    use gibblox_cache::CachedBlockReader;
    use gibblox_cache_store_opfs::OpfsCacheOps;
    use gibblox_core::BlockReader;
    use gibblox_http::HttpBlockReader;
    use std::sync::Arc;
    use ui::DEFAULT_ROOTFS_ARTIFACT;
    use url::Url;

    const DEFAULT_IMAGE_BLOCK_SIZE: u32 = 512;

    pub async fn build_rootfs_reader_pipeline(
        rootfs_artifact: &str,
    ) -> Result<Arc<dyn BlockReader>> {
        let rootfs_artifact = rootfs_artifact.trim();
        let rootfs_artifact = if rootfs_artifact.is_empty() {
            DEFAULT_ROOTFS_ARTIFACT
        } else {
            rootfs_artifact
        };
        let url = Url::parse(rootfs_artifact)
            .map_err(|err| anyhow!("parse rootfs URL {rootfs_artifact}: {err}"))?;
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
#[allow(dead_code)]
pub fn build_rootfs_reader_pipeline(
    _rootfs_artifact: &str,
) -> anyhow::Result<std::sync::Arc<dyn gibblox_core::BlockReader>> {
    anyhow::bail!("rootfs reader pipeline is only available on wasm32 targets")
}
