use async_trait::async_trait;
use flate2::read::GzDecoder;
use gibblox_casync::{CasyncChunkId, CasyncChunkStore, CasyncIndexSource};
use gibblox_core::{GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
use reqwest::{Client, StatusCode};
use ruzstd::decoding::StreamingDecoder;
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    path::PathBuf,
    sync::Arc,
    time::Instant,
};
use tokio::sync::{Mutex, Notify};
use tracing::{trace, warn};
use url::Url;

const COMPRESSED_SUFFIX_DEFAULT: &str = ".cacnk";
const CHUNK_SIZE_LIMIT_MIN: usize = 1;
const CHUNK_SIZE_LIMIT_MAX: usize = 128 * 1024 * 1024;

const XZ_SIGNATURE: &[u8] = &[0xfd, b'7', b'z', b'X', b'Z', 0x00];
const GZIP_SIGNATURE: &[u8] = &[0x1f, 0x8b];
const ZSTD_SIGNATURE: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];

#[derive(Clone, Debug)]
pub enum StdCasyncIndexLocator {
    Url(Url),
    Path(PathBuf),
}

impl StdCasyncIndexLocator {
    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }

    pub fn url(url: Url) -> Self {
        Self::Url(url)
    }
}

pub struct StdCasyncIndexSource {
    locator: StdCasyncIndexLocator,
    client: Client,
}

impl StdCasyncIndexSource {
    pub fn new(locator: StdCasyncIndexLocator) -> GibbloxResult<Self> {
        Ok(Self {
            locator,
            client: build_http_client()?,
        })
    }

    async fn load_from_url(&self, url: &Url) -> GibbloxResult<Vec<u8>> {
        if url.scheme() == "file" {
            let path = url.to_file_path().map_err(|_| {
                GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    format!("index file URL is not a valid path: {url}"),
                )
            })?;
            return tokio::fs::read(path)
                .await
                .map_err(|err| io_err("read index file", err));
        }

        let response = self
            .client
            .get(url.as_str())
            .send()
            .await
            .map_err(|err| http_err("GET index", err))?;

        if !response.status().is_success() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Io,
                format!(
                    "GET index failed with HTTP status {}: {url}",
                    response.status()
                ),
            ));
        }

        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|err| http_err("read index body", err))
    }
}

#[async_trait]
impl CasyncIndexSource for StdCasyncIndexSource {
    async fn load_index_bytes(&self) -> GibbloxResult<Vec<u8>> {
        trace!(locator = ?self.locator, "loading casync index");
        match &self.locator {
            StdCasyncIndexLocator::Path(path) => tokio::fs::read(path)
                .await
                .map_err(|err| io_err("read index path", err)),
            StdCasyncIndexLocator::Url(url) => self.load_from_url(url).await,
        }
    }
}

#[derive(Clone, Debug)]
pub enum StdCasyncChunkStoreLocator {
    UrlPrefix(Url),
    PathPrefix(PathBuf),
}

impl StdCasyncChunkStoreLocator {
    pub fn url_prefix(url: Url) -> GibbloxResult<Self> {
        Ok(Self::UrlPrefix(normalize_url_prefix(url)?))
    }

    pub fn path_prefix(path: impl Into<PathBuf>) -> Self {
        Self::PathPrefix(path.into())
    }
}

#[derive(Clone, Debug)]
pub struct StdCasyncChunkStoreConfig {
    pub locator: StdCasyncChunkStoreLocator,
    pub cache_dir: Option<PathBuf>,
    pub offline: bool,
    pub compressed_suffix: String,
}

impl StdCasyncChunkStoreConfig {
    pub fn new(locator: StdCasyncChunkStoreLocator) -> Self {
        Self {
            locator,
            cache_dir: None,
            offline: false,
            compressed_suffix: COMPRESSED_SUFFIX_DEFAULT.to_string(),
        }
    }
}

pub struct StdCasyncChunkStore {
    locator: StdCasyncChunkStoreLocator,
    cache_dir: Option<PathBuf>,
    offline: bool,
    compressed_suffix: String,
    client: Client,
    in_flight: Mutex<BTreeMap<CasyncChunkId, Arc<Notify>>>,
}

impl StdCasyncChunkStore {
    pub fn new(config: StdCasyncChunkStoreConfig) -> GibbloxResult<Self> {
        if config.compressed_suffix.is_empty() || !config.compressed_suffix.starts_with('.') {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "compressed_suffix must start with '.'",
            ));
        }
        Ok(Self {
            locator: config.locator,
            cache_dir: config.cache_dir,
            offline: config.offline,
            compressed_suffix: config.compressed_suffix,
            client: build_http_client()?,
            in_flight: Mutex::new(BTreeMap::new()),
        })
    }

    fn cache_path_for_chunk(&self, id: &CasyncChunkId) -> Option<PathBuf> {
        self.cache_dir
            .as_ref()
            .map(|dir| dir.join(id.chunk_store_path(".raw")))
    }

    async fn load_from_cache(&self, id: &CasyncChunkId) -> GibbloxResult<Option<Vec<u8>>> {
        let Some(path) = self.cache_path_for_chunk(id) else {
            return Ok(None);
        };

        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                trace!(chunk = %id, bytes = bytes.len(), path = %path.display(), "chunk cache hit");
                Ok(Some(bytes))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(io_err("read chunk cache", err)),
        }
    }

    async fn write_to_cache(&self, id: &CasyncChunkId, payload: &[u8]) {
        let Some(path) = self.cache_path_for_chunk(id) else {
            return;
        };

        if let Some(parent) = path.parent() {
            if let Err(err) = tokio::fs::create_dir_all(parent).await {
                warn!(
                    chunk = %id,
                    path = %parent.display(),
                    error = %err,
                    "failed to create chunk cache directory"
                );
                return;
            }
        }

        if let Err(err) = tokio::fs::write(&path, payload).await {
            warn!(
                chunk = %id,
                path = %path.display(),
                error = %err,
                "failed to persist chunk in cache"
            );
        }
    }

    async fn load_from_source_locator(&self, relative: &str) -> GibbloxResult<Option<Vec<u8>>> {
        match &self.locator {
            StdCasyncChunkStoreLocator::PathPrefix(prefix) => {
                let path = prefix.join(relative);
                match tokio::fs::read(&path).await {
                    Ok(bytes) => Ok(Some(bytes)),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(err) => Err(io_err("read chunk path", err)),
                }
            }
            StdCasyncChunkStoreLocator::UrlPrefix(base) => {
                let url = chunk_url(base, relative)?;
                let response = self
                    .client
                    .get(url.as_str())
                    .send()
                    .await
                    .map_err(|err| http_err("GET chunk", err))?;

                if response.status() == StatusCode::NOT_FOUND {
                    return Ok(None);
                }
                if !response.status().is_success() {
                    return Err(GibbloxError::with_message(
                        GibbloxErrorKind::Io,
                        format!(
                            "GET chunk failed with HTTP status {}: {url}",
                            response.status()
                        ),
                    ));
                }

                response
                    .bytes()
                    .await
                    .map(|bytes| Some(bytes.to_vec()))
                    .map_err(|err| http_err("read chunk body", err))
            }
        }
    }

    async fn fetch_chunk_payload(
        &self,
        id: &CasyncChunkId,
        ctx: ReadContext,
    ) -> GibbloxResult<Vec<u8>> {
        let compressed_relative = id.chunk_store_path(&self.compressed_suffix);
        let raw_relative = id.chunk_store_path("");

        let fetch_start = Instant::now();

        let (encoded, source_kind) =
            if let Some(bytes) = self.load_from_source_locator(&compressed_relative).await? {
                (bytes, compressed_relative)
            } else if let Some(bytes) = self.load_from_source_locator(&raw_relative).await? {
                (bytes, raw_relative)
            } else {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    format!("chunk not found in source: {id}"),
                ));
            };

        trace!(
            chunk = %id,
            priority = ?ctx.priority,
            source = %source_kind,
            fetch_ms = fetch_start.elapsed().as_millis() as u64,
            encoded_bytes = encoded.len(),
            "fetched chunk payload"
        );

        let decoded = decode_chunk_payload(&encoded)?;
        validate_chunk_bounds(decoded.len())?;
        self.write_to_cache(id, &decoded).await;
        Ok(decoded)
    }

    async fn load_chunk_inner(
        &self,
        id: &CasyncChunkId,
        ctx: ReadContext,
    ) -> GibbloxResult<Vec<u8>> {
        loop {
            if let Some(hit) = self.load_from_cache(id).await? {
                return Ok(hit);
            }

            trace!(chunk = %id, "chunk cache miss");
            if self.offline {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    format!("offline mode and chunk is not cached: {id}"),
                ));
            }

            let waiter = {
                let mut guard = self.in_flight.lock().await;
                if let Some(notify) = guard.get(id) {
                    Some(Arc::clone(notify))
                } else {
                    guard.insert(*id, Arc::new(Notify::new()));
                    None
                }
            };

            if let Some(waiter) = waiter {
                waiter.notified().await;
                continue;
            }

            let result = self.fetch_chunk_payload(id, ctx).await;
            if let Some(notify) = self.in_flight.lock().await.remove(id) {
                notify.notify_waiters();
            }
            return result;
        }
    }
}

#[async_trait]
impl CasyncChunkStore for StdCasyncChunkStore {
    async fn load_chunk(&self, id: &CasyncChunkId, ctx: ReadContext) -> GibbloxResult<Vec<u8>> {
        self.load_chunk_inner(id, ctx).await
    }
}

fn normalize_url_prefix(url: Url) -> GibbloxResult<Url> {
    if url.cannot_be_a_base() {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            format!("chunk store URL cannot be a base: {url}"),
        ));
    }

    let mut value = url.as_str().to_owned();
    if !value.ends_with('/') {
        value.push('/');
    }
    Url::parse(&value).map_err(|err| {
        GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            format!("normalize chunk store URL: {err}"),
        )
    })
}

fn chunk_url(base: &Url, relative: &str) -> GibbloxResult<Url> {
    base.join(relative).map_err(|err| {
        GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            format!("join chunk URL for {relative}: {err}"),
        )
    })
}

fn build_http_client() -> GibbloxResult<Client> {
    Client::builder()
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|err| {
            GibbloxError::with_message(GibbloxErrorKind::Io, format!("build HTTP client: {err}"))
        })
}

fn detect_compression(payload: &[u8]) -> CompressionKind {
    if payload.starts_with(XZ_SIGNATURE) {
        return CompressionKind::Xz;
    }
    if payload.starts_with(GZIP_SIGNATURE) {
        return CompressionKind::Gzip;
    }
    if payload.starts_with(ZSTD_SIGNATURE) {
        return CompressionKind::Zstd;
    }
    CompressionKind::Raw
}

fn decode_chunk_payload(encoded: &[u8]) -> GibbloxResult<Vec<u8>> {
    validate_chunk_bounds(encoded.len())?;

    match detect_compression(encoded) {
        CompressionKind::Raw => Ok(encoded.to_vec()),
        CompressionKind::Gzip => decode_gzip(encoded),
        CompressionKind::Zstd => decode_zstd(encoded),
        CompressionKind::Xz => decode_xz(encoded),
    }
}

fn decode_gzip(encoded: &[u8]) -> GibbloxResult<Vec<u8>> {
    let mut decoder = GzDecoder::new(encoded);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|err| {
        GibbloxError::with_message(GibbloxErrorKind::Io, format!("decode gzip chunk: {err}"))
    })?;
    Ok(out)
}

fn decode_zstd(encoded: &[u8]) -> GibbloxResult<Vec<u8>> {
    let mut cursor = Cursor::new(encoded);
    let mut decoder = StreamingDecoder::new(&mut cursor).map_err(|err| {
        GibbloxError::with_message(GibbloxErrorKind::Io, format!("init zstd decoder: {err}"))
    })?;
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|err| {
        GibbloxError::with_message(GibbloxErrorKind::Io, format!("decode zstd chunk: {err}"))
    })?;
    Ok(out)
}

fn decode_xz(encoded: &[u8]) -> GibbloxResult<Vec<u8>> {
    let mut cursor = Cursor::new(encoded);
    let mut out = Vec::new();
    lzma_rs::xz_decompress(&mut cursor, &mut out).map_err(|err| {
        GibbloxError::with_message(GibbloxErrorKind::Io, format!("decode xz chunk: {err}"))
    })?;
    Ok(out)
}

fn validate_chunk_bounds(size: usize) -> GibbloxResult<()> {
    if !(CHUNK_SIZE_LIMIT_MIN..=CHUNK_SIZE_LIMIT_MAX).contains(&size) {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            format!("chunk size is out of bounds: {size}"),
        ));
    }
    Ok(())
}

fn io_err(op: &str, err: std::io::Error) -> GibbloxError {
    GibbloxError::with_message(GibbloxErrorKind::Io, format!("{op}: {err}"))
}

fn http_err(op: &str, err: reqwest::Error) -> GibbloxError {
    GibbloxError::with_message(GibbloxErrorKind::Io, format!("{op}: {err}"))
}

#[derive(Clone, Copy)]
enum CompressionKind {
    Raw,
    Gzip,
    Zstd,
    Xz,
}

#[cfg(test)]
mod tests {
    use super::{
        StdCasyncChunkStore, StdCasyncChunkStoreConfig, StdCasyncChunkStoreLocator,
        decode_chunk_payload,
    };
    use flate2::{Compression, write::GzEncoder};
    use gibblox_casync::{CasyncChunkId, CasyncChunkStore};
    use gibblox_core::ReadContext;
    use sha2::{Digest, Sha256};
    use std::{io::Write, path::Path};

    #[tokio::test]
    async fn path_source_populates_and_uses_cache() {
        let src = tempfile::tempdir().expect("src tempdir");
        let cache = tempfile::tempdir().expect("cache tempdir");

        let payload = b"chunk-payload".to_vec();
        let id = chunk_id_for(&payload);
        write_raw_chunk(src.path(), &id, &payload);

        let mut config = StdCasyncChunkStoreConfig::new(StdCasyncChunkStoreLocator::path_prefix(
            src.path().to_path_buf(),
        ));
        config.cache_dir = Some(cache.path().to_path_buf());
        let store = StdCasyncChunkStore::new(config).expect("build chunk store");

        let first = store
            .load_chunk(&id, ReadContext::FOREGROUND)
            .await
            .expect("first load");
        assert_eq!(first, payload);

        std::fs::remove_file(src.path().join(id.chunk_store_path("")))
            .expect("remove source chunk");
        let second = store
            .load_chunk(&id, ReadContext::FOREGROUND)
            .await
            .expect("second load from cache");
        assert_eq!(second, payload);
    }

    #[tokio::test]
    async fn offline_mode_fails_on_uncached_chunk() {
        let src = tempfile::tempdir().expect("src tempdir");
        let mut config = StdCasyncChunkStoreConfig::new(StdCasyncChunkStoreLocator::path_prefix(
            src.path().to_path_buf(),
        ));
        config.offline = true;

        let store = StdCasyncChunkStore::new(config).expect("build chunk store");
        let id = CasyncChunkId::from_bytes([0xab; 32]);

        let err = store
            .load_chunk(&id, ReadContext::FOREGROUND)
            .await
            .expect_err("offline miss should fail");
        assert_eq!(err.kind(), gibblox_core::GibbloxErrorKind::Io);
    }

    #[tokio::test]
    async fn compressed_cacnk_is_decoded_before_return() {
        let src = tempfile::tempdir().expect("src tempdir");
        let cache = tempfile::tempdir().expect("cache tempdir");

        let payload = b"hello compressed chunk".to_vec();
        let id = chunk_id_for(&payload);
        write_gzip_chunk(src.path(), &id, &payload);

        let mut config = StdCasyncChunkStoreConfig::new(StdCasyncChunkStoreLocator::path_prefix(
            src.path().to_path_buf(),
        ));
        config.cache_dir = Some(cache.path().to_path_buf());
        let store = StdCasyncChunkStore::new(config).expect("build chunk store");

        let loaded = store
            .load_chunk(&id, ReadContext::FOREGROUND)
            .await
            .expect("load compressed chunk");
        assert_eq!(loaded, payload);

        let decoded = decode_chunk_payload(&read_gzip_chunk(src.path(), &id));
        assert_eq!(decoded.expect("decode helper"), payload);
    }

    fn chunk_id_for(payload: &[u8]) -> CasyncChunkId {
        let digest = Sha256::digest(payload);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        CasyncChunkId::from_bytes(bytes)
    }

    fn write_raw_chunk(base: &Path, id: &CasyncChunkId, payload: &[u8]) {
        let relative = id.chunk_store_path("");
        let path = base.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create chunk dir");
        }
        std::fs::write(path, payload).expect("write raw chunk");
    }

    fn write_gzip_chunk(base: &Path, id: &CasyncChunkId, payload: &[u8]) {
        let relative = id.chunk_store_path(".cacnk");
        let path = base.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create chunk dir");
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).expect("encode payload");
        let encoded = encoder.finish().expect("finish gzip payload");
        std::fs::write(path, encoded).expect("write gzip chunk");
    }

    fn read_gzip_chunk(base: &Path, id: &CasyncChunkId) -> Vec<u8> {
        std::fs::read(base.join(id.chunk_store_path(".cacnk"))).expect("read gzip chunk")
    }
}
