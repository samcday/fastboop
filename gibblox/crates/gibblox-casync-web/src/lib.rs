#[cfg(target_arch = "wasm32")]
mod wasm {
    use async_trait::async_trait;
    use flate2::read::GzDecoder;
    use gibblox_casync::{CasyncChunkId, CasyncChunkStore, CasyncIndexSource};
    use gibblox_core::{GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext, ReadPriority};
    use js_sys::{Promise, Uint8Array};
    use ruzstd::decoding::StreamingDecoder;
    use std::{
        future::Future,
        io::{Cursor, Read},
        pin::Pin,
        task::{Context, Poll},
    };
    use tracing::{trace, warn};
    use url::Url;
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{
        Cache, CacheStorage, Headers, Request, RequestInit, RequestMode, Response,
        WorkerGlobalScope,
    };

    const CHUNK_SIZE_LIMIT_MIN: usize = 1;
    const CHUNK_SIZE_LIMIT_MAX: usize = 128 * 1024 * 1024;
    const COMPRESSED_SUFFIX_DEFAULT: &str = ".cacnk";

    const XZ_SIGNATURE: &[u8] = &[0xfd, b'7', b'z', b'X', b'Z', 0x00];
    const GZIP_SIGNATURE: &[u8] = &[0x1f, 0x8b];
    const ZSTD_SIGNATURE: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];

    struct SendJsFuture(JsFuture);

    unsafe impl Send for SendJsFuture {}

    struct SendJsValue(JsValue);

    unsafe impl Send for SendJsValue {}

    impl SendJsValue {
        fn as_js_value(&self) -> &JsValue {
            &self.0
        }

        fn into_js_value(self) -> JsValue {
            self.0
        }
    }

    impl From<Promise> for SendJsFuture {
        fn from(value: Promise) -> Self {
            Self(JsFuture::from(value))
        }
    }

    impl Future for SendJsFuture {
        type Output = Result<JsValue, JsValue>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            Future::poll(Pin::new(&mut self.0), cx)
        }
    }

    #[derive(Clone)]
    struct SendCache(Cache);

    unsafe impl Send for SendCache {}
    unsafe impl Sync for SendCache {}

    #[derive(Clone)]
    struct SendResponse(Response);

    unsafe impl Send for SendResponse {}
    unsafe impl Sync for SendResponse {}

    impl SendResponse {
        fn status(&self) -> u16 {
            self.0.status()
        }

        fn ok(&self) -> bool {
            self.0.ok()
        }

        fn clone_response(&self) -> GibbloxResult<SendResponse> {
            self.0
                .clone()
                .map(SendResponse)
                .map_err(js_io_with("clone response"))
        }

        fn array_buffer(&self) -> GibbloxResult<Promise> {
            self.0.array_buffer().map_err(js_io_with("array_buffer"))
        }
    }

    #[derive(Clone, Debug)]
    pub struct WebCasyncIndexSource {
        index_url: Url,
    }

    impl WebCasyncIndexSource {
        pub fn new(index_url: Url) -> Self {
            Self { index_url }
        }
    }

    #[async_trait]
    impl CasyncIndexSource for WebCasyncIndexSource {
        async fn load_index_bytes(&self) -> GibbloxResult<Vec<u8>> {
            let response = fetch_url(&self.index_url, ReadContext::FOREGROUND).await?;
            if !response.ok() {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    format!(
                        "fetch index failed with HTTP status {}: {}",
                        response.status(),
                        self.index_url
                    ),
                ));
            }

            response_to_bytes(response).await
        }
    }

    #[derive(Clone, Debug)]
    pub struct WebCasyncChunkStoreConfig {
        pub chunk_store_url: Url,
        pub cache_name: String,
        pub offline: bool,
        pub compressed_suffix: String,
    }

    impl WebCasyncChunkStoreConfig {
        pub fn new(chunk_store_url: Url) -> GibbloxResult<Self> {
            Ok(Self {
                chunk_store_url: normalize_url_prefix(chunk_store_url)?,
                cache_name: "gibblox-casync-chunks".to_string(),
                offline: false,
                compressed_suffix: COMPRESSED_SUFFIX_DEFAULT.to_string(),
            })
        }
    }

    pub struct WebCasyncChunkStore {
        chunk_store_url: Url,
        cache_name: String,
        offline: bool,
        compressed_suffix: String,
        cache: SendCache,
    }

    impl WebCasyncChunkStore {
        pub async fn new(config: WebCasyncChunkStoreConfig) -> GibbloxResult<Self> {
            if config.compressed_suffix.is_empty() || !config.compressed_suffix.starts_with('.') {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "compressed_suffix must start with '.'",
                ));
            }
            if config.cache_name.is_empty() {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "cache_name must be non-empty",
                ));
            }

            let cache = open_cache(&config.cache_name).await?;
            Ok(Self {
                chunk_store_url: config.chunk_store_url,
                cache_name: config.cache_name,
                offline: config.offline,
                compressed_suffix: config.compressed_suffix,
                cache,
            })
        }

        async fn load_cached_chunk(&self, id: &CasyncChunkId) -> GibbloxResult<Option<Vec<u8>>> {
            let compressed = id.chunk_store_path(&self.compressed_suffix);
            let raw = id.chunk_store_path("");

            let compressed_url = chunk_url(&self.chunk_store_url, &compressed)?;
            let raw_url = chunk_url(&self.chunk_store_url, &raw)?;

            if let Some(hit) = self
                .cache_match_bytes(&compressed_url, ChunkEncoding::Compressed)
                .await?
            {
                trace!(chunk = %id, cache = %self.cache_name, source = %compressed_url, bytes = hit.len(), "chunk cache hit");
                return Ok(Some(hit));
            }

            if let Some(hit) = self.cache_match_bytes(&raw_url, ChunkEncoding::Raw).await? {
                trace!(chunk = %id, cache = %self.cache_name, source = %raw_url, bytes = hit.len(), "chunk cache hit");
                return Ok(Some(hit));
            }

            Ok(None)
        }

        async fn cache_match_bytes(
            &self,
            url: &Url,
            encoding: ChunkEncoding,
        ) -> GibbloxResult<Option<Vec<u8>>> {
            let promise = {
                let request = build_request(url, ReadContext::FOREGROUND)?;
                self.cache.0.match_with_request(&request)
            };
            let value = SendJsValue(
                SendJsFuture::from(promise)
                    .await
                    .map_err(js_io_with("cache.match await"))?,
            );

            if value.as_js_value().is_undefined() || value.as_js_value().is_null() {
                return Ok(None);
            }

            let response = match value.into_js_value().dyn_into::<Response>() {
                Ok(response) => SendResponse(response),
                Err(err) => return Err(js_io_with("cache.match cast Response")(err)),
            };
            let decoded = response_to_bytes(response).await?;
            let payload = decode_chunk_payload(&decoded, encoding)?;
            validate_chunk_bounds(payload.len())?;
            Ok(Some(payload))
        }

        async fn cache_put_response(&self, url: &Url, response: SendResponse) {
            let cloned = match response.clone_response() {
                Ok(response) => response,
                Err(err) => {
                    warn!(chunk_url = %url, error = %err, "skip cache put because response clone failed");
                    return;
                }
            };

            let promise = {
                let request = match build_request(url, ReadContext::FOREGROUND) {
                    Ok(request) => request,
                    Err(err) => {
                        warn!(chunk_url = %url, error = %err, "skip cache put because request build failed");
                        return;
                    }
                };
                self.cache.0.put_with_request(&request, &cloned.0)
            };

            if let Err(err) = SendJsFuture::from(promise)
                .await
                .map_err(js_io_with("cache.put await"))
            {
                warn!(chunk_url = %url, error = %err, "cache put failed");
            }
        }

        async fn fetch_from_source(
            &self,
            id: &CasyncChunkId,
            ctx: ReadContext,
        ) -> GibbloxResult<Vec<u8>> {
            let compressed = id.chunk_store_path(&self.compressed_suffix);
            let raw = id.chunk_store_path("");
            let compressed_url = chunk_url(&self.chunk_store_url, &compressed)?;
            let raw_url = chunk_url(&self.chunk_store_url, &raw)?;

            let fetch_start = js_sys::Date::now();

            let (response, url, encoding) = match fetch_optional_url(&compressed_url, ctx).await? {
                Some(response) => (response, compressed_url, ChunkEncoding::Compressed),
                None => match fetch_optional_url(&raw_url, ctx).await? {
                    Some(response) => (response, raw_url, ChunkEncoding::Raw),
                    None => {
                        return Err(GibbloxError::with_message(
                            GibbloxErrorKind::Io,
                            format!("chunk not found in source: {id}"),
                        ));
                    }
                },
            };

            let elapsed = js_sys::Date::now() - fetch_start;
            trace!(
                chunk = %id,
                source = %url,
                priority = ?ctx.priority,
                fetch_ms = elapsed.max(0.0) as u64,
                "chunk fetched"
            );

            self.cache_put_response(&url, response.clone()).await;
            let encoded = response_to_bytes(response).await?;
            let decoded = decode_chunk_payload(&encoded, encoding)?;
            validate_chunk_bounds(decoded.len())?;
            Ok(decoded)
        }
    }

    #[async_trait]
    impl CasyncChunkStore for WebCasyncChunkStore {
        async fn load_chunk(&self, id: &CasyncChunkId, ctx: ReadContext) -> GibbloxResult<Vec<u8>> {
            if let Some(hit) = self.load_cached_chunk(id).await? {
                return Ok(hit);
            }

            trace!(chunk = %id, "chunk cache miss");
            if self.offline {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    format!("offline mode and chunk is not cached: {id}"),
                ));
            }

            self.fetch_from_source(id, ctx).await
        }
    }

    async fn open_cache(name: &str) -> GibbloxResult<SendCache> {
        let storage = cache_storage()?;
        let opened = SendJsFuture::from(storage.open(name))
            .await
            .map_err(js_io_with("caches.open await"))?;
        let cache: Cache = opened
            .dyn_into()
            .map_err(js_io_with("cast Cache from caches.open result"))?;
        Ok(SendCache(cache))
    }

    fn cache_storage() -> GibbloxResult<CacheStorage> {
        if let Some(window) = web_sys::window() {
            return window.caches().map_err(js_io_with("window.caches"));
        }
        if let Ok(worker) = js_sys::global().dyn_into::<WorkerGlobalScope>() {
            return worker.caches().map_err(js_io_with("worker.caches"));
        }

        Err(GibbloxError::with_message(
            GibbloxErrorKind::Unsupported,
            "no CacheStorage-capable web global scope",
        ))
    }

    async fn fetch_optional_url(
        url: &Url,
        ctx: ReadContext,
    ) -> GibbloxResult<Option<SendResponse>> {
        let response = fetch_url(url, ctx).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.ok() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Io,
                format!("fetch failed with HTTP status {}: {url}", response.status()),
            ));
        }
        Ok(Some(response))
    }

    async fn fetch_url(url: &Url, ctx: ReadContext) -> GibbloxResult<SendResponse> {
        let promise = {
            let request = build_request(url, ctx)?;
            fetch_with_request(&request)?
        };
        let value = SendJsValue(
            SendJsFuture::from(promise)
                .await
                .map_err(js_io_with("fetch await"))?,
        );
        js_value_into_response(value.into_js_value(), "cast fetch response")
    }

    fn fetch_with_request(request: &Request) -> GibbloxResult<Promise> {
        if let Some(window) = web_sys::window() {
            return Ok(window.fetch_with_request(request));
        }
        if let Ok(worker) = js_sys::global().dyn_into::<WorkerGlobalScope>() {
            return Ok(worker.fetch_with_request(request));
        }

        Err(GibbloxError::with_message(
            GibbloxErrorKind::Unsupported,
            "no fetch-capable web global scope",
        ))
    }

    fn build_request(url: &Url, ctx: ReadContext) -> GibbloxResult<Request> {
        let init = RequestInit::new();
        init.set_method("GET");
        init.set_mode(RequestMode::Cors);

        let headers = Headers::new().map_err(js_io_with("Headers::new"))?;
        headers
            .append("Priority", priority_header_value(ctx))
            .map_err(js_io_with("set Priority header"))?;
        init.set_headers(&headers);

        Request::new_with_str_and_init(url.as_str(), &init).map_err(js_io_with("build Request"))
    }

    async fn response_to_bytes(response: SendResponse) -> GibbloxResult<Vec<u8>> {
        let array_buffer = response.array_buffer()?;
        let buffer = SendJsFuture::from(array_buffer)
            .await
            .map_err(js_io_with("array_buffer await"))?;
        let array = Uint8Array::new(&buffer);
        let mut out = vec![0u8; array.length() as usize];
        array.copy_to(&mut out);
        Ok(out)
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

    fn decode_chunk_payload(encoded: &[u8], encoding: ChunkEncoding) -> GibbloxResult<Vec<u8>> {
        validate_chunk_bounds(encoded.len())?;

        match encoding {
            ChunkEncoding::Raw => Ok(encoded.to_vec()),
            ChunkEncoding::Compressed => decode_compressed_chunk_payload(encoded),
        }
    }

    fn decode_compressed_chunk_payload(encoded: &[u8]) -> GibbloxResult<Vec<u8>> {
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

    fn priority_header_value(ctx: ReadContext) -> &'static str {
        match ctx.priority {
            ReadPriority::High => "u=0, i",
            ReadPriority::Medium => "u=3",
            ReadPriority::Low => "u=7",
        }
    }

    fn js_io_with(op: &'static str) -> impl FnOnce(JsValue) -> GibbloxError {
        move |err| {
            GibbloxError::with_message(
                GibbloxErrorKind::Io,
                format!("{op}: {}", js_value_to_string(err)),
            )
        }
    }

    fn js_value_to_string(value: JsValue) -> String {
        js_sys::JSON::stringify(&value)
            .ok()
            .and_then(|s| s.as_string())
            .unwrap_or_else(|| format!("{value:?}"))
    }

    fn js_value_into_response(value: JsValue, op: &'static str) -> GibbloxResult<SendResponse> {
        let response: Response = value.dyn_into().map_err(js_io_with(op))?;
        Ok(SendResponse(response))
    }

    #[derive(Clone, Copy)]
    enum ChunkEncoding {
        Raw,
        Compressed,
    }

    #[derive(Clone, Copy)]
    enum CompressionKind {
        Raw,
        Gzip,
        Zstd,
        Xz,
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm::*;
