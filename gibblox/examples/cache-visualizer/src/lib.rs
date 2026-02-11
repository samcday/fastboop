use std::cell::RefCell;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use gibblox_cache::CachedBlockReader;
use gibblox_cache_store_opfs::OpfsCacheOps;
use gibblox_http::HttpBlockReader;
use tracing::{Level, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_wasm::{WASMLayer, WASMLayerConfigBuilder};
use url::Url;
use wasm_bindgen::prelude::*;

const DEFAULT_BLOCK_SIZE: u32 = 512;
const DEFAULT_URL: &str = "https://bleeding.fastboop.win/sdm845-live-fedora/20260208.ero";

// Thread-local state for the visualizer
thread_local! {
    static VISUALIZER_STATE: RefCell<Option<VisualizerState>> = RefCell::new(None);
}

struct VisualizerState {
    reader: Arc<CachedBlockReader<HttpBlockReader, OpfsCacheOps>>,
    total_blocks: u64,
    start_time_ms: f64,
}

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    init_tracing();
    info!("cache-visualizer initialized");
}

fn init_tracing() {
    // Setup tracing with console output only
    let wasm_layer = WASMLayer::new(
        WASMLayerConfigBuilder::default()
            .set_max_level(Level::TRACE)
            .build(),
    );

    registry().with(wasm_layer).init();
}

#[wasm_bindgen]
pub async fn load_url(url: String) -> Result<(), JsValue> {
    async fn load_url_impl(url: String) -> Result<()> {
        info!("Loading URL: {}", url);

        let parsed_url = Url::parse(&url).map_err(|e| anyhow!("failed to parse URL: {}", e))?;
        info!("Parsed URL: {}", parsed_url);

        // Create HTTP block reader
        info!("Creating HTTP block reader...");
        let http_reader = HttpBlockReader::new(parsed_url.clone(), DEFAULT_BLOCK_SIZE)
            .await
            .map_err(|e| anyhow!("failed to create HTTP block reader: {}", e))?;

        let size_bytes = http_reader.size_bytes();
        let total_blocks = size_bytes / DEFAULT_BLOCK_SIZE as u64;
        info!(
            "HTTP reader created: {} bytes ({} blocks)",
            size_bytes, total_blocks
        );

        // Open OPFS cache
        info!("Opening OPFS cache...");
        let cache = OpfsCacheOps::open_for_reader(&http_reader)
            .await
            .map_err(|e| anyhow!("failed to open OPFS cache: {}", e))?;
        info!("OPFS cache opened");

        // Create cached reader
        info!("Creating cached block reader...");
        let cached = CachedBlockReader::new(http_reader, cache)
            .await
            .map_err(|e| anyhow!("failed to create cached block reader: {}", e))?;
        info!("Cached block reader created");

        let cached = Arc::new(cached);

        // Get current time
        let window = web_sys::window().ok_or_else(|| anyhow!("no window"))?;
        let performance = window
            .performance()
            .ok_or_else(|| anyhow!("no performance"))?;
        let start_time_ms = performance.now();

        // Store state
        VISUALIZER_STATE.with(|cell| {
            *cell.borrow_mut() = Some(VisualizerState {
                reader: cached,
                total_blocks,
                start_time_ms,
            });
        });

        info!("Visualizer state initialized");
        Ok(())
    }

    load_url_impl(url)
        .await
        .map_err(|e| JsValue::from_str(&format!("{:#}", e)))
}

#[wasm_bindgen]
pub fn get_default_url() -> String {
    DEFAULT_URL.to_string()
}

#[wasm_bindgen]
pub async fn get_cache_stats() -> Result<JsValue, JsValue> {
    let reader = VISUALIZER_STATE.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|state| Arc::clone(&state.reader))
    });
    let Some(reader) = reader else {
        return Ok(JsValue::NULL);
    };

    let stats = reader.get_stats().await;

    serde_wasm_bindgen::to_value(&stats)
        .map_err(|e| JsValue::from_str(&format!("failed to serialize cache stats: {}", e)))
}

#[wasm_bindgen]
pub fn get_info() -> JsValue {
    VISUALIZER_STATE.with(|cell| {
        if let Some(state) = cell.borrow().as_ref() {
            let window = web_sys::window().unwrap();
            let performance = window.performance().unwrap();
            let elapsed_ms = performance.now() - state.start_time_ms;

            let obj = js_sys::Object::new();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("totalBlocks"),
                &JsValue::from_f64(state.total_blocks as f64),
            )
            .unwrap();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("elapsedMs"),
                &JsValue::from_f64(elapsed_ms),
            )
            .unwrap();
            JsValue::from(obj)
        } else {
            JsValue::NULL
        }
    })
}
