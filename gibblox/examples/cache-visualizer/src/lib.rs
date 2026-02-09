use std::cell::RefCell;
use std::io::Write;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use gibblox_cache::greedy::{GreedyCachedBlockReader, GreedyConfig};
use gibblox_cache::CachedBlockReader;
use gibblox_cache_store_opfs::OpfsCacheOps;
use gibblox_http::HttpBlockReader;
use tracing::{info, Level};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, registry, Layer};
use tracing_wasm::{WASMLayer, WASMLayerConfigBuilder};
use url::Url;
use wasm_bindgen::prelude::*;

const DEFAULT_BLOCK_SIZE: u32 = 512;
const DEFAULT_URL: &str = "https://bleeding.fastboop.win/sdm845-live-fedora/20260208.ero";

// Thread-local state for the visualizer
thread_local! {
    static VISUALIZER_STATE: RefCell<Option<VisualizerState>> = RefCell::new(None);
    static LOG_BUFFER: RefCell<Vec<String>> = RefCell::new(Vec::new());
}

struct VisualizerState {
    #[allow(dead_code)]
    reader: Arc<GreedyCachedBlockReader<HttpBlockReader, OpfsCacheOps>>,
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
    // Custom writer that captures logs to thread-local buffer
    struct LogCapturingWriter;

    impl Write for LogCapturingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let line = String::from_utf8_lossy(buf).into_owned();
            LOG_BUFFER.with(|cell| {
                let mut logs = cell.borrow_mut();
                logs.push(line.trim_end().to_string());
                // Keep only last 1000 lines
                if logs.len() > 1000 {
                    let excess = logs.len() - 1000;
                    logs.drain(0..excess);
                }
            });
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct LogCapturingMakeWriter;

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapturingMakeWriter {
        type Writer = LogCapturingWriter;

        fn make_writer(&'a self) -> Self::Writer {
            LogCapturingWriter
        }
    }

    // Setup tracing with both console and log capture
    let wasm_layer = WASMLayer::new(
        WASMLayerConfigBuilder::default()
            .set_max_level(Level::TRACE)
            .build(),
    );

    let fmt_layer = fmt::layer()
        .with_ansi(false)
        .without_time() // SystemTime not available in wasm32
        .with_writer(LogCapturingMakeWriter)
        .with_filter(tracing_subscriber::filter::LevelFilter::TRACE);

    registry().with(wasm_layer).with(fmt_layer).init();
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

        // Create greedy config optimized for web
        let config = GreedyConfig {
            yield_every_n_batches: Some(4), // Yield every 4 batches for cooperative multitasking
            hot_batch_size: 1024,            // ~512KB @ 512B blocks
            sweep_chunk_size: 2048,          // ~1MB @ 512B blocks
            ..Default::default()
        };
        info!("Greedy config: yield_every={:?}, hot_batch={}, sweep_chunk={}", 
            config.yield_every_n_batches, config.hot_batch_size, config.sweep_chunk_size);

        // Create greedy reader and workers
        info!("Creating greedy cached block reader...");
        let (greedy, workers) = GreedyCachedBlockReader::new(cached, config)
            .await
            .map_err(|e| anyhow!("failed to create greedy cached block reader: {}", e))?;
        info!("Greedy reader created, spawning workers...");

        // Spawn workers
        info!("Spawning hot worker...");
        wasm_bindgen_futures::spawn_local(workers.hot_worker);

        info!("Spawning 4 sweep workers...");
        for (i, worker) in workers.sweep_workers.into_iter().enumerate() {
            info!("Spawning sweep worker {}...", i);
            wasm_bindgen_futures::spawn_local(worker);
        }

        info!("All workers spawned successfully");

        // Get current time
        let window = web_sys::window().ok_or_else(|| anyhow!("no window"))?;
        let performance = window
            .performance()
            .ok_or_else(|| anyhow!("no performance"))?;
        let start_time_ms = performance.now();

        // Store state
        VISUALIZER_STATE.with(|cell| {
            *cell.borrow_mut() = Some(VisualizerState {
                reader: Arc::new(greedy),
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
pub fn get_log_lines(max: usize) -> Vec<JsValue> {
    LOG_BUFFER.with(|cell| {
        let logs = cell.borrow();
        logs.iter()
            .rev()
            .take(max)
            .map(|s| JsValue::from_str(s))
            .collect()
    })
}

#[wasm_bindgen]
pub fn get_default_url() -> String {
    DEFAULT_URL.to_string()
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
