#[cfg(target_arch = "wasm32")]
mod wasm {
    use crate::js::{current_module_script_url, js_value_to_string};
    use anyhow::{Result, anyhow};
    use gibblox_web_worker::GibbloxWebWorker;
    use web_sys::{Worker, WorkerOptions, WorkerType};

    const WORKER_NAME: &str = "fastboop-gibblox-worker";
    const LOG_LEVEL_HINT_KEY: &str = "__FASTBOOP_LOG_LEVEL";

    pub fn run_if_worker() -> bool {
        gibblox_web_worker::run_if_worker(WORKER_NAME)
    }

    pub async fn spawn_gibblox_worker(
        _channel: String,
        _channel_offset_bytes: u64,
        _channel_chunk_store_url: Option<String>,
    ) -> Result<GibbloxWebWorker> {
        let script_url = append_current_query_to_script_url(
            current_module_script_url("fastboop-web").map_err(anyhow::Error::msg)?,
        );
        tracing::info!(%script_url, "starting gibblox web worker");

        let opts = WorkerOptions::new();
        opts.set_type(WorkerType::Module);
        opts.set_name(WORKER_NAME);

        let worker = Worker::new_with_options(&script_url, &opts)
            .map_err(|err| anyhow!("start gibblox worker: {}", js_value_to_string(&err)))?;
        GibbloxWebWorker::new(worker)
            .await
            .map_err(|err| anyhow!("initialize gibblox worker: {err}"))
    }

    fn append_current_query_to_script_url(mut script_url: String) -> String {
        if script_url.contains('?') {
            return script_url;
        }
        if let Some(level) = global_log_level_hint() {
            script_url.push_str("?log=");
            script_url.push_str(level.as_str());
            return script_url;
        }
        let Some(window) = web_sys::window() else {
            return script_url;
        };
        let Ok(search) = window.location().search() else {
            return script_url;
        };
        if search.is_empty() {
            return script_url;
        }
        script_url.push_str(&search);
        script_url
    }

    fn global_log_level_hint() -> Option<String> {
        let global = js_sys::global();
        let value = js_sys::Reflect::get(
            &global,
            &wasm_bindgen::JsValue::from_str(LOG_LEVEL_HINT_KEY),
        )
        .ok()?;
        let text = value.as_string()?;
        match text.to_ascii_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => Some(text),
            _ => None,
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm::*;

#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
mod non_wasm {
    use anyhow::{Result, bail};

    pub fn run_if_worker() -> bool {
        false
    }

    pub async fn spawn_gibblox_worker(
        _channel: String,
        _channel_offset_bytes: u64,
        _channel_chunk_store_url: Option<String>,
    ) -> Result<()> {
        bail!("gibblox web worker is only available on wasm32 targets")
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use non_wasm::*;
