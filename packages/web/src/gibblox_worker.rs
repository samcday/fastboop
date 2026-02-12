#[cfg(target_arch = "wasm32")]
mod wasm {
    use anyhow::{anyhow, Result};
    use gibblox_web_worker::GibbloxWebWorker;
    use js_sys::{Object, Reflect};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::spawn_local;
    use web_sys::{
        DedicatedWorkerGlobalScope, HtmlScriptElement, Worker, WorkerOptions, WorkerType,
    };

    const WORKER_NAME: &str = "fastboop-gibblox-worker";

    pub fn run_if_worker() -> bool {
        let Ok(scope) = js_sys::global().dyn_into::<DedicatedWorkerGlobalScope>() else {
            return false;
        };
        if scope.name() != WORKER_NAME {
            return false;
        }

        spawn_local(async move {
            match crate::rootfs_source::build_rootfs_reader_pipeline().await {
                Ok(reader) => GibbloxWebWorker::start_worker(scope, reader),
                Err(err) => {
                    tracing::error!(error = %err, "failed to initialize gibblox worker rootfs pipeline");
                    let _ = post_worker_error(&scope, &format!("{err:#}"));
                }
            }
        });

        true
    }

    pub async fn spawn_gibblox_worker() -> Result<GibbloxWebWorker> {
        let script_url = append_current_query_to_script_url(current_module_script_url()?);
        tracing::info!(%script_url, "starting gibblox web worker");

        let opts = WorkerOptions::new();
        opts.set_type(WorkerType::Module);
        opts.set_name(WORKER_NAME);

        let worker = Worker::new_with_options(&script_url, &opts)
            .map_err(|err| anyhow!("start gibblox worker: {}", js_value_to_string(err)))?;
        Ok(GibbloxWebWorker::new(worker))
    }

    fn post_worker_error(scope: &DedicatedWorkerGlobalScope, message: &str) -> Result<()> {
        let response = Object::new();
        set_prop(
            &response,
            "cmd",
            JsValue::from_str("error"),
            "build gibblox worker error response",
        )?;
        set_prop(
            &response,
            "error",
            JsValue::from_str(message),
            "build gibblox worker error response",
        )?;
        scope.post_message(&response.into()).map_err(|err| {
            anyhow!(
                "send gibblox worker startup error response: {}",
                js_value_to_string(err)
            )
        })
    }

    fn current_module_script_url() -> Result<String> {
        let window = web_sys::window().ok_or_else(|| anyhow!("window is unavailable"))?;
        let document = window
            .document()
            .ok_or_else(|| anyhow!("document is unavailable"))?;
        let scripts = document.scripts();

        let mut candidate = None;
        for index in 0..scripts.length() {
            let Some(script) = scripts.item(index) else {
                continue;
            };
            let Ok(script) = script.dyn_into::<HtmlScriptElement>() else {
                continue;
            };
            let src = script.src();
            if src.ends_with(".js") && src.contains("fastboop-web") {
                candidate = Some(src);
            }
        }

        candidate.ok_or_else(|| anyhow!("failed to determine fastboop web module script URL"))
    }

    fn append_current_query_to_script_url(mut script_url: String) -> String {
        if script_url.contains('?') {
            return script_url;
        }
        if let Some(level) = crate::global_log_level_hint() {
            script_url.push_str("?log=");
            script_url.push_str(match level {
                tracing::Level::TRACE => "trace",
                tracing::Level::DEBUG => "debug",
                tracing::Level::INFO => "info",
                tracing::Level::WARN => "warn",
                tracing::Level::ERROR => "error",
            });
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

    fn set_prop(target: &Object, key: &str, value: JsValue, context: &str) -> Result<()> {
        Reflect::set(target.as_ref(), &JsValue::from_str(key), &value)
            .map(|_| ())
            .map_err(|err| anyhow!("{context}: {}", js_value_to_string(err)))
    }

    fn js_value_to_string(value: JsValue) -> String {
        js_sys::JSON::stringify(&value)
            .ok()
            .and_then(|s| s.as_string())
            .unwrap_or_else(|| format!("{value:?}"))
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm::*;

#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
mod non_wasm {
    use anyhow::{bail, Result};

    pub fn run_if_worker() -> bool {
        false
    }

    pub async fn spawn_gibblox_worker() -> Result<()> {
        bail!("gibblox web worker is only available on wasm32 targets")
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_imports)]
pub use non_wasm::*;
