#[cfg(target_arch = "wasm32")]
mod wasm {
    use anyhow::{anyhow, bail, Result};
    use futures_channel::oneshot;
    use futures_util::{future::select, FutureExt};
    use gibblox_blockreader_messageport::{
        MessagePortBlockReaderClient, MessagePortBlockReaderServer,
    };
    use gibblox_core::BlockReader;
    use gloo_timers::future::sleep;
    use js_sys::{Array, Object, Reflect};
    use std::time::Duration;
    use std::{
        cell::RefCell,
        sync::{Arc, Mutex},
    };
    use wasm_bindgen::{closure::Closure, JsCast, JsValue};
    use wasm_bindgen_futures::spawn_local;
    use web_sys::{
        DedicatedWorkerGlobalScope, HtmlScriptElement, MessageChannel, MessageEvent, MessagePort,
        Worker, WorkerOptions, WorkerType,
    };

    use fastboop_erofs_rootfs::open_erofs_rootfs;

    #[derive(Clone)]
    pub struct GibbloxWorkerLease {
        _inner: Arc<WorkerLeaseInner>,
    }

    struct WorkerLeaseInner {
        worker: Worker,
    }

    impl Drop for WorkerLeaseInner {
        fn drop(&mut self) {
            self.worker.terminate();
        }
    }

    pub struct WorkerRootfs {
        pub reader: Arc<dyn BlockReader>,
        pub size_bytes: u64,
        pub identity: String,
        pub lease: GibbloxWorkerLease,
    }

    pub fn run_if_worker() -> bool {
        let Ok(scope) = js_sys::global().dyn_into::<DedicatedWorkerGlobalScope>() else {
            return false;
        };
        tracing::info!("gibblox worker mode: installing RPC handler");
        install_worker_rpc(scope);
        true
    }

    pub async fn start_gibblox_worker_rootfs(rootfs_url: &str) -> Result<WorkerRootfs> {
        let script_url = current_module_script_url()?;
        tracing::info!(%script_url, "starting gibblox web worker");

        let opts = WorkerOptions::new();
        opts.set_type(WorkerType::Module);
        opts.set_name("fastboop-gibblox-worker");

        let worker = Worker::new_with_options(&script_url, &opts)
            .map_err(|err| anyhow!("start gibblox worker: {}", js_value_to_string(err)))?;
        let channel = MessageChannel::new().map_err(|err| {
            anyhow!(
                "create message channel for gibblox worker: {}",
                js_value_to_string(err)
            )
        })?;
        let pending_port = Arc::new(Mutex::new(Some(channel.port2())));
        let rootfs_url = rootfs_url.to_string();

        let (tx, rx) = oneshot::channel::<Result<StartAck>>();
        let tx = Arc::new(Mutex::new(Some(tx)));
        let tx_for_message = tx.clone();
        let pending_port_for_message = pending_port.clone();
        let worker_for_message = worker.clone();
        let rootfs_url_for_message = rootfs_url.clone();
        let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let data = event.data();
            let cmd = match prop_string(&data, "cmd") {
                Ok(cmd) => cmd,
                Err(_) => return,
            };
            if cmd == "ready" {
                tracing::info!("gibblox worker reported ready; sending start command");
                let port = pending_port_for_message
                    .lock()
                    .ok()
                    .and_then(|mut slot| slot.take());
                let Some(port) = port else {
                    return;
                };
                if let Err(err) =
                    send_start_command(&worker_for_message, &rootfs_url_for_message, port)
                {
                    if let Some(tx) = tx_for_message.lock().ok().and_then(|mut slot| slot.take()) {
                        let _ = tx.send(Err(err));
                    }
                }
                return;
            }
            if let Some(tx) = tx_for_message.lock().ok().and_then(|mut slot| slot.take()) {
                let _ = tx.send(parse_start_ack(data));
            }
        });
        worker.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        let tx_for_error = tx.clone();
        let on_error = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            if let Some(tx) = tx_for_error.lock().ok().and_then(|mut slot| slot.take()) {
                let _ = tx.send(Err(anyhow!(
                    "gibblox worker startup error: {}",
                    js_value_to_string(event.into())
                )));
            }
        });
        worker.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        let ack_future = async {
            rx.await
                .map_err(|_| anyhow!("gibblox worker start response channel closed"))?
        }
        .fuse();
        let timeout = sleep(Duration::from_secs(20)).fuse();
        futures_util::pin_mut!(ack_future, timeout);
        let ack = match select(ack_future, timeout).await {
            futures_util::future::Either::Left((result, _)) => result?,
            futures_util::future::Either::Right((_, _)) => {
                worker.terminate();
                bail!("timed out waiting for gibblox worker start response")
            }
        };
        worker.set_onmessage(None);
        worker.set_onerror(None);
        tracing::info!(size_bytes = ack.size_bytes, identity = %ack.identity, "gibblox worker started");

        let reader_client = MessagePortBlockReaderClient::connect(channel.port1())
            .await
            .map_err(|err| anyhow!("connect MessagePort block reader client: {err}"))?;
        let reader: Arc<dyn BlockReader> = Arc::new(reader_client);

        Ok(WorkerRootfs {
            reader,
            size_bytes: ack.size_bytes,
            identity: ack.identity,
            lease: GibbloxWorkerLease {
                _inner: Arc::new(WorkerLeaseInner { worker }),
            },
        })
    }

    struct StartAck {
        size_bytes: u64,
        identity: String,
    }

    struct WorkerState {
        _server: MessagePortBlockReaderServer,
    }

    thread_local! {
        static WORKER_STATE: RefCell<Option<WorkerState>> = const { RefCell::new(None) };
    }

    fn install_worker_rpc(scope: DedicatedWorkerGlobalScope) {
        let scope_for_handler = scope.clone();
        let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let scope = scope_for_handler.clone();
            spawn_local(async move {
                if let Err(err) = handle_worker_message(&scope, event).await {
                    tracing::error!(error = %err, "gibblox worker request failed");
                    let _ = post_error_response(&scope, &format!("{err:#}"));
                }
            });
        });
        scope.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        on_message.forget();
        if let Err(err) = post_ready_response(&scope) {
            tracing::error!(error = %err, "failed to post gibblox worker ready event");
        }
    }

    fn send_start_command(worker: &Worker, rootfs_url: &str, port: MessagePort) -> Result<()> {
        let request = Object::new();
        set_prop(
            &request,
            "cmd",
            JsValue::from_str("start"),
            "build gibblox start command",
        )?;
        set_prop(
            &request,
            "rootfs_url",
            JsValue::from_str(rootfs_url),
            "build gibblox start command",
        )?;
        set_prop(
            &request,
            "port",
            port.clone().into(),
            "build gibblox start command",
        )?;

        let transfer = Array::new();
        transfer.push(port.as_ref());
        worker
            .post_message_with_transfer(&request.into(), transfer.as_ref())
            .map_err(|err| anyhow!("send gibblox start command: {}", js_value_to_string(err)))
    }

    fn post_ready_response(scope: &DedicatedWorkerGlobalScope) -> Result<()> {
        let response = Object::new();
        set_prop(
            &response,
            "cmd",
            JsValue::from_str("ready"),
            "build gibblox ready response",
        )?;
        scope
            .post_message(&response.into())
            .map_err(|err| anyhow!("send gibblox ready response: {}", js_value_to_string(err)))
    }

    async fn handle_worker_message(
        scope: &DedicatedWorkerGlobalScope,
        event: MessageEvent,
    ) -> Result<()> {
        let data = event.data();
        let cmd = prop_string(&data, "cmd")?;
        tracing::info!(%cmd, "gibblox worker received command");
        if cmd != "start" {
            bail!("unsupported gibblox worker command: {cmd}");
        }
        if WORKER_STATE.with(|state| state.borrow().is_some()) {
            bail!("gibblox worker is already started");
        }
        let rootfs_url = prop_string(&data, "rootfs_url")?;

        let ports = event.ports();
        let port = if ports.length() != 0 {
            ports
                .get(0)
                .dyn_into::<MessagePort>()
                .map_err(|_| anyhow!("start command transfer[0] is not a MessagePort"))?
        } else {
            Reflect::get(&data, &JsValue::from_str("port"))
                .map_err(|err| anyhow!("read start.port: {}", js_value_to_string(err)))?
                .dyn_into::<MessagePort>()
                .map_err(|_| anyhow!("start command missing MessagePort transfer"))?
        };

        tracing::info!(%rootfs_url, "gibblox worker opening rootfs");
        let opened = open_erofs_rootfs(&rootfs_url).await?;
        let size_bytes = opened.size_bytes;
        let identity = opened.identity();
        let server = MessagePortBlockReaderServer::serve(port, opened.reader.clone())
            .map_err(|err| anyhow!("start MessagePort block reader server: {err}"))?;
        tracing::info!(size_bytes, identity = %identity, "gibblox worker MessagePort server ready");

        WORKER_STATE.with(|state| {
            *state.borrow_mut() = Some(WorkerState { _server: server });
        });

        post_started_response(scope, size_bytes, &identity)
    }

    fn parse_start_ack(data: JsValue) -> Result<StartAck> {
        let cmd = prop_string(&data, "cmd")?;
        match cmd.as_str() {
            "started" => {
                let size_bytes = prop_u64_string(&data, "size_bytes")?;
                let identity = prop_string(&data, "identity")?;
                Ok(StartAck {
                    size_bytes,
                    identity,
                })
            }
            "error" => {
                let message = prop_string(&data, "error")
                    .unwrap_or_else(|_| "unknown gibblox worker error".to_string());
                Err(anyhow!("gibblox worker start failed: {message}"))
            }
            _ => Err(anyhow!("unexpected gibblox worker response command: {cmd}")),
        }
    }

    fn post_started_response(
        scope: &DedicatedWorkerGlobalScope,
        size_bytes: u64,
        identity: &str,
    ) -> Result<()> {
        let response = Object::new();
        set_prop(
            &response,
            "cmd",
            JsValue::from_str("started"),
            "build gibblox started response",
        )?;
        set_prop(
            &response,
            "size_bytes",
            JsValue::from_str(&size_bytes.to_string()),
            "build gibblox started response",
        )?;
        set_prop(
            &response,
            "identity",
            JsValue::from_str(identity),
            "build gibblox started response",
        )?;
        scope
            .post_message(&response.into())
            .map_err(|err| anyhow!("send gibblox started response: {}", js_value_to_string(err)))
    }

    fn post_error_response(scope: &DedicatedWorkerGlobalScope, message: &str) -> Result<()> {
        let response = Object::new();
        set_prop(
            &response,
            "cmd",
            JsValue::from_str("error"),
            "build gibblox error response",
        )?;
        set_prop(
            &response,
            "error",
            JsValue::from_str(message),
            "build gibblox error response",
        )?;
        scope
            .post_message(&response.into())
            .map_err(|err| anyhow!("send gibblox error response: {}", js_value_to_string(err)))
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

    fn set_prop(target: &Object, key: &str, value: JsValue, context: &str) -> Result<()> {
        Reflect::set(target.as_ref(), &JsValue::from_str(key), &value)
            .map(|_| ())
            .map_err(|err| anyhow!("{context}: {}", js_value_to_string(err)))
    }

    fn prop_string(target: &JsValue, key: &str) -> Result<String> {
        Reflect::get(target, &JsValue::from_str(key))
            .map_err(|err| anyhow!("read response field {key}: {}", js_value_to_string(err)))?
            .as_string()
            .ok_or_else(|| anyhow!("field {key} is missing or not a string"))
    }

    fn prop_u64_string(target: &JsValue, key: &str) -> Result<u64> {
        let value = prop_string(target, key)?;
        value
            .parse::<u64>()
            .map_err(|_| anyhow!("field {key} has invalid u64 value"))
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
    use gibblox_core::BlockReader;
    use std::sync::Arc;

    #[derive(Clone)]
    pub struct GibbloxWorkerLease;

    pub struct WorkerRootfs {
        pub reader: Arc<dyn BlockReader>,
        pub size_bytes: u64,
        pub identity: String,
        pub lease: GibbloxWorkerLease,
    }

    pub fn run_if_worker() -> bool {
        false
    }

    pub async fn start_gibblox_worker_rootfs(_rootfs_url: &str) -> Result<WorkerRootfs> {
        bail!("gibblox worker rootfs is only available on wasm32 targets")
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_imports)]
pub use non_wasm::*;
