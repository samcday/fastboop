#[cfg(target_arch = "wasm32")]
mod wasm {
    use futures_channel::oneshot;
    use futures_util::{FutureExt, future::select};
    use gibblox_blockreader_messageport::{
        MessagePortBlockReaderClient, MessagePortBlockReaderServer,
    };
    use gibblox_core::{
        BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, block_identity_string,
    };
    use gloo_timers::future::sleep;
    use js_sys::{Array, Object, Reflect};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tracing::{error, info};
    use wasm_bindgen::{JsCast, JsValue, closure::Closure};
    use wasm_bindgen_futures::spawn_local;
    use web_sys::{DedicatedWorkerGlobalScope, MessageChannel, MessageEvent, MessagePort, Worker};

    const ATTACH_TIMEOUT: Duration = Duration::from_secs(20);

    #[derive(Clone, Debug)]
    pub struct WorkerMetadata {
        pub size_bytes: u64,
        pub identity: String,
    }

    #[derive(Clone)]
    pub struct GibbloxWebWorker {
        inner: Arc<WorkerInner>,
    }

    struct WorkerInner {
        worker: Worker,
        next_id: AtomicU32,
        pending: Arc<Mutex<BTreeMap<u32, oneshot::Sender<GibbloxResult<WorkerMetadata>>>>>,
        metadata: Arc<Mutex<Option<WorkerMetadata>>>,
        _on_message: Closure<dyn FnMut(MessageEvent)>,
        _on_error: Closure<dyn FnMut(web_sys::Event)>,
    }

    impl Drop for WorkerInner {
        fn drop(&mut self) {
            self.worker.set_onmessage(None);
            self.worker.set_onerror(None);
            self.worker.terminate();
            reject_all_pending(
                &self.pending,
                GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    "gibblox web worker dropped before attach completed",
                ),
            );
        }
    }

    impl GibbloxWebWorker {
        pub fn new(worker: Worker) -> Self {
            let pending: Arc<Mutex<BTreeMap<u32, oneshot::Sender<GibbloxResult<WorkerMetadata>>>>> =
                Arc::new(Mutex::new(BTreeMap::new()));
            let metadata = Arc::new(Mutex::new(None::<WorkerMetadata>));

            let pending_for_message = pending.clone();
            let metadata_for_message = metadata.clone();
            let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                let data = event.data();
                let Ok(cmd) = prop_string(&data, "cmd") else {
                    return;
                };
                match cmd.as_str() {
                    "ready" => {
                        if let Ok(meta) = parse_worker_metadata(&data) {
                            if let Ok(mut slot) = metadata_for_message.lock() {
                                *slot = Some(meta);
                            }
                        }
                    }
                    "attached" => {
                        let Some(id) = prop_u32(&data, "id") else {
                            return;
                        };
                        let tx = pending_for_message
                            .lock()
                            .ok()
                            .and_then(|mut map| map.remove(&id));
                        let Some(tx) = tx else {
                            return;
                        };
                        let result = parse_worker_metadata(&data);
                        if let Ok(meta) = &result {
                            if let Ok(mut slot) = metadata_for_message.lock() {
                                *slot = Some(meta.clone());
                            }
                        }
                        let _ = tx.send(result);
                    }
                    "error" => {
                        let Some(id) = prop_u32(&data, "id") else {
                            return;
                        };
                        let tx = pending_for_message
                            .lock()
                            .ok()
                            .and_then(|mut map| map.remove(&id));
                        let Some(tx) = tx else {
                            return;
                        };
                        let message = prop_string(&data, "error")
                            .unwrap_or_else(|_| "unknown worker error".to_string());
                        let _ = tx.send(Err(GibbloxError::with_message(
                            GibbloxErrorKind::Io,
                            format!("gibblox worker attach failed: {message}"),
                        )));
                    }
                    _ => {}
                }
            });
            worker.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

            let pending_for_error = pending.clone();
            let on_error =
                Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
                    reject_all_pending(
                        &pending_for_error,
                        GibbloxError::with_message(
                            GibbloxErrorKind::Io,
                            format!(
                                "gibblox worker transport error: {}",
                                js_value_to_string(event.into())
                            ),
                        ),
                    );
                });
            worker.set_onerror(Some(on_error.as_ref().unchecked_ref()));

            Self {
                inner: Arc::new(WorkerInner {
                    worker,
                    next_id: AtomicU32::new(1),
                    pending,
                    metadata,
                    _on_message: on_message,
                    _on_error: on_error,
                }),
            }
        }

        pub fn metadata(&self) -> Option<WorkerMetadata> {
            self.inner
                .metadata
                .lock()
                .ok()
                .and_then(|slot| slot.clone())
        }

        pub async fn create_reader(&self) -> GibbloxResult<MessagePortBlockReaderClient> {
            let channel = MessageChannel::new().map_err(js_io)?;
            let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
            let request = Object::new();
            set_prop(
                &request,
                "id",
                JsValue::from_f64(id as f64),
                "build attach request",
            )?;
            set_prop(
                &request,
                "cmd",
                JsValue::from_str("attach"),
                "build attach request",
            )?;
            set_prop(
                &request,
                "port",
                channel.port2().clone().into(),
                "build attach request",
            )?;

            let (tx, rx) = oneshot::channel::<GibbloxResult<WorkerMetadata>>();
            {
                let mut pending = self.inner.pending.lock().map_err(|_| {
                    GibbloxError::with_message(
                        GibbloxErrorKind::Io,
                        "gibblox worker pending map lock poisoned",
                    )
                })?;
                pending.insert(id, tx);
            }

            let transfer = Array::new();
            transfer.push(channel.port2().as_ref());
            if let Err(err) = self
                .inner
                .worker
                .post_message_with_transfer(&request.into(), transfer.as_ref())
            {
                if let Ok(mut pending) = self.inner.pending.lock() {
                    let _ = pending.remove(&id);
                }
                return Err(js_io(err));
            }

            let ack_future = async {
                rx.await.map_err(|_| {
                    GibbloxError::with_message(
                        GibbloxErrorKind::Io,
                        "gibblox worker attach response channel closed",
                    )
                })?
            }
            .fuse();
            let timeout = sleep(ATTACH_TIMEOUT).fuse();
            futures_util::pin_mut!(ack_future, timeout);
            let metadata = match select(ack_future, timeout).await {
                futures_util::future::Either::Left((result, _)) => result?,
                futures_util::future::Either::Right((_, _)) => {
                    if let Ok(mut pending) = self.inner.pending.lock() {
                        let _ = pending.remove(&id);
                    }
                    return Err(GibbloxError::with_message(
                        GibbloxErrorKind::Io,
                        "timed out waiting for gibblox worker attach response",
                    ));
                }
            };

            if let Ok(mut slot) = self.inner.metadata.lock() {
                *slot = Some(metadata);
            }

            MessagePortBlockReaderClient::connect(channel.port1()).await
        }

        pub fn start_worker(scope: DedicatedWorkerGlobalScope, reader: Arc<dyn BlockReader>) {
            info!("gibblox web worker mode: installing attach handler");
            let identity = block_identity_string(reader.as_ref());

            WORKER_STATE.with(|state| {
                *state.borrow_mut() = Some(WorkerState {
                    reader: reader.clone(),
                    identity: identity.clone(),
                    servers: Vec::new(),
                });
            });

            let scope_for_handler = scope.clone();
            let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                let scope = scope_for_handler.clone();
                spawn_local(async move {
                    if let Err(err) = handle_worker_message(&scope, event).await {
                        error!(error = %err, "gibblox worker request failed");
                        let _ = post_error_response(&scope, None, &err.to_string());
                    }
                });
            });
            scope.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
            on_message.forget();

            spawn_local(async move {
                match size_bytes_for_reader(reader).await {
                    Ok(size_bytes) => {
                        let _ = post_state_response(&scope, "ready", None, size_bytes, &identity);
                    }
                    Err(err) => {
                        error!(error = %err, "gibblox worker failed to compute reader metadata");
                        let _ = post_error_response(&scope, None, &err.to_string());
                    }
                }
            });
        }
    }

    struct WorkerState {
        reader: Arc<dyn BlockReader>,
        identity: String,
        servers: Vec<MessagePortBlockReaderServer>,
    }

    thread_local! {
        static WORKER_STATE: RefCell<Option<WorkerState>> = const { RefCell::new(None) };
    }

    async fn handle_worker_message(
        scope: &DedicatedWorkerGlobalScope,
        event: MessageEvent,
    ) -> GibbloxResult<()> {
        let data = event.data();
        let cmd = prop_string(&data, "cmd")?;
        let Some(id) = prop_u32(&data, "id") else {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "gibblox worker command missing id",
            ));
        };

        match cmd.as_str() {
            "attach" => {
                let port = extract_port(&event, &data, "attach")?;
                let reader = WORKER_STATE.with(|state| {
                    state
                        .borrow()
                        .as_ref()
                        .map(|s| s.reader.clone())
                        .ok_or_else(|| {
                            GibbloxError::with_message(
                                GibbloxErrorKind::Io,
                                "gibblox worker state not initialized",
                            )
                        })
                })?;
                let identity = WORKER_STATE.with(|state| {
                    state
                        .borrow()
                        .as_ref()
                        .map(|s| s.identity.clone())
                        .ok_or_else(|| {
                            GibbloxError::with_message(
                                GibbloxErrorKind::Io,
                                "gibblox worker state not initialized",
                            )
                        })
                })?;

                let server = MessagePortBlockReaderServer::serve(port, reader.clone())?;
                WORKER_STATE.with(|state| {
                    if let Some(state) = state.borrow_mut().as_mut() {
                        state.servers.push(server);
                    }
                });

                let size_bytes = size_bytes_for_reader(reader).await?;
                post_state_response(scope, "attached", Some(id), size_bytes, &identity)
            }
            _ => post_error_response(
                scope,
                Some(id),
                &format!("unsupported gibblox worker command: {cmd}"),
            ),
        }
    }

    async fn size_bytes_for_reader(reader: Arc<dyn BlockReader>) -> GibbloxResult<u64> {
        let total_blocks = reader.total_blocks().await?;
        total_blocks
            .checked_mul(reader.block_size() as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "size overflow")
            })
    }

    fn parse_worker_metadata(data: &JsValue) -> GibbloxResult<WorkerMetadata> {
        let size_bytes = prop_u64_string(data, "size_bytes")?;
        let identity = prop_string(data, "identity")?;
        Ok(WorkerMetadata {
            size_bytes,
            identity,
        })
    }

    fn extract_port(event: &MessageEvent, data: &JsValue, cmd: &str) -> GibbloxResult<MessagePort> {
        let ports = event.ports();
        if ports.length() != 0 {
            return ports.get(0).dyn_into::<MessagePort>().map_err(|_| {
                GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    format!("{cmd} transfer[0] is not MessagePort"),
                )
            });
        }

        Reflect::get(data, &JsValue::from_str("port"))
            .map_err(js_io)?
            .dyn_into::<MessagePort>()
            .map_err(|_| {
                GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    format!("{cmd} command missing MessagePort transfer"),
                )
            })
    }

    fn post_state_response(
        scope: &DedicatedWorkerGlobalScope,
        cmd: &str,
        id: Option<u32>,
        size_bytes: u64,
        identity: &str,
    ) -> GibbloxResult<()> {
        let response = Object::new();
        set_prop(
            &response,
            "cmd",
            JsValue::from_str(cmd),
            "build worker state response",
        )?;
        if let Some(id) = id {
            set_prop(
                &response,
                "id",
                JsValue::from_f64(id as f64),
                "build worker state response",
            )?;
        }
        set_prop(
            &response,
            "size_bytes",
            JsValue::from_str(&size_bytes.to_string()),
            "build worker state response",
        )?;
        set_prop(
            &response,
            "identity",
            JsValue::from_str(identity),
            "build worker state response",
        )?;
        scope.post_message(&response.into()).map_err(js_io)
    }

    fn post_error_response(
        scope: &DedicatedWorkerGlobalScope,
        id: Option<u32>,
        message: &str,
    ) -> GibbloxResult<()> {
        let response = Object::new();
        set_prop(
            &response,
            "cmd",
            JsValue::from_str("error"),
            "build worker error response",
        )?;
        if let Some(id) = id {
            set_prop(
                &response,
                "id",
                JsValue::from_f64(id as f64),
                "build worker error response",
            )?;
        }
        set_prop(
            &response,
            "error",
            JsValue::from_str(message),
            "build worker error response",
        )?;
        scope.post_message(&response.into()).map_err(js_io)
    }

    fn set_prop(target: &Object, key: &str, value: JsValue, context: &str) -> GibbloxResult<()> {
        Reflect::set(target.as_ref(), &JsValue::from_str(key), &value)
            .map(|_| ())
            .map_err(|err| {
                GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    format!("{context}: {}", js_value_to_string(err)),
                )
            })
    }

    fn prop_string(target: &JsValue, key: &str) -> GibbloxResult<String> {
        Reflect::get(target, &JsValue::from_str(key))
            .map_err(js_io)?
            .as_string()
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    format!("field {key} is missing or not a string"),
                )
            })
    }

    fn prop_u64_string(target: &JsValue, key: &str) -> GibbloxResult<u64> {
        let value = prop_string(target, key)?;
        value.parse::<u64>().map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                format!("field {key} has invalid u64 value"),
            )
        })
    }

    fn prop_u32(target: &JsValue, key: &str) -> Option<u32> {
        Reflect::get(target, &JsValue::from_str(key))
            .ok()
            .and_then(|value| value.as_f64())
            .and_then(|value| {
                if value.is_finite() && value >= 0.0 && value <= u32::MAX as f64 {
                    Some(value as u32)
                } else {
                    None
                }
            })
    }

    fn reject_all_pending(
        pending: &Arc<Mutex<BTreeMap<u32, oneshot::Sender<GibbloxResult<WorkerMetadata>>>>>,
        err: GibbloxError,
    ) {
        let senders = if let Ok(mut map) = pending.lock() {
            std::mem::take(&mut *map).into_values().collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        for sender in senders {
            let _ = sender.send(Err(err.clone()));
        }
    }

    fn js_io(err: JsValue) -> GibbloxError {
        GibbloxError::with_message(GibbloxErrorKind::Io, js_value_to_string(err))
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
