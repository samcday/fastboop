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
    use std::rc::Rc;
    use std::sync::Arc;
    use std::time::Duration;
    use tracing::{error, info};
    use wasm_bindgen::{JsCast, JsValue, closure::Closure};
    use wasm_bindgen_futures::spawn_local;
    use web_sys::{DedicatedWorkerGlobalScope, MessageChannel, MessageEvent, MessagePort, Worker};

    const READY_TIMEOUT: Duration = Duration::from_secs(5);

    #[derive(Clone, Debug)]
    pub struct WorkerMetadata {
        pub size_bytes: u64,
        pub identity: String,
    }

    #[derive(Clone)]
    pub struct GibbloxWebWorker {
        worker: Worker,
        metadata: WorkerMetadata,
    }

    impl GibbloxWebWorker {
        pub async fn new(worker: Worker) -> GibbloxResult<Self> {
            let (ready_tx, ready_rx) = oneshot::channel::<GibbloxResult<WorkerMetadata>>();
            let ready_tx = Rc::new(RefCell::new(Some(ready_tx)));

            let ready_tx_for_message = ready_tx.clone();
            let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                let data = event.data();
                let Ok(cmd) = prop_string(&data, "cmd") else {
                    return;
                };
                match cmd.as_str() {
                    "ready" => {
                        let _ = try_send_ready_once(
                            &ready_tx_for_message,
                            parse_worker_metadata(&data).map_err(|err| {
                                GibbloxError::with_message(
                                    GibbloxErrorKind::Io,
                                    format!("gibblox worker ready payload invalid: {err}"),
                                )
                            }),
                        );
                    }
                    "error" => {
                        let message = prop_string(&data, "error")
                            .unwrap_or_else(|_| "unknown worker startup error".to_string());
                        let _ = try_send_ready_once(
                            &ready_tx_for_message,
                            Err(GibbloxError::with_message(
                                GibbloxErrorKind::Io,
                                format!("gibblox worker startup failed: {message}"),
                            )),
                        );
                    }
                    _ => {}
                }
            });
            worker.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

            let ready_tx_for_error = ready_tx.clone();
            let on_error =
                Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
                    let _ = try_send_ready_once(
                        &ready_tx_for_error,
                        Err(GibbloxError::with_message(
                            GibbloxErrorKind::Io,
                            format!(
                                "gibblox worker transport error: {}",
                                js_value_to_string(event.into())
                            ),
                        )),
                    );
                });
            worker.set_onerror(Some(on_error.as_ref().unchecked_ref()));

            let ready_future = async {
                ready_rx.await.map_err(|_| {
                    GibbloxError::with_message(
                        GibbloxErrorKind::Io,
                        "gibblox worker readiness channel closed",
                    )
                })?
            }
            .fuse();
            let timeout = sleep(READY_TIMEOUT).fuse();
            futures_util::pin_mut!(ready_future, timeout);
            let metadata = match select(ready_future, timeout).await {
                futures_util::future::Either::Left((result, _)) => result?,
                futures_util::future::Either::Right((_, _)) => {
                    worker.set_onmessage(None);
                    worker.set_onerror(None);
                    worker.terminate();
                    return Err(GibbloxError::with_message(
                        GibbloxErrorKind::Io,
                        "timed out waiting for gibblox worker ready state",
                    ));
                }
            };

            worker.set_onmessage(None);
            worker.set_onerror(None);
            drop(on_message);
            drop(on_error);

            Ok(Self { worker, metadata })
        }

        pub fn metadata(&self) -> &WorkerMetadata {
            &self.metadata
        }

        pub async fn create_reader(&self) -> GibbloxResult<MessagePortBlockReaderClient> {
            let channel = MessageChannel::new().map_err(js_io)?;
            let request = Object::new();
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

            let transfer = Array::new();
            transfer.push(channel.port2().as_ref());
            self.worker
                .post_message_with_transfer(&request.into(), transfer.as_ref())
                .map_err(js_io)?;

            MessagePortBlockReaderClient::connect(channel.port1()).await
        }

        pub fn start_worker(scope: DedicatedWorkerGlobalScope, reader: Arc<dyn BlockReader>) {
            info!("gibblox web worker mode: installing attach handler");
            let identity = block_identity_string(reader.as_ref());

            WORKER_STATE.with(|state| {
                *state.borrow_mut() = Some(WorkerState {
                    reader: reader.clone(),
                    servers: Vec::new(),
                });
            });

            let scope_for_handler = scope.clone();
            let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                let scope = scope_for_handler.clone();
                spawn_local(async move {
                    if let Err(err) = handle_worker_message(&scope, event).await {
                        error!(error = %err, "gibblox worker request failed");
                        let _ = post_error_response(&scope, &err.to_string());
                    }
                });
            });
            scope.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
            on_message.forget();

            spawn_local(async move {
                match size_bytes_for_reader(reader).await {
                    Ok(size_bytes) => {
                        let _ = post_ready_response(&scope, size_bytes, &identity);
                    }
                    Err(err) => {
                        error!(error = %err, "gibblox worker failed to compute reader metadata");
                        let _ = post_error_response(&scope, &err.to_string());
                    }
                }
            });
        }
    }

    struct WorkerState {
        reader: Arc<dyn BlockReader>,
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

                let server = MessagePortBlockReaderServer::serve(port, reader)?;
                WORKER_STATE.with(|state| {
                    if let Some(state) = state.borrow_mut().as_mut() {
                        state.servers.push(server);
                    }
                });

                Ok(())
            }
            _ => post_error_response(scope, &format!("unsupported gibblox worker command: {cmd}")),
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

    fn try_send_ready_once(
        sender: &Rc<RefCell<Option<oneshot::Sender<GibbloxResult<WorkerMetadata>>>>>,
        value: GibbloxResult<WorkerMetadata>,
    ) -> bool {
        if let Some(sender) = sender.borrow_mut().take() {
            let _ = sender.send(value);
            return true;
        }
        false
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

    fn post_ready_response(
        scope: &DedicatedWorkerGlobalScope,
        size_bytes: u64,
        identity: &str,
    ) -> GibbloxResult<()> {
        let response = Object::new();
        set_prop(
            &response,
            "cmd",
            JsValue::from_str("ready"),
            "build worker ready response",
        )?;
        set_prop(
            &response,
            "size_bytes",
            JsValue::from_str(&size_bytes.to_string()),
            "build worker ready response",
        )?;
        set_prop(
            &response,
            "identity",
            JsValue::from_str(identity),
            "build worker ready response",
        )?;
        scope.post_message(&response.into()).map_err(js_io)
    }

    fn post_error_response(scope: &DedicatedWorkerGlobalScope, message: &str) -> GibbloxResult<()> {
        let response = Object::new();
        set_prop(
            &response,
            "cmd",
            JsValue::from_str("error"),
            "build worker error response",
        )?;
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
