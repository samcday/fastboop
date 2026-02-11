#[cfg(target_arch = "wasm32")]
mod wasm {
    use async_trait::async_trait;
    use futures_channel::oneshot;
    use gibblox_core::{
        BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext, ReadPriority,
    };
    use js_sys::{Array, Object, Reflect, Uint8Array};
    use std::{
        collections::BTreeMap,
        fmt,
        sync::atomic::{AtomicBool, AtomicU32, Ordering},
        sync::{Arc, Mutex},
    };
    use tracing::trace;
    use wasm_bindgen::{JsCast, JsValue, closure::Closure};
    use web_sys::{Event, MessageEvent, MessagePort};

    type PendingMap = Arc<Mutex<BTreeMap<u32, oneshot::Sender<GibbloxResult<SendJsValue>>>>>;

    #[derive(Clone)]
    struct SendJsValue(JsValue);

    unsafe impl Send for SendJsValue {}
    unsafe impl Sync for SendJsValue {}

    impl SendJsValue {
        fn as_js_value(&self) -> &JsValue {
            &self.0
        }
    }

    pub struct MessagePortBlockReaderClient {
        port: Option<MessagePort>,
        pending: PendingMap,
        next_id: AtomicU32,
        block_size: u32,
        identity: Arc<str>,
        _on_message: Closure<dyn FnMut(MessageEvent)>,
        _on_error: Closure<dyn FnMut(Event)>,
    }

    unsafe impl Send for MessagePortBlockReaderClient {}
    unsafe impl Sync for MessagePortBlockReaderClient {}

    impl MessagePortBlockReaderClient {
        pub async fn connect(port: MessagePort) -> GibbloxResult<Self> {
            let pending: PendingMap = Arc::new(Mutex::new(BTreeMap::new()));

            let pending_for_message = pending.clone();
            let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                let data = event.data();
                let Some(id) = get_message_id(&data) else {
                    return;
                };
                let tx = pending_for_message
                    .lock()
                    .ok()
                    .and_then(|mut map| map.remove(&id));
                let Some(tx) = tx else {
                    return;
                };
                if is_ok_response(&data) {
                    let _ = tx.send(Ok(SendJsValue(data)));
                } else {
                    let _ = tx.send(Err(response_error(&data)));
                }
            });
            port.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

            let pending_for_error = pending.clone();
            let on_error = Closure::<dyn FnMut(Event)>::new(move |event: Event| {
                reject_all_pending(
                    &pending_for_error,
                    GibbloxError::with_message(
                        GibbloxErrorKind::Io,
                        format!(
                            "MessagePort transport error: {}",
                            js_value_to_string(event.into())
                        ),
                    ),
                );
            });
            port.set_onmessageerror(Some(on_error.as_ref().unchecked_ref()));
            port.start();

            let mut client = Self {
                port: Some(port),
                pending,
                next_id: AtomicU32::new(1),
                block_size: 0,
                identity: Arc::<str>::from(""),
                _on_message: on_message,
                _on_error: on_error,
            };

            let response = client.request(RpcMessage::new()?.with_op("init")?).await?;
            client.block_size = response_u32(&response, "block_size")?;
            client.identity = Arc::<str>::from(response_string(&response, "identity")?);
            if client.block_size == 0 {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "block_size must be non-zero",
                ));
            }

            Ok(client)
        }

        pub fn into_port(mut self) -> MessagePort {
            let port = self
                .port
                .take()
                .expect("MessagePortBlockReaderClient port already moved");
            port.set_onmessage(None);
            port.set_onmessageerror(None);
            reject_all_pending(
                &self.pending,
                GibbloxError::with_message(GibbloxErrorKind::Io, "MessagePort client transferred"),
            );
            port
        }

        async fn request(&self, mut message: RpcMessage) -> GibbloxResult<SendJsValue> {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            message.set_id(id)?;
            let op = Reflect::get(message.value().as_js_value(), &JsValue::from_str("op"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_else(|| "<unknown>".to_string());
            trace!(id, op = %op, "messageport client request send");

            let (tx, rx) = oneshot::channel();
            {
                let mut pending = self.pending.lock().map_err(|_| {
                    GibbloxError::with_message(
                        GibbloxErrorKind::Io,
                        "MessagePort client pending map poisoned",
                    )
                })?;
                pending.insert(id, tx);
            }

            {
                let port = self.port.as_ref().ok_or_else(|| {
                    GibbloxError::with_message(GibbloxErrorKind::Io, "MessagePort client is closed")
                })?;
                let post_result = if let Some(transfer) = message.transfer() {
                    port.post_message_with_transferable(
                        message.value().as_js_value(),
                        transfer.as_ref(),
                    )
                } else {
                    port.post_message(message.value().as_js_value())
                };
                if let Err(err) = post_result {
                    if let Ok(mut pending) = self.pending.lock() {
                        let _ = pending.remove(&id);
                    }
                    return Err(js_io(err));
                }
            }

            match rx.await {
                Ok(result) => {
                    trace!(id, op = %op, "messageport client request complete");
                    result
                }
                Err(_) => Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    "MessagePort response channel closed",
                )),
            }
        }
    }

    impl Drop for MessagePortBlockReaderClient {
        fn drop(&mut self) {
            let Some(port) = self.port.as_ref() else {
                return;
            };
            if let Ok(mut close) = RpcMessage::new().and_then(|msg| msg.with_op("close")) {
                if close.set_id(0).is_ok() {
                    let _ = port.post_message(close.value().as_js_value());
                }
            }
            port.set_onmessage(None);
            port.set_onmessageerror(None);
            port.close();
            reject_all_pending(
                &self.pending,
                GibbloxError::with_message(GibbloxErrorKind::Io, "MessagePort client dropped"),
            );
        }
    }

    #[async_trait]
    impl BlockReader for MessagePortBlockReaderClient {
        fn block_size(&self) -> u32 {
            self.block_size
        }

        async fn total_blocks(&self) -> GibbloxResult<u64> {
            let response = self
                .request(RpcMessage::new()?.with_op("total_blocks")?)
                .await?;
            response_u64_string(&response, "total_blocks")
        }

        fn write_identity(&self, out: &mut dyn fmt::Write) -> fmt::Result {
            out.write_str(self.identity.as_ref())
        }

        async fn read_blocks(
            &self,
            lba: u64,
            buf: &mut [u8],
            ctx: ReadContext,
        ) -> GibbloxResult<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let len = u32::try_from(buf.len()).map_err(|_| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "read buffer too large")
            })?;
            let response = self
                .request(
                    RpcMessage::new()?
                        .with_op("read_blocks")?
                        .with_u64_string("lba", lba)?
                        .with_u32("length", len)?
                        .with_u32("priority", read_priority_to_u32(ctx.priority))?,
                )
                .await?;
            let data = get_property(&response, "data")?;
            let bytes = Uint8Array::new(data.as_js_value());
            let read = response_u32(&response, "read")? as usize;
            if read > buf.len() || read > bytes.length() as usize {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "invalid read length in response",
                ));
            }
            bytes.subarray(0, read as u32).copy_to(&mut buf[..read]);
            Ok(read)
        }
    }

    pub struct MessagePortBlockReaderServer {
        port: MessagePort,
        closed: Arc<AtomicBool>,
        _on_message: Closure<dyn FnMut(MessageEvent)>,
        _on_error: Closure<dyn FnMut(Event)>,
    }

    unsafe impl Send for MessagePortBlockReaderServer {}
    unsafe impl Sync for MessagePortBlockReaderServer {}

    impl MessagePortBlockReaderServer {
        pub fn serve(port: MessagePort, reader: Arc<dyn BlockReader>) -> GibbloxResult<Self> {
            let closed = Arc::new(AtomicBool::new(false));

            let port_for_message = port.clone();
            let reader_for_message = reader.clone();
            let closed_for_message = closed.clone();
            let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                let data = event.data();
                let Some(id) = get_message_id(&data) else {
                    return;
                };
                let op = match get_op(&data) {
                    Ok(op) => op,
                    Err(err) => {
                        let _ = post_error_response(&port_for_message, id, err);
                        return;
                    }
                };

                let port_for_task = port_for_message.clone();
                let reader_for_task = reader_for_message.clone();
                let closed_for_task = closed_for_message.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let result = handle_server_request(reader_for_task, closed_for_task, op).await;
                    let _ = match result {
                        Ok(response) => {
                            post_response(&port_for_task, response.value(), response.transfer())
                        }
                        Err(err) => post_error_response(&port_for_task, id, err),
                    };
                });
            });
            port.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

            let on_error = Closure::<dyn FnMut(Event)>::new(move |_event: Event| {});
            port.set_onmessageerror(Some(on_error.as_ref().unchecked_ref()));
            port.start();

            Ok(Self {
                port,
                closed,
                _on_message: on_message,
                _on_error: on_error,
            })
        }

        pub fn stop(&self) {
            self.closed.store(true, Ordering::Relaxed);
            self.port.close();
        }
    }

    impl Drop for MessagePortBlockReaderServer {
        fn drop(&mut self) {
            self.closed.store(true, Ordering::Relaxed);
            self.port.set_onmessage(None);
            self.port.set_onmessageerror(None);
            self.port.close();
        }
    }

    enum RequestOp {
        Init {
            id: u32,
        },
        TotalBlocks {
            id: u32,
        },
        ReadBlocks {
            id: u32,
            lba: u64,
            length: u32,
            priority: ReadPriority,
        },
        Close {
            id: u32,
        },
    }

    async fn handle_server_request(
        reader: Arc<dyn BlockReader>,
        closed: Arc<AtomicBool>,
        op: RequestOp,
    ) -> GibbloxResult<RpcMessage> {
        match op {
            RequestOp::Init { id } => {
                let mut response = RpcMessage::new()?.with_id(id)?.with_ok(true)?;
                response = response.with_u32("block_size", reader.block_size())?;
                let mut identity = String::new();
                let _ = reader.write_identity(&mut identity);
                response = response.with_string("identity", identity)?;
                Ok(response)
            }
            RequestOp::TotalBlocks { id } => {
                let total_blocks = reader.total_blocks().await?;
                RpcMessage::new()?
                    .with_id(id)?
                    .with_ok(true)?
                    .with_u64_string("total_blocks", total_blocks)
            }
            RequestOp::ReadBlocks {
                id,
                lba,
                length,
                priority,
            } => {
                trace!(
                    id,
                    lba,
                    length,
                    ?priority,
                    "messageport server read_blocks begin"
                );
                let mut buf = vec![0u8; length as usize];
                let read = reader
                    .read_blocks(lba, &mut buf, ReadContext { priority })
                    .await?;
                trace!(id, lba, read, "messageport server read_blocks complete");
                if read > buf.len() {
                    return Err(GibbloxError::with_message(
                        GibbloxErrorKind::OutOfRange,
                        "read exceeded requested length",
                    ));
                }
                let mut response = RpcMessage::new()?.with_id(id)?.with_ok(true)?;
                response = response.with_u32(
                    "read",
                    u32::try_from(read).map_err(|_| {
                        GibbloxError::with_message(
                            GibbloxErrorKind::OutOfRange,
                            "read length exceeds u32",
                        )
                    })?,
                )?;
                response.with_bytes("data", &buf[..read])
            }
            RequestOp::Close { id } => {
                closed.store(true, Ordering::Relaxed);
                RpcMessage::new()?.with_id(id)?.with_ok(true)
            }
        }
    }

    fn get_op(data: &JsValue) -> GibbloxResult<RequestOp> {
        let id = get_message_id(data).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::InvalidInput, "missing request id")
        })?;
        let op = Reflect::get(data, &JsValue::from_str("op"))
            .map_err(js_io)?
            .as_string()
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::InvalidInput, "missing op")
            })?;
        match op.as_str() {
            "init" => Ok(RequestOp::Init { id }),
            "total_blocks" => Ok(RequestOp::TotalBlocks { id }),
            "read_blocks" => {
                let lba = parse_u64_string(data, "lba")?;
                let length = parse_u32(data, "length")?;
                let priority = read_priority_from_u32(parse_u32(data, "priority")?);
                Ok(RequestOp::ReadBlocks {
                    id,
                    lba,
                    length,
                    priority,
                })
            }
            "close" => Ok(RequestOp::Close { id }),
            _ => Err(GibbloxError::with_message(
                GibbloxErrorKind::Unsupported,
                format!("unsupported op: {op}"),
            )),
        }
    }

    fn read_priority_to_u32(priority: ReadPriority) -> u32 {
        match priority {
            ReadPriority::High => 0,
            ReadPriority::Medium => 1,
            ReadPriority::Low => 2,
        }
    }

    fn read_priority_from_u32(value: u32) -> ReadPriority {
        match value {
            1 => ReadPriority::Medium,
            2 => ReadPriority::Low,
            _ => ReadPriority::High,
        }
    }

    fn post_response(
        port: &MessagePort,
        value: &SendJsValue,
        transfer: Option<&Array>,
    ) -> GibbloxResult<()> {
        if let Some(transfer) = transfer {
            port.post_message_with_transferable(value.as_js_value(), transfer.as_ref())
                .map_err(js_io)
        } else {
            port.post_message(value.as_js_value()).map_err(js_io)
        }
    }

    fn post_error_response(port: &MessagePort, id: u32, err: GibbloxError) -> GibbloxResult<()> {
        let response = RpcMessage::new()?
            .with_id(id)?
            .with_ok(false)?
            .with_string("err", err.to_string())?;
        post_response(port, response.value(), response.transfer())
    }

    fn get_property(target: &SendJsValue, key: &str) -> GibbloxResult<SendJsValue> {
        Reflect::get(target.as_js_value(), &JsValue::from_str(key))
            .map(SendJsValue)
            .map_err(js_io)
    }

    fn response_u32(target: &SendJsValue, key: &str) -> GibbloxResult<u32> {
        let value = get_property(target, key)?;
        value
            .as_js_value()
            .as_f64()
            .and_then(f64_to_u32)
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    format!("response field {key} has invalid u32 value"),
                )
            })
    }

    fn response_u64_string(target: &SendJsValue, key: &str) -> GibbloxResult<u64> {
        let value = response_string(target, key)?;
        value.parse::<u64>().map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                format!("response field {key} has invalid u64 value"),
            )
        })
    }

    fn response_string(target: &SendJsValue, key: &str) -> GibbloxResult<String> {
        let value = get_property(target, key)?;
        value.as_js_value().as_string().ok_or_else(|| {
            GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                format!("response field {key} has invalid string value"),
            )
        })
    }

    fn get_message_id(target: &JsValue) -> Option<u32> {
        Reflect::get(target, &JsValue::from_str("id"))
            .ok()
            .and_then(|v| v.as_f64())
            .and_then(f64_to_u32)
    }

    fn parse_u32(target: &JsValue, key: &str) -> GibbloxResult<u32> {
        Reflect::get(target, &JsValue::from_str(key))
            .map_err(js_io)?
            .as_f64()
            .and_then(f64_to_u32)
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    format!("request field {key} has invalid u32 value"),
                )
            })
    }

    fn parse_u64_string(target: &JsValue, key: &str) -> GibbloxResult<u64> {
        let value = Reflect::get(target, &JsValue::from_str(key))
            .map_err(js_io)?
            .as_string()
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    format!("request field {key} has invalid string value"),
                )
            })?;
        value.parse::<u64>().map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                format!("request field {key} has invalid u64 value"),
            )
        })
    }

    fn is_ok_response(target: &JsValue) -> bool {
        Reflect::get(target, &JsValue::from_str("ok"))
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    fn response_error(target: &JsValue) -> GibbloxError {
        let message = Reflect::get(target, &JsValue::from_str("err"))
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_else(|| "remote message port error".to_string());
        GibbloxError::with_message(GibbloxErrorKind::Io, message)
    }

    fn reject_all_pending(pending: &PendingMap, err: GibbloxError) {
        let senders = if let Ok(mut map) = pending.lock() {
            let ids: Vec<u32> = map.keys().copied().collect();
            ids.into_iter()
                .filter_map(|id| map.remove(&id))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        for sender in senders {
            let _ = sender.send(Err(err.clone()));
        }
    }

    fn set_property(target: &SendJsValue, key: &str, value: &JsValue) -> GibbloxResult<()> {
        Reflect::set(target.as_js_value(), &JsValue::from_str(key), value)
            .map_err(js_io)
            .map(|_| ())
    }

    fn f64_to_u32(value: f64) -> Option<u32> {
        if value.is_finite() && value >= 0.0 && value <= u32::MAX as f64 {
            Some(value as u32)
        } else {
            None
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

    struct RpcMessage {
        value: SendJsValue,
        transfer: Option<Array>,
    }

    unsafe impl Send for RpcMessage {}
    unsafe impl Sync for RpcMessage {}

    impl RpcMessage {
        fn new() -> GibbloxResult<Self> {
            Ok(Self {
                value: SendJsValue(Object::new().into()),
                transfer: None,
            })
        }

        fn with_id(self, id: u32) -> GibbloxResult<Self> {
            self.with_u32("id", id)
        }

        fn with_ok(self, ok: bool) -> GibbloxResult<Self> {
            self.with_js("ok", JsValue::from_bool(ok))
        }

        fn with_op(self, op: &str) -> GibbloxResult<Self> {
            self.with_string("op", op)
        }

        fn with_u32(self, key: &str, value: u32) -> GibbloxResult<Self> {
            self.with_js(key, JsValue::from_f64(value as f64))
        }

        fn with_u64_string(self, key: &str, value: u64) -> GibbloxResult<Self> {
            self.with_string(key, value.to_string())
        }

        fn with_string(self, key: &str, value: impl Into<String>) -> GibbloxResult<Self> {
            self.with_js(key, JsValue::from_str(&value.into()))
        }

        fn with_bytes(self, key: &str, bytes: &[u8]) -> GibbloxResult<Self> {
            let len = u32::try_from(bytes.len()).map_err(|_| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "payload too large")
            })?;
            let payload = Uint8Array::new_with_length(len);
            payload.copy_from(bytes);
            let buffer = payload.buffer();
            let mut out = self.with_js(key, buffer.clone().into())?;
            let transfer = Array::new();
            transfer.push(&buffer);
            out.transfer = Some(transfer);
            Ok(out)
        }

        fn with_js(self, key: &str, value: JsValue) -> GibbloxResult<Self> {
            set_property(&self.value, key, &value)?;
            Ok(self)
        }

        fn set_id(&mut self, id: u32) -> GibbloxResult<()> {
            set_property(&self.value, "id", &JsValue::from_f64(id as f64))
        }

        fn value(&self) -> &SendJsValue {
            &self.value
        }

        fn transfer(&self) -> Option<&Array> {
            self.transfer.as_ref()
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm::*;
