use async_trait::async_trait;
use futures_channel::oneshot;
use gibblox_cache::{CacheOps, derive_cached_reader_identity_id};
use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult};
use js_sys::{Array, Object, Reflect, Uint8Array};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU32, Ordering},
    sync::{Arc, Mutex},
};
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsCast, closure::Closure};
use web_sys::{Blob, BlobPropertyBag, Event, MessageEvent, Url, Worker};

const JS_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
const WORKER_SCRIPT: &str = r#"
let accessHandle = null;

function toErrorMessage(err) {
  if (err && typeof err.message === "string") {
    return err.message;
  }
  try {
    return String(err);
  } catch (_) {
    return "unknown worker error";
  }
}

async function openHandle(cacheId) {
  const root = await navigator.storage.getDirectory();
  const dir = await root.getDirectoryHandle("gibblox", { create: true });
  const name = `${cacheId.toString(16).padStart(8, "0")}.bin`;
  const file = await dir.getFileHandle(name, { create: true });
  accessHandle = await file.createSyncAccessHandle();
}

self.onmessage = async (event) => {
  const msg = event.data || {};
  const id = msg.id;
  try {
    switch (msg.op) {
      case "open": {
        if (accessHandle) {
          accessHandle.close();
          accessHandle = null;
        }
        await openHandle(msg.cache_id >>> 0);
        self.postMessage({ id, ok: true });
        break;
      }
      case "read_at": {
        if (!accessHandle) {
          throw new Error("cache file not open");
        }
        const length = msg.length >>> 0;
        const data = new ArrayBuffer(length);
        const view = new Uint8Array(data);
        const read = accessHandle.read(view, { at: Number(msg.offset) });
        self.postMessage({ id, ok: true, read, data }, [data]);
        break;
      }
      case "write_at": {
        if (!accessHandle) {
          throw new Error("cache file not open");
        }
        const view = new Uint8Array(msg.data);
        let written = 0;
        const baseOffset = Number(msg.offset);
        while (written < view.length) {
          const n = accessHandle.write(view.subarray(written), { at: baseOffset + written });
          if (n <= 0) {
            throw new Error("short write to OPFS sync handle");
          }
          written += n;
        }
        self.postMessage({ id, ok: true });
        break;
      }
      case "set_len": {
        if (!accessHandle) {
          throw new Error("cache file not open");
        }
        const target = Number(msg.length);
        const current = accessHandle.getSize();
        if (target < current) {
          accessHandle.truncate(target);
        }
        self.postMessage({ id, ok: true });
        break;
      }
      case "flush": {
        if (!accessHandle) {
          throw new Error("cache file not open");
        }
        accessHandle.flush();
        self.postMessage({ id, ok: true });
        break;
      }
      case "close": {
        if (accessHandle) {
          accessHandle.flush();
          accessHandle.close();
          accessHandle = null;
        }
        self.postMessage({ id, ok: true });
        break;
      }
      default:
        throw new Error(`unknown op ${msg.op}`);
    }
  } catch (err) {
    self.postMessage({ id, ok: false, err: toErrorMessage(err) });
  }
};
"#;

/// OPFS-backed cache file implementation for wasm web targets.
pub struct OpfsCacheOps {
    worker: Arc<OpfsWorkerClient>,
}

impl OpfsCacheOps {
    /// Open or create an OPFS cache file under the `gibblox` origin-private directory.
    pub async fn open(cache_id: u32) -> GibbloxResult<Self> {
        let worker = OpfsWorkerClient::new()?;
        let message = RpcMessage::new()?
            .with_op("open")?
            .with_u64("cache_id", cache_id as u64)?;
        worker.request(message).await?;
        Ok(Self {
            worker: Arc::new(worker),
        })
    }

    pub async fn open_for_reader<R: BlockReader + ?Sized>(reader: &R) -> GibbloxResult<Self> {
        let total_blocks = reader.total_blocks().await?;
        let cache_id = derive_cached_reader_identity_id(reader, total_blocks);
        Self::open(cache_id).await
    }
}

#[derive(Clone)]
struct SendJsValue(JsValue);

unsafe impl Send for SendJsValue {}
unsafe impl Sync for SendJsValue {}

impl SendJsValue {
    fn as_js_value(&self) -> &JsValue {
        &self.0
    }
}

type PendingMap = Arc<Mutex<BTreeMap<u32, oneshot::Sender<GibbloxResult<SendJsValue>>>>>;

struct OpfsWorkerClient {
    worker: Worker,
    pending: PendingMap,
    next_id: AtomicU32,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_error: Closure<dyn FnMut(Event)>,
}

unsafe impl Send for OpfsWorkerClient {}
unsafe impl Sync for OpfsWorkerClient {}

impl OpfsWorkerClient {
    fn new() -> GibbloxResult<Self> {
        let parts = Array::new();
        parts.push(&JsValue::from_str(WORKER_SCRIPT));

        let bag = BlobPropertyBag::new();
        bag.set_type("text/javascript");
        let blob = Blob::new_with_str_sequence_and_options(&parts, &bag).map_err(js_io)?;
        let url = Url::create_object_url_with_blob(&blob).map_err(js_io)?;
        let worker = Worker::new(&url).map_err(js_io)?;
        Url::revoke_object_url(&url).map_err(js_io)?;

        let pending: PendingMap = Arc::new(Mutex::new(BTreeMap::new()));

        let pending_for_message = Arc::clone(&pending);
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
                let message = response_error_message(&data);
                let _ = tx.send(Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    message,
                )));
            }
        });
        worker.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        let pending_for_error = Arc::clone(&pending);
        let on_error = Closure::<dyn FnMut(Event)>::new(move |event: Event| {
            let message = js_value_to_string(event.into());
            reject_all_pending(
                &pending_for_error,
                GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    format!("OPFS worker error: {message}"),
                ),
            );
        });
        worker.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        Ok(Self {
            worker,
            pending,
            next_id: AtomicU32::new(1),
            _on_message: on_message,
            _on_error: on_error,
        })
    }

    async fn request(&self, mut message: RpcMessage) -> GibbloxResult<SendJsValue> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        message.set_id(id)?;

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().map_err(|_| {
                GibbloxError::with_message(GibbloxErrorKind::Io, "OPFS worker state poisoned")
            })?;
            pending.insert(id, tx);
        }

        {
            let post_result = if let Some(transfer) = message.transfer() {
                self.worker
                    .post_message_with_transfer(message.value().as_js_value(), transfer.as_ref())
            } else {
                self.worker.post_message(message.value().as_js_value())
            };
            if let Err(err) = post_result {
                let mut pending = self.pending.lock().map_err(|_| {
                    GibbloxError::with_message(GibbloxErrorKind::Io, "OPFS worker state poisoned")
                })?;
                let _ = pending.remove(&id);
                return Err(js_io(err));
            }
        }

        match rx.await {
            Ok(result) => result,
            Err(_) => Err(GibbloxError::with_message(
                GibbloxErrorKind::Io,
                "OPFS worker channel closed",
            )),
        }
    }
}

impl Drop for OpfsWorkerClient {
    fn drop(&mut self) {
        let mut close = match RpcMessage::new().and_then(|msg| msg.with_op("close")) {
            Ok(message) => message,
            Err(_) => {
                self.worker.terminate();
                return;
            }
        };
        if close.set_id(0).is_ok() {
            let _ = self.worker.post_message(close.value().as_js_value());
        }
        self.worker.terminate();
    }
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

    fn with_op(self, op: &str) -> GibbloxResult<Self> {
        self.with_js("op", JsValue::from_str(op))
    }

    fn with_u64(self, key: &str, value: u64) -> GibbloxResult<Self> {
        let value = to_js_number(value, key)?;
        set_property(&self.value, key, &JsValue::from_f64(value))?;
        Ok(self)
    }

    fn with_bytes(self, key: &str, bytes: &[u8]) -> GibbloxResult<Self> {
        let data_len = u32::try_from(bytes.len()).map_err(|_| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "write payload too large")
        })?;
        let payload = Uint8Array::new_with_length(data_len);
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

#[async_trait]
impl CacheOps for OpfsCacheOps {
    async fn read_at(&self, offset: u64, out: &mut [u8]) -> GibbloxResult<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        let (bytes, read) = read_at_opfs(self.worker.as_ref(), offset, out.len() as u64).await?;
        let copy_len = out.len().min(read);
        bytes
            .subarray(0, copy_len as u32)
            .copy_to(&mut out[..copy_len]);
        Ok(copy_len)
    }

    async fn write_at(&self, offset: u64, data: &[u8]) -> GibbloxResult<()> {
        if data.is_empty() {
            return Ok(());
        }
        write_at_opfs(self.worker.as_ref(), offset, data).await
    }

    async fn set_len(&self, len: u64) -> GibbloxResult<()> {
        truncate_opfs(self.worker.as_ref(), len).await
    }

    async fn flush(&self) -> GibbloxResult<()> {
        flush_opfs(self.worker.as_ref()).await
    }
}

async fn read_at_opfs(
    worker: &OpfsWorkerClient,
    offset: u64,
    len: u64,
) -> GibbloxResult<(Uint8Array, usize)> {
    let _ = to_js_number(offset, "offset")?;
    let _ = to_js_number(len, "length")?;
    let _ = offset.checked_add(len).ok_or_else(|| {
        GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "read range overflow")
    })?;

    let request = RpcMessage::new()?
        .with_op("read_at")?
        .with_u64("offset", offset)?
        .with_u64("length", len)?;
    let response = worker.request(request).await?;
    let array_buffer = get_property(&response, "data")?;
    let bytes = Uint8Array::new(array_buffer.as_js_value());
    let read = get_property(&response, "read")?
        .as_js_value()
        .as_f64()
        .ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::Io, "OPFS worker read has invalid type")
        })?;
    if !(0.0..=len as f64).contains(&read) {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            "OPFS worker read exceeds requested length",
        ));
    }
    Ok((bytes, read as usize))
}

async fn write_at_opfs(worker: &OpfsWorkerClient, offset: u64, bytes: &[u8]) -> GibbloxResult<()> {
    let request = RpcMessage::new()?
        .with_op("write_at")?
        .with_u64("offset", offset)?
        .with_bytes("data", bytes)?;
    worker.request(request).await?;
    Ok(())
}

async fn truncate_opfs(worker: &OpfsWorkerClient, len: u64) -> GibbloxResult<()> {
    let request = RpcMessage::new()?
        .with_op("set_len")?
        .with_u64("length", len)?;
    worker.request(request).await?;
    Ok(())
}

async fn flush_opfs(worker: &OpfsWorkerClient) -> GibbloxResult<()> {
    let request = RpcMessage::new()?.with_op("flush")?;
    worker.request(request).await?;
    Ok(())
}

fn get_property(target: &SendJsValue, key: &str) -> GibbloxResult<SendJsValue> {
    Reflect::get(target.as_js_value(), &JsValue::from_str(key))
        .map(SendJsValue)
        .map_err(js_io)
}

fn get_message_id(target: &JsValue) -> Option<u32> {
    Reflect::get(target, &JsValue::from_str("id"))
        .ok()
        .and_then(|v| v.as_f64())
        .and_then(|v| {
            if v.is_finite() && v >= 0.0 && v <= u32::MAX as f64 {
                Some(v as u32)
            } else {
                None
            }
        })
}

fn is_ok_response(target: &JsValue) -> bool {
    Reflect::get(target, &JsValue::from_str("ok"))
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn response_error_message(target: &JsValue) -> String {
    Reflect::get(target, &JsValue::from_str("err"))
        .ok()
        .map(js_value_to_string)
        .unwrap_or_else(|| "unknown OPFS worker failure".to_string())
}

fn reject_all_pending(pending: &PendingMap, err: GibbloxError) {
    let senders = if let Ok(mut pending) = pending.lock() {
        pending
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<u32>>()
            .into_iter()
            .filter_map(|id| pending.remove(&id))
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

fn to_js_number(value: u64, label: &str) -> GibbloxResult<f64> {
    if value > JS_SAFE_INTEGER_MAX {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            format!("{label} exceeds JavaScript safe integer"),
        ));
    }
    Ok(value as f64)
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
