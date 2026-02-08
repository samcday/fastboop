use async_trait::async_trait;
use gibblox_cache::{CacheOps, cache_file_name};
use gibblox_core::{GibbloxError, GibbloxErrorKind, GibbloxResult};
use js_sys::{Promise, Uint8Array};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

const JS_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;

#[wasm_bindgen(inline_js = r#"
export async function gibbloxOpfsOpen(name) {
  const root = await navigator.storage.getDirectory();
  const dir = await root.getDirectoryHandle("gibblox", { create: true });
  return await dir.getFileHandle(name, { create: true });
}

export async function gibbloxOpfsReadAt(handle, offset, len) {
  const start = Number(offset);
  const size = Number(len);
  const file = await handle.getFile();
  const blob = file.slice(start, start + size);
  const buffer = await blob.arrayBuffer();
  return new Uint8Array(buffer);
}

export async function gibbloxOpfsWriteAt(handle, offset, bytes) {
  const stream = await handle.createWritable({ keepExistingData: true });
  await stream.seek(Number(offset));
  await stream.write(bytes);
  await stream.close();
}

export async function gibbloxOpfsSetLen(handle, len) {
  const stream = await handle.createWritable({ keepExistingData: true });
  await stream.truncate(Number(len));
  await stream.close();
}

export async function gibbloxOpfsFlush(_handle) {
  return;
}
"#)]
extern "C" {
    #[wasm_bindgen(catch, js_name = gibbloxOpfsOpen)]
    fn js_opfs_open(name: &str) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_name = gibbloxOpfsReadAt)]
    fn js_opfs_read_at(handle: &JsValue, offset: f64, len: f64) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_name = gibbloxOpfsWriteAt)]
    fn js_opfs_write_at(
        handle: &JsValue,
        offset: f64,
        bytes: &Uint8Array,
    ) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_name = gibbloxOpfsSetLen)]
    fn js_opfs_set_len(handle: &JsValue, len: f64) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_name = gibbloxOpfsFlush)]
    fn js_opfs_flush(handle: &JsValue) -> Result<Promise, JsValue>;
}

/// OPFS-backed cache file implementation for wasm web targets.
pub struct OpfsCacheOps {
    handle: SendJsValue,
}

impl OpfsCacheOps {
    /// Open or create an OPFS cache file under the `gibblox` origin-private directory.
    pub async fn open(identity: &str) -> GibbloxResult<Self> {
        let name = cache_file_name(identity);
        let promise = js_opfs_open(&name).map_err(js_io)?;
        let handle = SendJsFuture::from(promise).await.map_err(js_io)?;
        Ok(Self {
            handle: SendJsValue(handle),
        })
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

struct SendJsFuture(JsFuture);

unsafe impl Send for SendJsFuture {}

impl From<Promise> for SendJsFuture {
    fn from(promise: Promise) -> Self {
        Self(JsFuture::from(promise))
    }
}

impl Future for SendJsFuture {
    type Output = Result<JsValue, JsValue>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

#[async_trait]
impl CacheOps for OpfsCacheOps {
    async fn read_at(&self, offset: u64, out: &mut [u8]) -> GibbloxResult<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let offset = to_js_number(offset, "offset")?;
        let len = to_js_number(out.len() as u64, "length")?;
        let promise = js_opfs_read_at(self.handle.as_js_value(), offset, len).map_err(js_io)?;
        let value = SendJsFuture::from(promise).await.map_err(js_io)?;
        let bytes = Uint8Array::new(&value);
        let read = bytes.length() as usize;
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
        let offset = to_js_number(offset, "offset")?;
        let data_len = u32::try_from(data.len()).map_err(|_| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "write payload too large")
        })?;
        let promise = {
            let bytes = Uint8Array::new_with_length(data_len);
            bytes.copy_from(data);
            js_opfs_write_at(self.handle.as_js_value(), offset, &bytes).map_err(js_io)?
        };
        let _ = SendJsFuture::from(promise).await.map_err(js_io)?;
        Ok(())
    }

    async fn set_len(&self, len: u64) -> GibbloxResult<()> {
        let len = to_js_number(len, "length")?;
        let promise = js_opfs_set_len(self.handle.as_js_value(), len).map_err(js_io)?;
        let _ = SendJsFuture::from(promise).await.map_err(js_io)?;
        Ok(())
    }

    async fn flush(&self) -> GibbloxResult<()> {
        let promise = js_opfs_flush(self.handle.as_js_value()).map_err(js_io)?;
        let _ = SendJsFuture::from(promise).await.map_err(js_io)?;
        Ok(())
    }
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
