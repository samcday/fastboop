#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(target_arch = "wasm32")]
mod wasm {
    use alloc::{boxed::Box, format, string::String, sync::Arc};
    use async_trait::async_trait;
    use core::{
        fmt,
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };
    use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
    use js_sys::{Promise, Uint8Array};
    use tracing::{debug, trace};
    use wasm_bindgen::JsValue;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Blob, File};

    const JS_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;

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

    #[derive(Clone)]
    struct SendFile(File);

    unsafe impl Send for SendFile {}
    unsafe impl Sync for SendFile {}

    impl SendFile {
        fn as_blob(&self) -> &Blob {
            self.0.as_ref()
        }

        fn name(&self) -> String {
            self.0.name()
        }

        fn last_modified(&self) -> f64 {
            self.0.last_modified()
        }
    }

    pub struct WebFileBlockReader {
        file: SendFile,
        size_bytes: u64,
        block_size: u32,
        identity: Arc<str>,
    }

    impl WebFileBlockReader {
        pub fn new(file: File, block_size: u32) -> GibbloxResult<Self> {
            if block_size == 0 || !block_size.is_power_of_two() {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "block size must be non-zero power of two",
                ));
            }

            let file = SendFile(file);
            let size_bytes = f64_to_u64(file.as_blob().size(), "file size")?;
            let last_modified = f64_to_i64(file.last_modified(), "file last_modified")?;
            let name = file.name();
            debug!(
                name = %name,
                size_bytes,
                last_modified,
                block_size,
                "opening web file-backed source"
            );

            let identity = Arc::<str>::from(format!(
                "web-file:{}:{}:{}",
                name, size_bytes, last_modified
            ));

            Ok(Self {
                file,
                size_bytes,
                block_size,
                identity,
            })
        }

        pub fn size_bytes(&self) -> u64 {
            self.size_bytes
        }
    }

    #[async_trait]
    impl BlockReader for WebFileBlockReader {
        fn block_size(&self) -> u32 {
            self.block_size
        }

        async fn total_blocks(&self) -> GibbloxResult<u64> {
            Ok(self.size_bytes.div_ceil(self.block_size as u64))
        }

        fn write_identity(&self, out: &mut dyn fmt::Write) -> fmt::Result {
            out.write_str(self.identity.as_ref())
        }

        async fn read_blocks(
            &self,
            lba: u64,
            buf: &mut [u8],
            _ctx: ReadContext,
        ) -> GibbloxResult<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            if !buf.len().is_multiple_of(self.block_size as usize) {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "buffer length must align to block size",
                ));
            }

            let total_blocks = self.total_blocks().await?;
            if lba >= total_blocks {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "requested block out of range",
                ));
            }

            let offset = lba.checked_mul(self.block_size as u64).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
            })?;
            let remaining = self.size_bytes.checked_sub(offset).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "offset out of range")
            })?;
            let read_len = (buf.len() as u64).min(remaining) as usize;
            let end = offset.checked_add(read_len as u64).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "read range overflow")
            })?;

            let promise = self
                .file
                .as_blob()
                .slice_with_f64_and_f64(
                    to_js_number(offset, "read start")?,
                    to_js_number(end, "read end")?,
                )
                .map_err(js_io("slice file"))?
                .array_buffer();
            let buffer = SendJsFuture::from(promise)
                .await
                .map_err(js_io("await file read"))?;
            let bytes = Uint8Array::new(&buffer);

            let available = bytes.length() as usize;
            let read = read_len.min(available);
            bytes.subarray(0, read as u32).copy_to(&mut buf[..read]);
            if read < read_len {
                debug!(
                    expected = read_len,
                    read, "short read while reading web file slice"
                );
            }
            if read < buf.len() {
                buf[read..].fill(0);
            }

            trace!(
                lba,
                offset,
                requested = buf.len(),
                read,
                "performed web file block read"
            );
            Ok(buf.len())
        }
    }

    fn to_js_number(value: u64, label: &'static str) -> GibbloxResult<f64> {
        if value > JS_SAFE_INTEGER_MAX {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                format!("{label} exceeds JavaScript safe integer"),
            ));
        }
        Ok(value as f64)
    }

    fn f64_to_u64(value: f64, label: &'static str) -> GibbloxResult<u64> {
        if !value.is_finite() || value < 0.0 || value.fract() != 0.0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                format!("invalid {label} from web file"),
            ));
        }
        to_js_number(value as u64, label).map(|_| value as u64)
    }

    fn f64_to_i64(value: f64, label: &'static str) -> GibbloxResult<i64> {
        if !value.is_finite() || value.fract() != 0.0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                format!("invalid {label} from web file"),
            ));
        }
        if value.abs() > JS_SAFE_INTEGER_MAX as f64
            || value < i64::MIN as f64
            || value > i64::MAX as f64
        {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                format!("{label} exceeds supported range"),
            ));
        }
        Ok(value as i64)
    }

    fn js_io(op: &'static str) -> impl FnOnce(JsValue) -> GibbloxError {
        move |err| {
            GibbloxError::with_message(
                GibbloxErrorKind::Io,
                format!("{op}: {}", js_value_to_string(err)),
            )
        }
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
