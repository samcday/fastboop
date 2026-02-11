use async_trait::async_trait;
use gibblox_cache::{CacheOps, derive_cached_reader_identity_id};
use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult};
use std::sync::{Arc, Mutex};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    FileSystemDirectoryHandle, FileSystemFileHandle, FileSystemGetDirectoryOptions,
    FileSystemGetFileOptions, FileSystemReadWriteOptions, FileSystemSyncAccessHandle,
    WorkerGlobalScope,
};

const JS_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;

/// OPFS-backed cache file implementation for wasm web worker targets.
pub struct OpfsCacheOps {
    handle: Arc<SyncHandle>,
}

impl OpfsCacheOps {
    /// Open or create an OPFS cache file under the `gibblox` origin-private directory.
    pub async fn open(cache_id: u32) -> GibbloxResult<Self> {
        let root = get_root_directory().await?;

        let dir_opts = FileSystemGetDirectoryOptions::new();
        dir_opts.set_create(true);
        let gibblox_dir =
            JsFuture::from(root.get_directory_handle_with_options("gibblox", &dir_opts))
                .await
                .map_err(js_io)?
                .dyn_into::<FileSystemDirectoryHandle>()
                .map_err(js_io)?;

        let file_opts = FileSystemGetFileOptions::new();
        file_opts.set_create(true);
        let name = format!("{:08x}.bin", cache_id);
        let file = JsFuture::from(gibblox_dir.get_file_handle_with_options(&name, &file_opts))
            .await
            .map_err(js_io)?
            .dyn_into::<FileSystemFileHandle>()
            .map_err(js_io)?;

        let handle = JsFuture::from(file.create_sync_access_handle())
            .await
            .map_err(js_io)?
            .dyn_into::<FileSystemSyncAccessHandle>()
            .map_err(js_io)?;

        Ok(Self {
            handle: Arc::new(SyncHandle::new(handle)),
        })
    }

    pub async fn open_for_reader<R: BlockReader + ?Sized>(reader: &R) -> GibbloxResult<Self> {
        let total_blocks = reader.total_blocks().await?;
        let cache_id = derive_cached_reader_identity_id(reader, total_blocks);
        Self::open(cache_id).await
    }
}

#[async_trait]
impl CacheOps for OpfsCacheOps {
    async fn read_at(&self, offset: u64, out: &mut [u8]) -> GibbloxResult<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let at = to_js_number(offset, "offset")?;
        let opts = FileSystemReadWriteOptions::new();
        opts.set_at(at);

        let handle = self.handle.lock()?;
        let read = handle
            .read_with_u8_array_and_options(out, &opts)
            .map_err(js_io)?;
        f64_to_usize(read, "read size")
    }

    async fn write_at(&self, offset: u64, data: &[u8]) -> GibbloxResult<()> {
        if data.is_empty() {
            return Ok(());
        }
        let at = to_js_number(offset, "offset")?;
        let opts = FileSystemReadWriteOptions::new();
        opts.set_at(at);

        let handle = self.handle.lock()?;
        let mut written = 0usize;
        while written < data.len() {
            let n = handle
                .write_with_u8_array_and_options(&data[written..], &opts)
                .map_err(js_io)?;
            let n = f64_to_usize(n, "write size")?;
            if n == 0 {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    "short write to OPFS sync access handle",
                ));
            }
            written += n;
            let next_offset = offset.checked_add(written as u64).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "write range overflow")
            })?;
            opts.set_at(to_js_number(next_offset, "offset")?);
        }

        Ok(())
    }

    async fn set_len(&self, len: u64) -> GibbloxResult<()> {
        let len = to_js_number(len, "length")?;
        let handle = self.handle.lock()?;
        handle.truncate_with_f64(len).map_err(js_io)
    }

    async fn flush(&self) -> GibbloxResult<()> {
        let handle = self.handle.lock()?;
        handle.flush().map_err(js_io)
    }
}

struct SyncHandle(Mutex<FileSystemSyncAccessHandle>);

unsafe impl Send for SyncHandle {}
unsafe impl Sync for SyncHandle {}

impl SyncHandle {
    fn new(handle: FileSystemSyncAccessHandle) -> Self {
        Self(Mutex::new(handle))
    }

    fn lock(&self) -> GibbloxResult<std::sync::MutexGuard<'_, FileSystemSyncAccessHandle>> {
        self.0.lock().map_err(|_| {
            GibbloxError::with_message(GibbloxErrorKind::Io, "OPFS sync handle lock poisoned")
        })
    }
}

impl Drop for OpfsCacheOps {
    fn drop(&mut self) {
        if let Ok(handle) = self.handle.lock() {
            let _ = handle.flush();
            handle.close();
        }
    }
}

async fn get_root_directory() -> GibbloxResult<FileSystemDirectoryHandle> {
    let global = js_sys::global()
        .dyn_into::<WorkerGlobalScope>()
        .map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::Unsupported,
                "OpfsCacheOps requires a web worker global scope",
            )
        })?;
    let storage = global.navigator().storage();
    JsFuture::from(storage.get_directory())
        .await
        .map_err(js_io)?
        .dyn_into::<FileSystemDirectoryHandle>()
        .map_err(js_io)
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

fn f64_to_usize(value: f64, label: &str) -> GibbloxResult<usize> {
    if !value.is_finite() || value < 0.0 || value > usize::MAX as f64 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            format!("invalid {label} from OPFS API"),
        ));
    }
    Ok(value as usize)
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
