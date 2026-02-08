use alloc::string::String;
use js_sys::{ArrayBuffer, Uint8Array};
use smoo_host_blocksource_cached::CacheStore;
use smoo_host_core::{BlockSourceError, BlockSourceErrorKind, BlockSourceResult};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{DomException, IdbDatabase, IdbOpenDbRequest, IdbTransactionMode};

pub struct IdbCacheStore {
    db: IdbDatabase,
    block_size: u32,
    total_blocks: u64,
}

impl IdbCacheStore {
    pub async fn open(
        name: impl Into<String>,
        block_size: u32,
        total_blocks: u64,
    ) -> BlockSourceResult<Self> {
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "block size must be non-zero power of two",
            ));
        }
        let name = name.into();
        let window = web_sys::window().ok_or_else(|| {
            BlockSourceError::with_message(
                BlockSourceErrorKind::Unsupported,
                "window not available",
            )
        })?;
        let factory = window.indexed_db().map_err(js_io)?.ok_or_else(|| {
            BlockSourceError::with_message(
                BlockSourceErrorKind::Unsupported,
                "indexedDB unavailable",
            )
        })?;
        let request = factory.open_with_u32(&name, 1).map_err(js_io)?;
        {
            let on_upgrade = {
                let request = request.clone();
                let meta_block_size = block_size;
                let meta_total_blocks = total_blocks;
                wasm_bindgen::closure::Closure::wrap(Box::new(move |event: web_sys::Event| {
                    let request: IdbOpenDbRequest = event
                        .target()
                        .and_then(|t| t.dyn_into::<IdbOpenDbRequest>().ok())
                        .expect("upgrade target is open request");
                    let db: IdbDatabase = request
                        .result()
                        .expect("upgrade result present")
                        .dyn_into()
                        .expect("upgrade result is database");
                    if db
                        .object_store_names()
                        .to_vec()
                        .iter()
                        .all(|s| s != "blocks")
                    {
                        let _ = db.create_object_store("blocks");
                    }
                    if db.object_store_names().to_vec().iter().all(|s| s != "meta") {
                        let store = db
                            .create_object_store("meta")
                            .expect("create meta store succeeds");
                        let meta = meta_object(meta_block_size, meta_total_blocks);
                        let _ = store.put_with_key(&meta, &JsValue::from_str("meta"));
                    } else {
                        let tx = db
                            .transaction_with_str_and_mode("meta", IdbTransactionMode::Readwrite)
                            .expect("upgrade meta transaction");
                        let store = tx.object_store("meta").expect("open meta store");
                        let meta = meta_object(meta_block_size, meta_total_blocks);
                        let _ = store.put_with_key(&meta, &JsValue::from_str("meta"));
                    }
                }) as Box<dyn FnMut(_)>)
            };
            request.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));
            on_upgrade.forget();
        }
        let _ = JsFuture::from(request.clone()).await.map_err(js_io)?;
        let db: IdbDatabase = request.result().map_err(js_io)?.dyn_into().map_err(js_io)?;
        validate_meta(&db, block_size, total_blocks).await?;
        Ok(Self {
            db,
            block_size,
            total_blocks,
        })
    }
}

#[async_trait::async_trait]
impl CacheStore for IdbCacheStore {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    async fn read_block(&self, block_idx: u64, out: &mut [u8]) -> BlockSourceResult<bool> {
        if out.len() != self.block_size as usize {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "buffer length must equal block size",
            ));
        }
        let tx = self
            .db
            .transaction_with_str_and_mode("blocks", IdbTransactionMode::Readonly)
            .map_err(js_io)?;
        let store = tx.object_store("blocks").map_err(js_io)?;
        let request = store
            .get(&JsValue::from_f64(block_idx as f64))
            .map_err(js_io)?;
        let value = JsFuture::from(request).await.map_err(js_io)?;
        if value.is_null() || value.is_undefined() {
            return Ok(false);
        }
        let array = Uint8Array::new(&value);
        if array.length() as usize != self.block_size as usize {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::Io,
                "cached block length mismatch",
            ));
        }
        array.copy_to(out);
        Ok(true)
    }

    async fn write_blocks(&self, start_block: u64, data: &[u8]) -> BlockSourceResult<()> {
        if !data.len().is_multiple_of(self.block_size as usize) {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "write payload must align to block size",
            ));
        }
        let blocks = (data.len() / self.block_size as usize) as u64;
        let end = start_block.checked_add(blocks).ok_or_else(|| {
            BlockSourceError::with_message(BlockSourceErrorKind::OutOfRange, "block overflow")
        })?;
        if end > self.total_blocks {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::OutOfRange,
                "write exceeds cache bounds",
            ));
        }
        let tx = self
            .db
            .transaction_with_str_and_mode("blocks", IdbTransactionMode::Readwrite)
            .map_err(js_io)?;
        let store = tx.object_store("blocks").map_err(js_io)?;
        let mut offset = 0usize;
        for block in start_block..end {
            let chunk = &data[offset..offset + self.block_size as usize];
            let buffer = ArrayBuffer::new(chunk.len() as u32);
            let view = Uint8Array::new(&buffer);
            view.copy_from(chunk);
            store
                .put_with_key(&view, &JsValue::from_f64(block as f64))
                .map_err(js_io)?;
            offset += self.block_size as usize;
        }
        JsFuture::from(tx.done()).await.map_err(js_io)?;
        Ok(())
    }
}

async fn validate_meta(
    db: &IdbDatabase,
    block_size: u32,
    total_blocks: u64,
) -> BlockSourceResult<()> {
    let tx = db
        .transaction_with_str_and_mode("meta", IdbTransactionMode::Readonly)
        .map_err(js_io)?;
    let store = tx.object_store("meta").map_err(js_io)?;
    let request = store.get(&JsValue::from_str("meta")).map_err(js_io)?;
    let value = JsFuture::from(request).await.map_err(js_io)?;
    if value.is_null() || value.is_undefined() {
        return Err(BlockSourceError::with_message(
            BlockSourceErrorKind::Io,
            "indexeddb cache missing meta record",
        ));
    }
    let stored_block_size = js_sys::Reflect::get(&value, &JsValue::from_str("block_size"))
        .map_err(js_io)?
        .as_f64()
        .ok_or_else(|| {
            BlockSourceError::with_message(
                BlockSourceErrorKind::Io,
                "indexeddb meta missing block_size",
            )
        })? as u32;
    let stored_total_blocks = js_sys::Reflect::get(&value, &JsValue::from_str("total_blocks"))
        .map_err(js_io)?
        .as_f64()
        .ok_or_else(|| {
            BlockSourceError::with_message(
                BlockSourceErrorKind::Io,
                "indexeddb meta missing total_blocks",
            )
        })? as u64;
    if stored_block_size != block_size || stored_total_blocks != total_blocks {
        return Err(BlockSourceError::with_message(
            BlockSourceErrorKind::InvalidInput,
            "indexeddb cache metadata mismatch",
        ));
    }
    Ok(())
}

fn meta_object(block_size: u32, total_blocks: u64) -> JsValue {
    let meta = js_sys::Object::new();
    let _ = js_sys::Reflect::set(
        &meta,
        &JsValue::from_str("block_size"),
        &JsValue::from_f64(block_size as f64),
    );
    let _ = js_sys::Reflect::set(
        &meta,
        &JsValue::from_str("total_blocks"),
        &JsValue::from_f64(total_blocks as f64),
    );
    meta.into()
}

fn js_io(err: impl Into<JsValue>) -> BlockSourceError {
    BlockSourceError::with_message(BlockSourceErrorKind::Io, js_value_to_string(err.into()))
}

fn js_value_to_string(value: JsValue) -> String {
    if let Some(exc) = value.dyn_ref::<DomException>() {
        return format!("{}: {}", exc.name(), exc.message());
    }
    js_sys::JSON::stringify(&value)
        .ok()
        .and_then(|s| s.as_string())
        .unwrap_or_else(|| format!("{value:?}"))
}
