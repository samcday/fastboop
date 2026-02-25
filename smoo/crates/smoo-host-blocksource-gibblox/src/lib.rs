use async_trait::async_trait;
use core::hash::Hasher;
use gibblox_core::{BlockReader, GibbloxErrorKind, ReadContext};
use smoo_host_core::{BlockSource, BlockSourceError, BlockSourceErrorKind, BlockSourceResult};
use std::sync::Arc;

#[derive(Clone)]
pub struct GibbloxBlockSource {
    reader: Arc<dyn BlockReader>,
    identity: Arc<str>,
}

impl GibbloxBlockSource {
    pub fn new(reader: Arc<dyn BlockReader>, identity: impl Into<Arc<str>>) -> Self {
        Self {
            reader,
            identity: identity.into(),
        }
    }
}

#[async_trait]
impl BlockSource for GibbloxBlockSource {
    fn block_size(&self) -> u32 {
        self.reader.block_size()
    }

    async fn total_blocks(&self) -> BlockSourceResult<u64> {
        self.reader.total_blocks().await.map_err(map_error)
    }

    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        self.reader
            .read_blocks(lba, buf, ReadContext::FOREGROUND)
            .await
            .map_err(map_error)
    }

    async fn write_blocks(&self, _lba: u64, _buf: &[u8]) -> BlockSourceResult<usize> {
        Err(BlockSourceError::with_message(
            BlockSourceErrorKind::Unsupported,
            "gibblox source is read-only",
        ))
    }

    async fn flush(&self) -> BlockSourceResult<()> {
        Ok(())
    }

    async fn discard(&self, _lba: u64, _num_blocks: u32) -> BlockSourceResult<()> {
        Err(BlockSourceError::with_message(
            BlockSourceErrorKind::Unsupported,
            "gibblox source is read-only",
        ))
    }

    fn write_export_id(&self, state: &mut dyn Hasher) {
        state.write(self.identity.as_bytes());
    }
}

impl smoo_host_core::ExportIdentity for GibbloxBlockSource {
    fn write_export_id(&self, state: &mut dyn Hasher) {
        state.write(self.identity.as_bytes());
    }
}

fn map_error(err: gibblox_core::GibbloxError) -> BlockSourceError {
    let kind = match err.kind() {
        GibbloxErrorKind::InvalidInput => BlockSourceErrorKind::InvalidInput,
        GibbloxErrorKind::OutOfRange => BlockSourceErrorKind::OutOfRange,
        GibbloxErrorKind::Io => BlockSourceErrorKind::Io,
        GibbloxErrorKind::Unsupported => BlockSourceErrorKind::Unsupported,
        GibbloxErrorKind::Other => BlockSourceErrorKind::Other,
    };
    match err.message() {
        Some(msg) => BlockSourceError::with_message(kind, msg),
        None => BlockSourceError::new(kind),
    }
}
