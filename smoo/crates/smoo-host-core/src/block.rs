use crate::export_id::ExportIdentity;
use alloc::{boxed::Box, string::String, sync::Arc};
use async_trait::async_trait;
use core::{fmt, hash::Hasher};

pub type BlockSourceResult<T> = core::result::Result<T, BlockSourceError>;

/// Describes the failure category for block source operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockSourceErrorKind {
    InvalidInput,
    OutOfRange,
    Io,
    Unsupported,
    Other,
}

/// Error surfaced by [`BlockSource`] implementations.
#[derive(Clone, Debug)]
pub struct BlockSourceError {
    kind: BlockSourceErrorKind,
    message: Option<String>,
}

impl BlockSourceError {
    pub const fn new(kind: BlockSourceErrorKind) -> Self {
        Self {
            kind,
            message: None,
        }
    }

    pub fn with_message(kind: BlockSourceErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: Some(message.into()),
        }
    }

    pub fn kind(&self) -> BlockSourceErrorKind {
        self.kind
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for BlockSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(msg) => write!(f, "{:?}: {}", self.kind, msg),
            None => write!(f, "{:?}", self.kind),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BlockSourceError {}

/// Abstraction over a readable/writable block storage source.
///
/// Implementations operate on logical block units (typically 512 bytes) and the caller
/// is expected to pass buffers whose lengths are exact multiples of the reported block size.
#[async_trait]
pub trait BlockSource: Send + Sync {
    /// Logical block size in bytes.
    fn block_size(&self) -> u32;

    /// Total number of logical blocks available.
    async fn total_blocks(&self) -> BlockSourceResult<u64>;

    /// Read one or more blocks starting at `lba` into `buf`.
    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize>;

    /// Write one or more blocks starting at `lba` from `buf`.
    async fn write_blocks(&self, lba: u64, buf: &[u8]) -> BlockSourceResult<usize>;

    /// Flush outstanding writes to durable media.
    async fn flush(&self) -> BlockSourceResult<()> {
        Ok(())
    }

    /// Hint that the given range may be discarded.
    async fn discard(&self, _lba: u64, _num_blocks: u32) -> BlockSourceResult<()> {
        Ok(())
    }

    /// Feed identifying bytes for export_id derivation.
    ///
    /// Implementations should write stable, canonical data that uniquely
    /// distinguishes the backing (e.g. canonical path, URL, seed).
    fn write_export_id(&self, _state: &mut dyn Hasher) {}
}

/// Object-safe trait that bundles [`BlockSource`] with [`ExportIdentity`].
pub trait DynBlockSource: BlockSource + ExportIdentity {}

impl<T> DynBlockSource for T where T: BlockSource + ExportIdentity {}

/// Cloneable, identity-carrying wrapper around a block source.
pub struct BlockSourceHandle {
    source: Arc<dyn DynBlockSource>,
    identity: Arc<str>,
}

impl ExportIdentity for Arc<dyn DynBlockSource> {
    fn write_export_id(&self, state: &mut dyn Hasher) {
        ExportIdentity::write_export_id(&(**self), state);
    }
}

impl BlockSourceHandle {
    pub fn new<S>(source: S, identity: impl Into<Arc<str>>) -> Self
    where
        S: DynBlockSource + 'static,
    {
        Self {
            source: Arc::new(source),
            identity: identity.into(),
        }
    }

    pub fn from_arc(source: Arc<dyn DynBlockSource>, identity: impl Into<Arc<str>>) -> Self {
        Self {
            source,
            identity: identity.into(),
        }
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn inner(&self) -> Arc<dyn DynBlockSource> {
        Arc::clone(&self.source)
    }
}

impl Clone for BlockSourceHandle {
    fn clone(&self) -> Self {
        Self {
            source: Arc::clone(&self.source),
            identity: Arc::clone(&self.identity),
        }
    }
}

#[async_trait]
impl BlockSource for BlockSourceHandle {
    fn block_size(&self) -> u32 {
        self.source.block_size()
    }

    async fn total_blocks(&self) -> BlockSourceResult<u64> {
        self.source.total_blocks().await
    }

    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        self.source.read_blocks(lba, buf).await
    }

    async fn write_blocks(&self, lba: u64, buf: &[u8]) -> BlockSourceResult<usize> {
        self.source.write_blocks(lba, buf).await
    }

    async fn flush(&self) -> BlockSourceResult<()> {
        self.source.flush().await
    }

    async fn discard(&self, lba: u64, num_blocks: u32) -> BlockSourceResult<()> {
        self.source.discard(lba, num_blocks).await
    }

    fn write_export_id(&self, state: &mut dyn Hasher) {
        ExportIdentity::write_export_id(&self.source, state);
    }
}

impl ExportIdentity for BlockSourceHandle {
    fn write_export_id(&self, state: &mut dyn Hasher) {
        ExportIdentity::write_export_id(&self.source, state);
    }
}
