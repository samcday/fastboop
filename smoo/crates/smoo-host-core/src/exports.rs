use crate::{BlockSource, ExportIdentity, derive_export_id_from_source};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::fmt;
use smoo_proto::ConfigExport;

/// Error categories returned when constructing export metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportConfigErrorKind {
    /// Block size of the source does not match the configured block size.
    BlockSizeMismatch,
    /// Backing size is not aligned to the configured block size.
    MisalignedSize,
    /// Derived `export_id` collided with an existing entry.
    DuplicateExportId,
}

/// Errors surfaced by [`register_export`].
#[derive(Clone, Debug)]
pub struct ExportConfigError {
    kind: ExportConfigErrorKind,
    message: Option<String>,
}

impl ExportConfigError {
    pub fn new(kind: ExportConfigErrorKind) -> Self {
        Self {
            kind,
            message: None,
        }
    }

    pub fn with_message(kind: ExportConfigErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: Some(message.into()),
        }
    }

    pub fn kind(&self) -> ExportConfigErrorKind {
        self.kind
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for ExportConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(msg) => write!(f, "{:?}: {}", self.kind, msg),
            None => write!(f, "{:?}", self.kind),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExportConfigError {}

/// Validate and register a backing source, producing a `ConfigExport` entry.
///
/// Ensures the source block size matches `block_size`, the size aligns to the block size,
/// and the derived `export_id` is unique within `sources`.
pub fn register_export<S>(
    sources: &mut BTreeMap<u32, S>,
    entries: &mut Vec<ConfigExport>,
    source: S,
    identity: impl Into<String>,
    block_size: u32,
    size_bytes: u64,
) -> Result<(), ExportConfigError>
where
    S: BlockSource + ExportIdentity + Clone,
{
    let identity = identity.into();
    let source_block_size = source.block_size();
    if source_block_size != block_size {
        return Err(ExportConfigError::with_message(
            ExportConfigErrorKind::BlockSizeMismatch,
            format!(
                "backing {identity} block size {source_block_size} disagrees with configuration {block_size}"
            ),
        ));
    }
    if !size_bytes.is_multiple_of(block_size as u64) {
        return Err(ExportConfigError::with_message(
            ExportConfigErrorKind::MisalignedSize,
            format!("backing size for {identity} must align to block size"),
        ));
    }
    let block_count = size_bytes / block_size as u64;
    let export_id = derive_export_id_from_source(&source, block_count);
    if sources.contains_key(&export_id) {
        return Err(ExportConfigError::with_message(
            ExportConfigErrorKind::DuplicateExportId,
            format!(
                "derived duplicate export_id {export_id} for backing {identity}; check for repeated inputs or adjust backing parameters to avoid collisions"
            ),
        ));
    }
    sources.insert(export_id, source);
    entries.push(ConfigExport {
        export_id,
        block_size,
        size_bytes,
    });
    Ok(())
}
