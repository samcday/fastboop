extern crate alloc;

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use async_trait::async_trait;
use core::{error::Error, fmt};
use ext4_view::Ext4ReadAsync;
use gibblox_core::{
    BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext, block_identity_string,
};
use tracing::{info, trace};

pub use ext4_view as ext4_view_rs;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ext4EntryType {
    File,
    Directory,
    Symlink,
    Other,
}

/// Async-friendly ext4 filesystem wrapper backed by a gibblox `BlockReader`.
#[derive(Clone)]
pub struct Ext4Fs {
    fs: ext4_view_rs::Ext4,
    source_identity: String,
}

impl Ext4Fs {
    /// Open an ext4 filesystem from a block reader source.
    pub async fn open<S: BlockReader + 'static>(source: S) -> GibbloxResult<Self> {
        let source_block_size = source.block_size();
        if source_block_size == 0 || !source_block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "source block size must be non-zero power of two",
            ));
        }

        let total_blocks = source.total_blocks().await?;
        let source_identity = block_identity_string(&source);
        let source_size_bytes = total_blocks
            .checked_mul(source_block_size as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "source size overflow")
            })?;

        let adapter = AsyncBlockAdapter {
            inner: Arc::new(source),
            block_size: source_block_size as usize,
            size_bytes: source_size_bytes,
        };

        info!(
            source_block_size,
            total_blocks, source_size_bytes, "opening ext4 filesystem"
        );
        let fs = ext4_view_rs::Ext4::load_async(Box::new(adapter))
            .await
            .map_err(map_ext4_err("open ext4 image"))?;

        Ok(Self {
            fs,
            source_identity,
        })
    }

    pub fn source_identity(&self) -> &str {
        self.source_identity.as_str()
    }

    pub async fn read_all(&self, path: &str) -> GibbloxResult<Vec<u8>> {
        let normalized = normalize_path(path)?;
        trace!(path = normalized, "reading ext4 file");
        self.fs
            .read(normalized.as_str())
            .map_err(map_ext4_err("read ext4 file"))
    }

    pub async fn read_range(&self, path: &str, offset: u64, len: usize) -> GibbloxResult<Vec<u8>> {
        self.read_range_sync(path, offset, len)
    }

    fn read_range_sync(&self, path: &str, offset: u64, len: usize) -> GibbloxResult<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        let normalized = normalize_path(path)?;
        let mut file = self
            .fs
            .open(normalized.as_str())
            .map_err(map_ext4_err("open ext4 file"))?;
        file.seek_to(offset)
            .map_err(map_ext4_err("seek ext4 file"))?;

        let mut out = vec![0u8; len];
        let mut total = 0usize;
        while total < out.len() {
            let read = file
                .read_bytes(&mut out[total..])
                .map_err(map_ext4_err("read ext4 file range"))?;
            if read == 0 {
                break;
            }
            total += read;
        }
        out.truncate(total);
        Ok(out)
    }

    pub async fn read_dir(&self, path: &str) -> GibbloxResult<Vec<String>> {
        let normalized = normalize_path(path)?;
        let entries = self
            .fs
            .read_dir(normalized.as_str())
            .map_err(map_ext4_err("read ext4 directory"))?;

        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(map_ext4_err("read ext4 directory entry"))?;
            let name = entry.file_name().as_str().map_err(|err| {
                GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    format!("read ext4 directory entry name: {err}"),
                )
            })?;
            if name == "." || name == ".." {
                continue;
            }
            names.push(name.to_string());
        }
        Ok(names)
    }

    pub async fn entry_type(&self, path: &str) -> GibbloxResult<Option<Ext4EntryType>> {
        let normalized = normalize_path(path)?;
        match self.fs.symlink_metadata(normalized.as_str()) {
            Ok(metadata) => {
                let file_type = metadata.file_type();
                let entry_type = if file_type.is_regular_file() {
                    Ext4EntryType::File
                } else if file_type.is_dir() {
                    Ext4EntryType::Directory
                } else if file_type.is_symlink() {
                    Ext4EntryType::Symlink
                } else {
                    Ext4EntryType::Other
                };
                Ok(Some(entry_type))
            }
            Err(ext4_view_rs::Ext4Error::NotFound) => Ok(None),
            Err(err) => Err(map_ext4_err("read ext4 path metadata")(err)),
        }
    }

    pub async fn read_link(&self, path: &str) -> GibbloxResult<String> {
        let normalized = normalize_path(path)?;
        let target = self
            .fs
            .read_link(normalized.as_str())
            .map_err(map_ext4_err("read ext4 symlink target"))?;
        let target = target.to_str().map_err(|err| {
            GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                format!("ext4 symlink target is not UTF-8: {err}"),
            )
        })?;
        Ok(target.to_string())
    }

    pub async fn exists(&self, path: &str) -> GibbloxResult<bool> {
        let normalized = normalize_path(path)?;
        self.fs
            .exists(normalized.as_str())
            .map_err(map_ext4_err("check ext4 path existence"))
    }
}

/// File-backed block reader sourced from a file inside an ext4 image.
pub struct Ext4FileBlockReader {
    block_size: u32,
    file_size_bytes: u64,
    file_path: String,
    source_identity: String,
    source: Arc<dyn BlockReader>,
}

impl Ext4FileBlockReader {
    /// Build a block reader for `path` from an ext4 image exposed through `BlockReader`.
    pub async fn new<S: BlockReader + 'static>(
        source: S,
        path: &str,
        block_size: u32,
    ) -> GibbloxResult<Self> {
        info!(path, block_size, "constructing ext4-backed reader");
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "block size must be non-zero power of two",
            ));
        }

        let source: Arc<dyn BlockReader> = Arc::new(source);
        let fs = Ext4Fs::open(Arc::clone(&source)).await?;
        let file_path = normalize_path(path)?;
        let file_size_bytes = fs
            .fs
            .open(file_path.as_str())
            .map_err(map_ext4_err("open ext4 file"))?
            .metadata()
            .len();

        info!(path = file_path, file_size_bytes, "resolved file from ext4");
        Ok(Self {
            block_size,
            file_size_bytes,
            file_path,
            source_identity: fs.source_identity().to_string(),
            source,
        })
    }

    pub fn file_size_bytes(&self) -> u64 {
        self.file_size_bytes
    }
}

#[async_trait]
impl BlockReader for Ext4FileBlockReader {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        Ok(self.file_size_bytes.div_ceil(self.block_size as u64))
    }

    fn write_identity(&self, out: &mut dyn fmt::Write) -> fmt::Result {
        write!(
            out,
            "ext4-file:({}):{}",
            self.source_identity, self.file_path
        )
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

        let offset = lba.checked_mul(self.block_size as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
        })?;
        if offset >= self.file_size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "requested block out of range",
            ));
        }

        let read_len = ((buf.len() as u64).min(self.file_size_bytes - offset)) as usize;
        let fs = pollster::block_on(Ext4Fs::open(Arc::clone(&self.source)))?;
        let data = fs.read_range_sync(self.file_path.as_str(), offset, read_len)?;
        if data.len() < read_len {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Io,
                "short read from ext4 file",
            ));
        }
        buf[..read_len].copy_from_slice(&data[..read_len]);
        if read_len < buf.len() {
            buf[read_len..].fill(0);
        }
        Ok(buf.len())
    }
}

#[derive(Clone)]
struct AsyncBlockAdapter {
    inner: Arc<dyn BlockReader>,
    block_size: usize,
    size_bytes: u64,
}

#[async_trait(?Send)]
impl Ext4ReadAsync for AsyncBlockAdapter {
    async fn read(
        &self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if dst.is_empty() {
            return Ok(());
        }

        let end = start_byte
            .checked_add(dst.len() as u64)
            .ok_or_else(|| adapter_box_error("ext4 adapter read range overflow"))?;
        if end > self.size_bytes {
            return Err(adapter_box_error("ext4 adapter read past end of source"));
        }

        let bs = self.block_size as u64;
        let aligned_start = (start_byte / bs) * bs;
        let aligned_end = end.div_ceil(bs) * bs;
        let aligned_len = (aligned_end - aligned_start) as usize;

        let mut scratch = vec![0u8; aligned_len];
        let mut filled = 0usize;
        while filled < scratch.len() {
            let filled_u64 = u64::try_from(filled)
                .map_err(|_| adapter_box_error("ext4 adapter offset conversion overflow"))?;
            let lba = aligned_start
                .checked_add(filled_u64)
                .ok_or_else(|| adapter_box_error("ext4 adapter read offset overflow"))?
                / bs;
            let read = self
                .inner
                .read_blocks(lba, &mut scratch[filled..], ReadContext::FOREGROUND)
                .await
                .map_err(|err| adapter_box_error(format!("block read failed: {err}")))?;
            if read == 0 {
                return Err(adapter_box_error(
                    "unexpected EOF while servicing ext4 read",
                ));
            }
            if read % self.block_size != 0 && filled + read < scratch.len() {
                return Err(adapter_box_error("unaligned short read from block source"));
            }
            filled += read;
        }

        let head = (start_byte - aligned_start) as usize;
        dst.copy_from_slice(&scratch[head..head + dst.len()]);
        Ok(())
    }
}

fn normalize_path(path: &str) -> GibbloxResult<String> {
    let inner = path.trim_start_matches('/');
    if inner.is_empty() {
        return Ok("/".to_string());
    }
    Ok(format!("/{inner}"))
}

fn map_ext4_err(op: &'static str) -> impl FnOnce(ext4_view_rs::Ext4Error) -> GibbloxError {
    move |err| {
        let kind = match &err {
            ext4_view_rs::Ext4Error::Io(_) => GibbloxErrorKind::Io,
            ext4_view_rs::Ext4Error::Incompatible(_) => GibbloxErrorKind::Unsupported,
            ext4_view_rs::Ext4Error::Corrupt(_) => GibbloxErrorKind::InvalidInput,
            ext4_view_rs::Ext4Error::FileTooLarge => GibbloxErrorKind::OutOfRange,
            _ => GibbloxErrorKind::InvalidInput,
        };
        GibbloxError::with_message(kind, format!("{op}: {err}"))
    }
}

#[derive(Debug)]
struct AdapterError {
    message: String,
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message.as_str())
    }
}

impl Error for AdapterError {}

fn adapter_box_error(message: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    Box::new(AdapterError {
        message: message.into(),
    })
}
