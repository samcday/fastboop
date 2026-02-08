use std::fs::File;
#[cfg(target_family = "unix")]
use std::os::unix::fs::FileExt;
#[cfg(target_family = "windows")]
use std::os::windows::fs::FileExt;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
use tracing::{debug, trace};

/// Simple block-aligned source wrapper over `std::fs::File`.
pub struct StdFileBlockReader {
    file: File,
    size_bytes: u64,
    block_size: u32,
    identity_path: String,
}

impl StdFileBlockReader {
    pub fn open(path: impl AsRef<Path>, block_size: u32) -> GibbloxResult<Self> {
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "block size must be non-zero power of two",
            ));
        }
        debug!(path = %path.as_ref().display(), block_size, "opening file-backed source");
        let path = path.as_ref();
        let file = File::open(path).map_err(map_io_err("open file"))?;
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
        Self::from_file_with_identity(file, block_size, canonical.to_string_lossy().into_owned())
    }

    pub fn from_file(file: File, block_size: u32) -> GibbloxResult<Self> {
        Self::from_file_with_identity(file, block_size, String::from("<unknown>"))
    }

    pub fn from_file_with_identity(
        file: File,
        block_size: u32,
        identity_path: String,
    ) -> GibbloxResult<Self> {
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "block size must be non-zero power of two",
            ));
        }
        let size_bytes = file.metadata().map_err(map_io_err("stat file"))?.len();
        debug!(size_bytes, block_size, "initialized file-backed source");
        Ok(Self {
            file,
            size_bytes,
            block_size,
            identity_path,
        })
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

#[async_trait]
impl BlockReader for StdFileBlockReader {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        Ok(self.size_bytes.div_ceil(self.block_size as u64))
    }

    fn write_identity(&self, out: &mut dyn std::fmt::Write) -> std::fmt::Result {
        write!(out, "file:{}", self.identity_path)
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

        let read = read_file_at(&self.file, buf, offset).map_err(map_io_err("read file"))?;
        if read < buf.len() {
            buf[read..].fill(0);
        }

        trace!(
            lba,
            offset,
            requested = buf.len(),
            read,
            "performed file block read"
        );
        Ok(buf.len())
    }
}

#[cfg(target_family = "unix")]
fn read_file_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    file.read_at(buf, offset)
}

#[cfg(target_family = "windows")]
fn read_file_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    file.seek_read(buf, offset)
}

#[cfg(not(any(target_family = "unix", target_family = "windows")))]
fn read_file_at(_file: &File, _buf: &mut [u8], _offset: u64) -> std::io::Result<usize> {
    Err(std::io::Error::other(
        "StdFileBlockReader is unsupported on this target",
    ))
}

fn map_io_err(op: &'static str) -> impl FnOnce(std::io::Error) -> GibbloxError {
    move |err| GibbloxError::with_message(GibbloxErrorKind::Io, format!("{op}: {err}"))
}
