use async_trait::async_trait;
use gibblox_cache::{CacheOps, derive_cached_reader_identity_id};
use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult};
use std::env;
use std::fs::{File, OpenOptions, create_dir_all};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use tracing::debug;

#[cfg(target_family = "unix")]
use std::os::unix::fs::FileExt;
#[cfg(target_family = "windows")]
use std::os::windows::fs::FileExt;

/// Standard filesystem-backed cache file implementation.
pub struct StdCacheOps {
    path: PathBuf,
    file: Mutex<File>,
}

impl StdCacheOps {
    /// Open or create a cache file inside the process user's default cache location.
    pub fn open_default(cache_id: u32) -> GibbloxResult<Self> {
        let root = default_cache_root()?;
        debug!(cache_id = format!("{:08x}", cache_id), cache_root = %root.display(), "opening cache in default location");
        Self::open_in(root, cache_id)
    }

    /// Open or create a cache file for a block reader identity in the default cache root.
    pub async fn open_default_for_reader<R: BlockReader + ?Sized>(
        reader: &R,
    ) -> GibbloxResult<Self> {
        let total_blocks = reader.total_blocks().await?;
        let cache_id = derive_cached_reader_identity_id(reader, total_blocks);
        Self::open_default(cache_id)
    }

    /// Open or create a cache file under a caller-provided root directory.
    pub fn open_in(root: impl AsRef<Path>, cache_id: u32) -> GibbloxResult<Self> {
        create_dir_all(root.as_ref()).map_err(map_io_err("create cache directory"))?;
        let path = root.as_ref().join(cache_file_name(cache_id));
        Self::open_path(path)
    }

    /// Open or create a cache file for a block reader identity under a caller-provided root.
    pub async fn open_in_for_reader<R: BlockReader + ?Sized>(
        root: impl AsRef<Path>,
        reader: &R,
    ) -> GibbloxResult<Self> {
        let total_blocks = reader.total_blocks().await?;
        let cache_id = derive_cached_reader_identity_id(reader, total_blocks);
        Self::open_in(root, cache_id)
    }

    /// Open or create a cache file at an explicit path.
    pub fn open_path(path: impl AsRef<Path>) -> GibbloxResult<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(map_io_err("open cache file"))?;
        debug!(cache_path = %path.display(), "opened std cache file");
        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    /// Full path to the underlying cache file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lock_file(&self) -> GibbloxResult<MutexGuard<'_, File>> {
        self.file.lock().map_err(|_| {
            GibbloxError::with_message(GibbloxErrorKind::Io, "cache file lock poisoned")
        })
    }
}

fn cache_file_name(cache_id: u32) -> String {
    format!("{cache_id:08x}.bin")
}

#[async_trait]
impl CacheOps for StdCacheOps {
    async fn read_at(&self, offset: u64, out: &mut [u8]) -> GibbloxResult<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let file = self.lock_file()?;
        read_file_at(&file, out, offset).map_err(map_io_err("read cache file"))
    }

    async fn write_at(&self, offset: u64, data: &[u8]) -> GibbloxResult<()> {
        if data.is_empty() {
            return Ok(());
        }
        let file = self.lock_file()?;
        write_file_all_at(&file, data, offset).map_err(map_io_err("write cache file"))
    }

    async fn set_len(&self, len: u64) -> GibbloxResult<()> {
        let file = self.lock_file()?;
        file.set_len(len).map_err(map_io_err("resize cache file"))
    }

    async fn flush(&self) -> GibbloxResult<()> {
        let file = self.lock_file()?;
        file.sync_data().map_err(map_io_err("flush cache file"))
    }
}

fn default_cache_root() -> GibbloxResult<PathBuf> {
    if let Some(path) = env::var_os("XDG_CACHE_HOME") {
        if !path.is_empty() {
            return Ok(PathBuf::from(path).join("gibblox"));
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(path) = env::var_os("LOCALAPPDATA") {
            if !path.is_empty() {
                return Ok(PathBuf::from(path).join("gibblox"));
            }
        }
    }

    if let Some(path) = env::var_os("HOME") {
        if !path.is_empty() {
            return Ok(PathBuf::from(path).join(".cache").join("gibblox"));
        }
    }

    Err(GibbloxError::with_message(
        GibbloxErrorKind::Unsupported,
        "unable to determine cache root (set XDG_CACHE_HOME)",
    ))
}

#[cfg(target_family = "unix")]
fn read_file_at(file: &File, out: &mut [u8], offset: u64) -> std::io::Result<usize> {
    file.read_at(out, offset)
}

#[cfg(target_family = "windows")]
fn read_file_at(file: &File, out: &mut [u8], offset: u64) -> std::io::Result<usize> {
    file.seek_read(out, offset)
}

#[cfg(not(any(target_family = "unix", target_family = "windows")))]
fn read_file_at(_file: &File, _out: &mut [u8], _offset: u64) -> std::io::Result<usize> {
    Err(std::io::Error::other(
        "StdCacheOps is unsupported on this target",
    ))
}

#[cfg(target_family = "unix")]
fn write_file_at(file: &File, data: &[u8], offset: u64) -> std::io::Result<usize> {
    file.write_at(data, offset)
}

#[cfg(target_family = "windows")]
fn write_file_at(file: &File, data: &[u8], offset: u64) -> std::io::Result<usize> {
    file.seek_write(data, offset)
}

#[cfg(not(any(target_family = "unix", target_family = "windows")))]
fn write_file_at(_file: &File, _data: &[u8], _offset: u64) -> std::io::Result<usize> {
    Err(std::io::Error::other(
        "StdCacheOps is unsupported on this target",
    ))
}

fn write_file_all_at(file: &File, data: &[u8], offset: u64) -> std::io::Result<()> {
    let mut written = 0usize;
    while written < data.len() {
        let at = offset
            .checked_add(written as u64)
            .ok_or_else(|| std::io::Error::other("write offset overflow"))?;
        let count = write_file_at(file, &data[written..], at)?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "failed to write cache file",
            ));
        }
        written += count;
    }
    Ok(())
}

fn map_io_err(op: &'static str) -> impl FnOnce(std::io::Error) -> GibbloxError {
    move |err| GibbloxError::with_message(GibbloxErrorKind::Io, format!("{op}: {err}"))
}
