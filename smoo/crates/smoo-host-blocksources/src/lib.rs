pub mod device;
pub mod file;
pub mod random;

use anyhow::{Context, Result};
use smoo_host_core::{BlockSourceError, BlockSourceErrorKind};
use std::{
    io,
    os::unix::fs::{FileExt, FileTypeExt},
    os::unix::io::AsRawFd,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::{fs::OpenOptions, task};
use tracing::debug;

fn io_error(err: io::Error) -> BlockSourceError {
    BlockSourceError::with_message(BlockSourceErrorKind::Io, err.to_string())
}

struct BlockFile {
    file: std::fs::File,
    len: AtomicU64,
    writable: bool,
}

impl BlockFile {
    fn new(file: std::fs::File, len: u64, writable: bool) -> Self {
        Self {
            file,
            len: AtomicU64::new(len),
            writable,
        }
    }

    async fn size(&self) -> io::Result<u64> {
        Ok(self.len.load(Ordering::Relaxed))
    }

    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let file = self.file.try_clone()?;
        let len = buf.len();
        let tmp = task::spawn_blocking(move || {
            let mut tmp = vec![0u8; len];
            let mut read = 0;
            while read < len {
                let n = file.read_at(&mut tmp[read..], offset + read as u64)?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short read from block file",
                    ));
                }
                read += n;
            }
            Ok::<_, io::Error>(tmp)
        })
        .await
        .map_err(|err| io::Error::other(err.to_string()))??;
        buf.copy_from_slice(&tmp);
        Ok(())
    }

    async fn write_at(&self, offset: u64, buf: &[u8]) -> io::Result<()> {
        if !self.writable {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "block source opened in read-only mode",
            ));
        }

        let file = self.file.try_clone()?;
        let data = buf.to_vec();
        let len = data.len();
        task::spawn_blocking(move || {
            let mut written = 0;
            while written < len {
                let n = file.write_at(&data[written..], offset + written as u64)?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short write to block file",
                    ));
                }
                written += n;
            }
            Ok(())
        })
        .await
        .unwrap_or_else(|err| Err(io::Error::other(err.to_string())))?;

        let end = offset
            .checked_add(u64::try_from(len).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "write length exceeds u64")
            })?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "write offset overflow"))?;
        self.len.fetch_max(end, Ordering::Relaxed);
        Ok(())
    }

    async fn flush(&self) -> io::Result<()> {
        let file = self.file.try_clone()?;
        task::spawn_blocking(move || file.sync_data())
            .await
            .unwrap_or_else(|err| Err(io::Error::other(format!("flush join error: {err}"))))
    }
}

struct OpenedBlockFile {
    file: std::fs::File,
    len: u64,
    writable: bool,
}

#[cfg(target_os = "linux")]
const IOC_NRBITS: u8 = 8;
#[cfg(target_os = "linux")]
const IOC_TYPEBITS: u8 = 8;
#[cfg(target_os = "linux")]
const IOC_SIZEBITS: u8 = 14;
#[cfg(target_os = "linux")]
const IOC_NRSHIFT: u8 = 0;
#[cfg(target_os = "linux")]
const IOC_TYPESHIFT: u8 = IOC_NRSHIFT + IOC_NRBITS;
#[cfg(target_os = "linux")]
const IOC_SIZESHIFT: u8 = IOC_TYPESHIFT + IOC_TYPEBITS;
#[cfg(target_os = "linux")]
const IOC_DIRSHIFT: u8 = IOC_SIZESHIFT + IOC_SIZEBITS;
#[cfg(target_os = "linux")]
const IOC_READ: u8 = 2;

#[cfg(target_os = "linux")]
const fn ior(ty: u8, nr: u8, size: u32) -> libc::c_ulong {
    ((IOC_READ as libc::c_ulong) << IOC_DIRSHIFT)
        | ((ty as libc::c_ulong) << IOC_TYPESHIFT)
        | ((nr as libc::c_ulong) << IOC_NRSHIFT)
        | ((size as libc::c_ulong) << IOC_SIZESHIFT)
}

#[cfg(target_os = "linux")]
const BLKGETSIZE64: libc::c_ulong = ior(0x12, 114, core::mem::size_of::<libc::size_t>() as u32);

#[cfg(target_os = "linux")]
fn block_device_len(file: &std::fs::File) -> io::Result<u64> {
    let mut size = 0u64;
    let res = unsafe { libc::ioctl(file.as_raw_fd(), BLKGETSIZE64 as libc::Ioctl, &mut size) };
    if res == 0 {
        Ok(size)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn file_len(file: &std::fs::File) -> io::Result<u64> {
    let metadata = file.metadata()?;
    let len = metadata.len();
    if len > 0 || !metadata.file_type().is_block_device() {
        return Ok(len);
    }
    #[cfg(target_os = "linux")]
    {
        return block_device_len(file);
    }
    #[allow(unreachable_code)]
    Ok(len)
}

async fn open_block_file(path: &Path) -> Result<OpenedBlockFile> {
    let path_display = path.display().to_string();
    let rw_result = OpenOptions::new().read(true).write(true).open(path).await;

    let (file, writable) = match rw_result {
        Ok(file) => (file, true),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            let file = OpenOptions::new()
                .read(true)
                .open(path)
                .await
                .with_context(|| format!("open {path_display} read-only"))?;
            debug!(path = %path_display, "opened block source read-only");
            (file, false)
        }
        Err(err) => {
            return Err(err).context(format!("open {path_display}"));
        }
    };

    let file = file.into_std().await;
    let len = task::spawn_blocking({
        let file = file
            .try_clone()
            .with_context(|| format!("clone {path_display}"))?;
        let path_display = path_display.clone();
        move || file_len(&file).with_context(|| format!("stat {path_display}"))
    })
    .await
    .context("join file len task")??;
    if writable {
        debug!(path = %path_display, len = len, "opened block source read-write");
    }

    Ok(OpenedBlockFile {
        file,
        len,
        writable,
    })
}
