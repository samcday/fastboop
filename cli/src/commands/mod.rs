use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use fastboop_core::fastboot::{FastbootProtocolError, ProbeError};
use fastboop_core::{RootfsEntryType, RootfsProvider};

mod boot;
mod detect;
mod stage0;

pub use boot::{BootArgs, run_boot};
pub use detect::{DetectArgs, run_detect};
pub use stage0::{Stage0Args, run_stage0};

pub(crate) fn format_probe_error(
    err: ProbeError<FastbootProtocolError<fastboop_fastboot_rusb::FastbootRusbError>>,
) -> String {
    match err {
        ProbeError::Transport(err) => err.to_string(),
        ProbeError::MissingVar(name) => format!("missing getvar {name}"),
        ProbeError::Mismatch {
            name,
            expected,
            actual,
        } => format!("getvar {name} mismatch: expected '{expected}', got '{actual}'"),
    }
}

#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct DirectoryRootfs {
    pub(crate) root: PathBuf,
}

#[allow(dead_code)]
impl RootfsProvider for DirectoryRootfs {
    type Error = anyhow::Error;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        let path = resolve_rooted(&self.root, path)?;
        fs::read(&path).with_context(|| format!("reading {}", path.display()))
    }

    async fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        let path = resolve_rooted(&self.root, path)?;
        let mut f = fs::File::open(&path)
            .with_context(|| format!("opening {} for range read", path.display()))?;
        f.seek(SeekFrom::Start(offset))
            .with_context(|| format!("seeking {} to {}", path.display(), offset))?;
        let mut buf = vec![0u8; len];
        let n = f
            .read(&mut buf)
            .with_context(|| format!("reading range from {}", path.display()))?;
        buf.truncate(n);
        Ok(buf)
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>> {
        let path = resolve_rooted(&self.root, path)?;
        let entries =
            fs::read_dir(&path).with_context(|| format!("reading directory {}", path.display()))?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        Ok(names)
    }

    async fn entry_type(&self, path: &str) -> Result<Option<RootfsEntryType>> {
        let path = resolve_rooted(&self.root, path)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("reading metadata for {}", path.display()));
            }
        };
        let ty = metadata.file_type();
        let entry_type = if ty.is_file() {
            RootfsEntryType::File
        } else if ty.is_dir() {
            RootfsEntryType::Directory
        } else if ty.is_symlink() {
            RootfsEntryType::Symlink
        } else {
            RootfsEntryType::Other
        };
        Ok(Some(entry_type))
    }

    async fn read_link(&self, path: &str) -> Result<String> {
        let path = resolve_rooted(&self.root, path)?;
        let target = fs::read_link(&path)
            .with_context(|| format!("reading symlink target {}", path.display()))?;
        Ok(target.to_string_lossy().into_owned())
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let path = resolve_rooted(&self.root, path)?;
        Ok(path.exists())
    }
}

pub(crate) fn read_existing_initrd(path: &Option<PathBuf>) -> Result<Option<Vec<u8>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    Ok(Some(fs::read(path).with_context(|| {
        format!("reading initrd {}", path.display())
    })?))
}

pub(crate) fn read_dtbo_overlays(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for path in paths {
        let data = fs::read(path).with_context(|| format!("reading dtbo {}", path.display()))?;
        out.push(data);
    }
    Ok(out)
}

#[allow(dead_code)]
fn resolve_rooted(root: &Path, path: &str) -> Result<PathBuf> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        bail!("empty path");
    }
    Ok(root.join(trimmed))
}
