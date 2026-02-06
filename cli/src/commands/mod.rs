use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use fastboop_core::RootfsProvider;
use fastboop_core::fastboot::{FastbootProtocolError, ProbeError};

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

#[derive(Clone)]
pub(crate) struct DirectoryRootfs {
    pub(crate) root: PathBuf,
    pub(crate) smoo: Option<PathBuf>,
}

impl RootfsProvider for DirectoryRootfs {
    type Error = anyhow::Error;

    fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        if path == "smoo-gadget" {
            let smoo = self.smoo.as_ref().context("smoo-gadget not provided")?;
            return fs::read(smoo)
                .with_context(|| format!("reading smoo binary {}", smoo.display()));
        }
        let path = resolve_rooted(&self.root, path)?;
        fs::read(&path).with_context(|| format!("reading {}", path.display()))
    }

    fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
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

    fn read_dir(&self, path: &str) -> Result<Vec<String>> {
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

    fn exists(&self, path: &str) -> Result<bool> {
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

pub(crate) fn ensure_smoo_source(smoo: &Option<PathBuf>, existing: &Option<Vec<u8>>) -> Result<()> {
    if smoo.is_some() {
        return Ok(());
    }
    let Some(data) = existing else {
        bail!("--smoo is required unless --augment contains /usr/bin/smoo-gadget");
    };
    let has_smoo = fastboop_stage0::cpio_contains_path(data, "usr/bin/smoo-gadget")
        .map_err(|e| anyhow::anyhow!("invalid initrd: {e:?}"))?;
    if !has_smoo {
        bail!("--smoo is required unless --augment contains /usr/bin/smoo-gadget");
    }
    Ok(())
}

fn resolve_rooted(root: &Path, path: &str) -> Result<PathBuf> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        bail!("empty path");
    }
    Ok(root.join(trimmed))
}
