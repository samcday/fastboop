use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use fastboop_core::fastboot::{FastbootProtocolError, ProbeError};
use fastboop_core::{RootfsEntryType, RootfsProvider};
use fastboop_rootfs_erofs::normalize_ostree_deployment_path;

mod boot;
mod detect;
mod stage0;

pub use boot::{BootArgs, run_boot};
pub use detect::{DetectArgs, run_detect};
pub use stage0::{Stage0Args, run_stage0};

#[derive(Clone, Debug)]
pub(crate) enum OstreeArg {
    Disabled,
    AutoDetect,
    Explicit(String),
}

pub(crate) fn parse_ostree_arg(raw: Option<&Option<String>>) -> Result<OstreeArg> {
    match raw {
        None => Ok(OstreeArg::Disabled),
        Some(None) => Ok(OstreeArg::AutoDetect),
        Some(Some(path)) => Ok(OstreeArg::Explicit(normalize_ostree_deployment_path(path)?)),
    }
}

pub(crate) async fn auto_detect_ostree_deployment_path<P>(rootfs: &P) -> Result<String>
where
    P: RootfsProvider,
    P::Error: core::fmt::Display,
{
    const OSTREE_ROOT: &str = "/ostree";

    if !is_directory(rootfs, OSTREE_ROOT).await? {
        bail!("auto-detect ostree deployment failed: {OSTREE_ROOT} is not a directory");
    }

    for boot_dir in sorted_dir_entries(rootfs, OSTREE_ROOT).await? {
        if !boot_dir.starts_with("boot.") {
            continue;
        }
        let boot_path = format!("{OSTREE_ROOT}/{boot_dir}");
        if !is_directory(rootfs, &boot_path).await? {
            continue;
        }

        for stateroot in sorted_dir_entries(rootfs, &boot_path).await? {
            let stateroot_path = format!("{boot_path}/{stateroot}");
            if !is_directory(rootfs, &stateroot_path).await? {
                continue;
            }

            for checksum in sorted_dir_entries(rootfs, &stateroot_path).await? {
                let checksum_path = format!("{stateroot_path}/{checksum}");
                if !is_directory(rootfs, &checksum_path).await? {
                    continue;
                }

                for deploy_index in sorted_dir_entries(rootfs, &checksum_path).await? {
                    let candidate_path = format!("{checksum_path}/{deploy_index}");
                    if is_symlink(rootfs, &candidate_path).await? {
                        return Ok(candidate_path.trim_start_matches('/').to_string());
                    }
                }
            }
        }
    }

    bail!("auto-detect ostree deployment failed: no deployment symlink found under /ostree/boot.*")
}

async fn sorted_dir_entries<P>(rootfs: &P, path: &str) -> Result<Vec<String>>
where
    P: RootfsProvider,
    P::Error: core::fmt::Display,
{
    let mut entries = rootfs
        .read_dir(path)
        .await
        .map_err(|err| anyhow!("read directory {path}: {err}"))?;
    entries.sort();
    Ok(entries)
}

async fn is_directory<P>(rootfs: &P, path: &str) -> Result<bool>
where
    P: RootfsProvider,
    P::Error: core::fmt::Display,
{
    let ty = rootfs
        .entry_type(path)
        .await
        .map_err(|err| anyhow!("read entry type {path}: {err}"))?;
    Ok(matches!(ty, Some(RootfsEntryType::Directory)))
}

async fn is_symlink<P>(rootfs: &P, path: &str) -> Result<bool>
where
    P: RootfsProvider,
    P::Error: core::fmt::Display,
{
    let ty = rootfs
        .entry_type(path)
        .await
        .map_err(|err| anyhow!("read entry type {path}: {err}"))?;
    Ok(matches!(ty, Some(RootfsEntryType::Symlink)))
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MockRootfs {
        entry_types: BTreeMap<String, RootfsEntryType>,
        directories: BTreeMap<String, Vec<String>>,
    }

    impl MockRootfs {
        fn add_dir(&mut self, path: &str, entries: &[&str]) {
            self.entry_types
                .insert(path.to_string(), RootfsEntryType::Directory);
            self.directories.insert(
                path.to_string(),
                entries.iter().map(|entry| (*entry).to_string()).collect(),
            );
        }

        fn add_symlink(&mut self, path: &str) {
            self.entry_types
                .insert(path.to_string(), RootfsEntryType::Symlink);
        }
    }

    impl RootfsProvider for MockRootfs {
        type Error = anyhow::Error;

        async fn read_all(&self, path: &str) -> Result<Vec<u8>, Self::Error> {
            Err(anyhow!("unexpected read_all call for {path}"))
        }

        async fn read_range(
            &self,
            path: &str,
            _offset: u64,
            _len: usize,
        ) -> Result<Vec<u8>, Self::Error> {
            Err(anyhow!("unexpected read_range call for {path}"))
        }

        async fn read_dir(&self, path: &str) -> Result<Vec<String>, Self::Error> {
            self.directories
                .get(path)
                .cloned()
                .ok_or_else(|| anyhow!("missing directory {path}"))
        }

        async fn entry_type(&self, path: &str) -> Result<Option<RootfsEntryType>, Self::Error> {
            Ok(self.entry_types.get(path).copied())
        }

        async fn read_link(&self, path: &str) -> Result<String, Self::Error> {
            Err(anyhow!("unexpected read_link call for {path}"))
        }

        async fn exists(&self, path: &str) -> Result<bool, Self::Error> {
            Ok(self.entry_types.contains_key(path) || self.directories.contains_key(path))
        }
    }

    #[tokio::test]
    async fn auto_detect_ostree_picks_first_sorted_candidate() {
        let mut rootfs = MockRootfs::default();
        rootfs.add_dir("/ostree", &["boot.1", "boot.0"]);
        rootfs.add_dir("/ostree/boot.0", &["fedora"]);
        rootfs.add_dir("/ostree/boot.0/fedora", &["aaa"]);
        rootfs.add_dir("/ostree/boot.0/fedora/aaa", &["1"]);
        rootfs.add_symlink("/ostree/boot.0/fedora/aaa/1");

        rootfs.add_dir("/ostree/boot.1", &["fedora"]);
        rootfs.add_dir("/ostree/boot.1/fedora", &["bbb"]);
        rootfs.add_dir("/ostree/boot.1/fedora/bbb", &["0"]);
        rootfs.add_symlink("/ostree/boot.1/fedora/bbb/0");

        let detected = auto_detect_ostree_deployment_path(&rootfs).await.unwrap();
        assert_eq!(detected, "ostree/boot.0/fedora/aaa/1");
    }

    #[tokio::test]
    async fn auto_detect_ostree_errors_when_no_symlink_candidates_exist() {
        let mut rootfs = MockRootfs::default();
        rootfs.add_dir("/ostree", &["boot.1"]);
        rootfs.add_dir("/ostree/boot.1", &["fedora"]);
        rootfs.add_dir("/ostree/boot.1/fedora", &["aaa"]);
        rootfs.add_dir("/ostree/boot.1/fedora/aaa", &["0"]);

        let err = auto_detect_ostree_deployment_path(&rootfs)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no deployment symlink found"),
            "unexpected error: {err}"
        );
    }
}
