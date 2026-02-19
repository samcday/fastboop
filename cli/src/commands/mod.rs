use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use fastboop_core::fastboot::{FastbootProtocolError, ProbeError};
use fastboop_core::{RootfsEntryType, RootfsProvider};
use fastboop_rootfs_erofs::{DEFAULT_IMAGE_BLOCK_SIZE, normalize_ostree_deployment_path};
use gibblox_cache::CachedBlockReader;
use gibblox_cache_store_std::StdCacheOps;
use gibblox_casync::{CasyncBlockReader, CasyncReaderConfig};
use gibblox_casync_std::{
    StdCasyncChunkStore, StdCasyncChunkStoreConfig, StdCasyncChunkStoreLocator,
    StdCasyncIndexLocator, StdCasyncIndexSource,
};
use gibblox_core::{BlockReader, ReadContext};
use gibblox_file::StdFileBlockReader;
use gibblox_http::HttpBlockReader;
use tracing::info;
use url::Url;

mod boot;
mod detect;
mod stage0;

pub use boot::{BootArgs, run_boot};
pub use detect::{DetectArgs, run_detect};
pub use stage0::{Stage0Args, run_stage0};

pub(crate) async fn open_rootfs_block_reader(rootfs: &Path) -> Result<Arc<dyn BlockReader>> {
    let rootfs_str = rootfs.to_string_lossy();
    if rootfs_str.ends_with(".caidx") {
        bail!(
            "casync archive indexes (.caidx) are not supported for rootfs block reads; provide a casync blob index (.caibx)"
        );
    }

    if rootfs_str.starts_with("http://") || rootfs_str.starts_with("https://") {
        let url =
            Url::parse(&rootfs_str).with_context(|| format!("parse rootfs URL {rootfs_str}"))?;

        if url.path().ends_with(".caibx") {
            info!(index_url = %url, "using casync blob-index rootfs reader pipeline");
            return open_casync_reader(url).await;
        }

        let http_reader = HttpBlockReader::new(url.clone(), DEFAULT_IMAGE_BLOCK_SIZE)
            .await
            .map_err(|err| anyhow!("open HTTP reader {url}: {err}"))?;
        let cache = StdCacheOps::open_default_for_reader(&http_reader)
            .await
            .map_err(|err| anyhow!("open std cache: {err}"))?;
        let cached = CachedBlockReader::new(http_reader, cache)
            .await
            .map_err(|err| anyhow!("initialize std cache: {err}"))?;
        return Ok(Arc::new(cached));
    }

    let canonical =
        fs::canonicalize(rootfs).with_context(|| format!("canonicalize {}", rootfs.display()))?;
    let file_reader = StdFileBlockReader::open(&canonical, DEFAULT_IMAGE_BLOCK_SIZE)
        .map_err(|err| anyhow!("open file {}: {err}", canonical.display()))?;
    Ok(Arc::new(file_reader))
}

async fn open_casync_reader(index_url: Url) -> Result<Arc<dyn BlockReader>> {
    let index_source = StdCasyncIndexSource::new(StdCasyncIndexLocator::url(index_url.clone()))
        .map_err(|err| anyhow!("open casync index source {index_url}: {err}"))?;

    let chunk_store_url = derive_casync_chunk_store_url(&index_url)?;
    info!(
        index_url = %index_url,
        chunk_store_url = %chunk_store_url,
        "resolved casync chunk store URL"
    );

    let chunk_locator = StdCasyncChunkStoreLocator::url_prefix(chunk_store_url.clone())
        .map_err(|err| anyhow!("configure casync chunk store URL {chunk_store_url}: {err}"))?;
    let mut chunk_store_config = StdCasyncChunkStoreConfig::new(chunk_locator);
    chunk_store_config.cache_dir = Some(default_casync_cache_dir());
    let chunk_store = StdCasyncChunkStore::new(chunk_store_config)
        .map_err(|err| anyhow!("build casync chunk store: {err}"))?;

    let reader = CasyncBlockReader::open(
        index_source,
        chunk_store,
        CasyncReaderConfig {
            block_size: DEFAULT_IMAGE_BLOCK_SIZE,
            strict_verify: false,
        },
    )
    .await
    .map_err(|err| anyhow!("open casync reader {index_url}: {err}"))?;

    if !casync_blob_looks_like_erofs(&reader).await? {
        bail!(
            "casync blob index does not reference a raw EROFS image: {index_url}; expected EROFS superblock magic"
        );
    }
    Ok(Arc::new(reader))
}

async fn casync_blob_looks_like_erofs<R: BlockReader + ?Sized>(reader: &R) -> Result<bool> {
    const EROFS_SUPER_OFFSET: u64 = 1024;
    const EROFS_SUPER_MAGIC: u32 = 0xe0f5_e1e2;

    let block_size = reader.block_size() as u64;
    let total_blocks = reader.total_blocks().await?;
    let total_bytes = total_blocks
        .checked_mul(block_size)
        .ok_or_else(|| anyhow!("casync blob size overflow"))?;
    if total_bytes < EROFS_SUPER_OFFSET + 4 {
        return Ok(false);
    }

    let super_lba = EROFS_SUPER_OFFSET / block_size;
    let within_block = (EROFS_SUPER_OFFSET % block_size) as usize;
    let block_size_usize = block_size as usize;
    let required = within_block + 4;
    let blocks_to_read = required.div_ceil(block_size_usize);
    let mut scratch = vec![0u8; blocks_to_read * block_size_usize];
    let read = reader
        .read_blocks(super_lba, &mut scratch, ReadContext::FOREGROUND)
        .await?;
    if read < required {
        return Ok(false);
    }

    let magic = u32::from_le_bytes([
        scratch[within_block],
        scratch[within_block + 1],
        scratch[within_block + 2],
        scratch[within_block + 3],
    ]);
    Ok(magic == EROFS_SUPER_MAGIC)
}

fn derive_casync_chunk_store_url(index_url: &Url) -> Result<Url> {
    if let Some(segments) = index_url.path_segments() {
        let segments: Vec<&str> = segments.collect();
        if let Some(index_pos) = segments.iter().rposition(|segment| *segment == "indexes") {
            let mut base_segments = segments[..=index_pos].to_vec();
            base_segments[index_pos] = "chunks";
            let mut url = index_url.clone();
            let mut path = String::from("/");
            path.push_str(&base_segments.join("/"));
            if !path.ends_with('/') {
                path.push('/');
            }
            url.set_path(&path);
            url.set_query(None);
            url.set_fragment(None);
            return Ok(url);
        }
    }

    index_url
        .join("./")
        .with_context(|| format!("derive casync chunk store URL from {index_url}"))
}

fn default_casync_cache_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME") {
        if !path.is_empty() {
            return PathBuf::from(path).join("gibblox").join("casync");
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(path) = std::env::var_os("LOCALAPPDATA") {
            if !path.is_empty() {
                return PathBuf::from(path).join("gibblox").join("casync");
            }
        }
    }

    if let Some(path) = std::env::var_os("HOME") {
        if !path.is_empty() {
            return PathBuf::from(path)
                .join(".cache")
                .join("gibblox")
                .join("casync");
        }
    }

    std::env::temp_dir().join("gibblox").join("casync")
}

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
