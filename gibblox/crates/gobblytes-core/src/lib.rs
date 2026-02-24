#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

use alloc::{
    collections::{BTreeMap, VecDeque},
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemEntryType {
    File,
    Directory,
    Symlink,
    Other,
}

/// Minimal VFS-like access to a filesystem tree.
pub trait Filesystem {
    type Error;

    /// Read the full contents of a file at `path` (absolute or relative to root).
    async fn read_all(&self, path: &str) -> Result<Vec<u8>, Self::Error>;

    /// Read a range of bytes from a file at `path`.
    async fn read_range(&self, path: &str, offset: u64, len: usize)
    -> Result<Vec<u8>, Self::Error>;

    /// List entries (file/dir names) in a directory at `path`.
    async fn read_dir(&self, path: &str) -> Result<Vec<String>, Self::Error>;

    /// Return entry type for a path without following symlinks.
    ///
    /// Returns `Ok(None)` when the path does not exist.
    async fn entry_type(&self, path: &str) -> Result<Option<FilesystemEntryType>, Self::Error>;

    /// Read symlink target bytes as UTF-8 text.
    ///
    /// Implementations should return an error when `path` is not a symlink.
    async fn read_link(&self, path: &str) -> Result<String, Self::Error>;

    /// Check if a path exists.
    async fn exists(&self, path: &str) -> Result<bool, Self::Error>;
}

const MAX_SYMLINK_HOPS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OstreeError {
    message: String,
}

impl OstreeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for OstreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[derive(Clone)]
pub struct OstreeFs<P> {
    inner: P,
    deployment_root: String,
}

pub fn normalize_ostree_deployment_path(path: &str) -> Result<String, OstreeError> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(OstreeError::new("ostree path is empty"));
    }

    let mut components = Vec::new();
    for component in trimmed.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                return Err(OstreeError::new(format!(
                    "ostree path must not contain '..': {trimmed}"
                )));
            }
            _ => components.push(component.to_string()),
        }
    }

    if components.is_empty() {
        return Err(OstreeError::new("ostree path resolves to root or empty"));
    }

    Ok(components.join("/"))
}

fn split_non_parent_components(path: &str) -> Result<Vec<String>, OstreeError> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(OstreeError::new("path is empty"));
    }

    let mut components = Vec::new();
    for component in trimmed.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                return Err(OstreeError::new(format!(
                    "path must not contain '..': {trimmed}"
                )));
            }
            _ => components.push(component.to_string()),
        }
    }
    Ok(components)
}

fn apply_path_target(base: &mut Vec<String>, target: &str) -> Result<(), OstreeError> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err(OstreeError::new("symlink target is empty"));
    }

    if trimmed.starts_with('/') {
        base.clear();
    }

    for component in trimmed.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                base.pop();
            }
            _ => base.push(component.to_string()),
        }
    }

    Ok(())
}

impl<P> OstreeFs<P> {
    pub fn new(inner: P, deployment_path: &str) -> Result<Self, OstreeError> {
        let deployment_root = normalize_ostree_deployment_path(deployment_path)?;
        Ok(Self {
            inner,
            deployment_root,
        })
    }

    fn map_path(&self, path: &str) -> String {
        let suffix = path.trim().trim_start_matches('/');
        if suffix.is_empty() {
            format!("/{}", self.deployment_root)
        } else {
            format!("/{}/{}", self.deployment_root, suffix)
        }
    }
}

impl<P> OstreeFs<P>
where
    P: Filesystem,
    P::Error: fmt::Display,
{
    pub async fn resolve_deployment_path(
        inner: &P,
        deployment_path: &str,
    ) -> Result<String, OstreeError> {
        let normalized = normalize_ostree_deployment_path(deployment_path)?;
        let normalized_abs = format!("/{normalized}");
        let mut remaining = split_non_parent_components(&normalized_abs)?
            .into_iter()
            .collect::<VecDeque<_>>();
        let mut resolved = Vec::new();
        let mut symlink_hops = 0usize;

        while let Some(component) = remaining.pop_front() {
            resolved.push(component);
            let current_path = format!("/{}", resolved.join("/"));
            let entry_type = inner
                .entry_type(&current_path)
                .await
                .map_err(|err| OstreeError::new(format!("read entry type {current_path}: {err}")))?
                .ok_or_else(|| OstreeError::new(format!("missing path {current_path}")))?;

            if entry_type != FilesystemEntryType::Symlink {
                continue;
            }

            symlink_hops += 1;
            if symlink_hops > MAX_SYMLINK_HOPS {
                return Err(OstreeError::new(format!(
                    "symlink resolution exceeded {MAX_SYMLINK_HOPS} hops for {deployment_path}"
                )));
            }

            let link_target = inner.read_link(&current_path).await.map_err(|err| {
                OstreeError::new(format!("read symlink target {current_path}: {err}"))
            })?;
            resolved.pop();
            apply_path_target(&mut resolved, &link_target)?;

            let mut rewritten = resolved.into_iter().collect::<VecDeque<_>>();
            rewritten.extend(remaining.into_iter());
            remaining = rewritten;
            resolved = Vec::new();
        }

        let resolved_path = if resolved.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", resolved.join("/"))
        };
        let resolved_type = inner
            .entry_type(&resolved_path)
            .await
            .map_err(|err| OstreeError::new(format!("read entry type {resolved_path}: {err}")))?
            .ok_or_else(|| {
                OstreeError::new(format!(
                    "resolved ostree path does not exist: {resolved_path}"
                ))
            })?;
        if resolved_type != FilesystemEntryType::Directory {
            return Err(OstreeError::new(format!(
                "resolved ostree path is not a directory: {resolved_path}"
            )));
        }
        normalize_ostree_deployment_path(&resolved_path)
    }
}

impl<P> Filesystem for OstreeFs<P>
where
    P: Filesystem,
{
    type Error = P::Error;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>, Self::Error> {
        let mapped = self.map_path(path);
        self.inner.read_all(&mapped).await
    }

    async fn read_range(
        &self,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        let mapped = self.map_path(path);
        self.inner.read_range(&mapped, offset, len).await
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>, Self::Error> {
        let mapped = self.map_path(path);
        self.inner.read_dir(&mapped).await
    }

    async fn entry_type(&self, path: &str) -> Result<Option<FilesystemEntryType>, Self::Error> {
        let mapped = self.map_path(path);
        self.inner.entry_type(&mapped).await
    }

    async fn read_link(&self, path: &str) -> Result<String, Self::Error> {
        let mapped = self.map_path(path);
        self.inner.read_link(&mapped).await
    }

    async fn exists(&self, path: &str) -> Result<bool, Self::Error> {
        let mapped = self.map_path(path);
        self.inner.exists(&mapped).await
    }
}

#[derive(Clone, Debug, Default)]
pub struct MockFilesystem {
    entry_types: BTreeMap<String, FilesystemEntryType>,
    directories: BTreeMap<String, Vec<String>>,
    files: BTreeMap<String, Vec<u8>>,
    symlinks: BTreeMap<String, String>,
}

impl MockFilesystem {
    pub fn add_dir(&mut self, path: &str, entries: &[&str]) {
        self.entry_types
            .insert(path.to_string(), FilesystemEntryType::Directory);
        self.directories.insert(
            path.to_string(),
            entries.iter().map(|entry| (*entry).to_string()).collect(),
        );
    }

    pub fn add_file(&mut self, path: &str, data: &[u8]) {
        self.entry_types
            .insert(path.to_string(), FilesystemEntryType::File);
        self.files.insert(path.to_string(), data.to_vec());
    }

    pub fn add_symlink(&mut self, path: &str) {
        self.add_symlink_target(path, ".");
    }

    pub fn add_symlink_target(&mut self, path: &str, target: &str) {
        self.entry_types
            .insert(path.to_string(), FilesystemEntryType::Symlink);
        self.symlinks.insert(path.to_string(), target.to_string());
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MockFilesystemError {
    MissingPath(String),
    MissingDirectory(String),
    NotASymlink(String),
    OffsetOverflow(String),
}

impl fmt::Display for MockFilesystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPath(path) => write!(f, "missing path {path}"),
            Self::MissingDirectory(path) => write!(f, "missing directory {path}"),
            Self::NotASymlink(path) => write!(f, "path is not a symlink: {path}"),
            Self::OffsetOverflow(path) => write!(f, "range offset exceeds usize for {path}"),
        }
    }
}

impl Filesystem for MockFilesystem {
    type Error = MockFilesystemError;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>, Self::Error> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| MockFilesystemError::MissingPath(path.to_string()))
    }

    async fn read_range(
        &self,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        let data = self
            .files
            .get(path)
            .ok_or_else(|| MockFilesystemError::MissingPath(path.to_string()))?;
        let offset = usize::try_from(offset)
            .map_err(|_| MockFilesystemError::OffsetOverflow(path.to_string()))?;
        if offset >= data.len() {
            return Ok(Vec::new());
        }
        let end = (offset.saturating_add(len)).min(data.len());
        Ok(data[offset..end].to_vec())
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>, Self::Error> {
        self.directories
            .get(path)
            .cloned()
            .ok_or_else(|| MockFilesystemError::MissingDirectory(path.to_string()))
    }

    async fn entry_type(&self, path: &str) -> Result<Option<FilesystemEntryType>, Self::Error> {
        Ok(self.entry_types.get(path).copied())
    }

    async fn read_link(&self, path: &str) -> Result<String, Self::Error> {
        self.symlinks
            .get(path)
            .cloned()
            .ok_or_else(|| MockFilesystemError::NotASymlink(path.to_string()))
    }

    async fn exists(&self, path: &str) -> Result<bool, Self::Error> {
        Ok(self.entry_types.contains_key(path) || self.directories.contains_key(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use futures::executor::block_on;

    #[test]
    fn normalize_ostree_path_removes_root_prefix_and_dots() {
        let path = normalize_ostree_deployment_path(" /ostree//boot.1/./fedora/123/0/ ").unwrap();
        assert_eq!(path, "ostree/boot.1/fedora/123/0");
    }

    #[test]
    fn normalize_ostree_path_rejects_parent_components() {
        let err = normalize_ostree_deployment_path("/ostree/../etc").unwrap_err();
        assert!(err.to_string().contains("must not contain '..'"));
    }

    #[test]
    fn apply_path_target_handles_relative_parent_segments() {
        let mut base = vec![
            "ostree".to_string(),
            "boot.1.1".to_string(),
            "live-pocket-fedora".to_string(),
            "bootcsum".to_string(),
        ];
        apply_path_target(
            &mut base,
            "../../../deploy/live-pocket-fedora/deploy/deadbeef.0",
        )
        .unwrap();
        assert_eq!(
            base,
            vec![
                "ostree".to_string(),
                "deploy".to_string(),
                "live-pocket-fedora".to_string(),
                "deploy".to_string(),
                "deadbeef.0".to_string()
            ]
        );
    }

    #[test]
    fn apply_path_target_replaces_base_on_absolute_targets() {
        let mut base = vec!["ostree".to_string(), "boot.1".to_string()];
        apply_path_target(&mut base, "/ostree/deploy/live-pocket-fedora").unwrap();
        assert_eq!(
            base,
            vec![
                "ostree".to_string(),
                "deploy".to_string(),
                "live-pocket-fedora".to_string()
            ]
        );
    }

    #[test]
    fn ostree_decorator_maps_paths_into_deployment_root() {
        let rootfs =
            OstreeFs::new(MockFilesystem::default(), "/ostree/boot.1/fedora/abc123/0").unwrap();
        assert_eq!(
            rootfs.map_path("/lib/modules"),
            "/ostree/boot.1/fedora/abc123/0/lib/modules"
        );
        assert_eq!(
            rootfs.map_path("usr/lib/modules"),
            "/ostree/boot.1/fedora/abc123/0/usr/lib/modules"
        );
        assert_eq!(rootfs.map_path("/"), "/ostree/boot.1/fedora/abc123/0");
    }

    #[test]
    fn resolve_deployment_path_follows_relative_symlink() {
        let mut fs = MockFilesystem::default();
        fs.add_dir("/ostree", &["boot.1", "deploy"]);
        fs.add_dir("/ostree/boot.1", &["fedora"]);
        fs.add_dir("/ostree/boot.1/fedora", &["abc"]);
        fs.add_dir("/ostree/boot.1/fedora/abc", &["0"]);
        fs.add_symlink_target(
            "/ostree/boot.1/fedora/abc/0",
            "../../../deploy/fedora/deploy/deadbeef.0",
        );
        fs.add_dir("/ostree/deploy", &["fedora"]);
        fs.add_dir("/ostree/deploy/fedora", &["deploy"]);
        fs.add_dir("/ostree/deploy/fedora/deploy", &["deadbeef.0"]);
        fs.add_dir("/ostree/deploy/fedora/deploy/deadbeef.0", &[]);

        let resolved = block_on(OstreeFs::resolve_deployment_path(
            &fs,
            "/ostree/boot.1/fedora/abc/0",
        ))
        .unwrap();
        assert_eq!(resolved, "ostree/deploy/fedora/deploy/deadbeef.0");
    }
}
