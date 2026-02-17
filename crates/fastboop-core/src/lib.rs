#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod block_reader;
pub mod bootimg;
pub mod bootprofile;
pub mod builtin;
pub mod device;
pub mod devpro;
pub mod fastboot;
pub mod personalization;
pub mod prober;

use alloc::{string::String, vec::Vec};

pub use block_reader::*;
pub use bootprofile::*;
pub use device::*;
pub use devpro::*;
pub use personalization::*;
pub use prober::*;

/// Newline-separated list of modules to load, in deterministic order.
pub type ModuleLoadList = Vec<String>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootfsEntryType {
    File,
    Directory,
    Symlink,
    Other,
}

/// Minimal VFS-like access to a rootfs.
pub trait RootfsProvider {
    type Error;

    /// Read the full contents of a file at `path` (absolute or relative to rootfs).
    async fn read_all(&self, path: &str) -> Result<alloc::vec::Vec<u8>, Self::Error>;

    /// Read a range of bytes from a file at `path`.
    async fn read_range(
        &self,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<alloc::vec::Vec<u8>, Self::Error>;

    /// List entries (file/dir names) in a directory at `path`.
    async fn read_dir(&self, path: &str) -> Result<alloc::vec::Vec<String>, Self::Error>;

    /// Return entry type for a path without following symlinks.
    ///
    /// Returns `Ok(None)` when the path does not exist.
    async fn entry_type(&self, path: &str) -> Result<Option<RootfsEntryType>, Self::Error>;

    /// Read symlink target bytes as UTF-8 text.
    ///
    /// Implementations should return an error when `path` is not a symlink.
    async fn read_link(&self, path: &str) -> Result<String, Self::Error>;

    /// Check if a path exists.
    async fn exists(&self, path: &str) -> Result<bool, Self::Error>;
}
