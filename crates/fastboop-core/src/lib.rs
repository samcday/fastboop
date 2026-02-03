#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod bootimg;
pub mod devpro;
pub mod fastboot;
pub mod personalization;

use alloc::{string::String, vec::Vec};

pub use devpro::*;
pub use personalization::*;

/// Newline-separated list of modules to load, in deterministic order.
pub type ModuleLoadList = Vec<String>;

/// Minimal VFS-like access to a rootfs.
pub trait RootfsProvider {
    type Error;

    /// Read the full contents of a file at `path` (absolute or relative to rootfs).
    fn read_all(&self, path: &str) -> Result<alloc::vec::Vec<u8>, Self::Error>;

    /// Read a range of bytes from a file at `path`.
    fn read_range(
        &self,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<alloc::vec::Vec<u8>, Self::Error>;

    /// List entries (file/dir names) in a directory at `path`.
    fn read_dir(&self, path: &str) -> Result<alloc::vec::Vec<String>, Self::Error>;

    /// Check if a path exists.
    fn exists(&self, path: &str) -> Result<bool, Self::Error>;
}
