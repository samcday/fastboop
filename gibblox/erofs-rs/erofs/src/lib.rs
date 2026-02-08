#![cfg_attr(not(feature = "std"), no_std)]

//! A pure Rust library for reading EROFS (Enhanced Read-Only File System) images.
//!
//! EROFS is a read-only filesystem designed for performance and space efficiency,
//! commonly used in Android and other embedded systems.
//!
//! # Example
//!
//! ```no_run
//! use erofs_rs::EroFS;
//! use erofs_rs::ReadAt;
//! use alloc::sync::Arc;
//!
//! # struct MemReader(Arc<[u8]>);
//! # #[async_trait::async_trait]
//! # impl ReadAt for MemReader {
//! #   async fn read_at(&self, offset: u64, buf: &mut [u8]) -> erofs_rs::Result<usize> {
//! #     let offset = offset as usize;
//! #     let end = (offset + buf.len()).min(self.0.len());
//! #     let n = end.saturating_sub(offset);
//! #     buf[..n].copy_from_slice(&self.0[offset..offset + n]);
//! #     Ok(n)
//! #   }
//! # }
//! # async fn demo(bytes: Arc<[u8]>) -> erofs_rs::Result<()> {
//! let fs = EroFS::from_image(MemReader(bytes), 0).await?;
//!
//! // Read a file
//! let mut file = fs.open_path("/etc/passwd").await?;
//! let mut content = String::new();
//! # let mut out = vec![0u8; 64];
//! # let _ = file.read_into(&mut out).await?;
//! # Ok(())
//! # }
//! ```

extern crate alloc;

mod dirent;
mod error;
pub mod file;
pub mod filesystem;
mod image;
mod read;
pub mod types;

pub use dirent::DirEntry;
pub use error::*;
pub use filesystem::EroFS;
pub use image::ReadAt;
