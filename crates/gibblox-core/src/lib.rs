#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{boxed::Box, string::String};
use async_trait::async_trait;
use core::fmt;

mod erofs;

pub use erofs::EroBlockReader;
pub use erofs_rs;

pub type GibbloxResult<T> = core::result::Result<T, GibbloxError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GibbloxErrorKind {
    InvalidInput,
    OutOfRange,
    Io,
    Unsupported,
    Other,
}

#[derive(Clone, Debug)]
pub struct GibbloxError {
    kind: GibbloxErrorKind,
    message: Option<String>,
}

impl GibbloxError {
    pub const fn new(kind: GibbloxErrorKind) -> Self {
        Self {
            kind,
            message: None,
        }
    }

    pub fn with_message(kind: GibbloxErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: Some(message.into()),
        }
    }

    pub fn kind(&self) -> GibbloxErrorKind {
        self.kind
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for GibbloxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(msg) => write!(f, "{:?}: {}", self.kind, msg),
            None => write!(f, "{:?}", self.kind),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GibbloxError {}

#[async_trait]
pub trait BlockReader: Send + Sync {
    /// Logical block size in bytes.
    fn block_size(&self) -> u32;

    /// Total number of logical blocks available.
    async fn total_blocks(&self) -> GibbloxResult<u64>;

    /// Read one or more blocks starting at `lba` into `buf`.
    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> GibbloxResult<usize>;
}
