// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::error::BoxedError;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::error::Error;
use core::fmt::{self, Display, Formatter};

#[cfg(feature = "async")]
use async_trait::async_trait;

#[cfg(feature = "std")]
use {
    std::fs::File,
    std::io::{Seek, SeekFrom},
};

/// Interface used by [`Ext4`] to read the filesystem data from a storage
/// file or device.
///
/// [`Ext4`]: crate::Ext4
pub trait Ext4Read {
    /// Read bytes into `dst`, starting at `start_byte`.
    ///
    /// Exactly `dst.len()` bytes will be read; an error will be
    /// returned if there is not enough data to fill `dst`, or if the
    /// data cannot be read for any reason.
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), BoxedError>;
}

/// Async interface used by [`Ext4`] when loading from async-first sources.
///
/// [`Ext4`]: crate::Ext4
#[cfg(feature = "async")]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
#[async_trait(?Send)]
pub trait Ext4ReadAsync {
    /// Read bytes into `dst`, starting at `start_byte`.
    ///
    /// Exactly `dst.len()` bytes must be read. Return an error if the
    /// source cannot provide that data.
    async fn read(
        &self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), BoxedError>;
}

#[cfg(feature = "async")]
pub(crate) struct BlockingAsyncReader {
    inner: Box<dyn Ext4ReadAsync>,
}

#[cfg(feature = "async")]
impl BlockingAsyncReader {
    pub(crate) fn new(inner: Box<dyn Ext4ReadAsync>) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "async")]
impl Ext4Read for BlockingAsyncReader {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), BoxedError> {
        pollster::block_on(self.inner.read(start_byte, dst))
    }
}

#[cfg(feature = "std")]
impl Ext4Read for File {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), BoxedError> {
        use std::io::Read;

        self.seek(SeekFrom::Start(start_byte)).map_err(Box::new)?;
        self.read_exact(dst).map_err(Box::new)?;
        Ok(())
    }
}

/// Error type used by the [`Vec<u8>`] impl of [`Ext4Read`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemIoError {
    start: u64,
    read_len: usize,
    src_len: usize,
}

impl Display for MemIoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to read {} bytes at offset {} from a slice of length {}",
            self.read_len, self.start, self.src_len
        )
    }
}

impl Error for MemIoError {}

impl Ext4Read for Vec<u8> {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), BoxedError> {
        read_from_bytes(self, start_byte, dst).ok_or_else(|| {
            Box::new(MemIoError {
                start: start_byte,
                read_len: dst.len(),
                src_len: self.len(),
            })
            .into()
        })
    }
}

#[cfg(feature = "async")]
#[async_trait(?Send)]
impl Ext4ReadAsync for Vec<u8> {
    async fn read(
        &self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), BoxedError> {
        read_from_bytes(self, start_byte, dst).ok_or_else(|| {
            Box::new(MemIoError {
                start: start_byte,
                read_len: dst.len(),
                src_len: self.len(),
            })
            .into()
        })
    }
}

fn read_from_bytes(src: &[u8], start_byte: u64, dst: &mut [u8]) -> Option<()> {
    let start = usize::try_from(start_byte).ok()?;
    let end = start.checked_add(dst.len())?;
    let src = src.get(start..end)?;
    dst.copy_from_slice(src);

    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vec_read() {
        let mut src = vec![1, 2, 3];

        let mut dst = [0; 3];
        Ext4Read::read(&mut src, 0, &mut dst).unwrap();
        assert_eq!(dst, [1, 2, 3]);

        let mut dst = [0; 2];
        Ext4Read::read(&mut src, 1, &mut dst).unwrap();
        assert_eq!(dst, [2, 3]);

        let err = Ext4Read::read(&mut src, 4, &mut dst).unwrap_err();
        assert_eq!(
            format!("{err}"),
            format!(
                "failed to read 2 bytes at offset 4 from a slice of length 3"
            )
        );
    }

    #[cfg(feature = "async")]
    #[test]
    fn test_vec_read_async() {
        let src = vec![1, 2, 3];

        let mut dst = [0; 2];
        pollster::block_on(Ext4ReadAsync::read(&src, 1, &mut dst)).unwrap();
        assert_eq!(dst, [2, 3]);

        let err = pollster::block_on(Ext4ReadAsync::read(&src, 4, &mut dst))
            .unwrap_err();
        assert_eq!(
            format!("{err}"),
            format!(
                "failed to read 2 bytes at offset 4 from a slice of length 3"
            )
        );
    }
}
