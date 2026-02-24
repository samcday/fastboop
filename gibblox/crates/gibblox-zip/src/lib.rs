#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    sync::Arc,
};
use async_trait::async_trait;
use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
use tracing::trace;

mod zip;

use zip::archive::locate_entry;
use zip::bytes::ByteReader;

const STORED_COMPRESSION_METHOD: u16 = 0;

/// Block reader that exposes a single file entry from a ZIP archive.
pub struct ZipEntryBlockReader {
    block_size: u32,
    entry_name: String,
    entry_size_bytes: u64,
    entry_data_offset: u64,
    source: Arc<dyn BlockReader>,
    byte_reader: ByteReader,
}

impl ZipEntryBlockReader {
    /// Open `entry_name` from a ZIP archive exposed through `source`.
    pub async fn new(entry_name: &str, source: Arc<dyn BlockReader>) -> GibbloxResult<Self> {
        let entry_name = normalize_entry_name(entry_name)?;

        let source_block_size = source.block_size();
        if source_block_size == 0 || !source_block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "source block size must be non-zero power of two",
            ));
        }

        let total_blocks = source.total_blocks().await?;
        let archive_size_bytes = total_blocks
            .checked_mul(source_block_size as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "zip archive size overflow",
                )
            })?;

        let byte_reader = ByteReader::new(
            Arc::clone(&source),
            source_block_size as usize,
            archive_size_bytes,
        );
        let entry = locate_entry(&byte_reader, archive_size_bytes, &entry_name)
            .await
            .map_err(GibbloxError::from)?;

        if entry.compression_method != STORED_COMPRESSION_METHOD {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Unsupported,
                format!(
                    "ZIP entry '{}' compression method {} is unsupported (required: 0/store)",
                    entry.name, entry.compression_method
                ),
            ));
        }

        Ok(Self {
            block_size: source_block_size,
            entry_name: entry.name,
            entry_size_bytes: entry.size_bytes,
            entry_data_offset: entry.data_offset,
            source,
            byte_reader,
        })
    }

    pub fn entry_size_bytes(&self) -> u64 {
        self.entry_size_bytes
    }
}

#[async_trait]
impl BlockReader for ZipEntryBlockReader {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        Ok(self.entry_size_bytes.div_ceil(self.block_size as u64))
    }

    fn write_identity(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
        out.write_str("zip-entry:(")?;
        self.source.write_identity(out)?;
        write!(
            out,
            "):{}@{}+{}:{}+{}",
            self.entry_name,
            self.entry_data_offset,
            self.entry_size_bytes,
            STORED_COMPRESSION_METHOD,
            self.entry_size_bytes
        )
    }

    async fn read_blocks(
        &self,
        lba: u64,
        buf: &mut [u8],
        ctx: ReadContext,
    ) -> GibbloxResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !buf.len().is_multiple_of(self.block_size as usize) {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "buffer length must align to block size",
            ));
        }

        let offset = lba.checked_mul(self.block_size as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
        })?;
        if offset >= self.entry_size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "requested block out of range",
            ));
        }

        let read_len = ((buf.len() as u64).min(self.entry_size_bytes - offset)) as usize;
        trace!(
            lba,
            compression_method = STORED_COMPRESSION_METHOD,
            requested = buf.len(),
            read_len,
            "reading zip entry blocks"
        );

        let source_offset = self.entry_data_offset.checked_add(offset).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "zip entry offset overflow")
        })?;
        self.byte_reader
            .read_exact_at(source_offset, &mut buf[..read_len], ctx)
            .await?;

        if read_len < buf.len() {
            buf[read_len..].fill(0);
        }
        Ok(buf.len())
    }
}

fn normalize_entry_name(entry_name: &str) -> GibbloxResult<String> {
    let trimmed = entry_name.trim();
    if trimmed.is_empty() {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "zip entry name is empty",
        ));
    }
    if trimmed.starts_with('/') {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "zip entry name must be archive-relative",
        ));
    }
    if trimmed.contains('\0') {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "zip entry name contains NUL byte",
        ));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zip::bytes::ByteReader;
    use alloc::boxed::Box;
    use alloc::{vec, vec::Vec};
    use futures::executor::block_on;
    use std::sync::Mutex;

    struct FakeReader {
        block_size: u32,
        data: Vec<u8>,
    }

    #[async_trait]
    impl BlockReader for FakeReader {
        fn block_size(&self) -> u32 {
            self.block_size
        }

        async fn total_blocks(&self) -> GibbloxResult<u64> {
            Ok(self.data.len().div_ceil(self.block_size as usize) as u64)
        }

        fn write_identity(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
            write!(out, "fake-zip:{}:{}", self.block_size, self.data.len())
        }

        async fn read_blocks(
            &self,
            lba: u64,
            buf: &mut [u8],
            _ctx: ReadContext,
        ) -> GibbloxResult<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            if !buf.len().is_multiple_of(self.block_size as usize) {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "buffer length must align to block size",
                ));
            }
            let offset = (lba as usize)
                .checked_mul(self.block_size as usize)
                .ok_or_else(|| {
                    GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "offset overflow")
                })?;
            if offset >= self.data.len() {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "requested block out of range",
                ));
            }

            let read = (self.data.len() - offset).min(buf.len());
            buf[..read].copy_from_slice(&self.data[offset..offset + read]);
            if read < buf.len() {
                buf[read..].fill(0);
            }
            Ok(buf.len())
        }
    }

    #[test]
    fn zip_entry_reader_reads_and_zero_pads() {
        let archive = build_stored_zip("rootfs.ero", b"hello world", 0, 0);
        let reader = fake_reader(16, archive);

        let entry = block_on(ZipEntryBlockReader::new("rootfs.ero", reader))
            .expect("construct zip entry reader");
        assert_eq!(entry.entry_size_bytes(), 11);
        assert_eq!(block_on(entry.total_blocks()).expect("total blocks"), 1);

        let mut buf = vec![0u8; 16];
        let read =
            block_on(entry.read_blocks(0, &mut buf, ReadContext::FOREGROUND)).expect("read block");
        assert_eq!(read, 16);
        assert_eq!(&buf[..11], b"hello world");
        assert!(buf[11..].iter().all(|b| *b == 0));
    }

    #[test]
    fn zip_entry_reader_reports_missing_entry() {
        let archive = build_stored_zip("rootfs.ero", b"hello", 0, 0);
        let reader = fake_reader(32, archive);

        let err = block_on(ZipEntryBlockReader::new("missing.ero", reader))
            .err()
            .expect("missing entry should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::InvalidInput);
    }

    #[test]
    fn zip_entry_reader_rejects_unsupported_compression_method() {
        let archive = build_stored_zip("rootfs.ero", b"hello", 12, 0);
        let reader = fake_reader(32, archive);

        let err = block_on(ZipEntryBlockReader::new("rootfs.ero", reader))
            .err()
            .expect("unsupported method should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::Unsupported);
    }

    #[test]
    fn zip_entry_reader_handles_archive_padding_after_eocd() {
        let mut archive = build_stored_zip("rootfs.ero", b"abcdef", 0, 0);
        archive.extend_from_slice(&[0u8; 9]);

        let reader = fake_reader(8, archive);

        let entry = block_on(ZipEntryBlockReader::new("rootfs.ero", reader))
            .expect("construct zip entry reader");
        let mut buf = vec![0u8; 8];
        let read =
            block_on(entry.read_blocks(0, &mut buf, ReadContext::FOREGROUND)).expect("read block");
        assert_eq!(read, 8);
        assert_eq!(&buf[..6], b"abcdef");
        assert!(buf[6..].iter().all(|b| *b == 0));
    }

    #[test]
    fn byte_reader_coalesces_unaligned_large_reads() {
        struct RecordingReader {
            block_size: u32,
            data: Vec<u8>,
            requests: Arc<Mutex<Vec<(u64, usize)>>>,
        }

        #[async_trait]
        impl BlockReader for RecordingReader {
            fn block_size(&self) -> u32 {
                self.block_size
            }

            async fn total_blocks(&self) -> GibbloxResult<u64> {
                Ok(self.data.len().div_ceil(self.block_size as usize) as u64)
            }

            fn write_identity(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
                out.write_str("recording")
            }

            async fn read_blocks(
                &self,
                lba: u64,
                buf: &mut [u8],
                _ctx: ReadContext,
            ) -> GibbloxResult<usize> {
                self.requests
                    .lock()
                    .expect("lock request log")
                    .push((lba, buf.len()));
                let offset = (lba as usize)
                    .checked_mul(self.block_size as usize)
                    .ok_or_else(|| {
                        GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "offset overflow")
                    })?;
                let end = offset.checked_add(buf.len()).ok_or_else(|| {
                    GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "range overflow")
                })?;
                if end > self.data.len() {
                    return Err(GibbloxError::with_message(
                        GibbloxErrorKind::OutOfRange,
                        "read exceeds backing store",
                    ));
                }
                buf.copy_from_slice(&self.data[offset..end]);
                Ok(buf.len())
            }
        }

        let requests = Arc::new(Mutex::new(Vec::new()));
        let data = patterned_data(1024 * 1024);
        let source: Arc<dyn BlockReader> = Arc::new(RecordingReader {
            block_size: 512,
            data,
            requests: Arc::clone(&requests),
        });
        let reader = ByteReader::new(source, 512, 1024 * 1024);

        let mut out = vec![0u8; 64 * 1024];
        block_on(reader.read_exact_at(123, &mut out, ReadContext::FOREGROUND))
            .expect("read unaligned range");

        let calls = requests.lock().expect("lock request log");
        assert_eq!(calls.as_slice(), &[(0, 129 * 512)]);
    }

    fn fake_reader(block_size: u32, data: Vec<u8>) -> Arc<dyn BlockReader> {
        Arc::new(FakeReader { block_size, data })
    }

    fn patterned_data(len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        for (idx, byte) in out.iter_mut().enumerate() {
            *byte = ((idx * 31) % 251) as u8;
        }
        out
    }

    fn build_stored_zip(file_name: &str, payload: &[u8], method: u16, flags: u16) -> Vec<u8> {
        let len = payload.len() as u32;
        build_test_zip_with_entry(ZipTestEntry {
            file_name,
            local_payload: payload,
            method,
            flags,
            central_compressed_size: len,
            central_uncompressed_size: len,
            local_compressed_size: len,
            local_uncompressed_size: len,
            append_data_descriptor: false,
        })
    }

    struct ZipTestEntry<'a> {
        file_name: &'a str,
        local_payload: &'a [u8],
        method: u16,
        flags: u16,
        central_compressed_size: u32,
        central_uncompressed_size: u32,
        local_compressed_size: u32,
        local_uncompressed_size: u32,
        append_data_descriptor: bool,
    }

    fn build_test_zip_with_entry(spec: ZipTestEntry<'_>) -> Vec<u8> {
        let name = spec.file_name.as_bytes();
        let mut out = Vec::new();

        // Local file header
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&spec.flags.to_le_bytes());
        out.extend_from_slice(&spec.method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&spec.local_compressed_size.to_le_bytes());
        out.extend_from_slice(&spec.local_uncompressed_size.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(spec.local_payload);

        if spec.append_data_descriptor {
            out.extend_from_slice(&0x0807_4b50u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&spec.central_compressed_size.to_le_bytes());
            out.extend_from_slice(&spec.central_uncompressed_size.to_le_bytes());
        }

        let cd_offset = out.len() as u32;

        // Central directory file header
        out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&spec.flags.to_le_bytes());
        out.extend_from_slice(&spec.method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&spec.central_compressed_size.to_le_bytes());
        out.extend_from_slice(&spec.central_uncompressed_size.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(name);

        let cd_size = out.len() as u32 - cd_offset;

        // End of central directory
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());

        out
    }
}
