#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use async_trait::async_trait;
use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
use tracing::{info, trace};

const ISO_SECTOR_SIZE: usize = 2048;
const PVD_SECTOR: u64 = 16;
const VD_MAGIC: &[u8; 5] = b"CD001";
const VD_VERSION: u8 = 1;

/// File-backed block reader sourced from a file inside an ISO9660 image.
pub struct IsoFileBlockReader {
    block_size: u32,
    file_size_bytes: u64,
    file_path: String,
    file_offset_bytes: u64,
    source_size_bytes: u64,
    source: Arc<dyn BlockReader>,
    source_block_size: usize,
}

impl IsoFileBlockReader {
    /// Build a block reader for `path` from an ISO9660 image exposed through `BlockReader`.
    pub async fn new<S: BlockReader + 'static>(
        source: S,
        path: &str,
        block_size: u32,
    ) -> GibbloxResult<Self> {
        info!(path, block_size, "constructing ISO9660-backed reader");
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "block size must be non-zero power of two",
            ));
        }

        let source_block_size = source.block_size();
        if source_block_size == 0 || !source_block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "source block size must be non-zero power of two",
            ));
        }

        let source_total_blocks = source.total_blocks().await?;
        let source_size_bytes = source_total_blocks
            .checked_mul(source_block_size as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "image size overflow")
            })?;

        let source: Arc<dyn BlockReader> = Arc::new(source);
        let byte_reader = SourceByteReader {
            inner: Arc::clone(&source),
            block_size: source_block_size as usize,
            size_bytes: source_size_bytes,
        };

        let mut pvd = [0u8; ISO_SECTOR_SIZE];
        byte_reader
            .read_exact_at(PVD_SECTOR * ISO_SECTOR_SIZE as u64, &mut pvd)
            .await?;
        if pvd[0] != 1 || &pvd[1..6] != VD_MAGIC || pvd[6] != VD_VERSION {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "ISO9660 primary volume descriptor not found",
            ));
        }

        let logical_block_size = parse_u16_both_endian(&pvd[128..132])? as u64;
        if logical_block_size == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "ISO9660 logical block size is zero",
            ));
        }

        let root_len = pvd[156] as usize;
        if root_len == 0 || 156 + root_len > pvd.len() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "invalid ISO9660 root directory record",
            ));
        }
        let root = parse_dir_record(&pvd[156..156 + root_len])?;
        if !root.is_dir() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "ISO9660 root entry is not a directory",
            ));
        }

        let identity_path = normalize_identity_path(path)?;
        let target = resolve_path(&byte_reader, logical_block_size, &root, path).await?;
        if target.is_dir() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "path is not a regular file",
            ));
        }
        if (target.flags & 0x80) != 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Unsupported,
                "multi-extent ISO9660 files are unsupported",
            ));
        }

        let file_offset_bytes = (target.extent_lba as u64)
            .checked_mul(logical_block_size)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "file offset overflow")
            })?;
        let file_size_bytes = target.data_len as u64;
        let file_end = file_offset_bytes
            .checked_add(file_size_bytes)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "file range overflow")
            })?;
        if file_end > source_size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "file range exceeds source image",
            ));
        }

        info!(path, file_size_bytes, "resolved file inode from ISO9660");
        Ok(Self {
            block_size,
            file_size_bytes,
            file_path: identity_path,
            file_offset_bytes,
            source_size_bytes,
            source,
            source_block_size: source_block_size as usize,
        })
    }

    pub fn file_size_bytes(&self) -> u64 {
        self.file_size_bytes
    }
}

#[async_trait]
impl BlockReader for IsoFileBlockReader {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        Ok(self.file_size_bytes.div_ceil(self.block_size as u64))
    }

    fn write_identity(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
        out.write_str("iso-file:(")?;
        self.source.write_identity(out)?;
        write!(out, "):{}", self.file_path)
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

        let offset = lba.checked_mul(self.block_size as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
        })?;
        if offset >= self.file_size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "requested block out of range",
            ));
        }

        let read_len = ((buf.len() as u64).min(self.file_size_bytes - offset)) as usize;
        let source_offset = self.file_offset_bytes.checked_add(offset).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "offset overflow")
        })?;
        let byte_reader = SourceByteReader {
            inner: Arc::clone(&self.source),
            block_size: self.source_block_size,
            size_bytes: self.source_size_bytes,
        };

        trace!(
            lba,
            offset,
            requested = buf.len(),
            "reading file blocks from ISO9660"
        );
        byte_reader
            .read_exact_at(source_offset, &mut buf[..read_len])
            .await?;
        if read_len < buf.len() {
            buf[read_len..].fill(0);
        }
        Ok(buf.len())
    }
}

#[derive(Clone)]
struct SourceByteReader {
    inner: Arc<dyn BlockReader>,
    block_size: usize,
    size_bytes: u64,
}

impl SourceByteReader {
    async fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> GibbloxResult<()> {
        if out.is_empty() {
            return Ok(());
        }
        let end = offset.checked_add(out.len() as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "range overflow")
        })?;
        if end > self.size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "read range exceeds source size",
            ));
        }

        let bs = self.block_size as u64;
        let aligned_start = (offset / bs) * bs;
        let aligned_end = end.div_ceil(bs) * bs;
        let aligned_len = (aligned_end - aligned_start) as usize;

        let mut scratch = vec![0u8; aligned_len];
        let mut filled = 0usize;
        while filled < scratch.len() {
            let lba = (aligned_start as usize + filled) / self.block_size;
            let read = self
                .inner
                .read_blocks(lba as u64, &mut scratch[filled..], ReadContext::FOREGROUND)
                .await?;
            if read == 0 {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    "unexpected EOF while servicing aligned read",
                ));
            }
            if read % self.block_size != 0 && filled + read < scratch.len() {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    "unaligned short read from block source",
                ));
            }
            filled += read;
        }

        let head = (offset - aligned_start) as usize;
        out.copy_from_slice(&scratch[head..head + out.len()]);
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct DirRecord {
    extent_lba: u32,
    data_len: u32,
    flags: u8,
    file_id: Vec<u8>,
}

impl DirRecord {
    fn is_dir(&self) -> bool {
        (self.flags & 0x02) != 0
    }

    fn normalized_name(&self) -> Option<String> {
        normalize_iso_name(&self.file_id)
    }
}

async fn resolve_path(
    source: &SourceByteReader,
    logical_block_size: u64,
    root: &DirRecord,
    path: &str,
) -> GibbloxResult<DirRecord> {
    let parts = split_path(path)?;
    if parts.is_empty() {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "path must not be root",
        ));
    }

    let mut current = root.clone();
    for (idx, part) in parts.iter().enumerate() {
        if !current.is_dir() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "path traversal hit non-directory entry",
            ));
        }
        let entries = read_dir_entries(source, logical_block_size, &current).await?;
        let mut next = None;
        for entry in entries {
            let Some(name) = entry.normalized_name() else {
                continue;
            };
            if name == part.as_str() {
                next = Some(entry);
                break;
            }
        }
        let entry = next.ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::InvalidInput, "path not found")
        })?;
        let is_last = idx + 1 == parts.len();
        if is_last && entry.is_dir() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "path is not a regular file",
            ));
        }
        if !is_last && !entry.is_dir() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "path traversal hit non-directory entry",
            ));
        }
        current = entry;
    }

    Ok(current)
}

async fn read_dir_entries(
    source: &SourceByteReader,
    logical_block_size: u64,
    dir: &DirRecord,
) -> GibbloxResult<Vec<DirRecord>> {
    let dir_size = dir.data_len as usize;
    let mut data = vec![0u8; dir_size];
    let offset = (dir.extent_lba as u64)
        .checked_mul(logical_block_size)
        .ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "directory offset overflow")
        })?;
    source.read_exact_at(offset, &mut data).await?;

    let mut entries = Vec::new();
    let sector_size = logical_block_size as usize;
    let mut pos = 0usize;
    while pos < data.len() {
        let rec_len = data[pos] as usize;
        if rec_len == 0 {
            let next = ((pos / sector_size) + 1)
                .checked_mul(sector_size)
                .ok_or_else(|| {
                    GibbloxError::with_message(
                        GibbloxErrorKind::OutOfRange,
                        "directory entry offset overflow",
                    )
                })?;
            if next <= pos {
                break;
            }
            pos = next;
            continue;
        }
        if pos + rec_len > data.len() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "directory record exceeds directory size",
            ));
        }
        let rec = parse_dir_record(&data[pos..pos + rec_len])?;
        entries.push(rec);
        pos += rec_len;
    }
    Ok(entries)
}

fn split_path(path: &str) -> GibbloxResult<Vec<String>> {
    let mut out = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "parent traversal is not supported",
            ));
        }
        out.push(part.to_ascii_lowercase());
    }
    Ok(out)
}

fn normalize_identity_path(path: &str) -> GibbloxResult<String> {
    let parts = split_path(path)?;
    Ok(parts.join("/"))
}

fn parse_dir_record(raw: &[u8]) -> GibbloxResult<DirRecord> {
    if raw.len() < 34 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "ISO9660 directory record too short",
        ));
    }
    let len = raw[0] as usize;
    if len < 34 || len > raw.len() {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "invalid ISO9660 directory record length",
        ));
    }

    let extent_lba = parse_u32_both_endian(&raw[2..10])?;
    let data_len = parse_u32_both_endian(&raw[10..18])?;
    let flags = raw[25];
    let file_id_len = raw[32] as usize;
    let file_id_start = 33usize;
    let file_id_end = file_id_start.checked_add(file_id_len).ok_or_else(|| {
        GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "directory record overflow")
    })?;
    if file_id_end > len {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "invalid ISO9660 file identifier length",
        ));
    }
    Ok(DirRecord {
        extent_lba,
        data_len,
        flags,
        file_id: raw[file_id_start..file_id_end].to_vec(),
    })
}

fn normalize_iso_name(file_id: &[u8]) -> Option<String> {
    if file_id == [0] || file_id == [1] {
        return None;
    }
    let mut name = String::new();
    for b in file_id {
        if *b == b';' {
            break;
        }
        name.push((*b as char).to_ascii_lowercase());
    }
    while name.ends_with('.') {
        name.pop();
    }
    if name.is_empty() { None } else { Some(name) }
}

fn parse_u16_both_endian(raw: &[u8]) -> GibbloxResult<u16> {
    if raw.len() < 4 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "invalid both-endian u16",
        ));
    }
    let le = u16::from_le_bytes([raw[0], raw[1]]);
    let be = u16::from_be_bytes([raw[2], raw[3]]);
    if le != be {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "both-endian u16 mismatch",
        ));
    }
    Ok(le)
}

fn parse_u32_both_endian(raw: &[u8]) -> GibbloxResult<u32> {
    if raw.len() < 8 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "invalid both-endian u32",
        ));
    }
    let le = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let be = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    if le != be {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "both-endian u32 mismatch",
        ));
    }
    Ok(le)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use futures::executor::block_on;

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
            write!(out, "fake-iso:{}:{}", self.block_size, self.data.len())
        }

        async fn read_blocks(
            &self,
            lba: u64,
            buf: &mut [u8],
            _ctx: ReadContext,
        ) -> GibbloxResult<usize> {
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
    fn iso_file_reader_resolves_and_reads_path() {
        let iso = build_test_iso();
        let reader = FakeReader {
            block_size: 512,
            data: iso,
        };

        let source = block_on(IsoFileBlockReader::new(reader, "/LiveOS/squashfs.img", 4))
            .expect("construct iso file reader");
        assert_eq!(source.file_size_bytes(), 11);
        assert_eq!(block_on(source.total_blocks()).expect("total blocks"), 3);

        let mut buf = vec![0u8; 8];
        let read = block_on(source.read_blocks(0, &mut buf, ReadContext::FOREGROUND))
            .expect("read first blocks");
        assert_eq!(read, 8);
        assert_eq!(&buf, b"hello wo");

        let mut tail = vec![0u8; 4];
        let read = block_on(source.read_blocks(2, &mut tail, ReadContext::FOREGROUND))
            .expect("read tail block");
        assert_eq!(read, 4);
        assert_eq!(&tail, b"rld\0");
    }

    #[test]
    fn iso_file_reader_reports_path_not_found() {
        let iso = build_test_iso();
        let reader = FakeReader {
            block_size: 512,
            data: iso,
        };
        let err = block_on(IsoFileBlockReader::new(reader, "/LiveOS/missing.img", 512))
            .err()
            .expect("missing path should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::InvalidInput);
    }

    #[test]
    fn iso_file_reader_rejects_directory_path() {
        let iso = build_test_iso();
        let reader = FakeReader {
            block_size: 512,
            data: iso,
        };
        let err = block_on(IsoFileBlockReader::new(reader, "/LiveOS", 512))
            .err()
            .expect("directory path should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::InvalidInput);
    }

    fn build_test_iso() -> Vec<u8> {
        let sectors = 24usize;
        let mut iso = vec![0u8; sectors * ISO_SECTOR_SIZE];

        let pvd = sector_mut(&mut iso, 16);
        pvd[0] = 1;
        pvd[1..6].copy_from_slice(VD_MAGIC);
        pvd[6] = VD_VERSION;
        write_u16_both_endian(&mut pvd[128..132], ISO_SECTOR_SIZE as u16);
        let root = dir_record(20, ISO_SECTOR_SIZE as u32, true, &[0]);
        pvd[156..156 + root.len()].copy_from_slice(&root);

        let term = sector_mut(&mut iso, 17);
        term[0] = 255;
        term[1..6].copy_from_slice(VD_MAGIC);
        term[6] = VD_VERSION;

        {
            let root_dir = sector_mut(&mut iso, 20);
            let mut off = 0;
            off = append_record(
                root_dir,
                off,
                &dir_record(20, ISO_SECTOR_SIZE as u32, true, &[0]),
            );
            off = append_record(
                root_dir,
                off,
                &dir_record(20, ISO_SECTOR_SIZE as u32, true, &[1]),
            );
            let _ = append_record(
                root_dir,
                off,
                &dir_record(22, ISO_SECTOR_SIZE as u32, true, b"LIVEOS"),
            );
        }

        {
            let liveos_dir = sector_mut(&mut iso, 22);
            let mut off = 0;
            off = append_record(
                liveos_dir,
                off,
                &dir_record(22, ISO_SECTOR_SIZE as u32, true, &[0]),
            );
            off = append_record(
                liveos_dir,
                off,
                &dir_record(20, ISO_SECTOR_SIZE as u32, true, &[1]),
            );
            let _ = append_record(
                liveos_dir,
                off,
                &dir_record(21, 11, false, b"SQUASHFS.IMG;1"),
            );
        }

        let file = sector_mut(&mut iso, 21);
        file[..11].copy_from_slice(b"hello world");
        iso
    }

    fn sector_mut(iso: &mut [u8], sector: usize) -> &mut [u8] {
        let start = sector * ISO_SECTOR_SIZE;
        let end = start + ISO_SECTOR_SIZE;
        &mut iso[start..end]
    }

    fn append_record(sector: &mut [u8], offset: usize, rec: &[u8]) -> usize {
        sector[offset..offset + rec.len()].copy_from_slice(rec);
        offset + rec.len()
    }

    fn dir_record(extent: u32, data_len: u32, dir: bool, file_id: &[u8]) -> Vec<u8> {
        let pad = usize::from(!file_id.len().is_multiple_of(2));
        let len = 33 + file_id.len() + pad;
        let mut out = vec![0u8; len];
        out[0] = len as u8;
        out[1] = 0;
        write_u32_both_endian(&mut out[2..10], extent);
        write_u32_both_endian(&mut out[10..18], data_len);
        out[25] = if dir { 0x02 } else { 0x00 };
        out[26] = 0;
        out[27] = 0;
        write_u16_both_endian(&mut out[28..32], 1);
        out[32] = file_id.len() as u8;
        out[33..33 + file_id.len()].copy_from_slice(file_id);
        out
    }

    fn write_u16_both_endian(out: &mut [u8], v: u16) {
        out[..2].copy_from_slice(&v.to_le_bytes());
        out[2..4].copy_from_slice(&v.to_be_bytes());
    }

    fn write_u32_both_endian(out: &mut [u8], v: u32) {
        out[..4].copy_from_slice(&v.to_le_bytes());
        out[4..8].copy_from_slice(&v.to_be_bytes());
    }
}
