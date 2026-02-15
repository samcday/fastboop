use alloc::{format, string::String, vec::Vec};
use core::fmt;

use gibblox_core::{GibbloxError, GibbloxErrorKind, GibbloxResult};

pub const CASYNC_CHUNK_ID_LEN: usize = 32;

const CA_FORMAT_INDEX: u64 = 0x9682_4d9c_7b12_9ff9;
const CA_FORMAT_TABLE: u64 = 0xe75b_9e11_2f17_417d;
const CA_FORMAT_TABLE_TAIL_MARKER: u64 = 0x4b4f_050e_5549_ecd1;

const INDEX_HEADER_SIZE: usize = 48;
const TABLE_HEADER_SIZE: usize = 16;
const TABLE_ITEM_SIZE: usize = 40;
const TABLE_TAIL_SIZE: usize = 40;
const TABLE_START_OFFSET: usize = INDEX_HEADER_SIZE + TABLE_HEADER_SIZE;

const CASYNC_CHUNK_SIZE_LIMIT_MIN: u64 = 1;
const CASYNC_CHUNK_SIZE_LIMIT_MAX: u64 = 128 * 1024 * 1024;

const CASYNC_FEATURE_SHA512_256: u64 = 0x2000_0000_0000_0000;
const CASYNC_FEATURE_FLAGS_KNOWN_MASK: u64 = 0xf000_0001_ffff_ffff;

#[derive(Clone, Copy, Debug, Default)]
pub struct CasyncIndexValidation {
    pub strict: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CasyncChunkId([u8; CASYNC_CHUNK_ID_LEN]);

impl CasyncChunkId {
    pub const fn from_bytes(bytes: [u8; CASYNC_CHUNK_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; CASYNC_CHUNK_ID_LEN] {
        &self.0
    }

    pub fn to_hex_string(&self) -> String {
        let mut out = String::with_capacity(CASYNC_CHUNK_ID_LEN * 2);
        for byte in self.0 {
            out.push(nibble_to_hex(byte >> 4));
            out.push(nibble_to_hex(byte & 0x0f));
        }
        out
    }

    pub fn chunk_store_path(&self, suffix: &str) -> String {
        let hex = self.to_hex_string();
        let prefix = &hex[..4];
        format!("{prefix}/{hex}{suffix}")
    }
}

impl fmt::Debug for CasyncChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex_string())
    }
}

impl fmt::Display for CasyncChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CasyncChunkRef {
    id: CasyncChunkId,
    end_offset: u64,
}

impl CasyncChunkRef {
    pub const fn id(&self) -> &CasyncChunkId {
        &self.id
    }

    pub const fn end_offset(&self) -> u64 {
        self.end_offset
    }
}

#[derive(Clone, Debug)]
pub struct CasyncIndex {
    feature_flags: u64,
    chunk_size_min: u64,
    chunk_size_avg: u64,
    chunk_size_max: u64,
    chunks: Vec<CasyncChunkRef>,
    blob_size: u64,
}

impl CasyncIndex {
    pub fn parse(bytes: &[u8], validation: CasyncIndexValidation) -> GibbloxResult<Self> {
        if bytes.len() < TABLE_START_OFFSET + TABLE_TAIL_SIZE {
            return Err(invalid_index("index is too small"));
        }

        let index_size = read_u64_le(bytes, 0)?;
        let index_type = read_u64_le(bytes, 8)?;
        if index_size != INDEX_HEADER_SIZE as u64 {
            return Err(invalid_index("index header size mismatch"));
        }
        if index_type != CA_FORMAT_INDEX {
            return Err(invalid_index("index header type mismatch"));
        }

        let feature_flags = read_u64_le(bytes, 16)?;
        if validation.strict && (feature_flags & !CASYNC_FEATURE_FLAGS_KNOWN_MASK) != 0 {
            return Err(invalid_index("index has unknown feature flags"));
        }

        let chunk_size_min = read_u64_le(bytes, 24)?;
        let chunk_size_avg = read_u64_le(bytes, 32)?;
        let chunk_size_max = read_u64_le(bytes, 40)?;

        validate_chunk_limits(chunk_size_min, chunk_size_avg, chunk_size_max)?;

        let table_size = read_u64_le(bytes, INDEX_HEADER_SIZE)?;
        let table_type = read_u64_le(bytes, INDEX_HEADER_SIZE + 8)?;
        if table_size != u64::MAX {
            return Err(invalid_index("table header size mismatch"));
        }
        if table_type != CA_FORMAT_TABLE {
            return Err(invalid_index("table header type mismatch"));
        }

        let table_records = &bytes[TABLE_START_OFFSET..];
        if !table_records.len().is_multiple_of(TABLE_ITEM_SIZE) {
            return Err(invalid_index("table payload must align to table item size"));
        }

        let record_count = table_records.len() / TABLE_ITEM_SIZE;
        if record_count == 0 {
            return Err(invalid_index("index table missing tail marker"));
        }

        let chunk_count = record_count - 1;
        let tail_offset = TABLE_START_OFFSET + (chunk_count * TABLE_ITEM_SIZE);
        validate_tail(bytes, tail_offset, chunk_count)?;

        let mut previous_end = 0u64;
        let mut chunks = Vec::with_capacity(chunk_count);
        for idx in 0..chunk_count {
            let item_offset = TABLE_START_OFFSET + (idx * TABLE_ITEM_SIZE);
            let end_offset = read_u64_le(bytes, item_offset)?;
            if end_offset <= previous_end {
                return Err(invalid_index("chunk offsets must be strictly increasing"));
            }

            let chunk_size = end_offset - previous_end;
            if chunk_size > chunk_size_max {
                return Err(invalid_index("chunk exceeds max chunk size"));
            }

            let id = parse_chunk_id(bytes, item_offset + 8)?;
            chunks.push(CasyncChunkRef { id, end_offset });
            previous_end = end_offset;
        }

        Ok(Self {
            feature_flags,
            chunk_size_min,
            chunk_size_avg,
            chunk_size_max,
            chunks,
            blob_size: previous_end,
        })
    }

    pub const fn feature_flags(&self) -> u64 {
        self.feature_flags
    }

    pub const fn chunk_size_min(&self) -> u64 {
        self.chunk_size_min
    }

    pub const fn chunk_size_avg(&self) -> u64 {
        self.chunk_size_avg
    }

    pub const fn chunk_size_max(&self) -> u64 {
        self.chunk_size_max
    }

    pub fn chunks(&self) -> &[CasyncChunkRef] {
        &self.chunks
    }

    pub const fn blob_size(&self) -> u64 {
        self.blob_size
    }

    pub fn total_chunks(&self) -> usize {
        self.chunks.len()
    }

    pub fn uses_sha512_256(&self) -> bool {
        (self.feature_flags & CASYNC_FEATURE_SHA512_256) != 0
    }

    pub fn chunk_bounds(&self, chunk_idx: usize) -> Option<(u64, u64)> {
        let end = self.chunks.get(chunk_idx)?.end_offset;
        let start = if chunk_idx == 0 {
            0
        } else {
            self.chunks.get(chunk_idx - 1)?.end_offset
        };
        Some((start, end))
    }

    pub fn chunk_len(&self, chunk_idx: usize) -> Option<u64> {
        let (start, end) = self.chunk_bounds(chunk_idx)?;
        Some(end - start)
    }

    pub fn chunk_for_offset(&self, offset: u64) -> Option<usize> {
        if offset >= self.blob_size {
            return None;
        }
        let idx = self
            .chunks
            .partition_point(|chunk| chunk.end_offset <= offset);
        if idx < self.chunks.len() {
            Some(idx)
        } else {
            None
        }
    }
}

fn validate_chunk_limits(
    chunk_size_min: u64,
    chunk_size_avg: u64,
    chunk_size_max: u64,
) -> GibbloxResult<()> {
    if !(CASYNC_CHUNK_SIZE_LIMIT_MIN..=CASYNC_CHUNK_SIZE_LIMIT_MAX).contains(&chunk_size_min) {
        return Err(invalid_index("invalid chunk_size_min"));
    }
    if !(CASYNC_CHUNK_SIZE_LIMIT_MIN..=CASYNC_CHUNK_SIZE_LIMIT_MAX).contains(&chunk_size_avg) {
        return Err(invalid_index("invalid chunk_size_avg"));
    }
    if !(CASYNC_CHUNK_SIZE_LIMIT_MIN..=CASYNC_CHUNK_SIZE_LIMIT_MAX).contains(&chunk_size_max) {
        return Err(invalid_index("invalid chunk_size_max"));
    }
    if !(chunk_size_min <= chunk_size_avg && chunk_size_avg <= chunk_size_max) {
        return Err(invalid_index("chunk size limits are not ordered"));
    }
    Ok(())
}

fn validate_tail(bytes: &[u8], tail_offset: usize, chunk_count: usize) -> GibbloxResult<()> {
    let zero_fill_1 = read_u64_le(bytes, tail_offset)?;
    let zero_fill_2 = read_u64_le(bytes, tail_offset + 8)?;
    let index_offset = read_u64_le(bytes, tail_offset + 16)?;
    let table_size = read_u64_le(bytes, tail_offset + 24)?;
    let marker = read_u64_le(bytes, tail_offset + 32)?;

    if zero_fill_1 != 0 || zero_fill_2 != 0 {
        return Err(invalid_index("table tail zero-fill fields are non-zero"));
    }
    if index_offset != INDEX_HEADER_SIZE as u64 {
        return Err(invalid_index("table tail index offset mismatch"));
    }
    if marker != CA_FORMAT_TABLE_TAIL_MARKER {
        return Err(invalid_index("table tail marker mismatch"));
    }

    let expected_table_size =
        (TABLE_HEADER_SIZE + (chunk_count * TABLE_ITEM_SIZE) + TABLE_TAIL_SIZE) as u64;
    if table_size != expected_table_size {
        return Err(invalid_index("table tail size mismatch"));
    }

    let expected_file_size = INDEX_HEADER_SIZE as u64 + expected_table_size;
    if bytes.len() as u64 != expected_file_size {
        return Err(invalid_index(
            "index file length does not match table tail size",
        ));
    }

    Ok(())
}

fn parse_chunk_id(bytes: &[u8], offset: usize) -> GibbloxResult<CasyncChunkId> {
    let end = offset
        .checked_add(CASYNC_CHUNK_ID_LEN)
        .ok_or_else(|| invalid_index("chunk id offset overflow"))?;
    let Some(slice) = bytes.get(offset..end) else {
        return Err(invalid_index("chunk id is truncated"));
    };

    let mut id = [0u8; CASYNC_CHUNK_ID_LEN];
    id.copy_from_slice(slice);
    Ok(CasyncChunkId::from_bytes(id))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> GibbloxResult<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| invalid_index("u64 offset overflow"))?;
    let Some(slice) = bytes.get(offset..end) else {
        return Err(invalid_index("truncated u64 field"));
    };

    let mut arr = [0u8; 8];
    arr.copy_from_slice(slice);
    Ok(u64::from_le_bytes(arr))
}

fn invalid_index(message: &str) -> GibbloxError {
    GibbloxError::with_message(GibbloxErrorKind::InvalidInput, message)
}

fn nibble_to_hex(nibble: u8) -> char {
    match nibble & 0x0f {
        0..=9 => (b'0' + (nibble & 0x0f)) as char,
        value => (b'a' + (value - 10)) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CA_FORMAT_INDEX, CA_FORMAT_TABLE, CA_FORMAT_TABLE_TAIL_MARKER, CasyncChunkId, CasyncIndex,
        CasyncIndexValidation,
    };
    use alloc::vec::Vec;
    use sha2::{Digest, Sha256};

    const INDEX_HEADER_SIZE: usize = 48;
    const TABLE_HEADER_SIZE: usize = 16;
    const TABLE_ITEM_SIZE: usize = 40;
    const TABLE_TAIL_SIZE: usize = 40;
    const TABLE_START_OFFSET: usize = INDEX_HEADER_SIZE + TABLE_HEADER_SIZE;

    #[test]
    fn parses_valid_index() {
        let index_bytes = build_index_bytes(&[b"hello", b" world"], 0);
        let index = CasyncIndex::parse(&index_bytes, CasyncIndexValidation::default())
            .expect("index parses");

        assert_eq!(index.total_chunks(), 2);
        assert_eq!(index.blob_size(), 11);
        assert!(!index.uses_sha512_256());
        assert_eq!(index.chunk_bounds(0), Some((0, 5)));
        assert_eq!(index.chunk_bounds(1), Some((5, 11)));
        assert_eq!(index.chunk_for_offset(0), Some(0));
        assert_eq!(index.chunk_for_offset(4), Some(0));
        assert_eq!(index.chunk_for_offset(5), Some(1));
        assert_eq!(index.chunk_for_offset(10), Some(1));
        assert_eq!(index.chunk_for_offset(11), None);
    }

    #[test]
    fn rejects_bad_tail_marker() {
        let mut index_bytes = build_index_bytes(&[b"hello"], 0);
        let marker_offset = index_bytes.len() - 8;
        index_bytes[marker_offset..].copy_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
        let err = CasyncIndex::parse(&index_bytes, CasyncIndexValidation::default())
            .expect_err("tail marker should fail");
        assert_eq!(err.kind(), gibblox_core::GibbloxErrorKind::InvalidInput);
    }

    #[test]
    fn strict_mode_rejects_unknown_feature_flag() {
        let mut index_bytes = build_index_bytes(&[b"hello"], 0);
        let flags = 1u64 << 50;
        index_bytes[16..24].copy_from_slice(&flags.to_le_bytes());

        CasyncIndex::parse(&index_bytes, CasyncIndexValidation { strict: false })
            .expect("non-strict accepts unknown flags");

        let err = CasyncIndex::parse(&index_bytes, CasyncIndexValidation { strict: true })
            .expect_err("strict should reject unknown flags");
        assert_eq!(err.kind(), gibblox_core::GibbloxErrorKind::InvalidInput);
    }

    #[test]
    fn chunk_id_store_path_uses_casync_layout() {
        let id = CasyncChunkId::from_bytes([0xab; 32]);
        let path = id.chunk_store_path(".cacnk");
        assert!(path.starts_with("abab/"));
        assert!(path.ends_with(".cacnk"));
    }

    fn build_index_bytes(chunks: &[&[u8]], feature_flags: u64) -> Vec<u8> {
        let mut out = Vec::new();

        out.extend_from_slice(&(INDEX_HEADER_SIZE as u64).to_le_bytes());
        out.extend_from_slice(&CA_FORMAT_INDEX.to_le_bytes());
        out.extend_from_slice(&feature_flags.to_le_bytes());
        out.extend_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(&4096u64.to_le_bytes());
        out.extend_from_slice(&(128 * 1024 * 1024u64).to_le_bytes());

        out.extend_from_slice(&u64::MAX.to_le_bytes());
        out.extend_from_slice(&CA_FORMAT_TABLE.to_le_bytes());

        let mut end = 0u64;
        for chunk in chunks {
            end += chunk.len() as u64;
            out.extend_from_slice(&end.to_le_bytes());

            let digest = Sha256::digest(chunk);
            out.extend_from_slice(&digest);
        }

        let table_size =
            (TABLE_HEADER_SIZE + (chunks.len() * TABLE_ITEM_SIZE) + TABLE_TAIL_SIZE) as u64;
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&(INDEX_HEADER_SIZE as u64).to_le_bytes());
        out.extend_from_slice(&table_size.to_le_bytes());
        out.extend_from_slice(&CA_FORMAT_TABLE_TAIL_MARKER.to_le_bytes());

        assert_eq!(
            out.len(),
            TABLE_START_OFFSET + chunks.len() * TABLE_ITEM_SIZE + TABLE_TAIL_SIZE
        );
        out
    }
}
