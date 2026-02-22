#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::{boxed::Box, collections::BTreeMap, format, sync::Arc, vec, vec::Vec};
use async_lock::Mutex;
use async_trait::async_trait;
use core::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};
use crc32fast::Hasher;
use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
use tracing::{debug, trace};
use xz4rust::{DICT_SIZE_MAX, DICT_SIZE_MIN, XzDecoder, XzNextBlockResult};

const XZ_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];
const XZ_HEADER_LEN: usize = 12;
const XZ_FOOTER_LEN: usize = 12;
const XZ_FOOTER_MAGIC: [u8; 2] = [b'Y', b'Z'];
const DEFAULT_DECODED_CACHE_ENTRIES: usize = 64;
const DEFAULT_FOOTER_SCAN_WINDOW_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct XzReaderConfig {
    pub decoded_block_cache_entries: usize,
    pub footer_scan_window_bytes: usize,
}

impl Default for XzReaderConfig {
    fn default() -> Self {
        Self {
            decoded_block_cache_entries: DEFAULT_DECODED_CACHE_ENTRIES,
            footer_scan_window_bytes: DEFAULT_FOOTER_SCAN_WINDOW_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct XzIndexRecord {
    unpadded_size: u64,
    uncompressed_size: u64,
}

#[derive(Clone, Copy, Debug)]
struct XzIndexedBlock {
    compressed_start: u64,
    unpadded_size: u64,
    padded_size: u64,
    uncompressed_start: u64,
    uncompressed_end: u64,
}

impl XzIndexedBlock {
    fn uncompressed_size(&self) -> u64 {
        self.uncompressed_end
            .saturating_sub(self.uncompressed_start)
    }
}

#[derive(Debug)]
struct StreamLayout {
    compressed_size: u64,
    index_start: u64,
    records: Vec<XzIndexRecord>,
}

#[derive(Debug)]
struct ParsedFooter {
    backward_size: u32,
    stream_flags: [u8; 2],
}

#[derive(Debug)]
struct DecodedCacheState {
    entries: BTreeMap<usize, Arc<Vec<u8>>>,
    lru: Vec<usize>,
    hits: u64,
    misses: u64,
    evictions: u64,
    last_stats_log: u64,
}

impl DecodedCacheState {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            lru: Vec::new(),
            hits: 0,
            misses: 0,
            evictions: 0,
            last_stats_log: 0,
        }
    }

    fn touch(&mut self, block_idx: usize) {
        if let Some(pos) = self.lru.iter().position(|entry| *entry == block_idx) {
            self.lru.remove(pos);
        }
        self.lru.push(block_idx);
    }

    fn maybe_log_stats(&mut self) {
        let total = self.hits + self.misses;
        if total == 0 || total.saturating_sub(self.last_stats_log) < 1000 {
            return;
        }
        self.last_stats_log = total;
        let hit_rate = (self.hits as f64 / total as f64) * 100.0;
        debug!(
            hits = self.hits,
            misses = self.misses,
            evictions = self.evictions,
            resident_entries = self.entries.len(),
            hit_rate = format!("{hit_rate:.1}%"),
            "xz decoded block cache stats"
        );
    }
}

/// Block reader that exposes an XZ stream as random-access blocks.
///
/// The reader parses the XZ footer/index to map uncompressed offsets to XZ blocks,
/// then decodes individual XZ blocks on demand. Decoded blocks are memoized in an
/// internal LRU cache.
pub struct XzBlockReader {
    block_size: u32,
    total_blocks: u64,
    uncompressed_size_bytes: u64,
    compressed_size_bytes: u64,
    stream_header: [u8; XZ_HEADER_LEN],
    stream_flags: [u8; 2],
    blocks: Vec<XzIndexedBlock>,
    source: Arc<dyn BlockReader>,
    byte_reader: ByteReader,
    config: XzReaderConfig,
    decoded_cache: Mutex<DecodedCacheState>,
    decoded_blocks: AtomicU64,
}

impl XzBlockReader {
    pub async fn new(source: Arc<dyn BlockReader>) -> GibbloxResult<Self> {
        Self::new_with_config(source, XzReaderConfig::default()).await
    }

    pub async fn new_with_config(
        source: Arc<dyn BlockReader>,
        config: XzReaderConfig,
    ) -> GibbloxResult<Self> {
        if config.footer_scan_window_bytes < XZ_FOOTER_LEN {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "footer scan window must be at least 12 bytes",
            ));
        }

        let block_size = source.block_size();
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "source block size must be non-zero power of two",
            ));
        }

        let source_total_blocks = source.total_blocks().await?;
        let logical_size_bytes = source_total_blocks
            .checked_mul(block_size as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "compressed stream size overflow",
                )
            })?;
        if logical_size_bytes < (XZ_HEADER_LEN + XZ_FOOTER_LEN) as u64 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "input is too small to be a valid XZ stream",
            ));
        }

        let byte_reader =
            ByteReader::new(Arc::clone(&source), block_size as usize, logical_size_bytes);
        let stream_header_vec = byte_reader
            .read_vec_at(0, XZ_HEADER_LEN, ReadContext::FOREGROUND)
            .await?;
        let stream_flags = parse_stream_header(&stream_header_vec)?;

        let layout = locate_stream_layout(
            &byte_reader,
            logical_size_bytes,
            stream_flags,
            config.footer_scan_window_bytes,
        )
        .await?;

        let mut blocks = Vec::with_capacity(layout.records.len());
        let mut compressed_cursor = XZ_HEADER_LEN as u64;
        let mut uncompressed_cursor = 0u64;
        for record in &layout.records {
            let padded_size = padded_block_size(record.unpadded_size)?;
            let uncompressed_end = uncompressed_cursor
                .checked_add(record.uncompressed_size)
                .ok_or_else(|| {
                    GibbloxError::with_message(
                        GibbloxErrorKind::OutOfRange,
                        "uncompressed size overflow",
                    )
                })?;

            blocks.push(XzIndexedBlock {
                compressed_start: compressed_cursor,
                unpadded_size: record.unpadded_size,
                padded_size,
                uncompressed_start: uncompressed_cursor,
                uncompressed_end,
            });

            compressed_cursor = compressed_cursor.checked_add(padded_size).ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "compressed block cursor overflow",
                )
            })?;
            uncompressed_cursor = uncompressed_end;
        }

        if blocks.is_empty() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "XZ stream index has zero records",
            ));
        }

        if compressed_cursor != layout.index_start {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "XZ index records do not line up with stream block region",
            ));
        }

        let mut stream_header = [0u8; XZ_HEADER_LEN];
        stream_header.copy_from_slice(&stream_header_vec);

        let total_blocks = uncompressed_cursor.div_ceil(block_size as u64);
        debug!(
            compressed_size_bytes = layout.compressed_size,
            uncompressed_size_bytes = uncompressed_cursor,
            source_block_size = block_size,
            total_blocks,
            xz_blocks = blocks.len(),
            decoded_cache_entries = config.decoded_block_cache_entries,
            "xz block reader initialized"
        );

        Ok(Self {
            block_size,
            total_blocks,
            uncompressed_size_bytes: uncompressed_cursor,
            compressed_size_bytes: layout.compressed_size,
            stream_header,
            stream_flags,
            blocks,
            source,
            byte_reader,
            config,
            decoded_cache: Mutex::new(DecodedCacheState::new()),
            decoded_blocks: AtomicU64::new(0),
        })
    }

    pub fn uncompressed_size_bytes(&self) -> u64 {
        self.uncompressed_size_bytes
    }

    pub fn compressed_size_bytes(&self) -> u64 {
        self.compressed_size_bytes
    }

    pub fn xz_block_count(&self) -> usize {
        self.blocks.len()
    }

    pub fn decoded_block_count(&self) -> u64 {
        self.decoded_blocks.load(Ordering::Relaxed)
    }

    fn blocks_from_len(&self, len: usize) -> GibbloxResult<u64> {
        if len == 0 {
            return Ok(0);
        }
        let block_size = self.block_size as usize;
        if !len.is_multiple_of(block_size) {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "buffer length must align to block size",
            ));
        }
        Ok((len / block_size) as u64)
    }

    fn validate_read_range(&self, lba: u64, blocks: u64) -> GibbloxResult<()> {
        let end = lba.checked_add(blocks).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
        })?;
        if end > self.total_blocks {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "requested range exceeds stream size",
            ));
        }
        Ok(())
    }

    fn block_index_for_offset(&self, offset: u64) -> GibbloxResult<usize> {
        if offset >= self.uncompressed_size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "offset exceeds uncompressed stream size",
            ));
        }

        let mut lo = 0usize;
        let mut hi = self.blocks.len();
        while lo < hi {
            let mid = lo + ((hi - lo) / 2);
            let block = &self.blocks[mid];
            if offset < block.uncompressed_start {
                hi = mid;
            } else if offset >= block.uncompressed_end {
                lo = mid + 1;
            } else {
                return Ok(mid);
            }
        }

        Err(GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            "could not map uncompressed offset to XZ block",
        ))
    }

    async fn load_decoded_block(
        &self,
        block_idx: usize,
        ctx: ReadContext,
    ) -> GibbloxResult<Arc<Vec<u8>>> {
        {
            let mut cache = self.decoded_cache.lock().await;
            if let Some(hit) = cache.entries.get(&block_idx).cloned() {
                cache.hits = cache.hits.saturating_add(1);
                cache.touch(block_idx);
                cache.maybe_log_stats();
                return Ok(hit);
            }
            cache.misses = cache.misses.saturating_add(1);
            cache.maybe_log_stats();
        }

        let decoded = Arc::new(self.decode_block(block_idx, ctx).await?);
        if self.config.decoded_block_cache_entries == 0 {
            return Ok(decoded);
        }

        let mut cache = self.decoded_cache.lock().await;
        if let Some(hit) = cache.entries.get(&block_idx).cloned() {
            cache.hits = cache.hits.saturating_add(1);
            cache.touch(block_idx);
            cache.maybe_log_stats();
            return Ok(hit);
        }

        cache.entries.insert(block_idx, Arc::clone(&decoded));
        cache.touch(block_idx);

        while cache.entries.len() > self.config.decoded_block_cache_entries {
            if let Some(evict_idx) = cache.lru.first().copied() {
                cache.lru.remove(0);
                if cache.entries.remove(&evict_idx).is_some() {
                    cache.evictions = cache.evictions.saturating_add(1);
                }
            } else {
                break;
            }
        }

        Ok(decoded)
    }

    async fn decode_block(&self, block_idx: usize, ctx: ReadContext) -> GibbloxResult<Vec<u8>> {
        let block = self.blocks.get(block_idx).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "XZ block index out of range")
        })?;

        let block_len = usize::try_from(block.padded_size).map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "XZ block size does not fit in memory on this platform",
            )
        })?;
        let block_bytes = self
            .byte_reader
            .read_vec_at(block.compressed_start, block_len, ctx)
            .await?;

        let synthetic_stream = build_single_block_stream(
            &self.stream_header,
            self.stream_flags,
            block.unpadded_size,
            block.uncompressed_size(),
            &block_bytes,
        )?;

        let expected_len = usize::try_from(block.uncompressed_size()).map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "XZ block uncompressed size does not fit in memory on this platform",
            )
        })?;

        let decoded = decode_single_block_stream(&synthetic_stream, expected_len)?;
        self.decoded_blocks.fetch_add(1, Ordering::Relaxed);

        trace!(
            block_idx,
            compressed_start = block.compressed_start,
            compressed_padded_size = block.padded_size,
            uncompressed_size = block.uncompressed_size(),
            "decoded xz block"
        );

        Ok(decoded)
    }
}

#[async_trait]
impl BlockReader for XzBlockReader {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        Ok(self.total_blocks)
    }

    fn write_identity(&self, out: &mut dyn fmt::Write) -> fmt::Result {
        out.write_str("xz:(")?;
        self.source.write_identity(out)?;
        write!(
            out,
            "):compressed={}:uncompressed={}:xz_blocks={}",
            self.compressed_size_bytes,
            self.uncompressed_size_bytes,
            self.blocks.len()
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

        let blocks = self.blocks_from_len(buf.len())?;
        self.validate_read_range(lba, blocks)?;

        let read_start = lba.checked_mul(self.block_size as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
        })?;
        if read_start >= self.uncompressed_size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "requested start offset exceeds uncompressed stream size",
            ));
        }

        let requested_end = read_start.checked_add(buf.len() as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "requested range overflow")
        })?;
        let read_end = requested_end.min(self.uncompressed_size_bytes);

        buf.fill(0);
        let mut cursor = read_start;
        while cursor < read_end {
            let block_idx = self.block_index_for_offset(cursor)?;
            let block = &self.blocks[block_idx];
            let decoded = self.load_decoded_block(block_idx, ctx).await?;

            let copy_end = read_end.min(block.uncompressed_end);
            let src_start = usize::try_from(cursor - block.uncompressed_start).map_err(|_| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "source offset overflow")
            })?;
            let src_end = usize::try_from(copy_end - block.uncompressed_start).map_err(|_| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "source end overflow")
            })?;

            let dst_start = usize::try_from(cursor - read_start).map_err(|_| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "destination offset overflow",
                )
            })?;
            let dst_end = usize::try_from(copy_end - read_start).map_err(|_| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "destination end overflow")
            })?;

            buf[dst_start..dst_end].copy_from_slice(&decoded[src_start..src_end]);
            cursor = copy_end;
        }

        trace!(
            lba,
            blocks,
            bytes = buf.len(),
            effective_bytes = read_end - read_start,
            "served xz read"
        );

        Ok(buf.len())
    }
}

#[derive(Clone)]
struct ByteReader {
    inner: Arc<dyn BlockReader>,
    block_size: usize,
    size_bytes: u64,
}

impl ByteReader {
    fn new(inner: Arc<dyn BlockReader>, block_size: usize, size_bytes: u64) -> Self {
        Self {
            inner,
            block_size,
            size_bytes,
        }
    }

    async fn read_vec_at(
        &self,
        offset: u64,
        len: usize,
        ctx: ReadContext,
    ) -> GibbloxResult<Vec<u8>> {
        let mut out = vec![0u8; len];
        self.read_exact_at(offset, &mut out, ctx).await?;
        Ok(out)
    }

    async fn read_exact_at(
        &self,
        offset: u64,
        out: &mut [u8],
        ctx: ReadContext,
    ) -> GibbloxResult<()> {
        if out.is_empty() {
            return Ok(());
        }

        let end = offset.checked_add(out.len() as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "byte read range overflow")
        })?;
        if end > self.size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "byte read exceeds source size",
            ));
        }

        let bs = self.block_size as u64;
        if (offset % bs) == 0 && out.len().is_multiple_of(self.block_size) {
            self.read_full_blocks(offset / bs, out, ctx).await?;
            return Ok(());
        }

        let start_lba = offset / bs;
        let start_skip = (offset % bs) as usize;
        let aligned_end = end.div_ceil(bs);
        let aligned_blocks = aligned_end.saturating_sub(start_lba);
        let aligned_blocks_usize = usize::try_from(aligned_blocks).map_err(|_| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "aligned read too large")
        })?;
        let aligned_len = aligned_blocks_usize
            .checked_mul(self.block_size)
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "aligned read size overflow",
                )
            })?;

        let mut scratch = vec![0u8; aligned_len];
        self.read_full_blocks(start_lba, &mut scratch, ctx).await?;
        let end_skip = start_skip.checked_add(out.len()).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "aligned slice overflow")
        })?;
        out.copy_from_slice(&scratch[start_skip..end_skip]);
        Ok(())
    }

    async fn read_full_blocks(
        &self,
        lba: u64,
        out: &mut [u8],
        ctx: ReadContext,
    ) -> GibbloxResult<()> {
        if out.is_empty() {
            return Ok(());
        }
        if !out.len().is_multiple_of(self.block_size) {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "internal byte reader requested unaligned buffer",
            ));
        }

        let read = self.inner.read_blocks(lba, out, ctx).await?;
        if read != out.len() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Io,
                format!(
                    "source returned short read: expected {}, got {read}",
                    out.len()
                ),
            ));
        }
        Ok(())
    }
}

async fn locate_stream_layout(
    byte_reader: &ByteReader,
    logical_size_bytes: u64,
    expected_stream_flags: [u8; 2],
    footer_scan_window_bytes: usize,
) -> GibbloxResult<StreamLayout> {
    if logical_size_bytes < XZ_FOOTER_LEN as u64 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "input too small for XZ footer",
        ));
    }

    let min_scan = byte_reader.block_size.saturating_mul(4).max(XZ_FOOTER_LEN);
    let scan_window = footer_scan_window_bytes.max(min_scan);
    let logical_size_usize = match usize::try_from(logical_size_bytes) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    };
    let scan_len = logical_size_usize.min(scan_window);
    if scan_len < XZ_FOOTER_LEN {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "input too small to scan for XZ footer",
        ));
    }

    let scan_start = logical_size_bytes - scan_len as u64;
    let tail = byte_reader
        .read_vec_at(scan_start, scan_len, ReadContext::FOREGROUND)
        .await?;

    let max_pos = scan_len - XZ_FOOTER_LEN;
    for rel in (0..=max_pos).rev() {
        let footer_bytes = &tail[rel..rel + XZ_FOOTER_LEN];
        let Some(footer) = parse_stream_footer(footer_bytes) else {
            continue;
        };
        if footer.stream_flags != expected_stream_flags {
            continue;
        }

        let footer_offset = scan_start + rel as u64;
        let index_size = (u64::from(footer.backward_size) + 1)
            .checked_mul(4)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "XZ index size overflow")
            })?;
        if index_size < 8 || footer_offset < index_size {
            continue;
        }

        let index_len = match usize::try_from(index_size) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let index_start = footer_offset - index_size;
        let index_bytes = match byte_reader
            .read_vec_at(index_start, index_len, ReadContext::FOREGROUND)
            .await
        {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        let records = match parse_index_records(&index_bytes) {
            Ok(records) => records,
            Err(_) => continue,
        };
        if records.is_empty() {
            continue;
        }

        let mut block_cursor = XZ_HEADER_LEN as u64;
        let mut valid = true;
        for record in &records {
            let padded = match padded_block_size(record.unpadded_size) {
                Ok(value) => value,
                Err(_) => {
                    valid = false;
                    break;
                }
            };
            block_cursor = match block_cursor.checked_add(padded) {
                Some(value) => value,
                None => {
                    valid = false;
                    break;
                }
            };
        }
        if !valid || block_cursor != index_start {
            continue;
        }

        let compressed_size = footer_offset + XZ_FOOTER_LEN as u64;
        return Ok(StreamLayout {
            compressed_size,
            index_start,
            records,
        });
    }

    Err(GibbloxError::with_message(
        GibbloxErrorKind::Unsupported,
        "could not locate a valid single-stream XZ footer/index",
    ))
}

fn parse_stream_header(header_bytes: &[u8]) -> GibbloxResult<[u8; 2]> {
    if header_bytes.len() != XZ_HEADER_LEN {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "invalid XZ header length",
        ));
    }
    if header_bytes[..XZ_MAGIC.len()] != XZ_MAGIC {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "invalid XZ header magic",
        ));
    }

    let stream_flags = [header_bytes[6], header_bytes[7]];
    if stream_flags[0] != 0 || (stream_flags[1] & 0xF0) != 0 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::Unsupported,
            "unsupported XZ stream flags",
        ));
    }

    let expected_crc = u32::from_le_bytes([
        header_bytes[8],
        header_bytes[9],
        header_bytes[10],
        header_bytes[11],
    ]);
    let actual_crc = crc32(&header_bytes[6..8]);
    if expected_crc != actual_crc {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "invalid XZ header CRC32",
        ));
    }

    Ok(stream_flags)
}

fn parse_stream_footer(footer_bytes: &[u8]) -> Option<ParsedFooter> {
    if footer_bytes.len() != XZ_FOOTER_LEN {
        return None;
    }
    if footer_bytes[10..12] != XZ_FOOTER_MAGIC {
        return None;
    }

    let expected_crc = u32::from_le_bytes([
        footer_bytes[0],
        footer_bytes[1],
        footer_bytes[2],
        footer_bytes[3],
    ]);
    let actual_crc = crc32(&footer_bytes[4..10]);
    if expected_crc != actual_crc {
        return None;
    }

    let stream_flags = [footer_bytes[8], footer_bytes[9]];
    if stream_flags[0] != 0 || (stream_flags[1] & 0xF0) != 0 {
        return None;
    }

    Some(ParsedFooter {
        backward_size: u32::from_le_bytes([
            footer_bytes[4],
            footer_bytes[5],
            footer_bytes[6],
            footer_bytes[7],
        ]),
        stream_flags,
    })
}

fn parse_index_records(index_bytes: &[u8]) -> GibbloxResult<Vec<XzIndexRecord>> {
    if index_bytes.len() < 8 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "XZ index too small",
        ));
    }
    if index_bytes[0] != 0x00 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "invalid XZ index indicator",
        ));
    }

    let mut pos = 1usize;
    let count = decode_vli(index_bytes, &mut pos)?;
    let count_usize = usize::try_from(count).map_err(|_| {
        GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            "XZ index record count exceeds platform limits",
        )
    })?;

    let mut records = Vec::with_capacity(count_usize);
    for _ in 0..count_usize {
        let unpadded_size = decode_vli(index_bytes, &mut pos)?;
        let uncompressed_size = decode_vli(index_bytes, &mut pos)?;
        if unpadded_size == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "XZ index contains zero-sized block",
            ));
        }
        records.push(XzIndexRecord {
            unpadded_size,
            uncompressed_size,
        });
    }

    while pos % 4 != 0 {
        let Some(byte) = index_bytes.get(pos) else {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "truncated XZ index padding",
            ));
        };
        if *byte != 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "invalid XZ index padding",
            ));
        }
        pos += 1;
    }

    if pos + 4 != index_bytes.len() {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "XZ index size mismatch",
        ));
    }

    let expected_crc = u32::from_le_bytes([
        index_bytes[pos],
        index_bytes[pos + 1],
        index_bytes[pos + 2],
        index_bytes[pos + 3],
    ]);
    let actual_crc = crc32(&index_bytes[..pos]);
    if expected_crc != actual_crc {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "invalid XZ index CRC32",
        ));
    }

    Ok(records)
}

fn padded_block_size(unpadded_size: u64) -> GibbloxResult<u64> {
    let padding = (4 - (unpadded_size % 4)) % 4;
    unpadded_size.checked_add(padding).ok_or_else(|| {
        GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "XZ block size overflow")
    })
}

fn decode_vli(data: &[u8], pos: &mut usize) -> GibbloxResult<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;

    for _ in 0..9 {
        let byte = *data.get(*pos).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::InvalidInput, "truncated XZ VLI")
        })?;
        *pos += 1;

        let low_bits = u64::from(byte & 0x7F);
        if shift >= 64 || (shift == 63 && low_bits > 1) {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "XZ VLI overflow",
            ));
        }
        value |= low_bits << shift;

        if (byte & 0x80) == 0 {
            return Ok(value);
        }
        shift += 7;
    }

    Err(GibbloxError::with_message(
        GibbloxErrorKind::InvalidInput,
        "XZ VLI is too long",
    ))
}

fn encode_vli(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn build_single_record_index(unpadded_size: u64, uncompressed_size: u64) -> GibbloxResult<Vec<u8>> {
    let mut index = Vec::with_capacity(32);
    index.push(0x00);
    encode_vli(1, &mut index);
    encode_vli(unpadded_size, &mut index);
    encode_vli(uncompressed_size, &mut index);
    while index.len() % 4 != 0 {
        index.push(0);
    }

    let crc = crc32(&index);
    index.extend_from_slice(&crc.to_le_bytes());
    Ok(index)
}

fn build_stream_footer(
    stream_flags: [u8; 2],
    index_size: usize,
) -> GibbloxResult<[u8; XZ_FOOTER_LEN]> {
    if index_size == 0 || index_size % 4 != 0 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "invalid synthetic XZ index size",
        ));
    }
    let index_words = index_size / 4;
    if index_words == 0 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "invalid synthetic XZ index words",
        ));
    }

    let backward_size = u32::try_from(index_words - 1).map_err(|_| {
        GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            "synthetic XZ backward size does not fit in u32",
        )
    })?;

    let mut footer = [0u8; XZ_FOOTER_LEN];
    footer[4..8].copy_from_slice(&backward_size.to_le_bytes());
    footer[8..10].copy_from_slice(&stream_flags);
    footer[10..12].copy_from_slice(&XZ_FOOTER_MAGIC);

    let crc = crc32(&footer[4..10]);
    footer[..4].copy_from_slice(&crc.to_le_bytes());
    Ok(footer)
}

fn build_single_block_stream(
    stream_header: &[u8; XZ_HEADER_LEN],
    stream_flags: [u8; 2],
    unpadded_size: u64,
    uncompressed_size: u64,
    block_bytes: &[u8],
) -> GibbloxResult<Vec<u8>> {
    let index = build_single_record_index(unpadded_size, uncompressed_size)?;
    let footer = build_stream_footer(stream_flags, index.len())?;

    let total_size = stream_header
        .len()
        .checked_add(block_bytes.len())
        .and_then(|value| value.checked_add(index.len()))
        .and_then(|value| value.checked_add(footer.len()))
        .ok_or_else(|| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "synthetic XZ block stream size overflow",
            )
        })?;

    let mut stream = Vec::with_capacity(total_size);
    stream.extend_from_slice(stream_header);
    stream.extend_from_slice(block_bytes);
    stream.extend_from_slice(&index);
    stream.extend_from_slice(&footer);
    Ok(stream)
}

fn decode_single_block_stream(stream: &[u8], expected_output_len: usize) -> GibbloxResult<Vec<u8>> {
    let mut decoder = XzDecoder::with_alloc_dict_size(DICT_SIZE_MIN, DICT_SIZE_MAX);
    let mut input_pos = 0usize;
    let mut output = vec![0u8; expected_output_len.max(1)];
    let mut output_pos = 0usize;

    loop {
        if output_pos == output.len() {
            let grow_by = expected_output_len.max(4096);
            output.resize(output.len().saturating_add(grow_by), 0);
        }

        let result = decoder
            .decode(&stream[input_pos..], &mut output[output_pos..])
            .map_err(|err| {
                GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    format!("xz decode failed: {err}"),
                )
            })?;

        input_pos = input_pos
            .checked_add(result.input_consumed())
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "input cursor overflow")
            })?;
        output_pos = output_pos
            .checked_add(result.output_produced())
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "output cursor overflow")
            })?;

        match result {
            XzNextBlockResult::EndOfStream(_, _) => break,
            XzNextBlockResult::NeedMoreData(_, _) => {
                if input_pos >= stream.len() {
                    return Err(GibbloxError::with_message(
                        GibbloxErrorKind::InvalidInput,
                        "xz decode reached input end before stream end",
                    ));
                }
                if !result.made_progress() {
                    return Err(GibbloxError::with_message(
                        GibbloxErrorKind::InvalidInput,
                        "xz decode made no progress",
                    ));
                }
            }
        }
    }

    output.truncate(output_pos);
    if output.len() != expected_output_len {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            format!(
                "decoded block length mismatch: expected {expected_output_len}, got {}",
                output.len()
            ),
        ));
    }

    Ok(output)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::{XzBlockReader, XzReaderConfig};
    use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
    use async_trait::async_trait;
    use futures::executor::block_on;
    use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
    use std::sync::atomic::{AtomicU64, Ordering};

    const FIXTURE_XZ_HEX: &str = "fd377a585a000004e6d6b4460200210116000000742fe5a301003f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f004bf2930b9be698d00200210116000000742fe5a301003f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0050cc9737924cc2ce0200210116000000742fe5a301003f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf007d8e9b7389b22dec0200210116000000742fe5a301003fc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa0001020304003f30b53c1763decd0200210116000000742fe5a301002b05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30003e8eca7c8c57efac00055840584058405840442c20acdbdc14173b30030000000004595a";

    struct FakeReader {
        block_size: u32,
        data: Vec<u8>,
        reads: AtomicU64,
    }

    impl FakeReader {
        fn new(block_size: u32, data: Vec<u8>) -> Self {
            Self {
                block_size,
                data,
                reads: AtomicU64::new(0),
            }
        }

        fn reads(&self) -> u64 {
            self.reads.load(Ordering::Relaxed)
        }
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
            write!(out, "fake-xz:{}:{}", self.block_size, self.data.len())
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

            self.reads.fetch_add(1, Ordering::Relaxed);

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
    fn opens_and_reads_full_payload() {
        let compressed = fixture_xz_bytes();
        let source = Arc::new(FakeReader::new(16, compressed));
        let reader = block_on(XzBlockReader::new(
            Arc::clone(&source) as Arc<dyn BlockReader>
        ))
        .expect("open xz reader");

        assert_eq!(reader.uncompressed_size_bytes(), 300);
        assert_eq!(reader.xz_block_count(), 5);

        let total_blocks = block_on(reader.total_blocks()).expect("total blocks");
        assert_eq!(total_blocks, 19);

        let mut buf = vec![0u8; total_blocks as usize * reader.block_size() as usize];
        let read = block_on(reader.read_blocks(0, &mut buf, ReadContext::FOREGROUND))
            .expect("read full output");
        assert_eq!(read, buf.len());

        let payload = fixture_payload();
        assert_eq!(&buf[..payload.len()], payload.as_slice());
        assert!(buf[payload.len()..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn reuses_decoded_block_from_lru() {
        let compressed = fixture_xz_bytes();
        let source = Arc::new(FakeReader::new(16, compressed));
        let reader = block_on(XzBlockReader::new_with_config(
            Arc::clone(&source) as Arc<dyn BlockReader>,
            XzReaderConfig {
                decoded_block_cache_entries: 8,
                footer_scan_window_bytes: 4096,
            },
        ))
        .expect("open xz reader");

        let mut a = [0u8; 16];
        block_on(reader.read_blocks(0, &mut a, ReadContext::FOREGROUND)).expect("read #1");
        let mut b = [0u8; 16];
        block_on(reader.read_blocks(1, &mut b, ReadContext::FOREGROUND)).expect("read #2");

        assert_eq!(reader.decoded_block_count(), 1);
    }

    #[test]
    fn reads_across_xz_block_boundary() {
        let compressed = fixture_xz_bytes();
        let source = Arc::new(FakeReader::new(16, compressed));
        let reader = block_on(XzBlockReader::new_with_config(
            Arc::clone(&source) as Arc<dyn BlockReader>,
            XzReaderConfig {
                decoded_block_cache_entries: 8,
                footer_scan_window_bytes: 4096,
            },
        ))
        .expect("open xz reader");

        let mut out = [0u8; 32]; // starts at byte 48, ends at byte 80 (crosses 64-byte xz block boundary)
        block_on(reader.read_blocks(3, &mut out, ReadContext::FOREGROUND)).expect("read boundary");

        let payload = fixture_payload();
        assert_eq!(&out[..], &payload[48..80]);
        assert_eq!(reader.decoded_block_count(), 2);
    }

    #[test]
    fn keeps_operating_after_tail_zero_padding() {
        let mut compressed = fixture_xz_bytes();
        compressed.extend_from_slice(&[0u8; 32]);
        let source = Arc::new(FakeReader::new(16, compressed));
        let reader = block_on(XzBlockReader::new(
            Arc::clone(&source) as Arc<dyn BlockReader>
        ))
        .expect("open xz reader with trailing zeros");

        let mut out = [0u8; 16];
        block_on(reader.read_blocks(0, &mut out, ReadContext::FOREGROUND)).expect("read");
        assert_eq!(out, fixture_payload()[..16]);
        assert!(source.reads() > 0);
    }

    fn fixture_payload() -> Vec<u8> {
        (0u16..300u16).map(|idx| (idx % 251) as u8).collect()
    }

    fn fixture_xz_bytes() -> Vec<u8> {
        decode_hex(FIXTURE_XZ_HEX)
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        assert!(input.len().is_multiple_of(2), "hex length must be even");
        let mut out = Vec::with_capacity(input.len() / 2);
        let bytes = input.as_bytes();
        for i in (0..bytes.len()).step_by(2) {
            let high = decode_hex_nibble(bytes[i]);
            let low = decode_hex_nibble(bytes[i + 1]);
            out.push((high << 4) | low);
        }
        out
    }

    fn decode_hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex nibble: {byte}"),
        }
    }
}
