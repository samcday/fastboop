#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::{boxed::Box, format, vec, vec::Vec};
use async_trait::async_trait;
use core::fmt;
use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
use tracing::{debug, trace};

const SPARSE_HEADER_MAGIC: u32 = 0xed26_ff3a;
const SPARSE_MAJOR_VERSION: u16 = 1;
const SPARSE_HEADER_LEN: usize = 28;
const CHUNK_HEADER_LEN: usize = 12;

const CHUNK_TYPE_RAW: u16 = 0xCAC1;
const CHUNK_TYPE_FILL: u16 = 0xCAC2;
const CHUNK_TYPE_DONT_CARE: u16 = 0xCAC3;
const CHUNK_TYPE_CRC32: u16 = 0xCAC4;

/// Read-only block reader over Android sparse image streams.
///
/// The sparse image header and all chunk headers are parsed and validated up-front
/// during construction.
pub struct AndroidSparseBlockReader<S> {
    source: S,
    source_block_size: usize,
    source_size_bytes: u64,
    block_size: u32,
    total_blocks: u64,
    expanded_size_bytes: u64,
    declared_chunks: u32,
    image_checksum: u32,
    chunks: Vec<SparseChunk>,
}

impl<S> AndroidSparseBlockReader<S>
where
    S: BlockReader,
{
    /// Parse and validate an Android sparse stream exposed by `source`.
    pub async fn new(source: S) -> GibbloxResult<Self> {
        let source_block_size_u32 = source.block_size();
        if source_block_size_u32 == 0 || !source_block_size_u32.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "source block size must be non-zero power of two",
            ));
        }

        let source_total_blocks = source.total_blocks().await?;
        let source_size_bytes = source_total_blocks
            .checked_mul(source_block_size_u32 as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "source size overflow")
            })?;
        let source_block_size = source_block_size_u32 as usize;

        let mut sparse_header_raw = [0u8; SPARSE_HEADER_LEN];
        read_source_exact(
            &source,
            source_block_size,
            source_size_bytes,
            0,
            &mut sparse_header_raw,
            ReadContext::FOREGROUND,
        )
        .await?;
        let sparse_header = SparseHeader::parse(&sparse_header_raw);

        validate_sparse_header(&sparse_header)?;

        let sparse_block_size = sparse_header.blk_sz;
        let total_blocks = u64::from(sparse_header.total_blks);
        let expanded_size_bytes = total_blocks
            .checked_mul(sparse_block_size as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "sparse expanded image size overflow",
                )
            })?;

        let chunk_header_size = u64::from(sparse_header.chunk_hdr_sz);
        let mut chunk_cursor = u64::from(sparse_header.file_hdr_sz);
        if chunk_cursor > source_size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "sparse file header exceeds source size",
            ));
        }

        let total_chunks = usize::try_from(sparse_header.total_chunks).map_err(|_| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "chunk count overflow")
        })?;
        let mut chunks = Vec::with_capacity(total_chunks);
        let mut output_cursor = 0u64;

        for chunk_index in 0..total_chunks {
            let mut chunk_header_raw = [0u8; CHUNK_HEADER_LEN];
            read_source_exact(
                &source,
                source_block_size,
                source_size_bytes,
                chunk_cursor,
                &mut chunk_header_raw,
                ReadContext::FOREGROUND,
            )
            .await?;
            let chunk_header = SparseChunkHeader::parse(&chunk_header_raw);

            let chunk_total_size = u64::from(chunk_header.total_sz);
            if chunk_total_size < chunk_header_size {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    format!("chunk {chunk_index} total size is smaller than chunk header size"),
                ));
            }

            let chunk_end = chunk_cursor.checked_add(chunk_total_size).ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    format!("chunk {chunk_index} range overflow"),
                )
            })?;
            if chunk_end > source_size_bytes {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    format!("chunk {chunk_index} exceeds source size"),
                ));
            }

            let chunk_payload_offset =
                chunk_cursor.checked_add(chunk_header_size).ok_or_else(|| {
                    GibbloxError::with_message(
                        GibbloxErrorKind::OutOfRange,
                        format!("chunk {chunk_index} payload offset overflow"),
                    )
                })?;
            let chunk_payload_size = chunk_total_size - chunk_header_size;
            let chunk_output_bytes = u64::from(chunk_header.chunk_sz)
                .checked_mul(sparse_block_size as u64)
                .ok_or_else(|| {
                    GibbloxError::with_message(
                        GibbloxErrorKind::OutOfRange,
                        format!("chunk {chunk_index} output size overflow"),
                    )
                })?;

            match chunk_header.chunk_type {
                CHUNK_TYPE_RAW => {
                    if chunk_payload_size != chunk_output_bytes {
                        return Err(GibbloxError::with_message(
                            GibbloxErrorKind::InvalidInput,
                            format!(
                                "chunk {chunk_index} raw payload size mismatch (expected {chunk_output_bytes}, got {chunk_payload_size})"
                            ),
                        ));
                    }
                    if let Some((output_start, output_end)) = claim_output_span(
                        &mut output_cursor,
                        chunk_output_bytes,
                        expanded_size_bytes,
                        chunk_index,
                    )? {
                        chunks.push(SparseChunk {
                            output_start,
                            output_end,
                            kind: SparseChunkKind::Raw {
                                source_offset: chunk_payload_offset,
                            },
                        });
                    }
                }
                CHUNK_TYPE_FILL => {
                    if chunk_payload_size != 4 {
                        return Err(GibbloxError::with_message(
                            GibbloxErrorKind::InvalidInput,
                            format!(
                                "chunk {chunk_index} fill payload size mismatch (expected 4, got {chunk_payload_size})"
                            ),
                        ));
                    }

                    let mut pattern = [0u8; 4];
                    read_source_exact(
                        &source,
                        source_block_size,
                        source_size_bytes,
                        chunk_payload_offset,
                        &mut pattern,
                        ReadContext::FOREGROUND,
                    )
                    .await?;

                    if let Some((output_start, output_end)) = claim_output_span(
                        &mut output_cursor,
                        chunk_output_bytes,
                        expanded_size_bytes,
                        chunk_index,
                    )? {
                        chunks.push(SparseChunk {
                            output_start,
                            output_end,
                            kind: SparseChunkKind::Fill { pattern },
                        });
                    }
                }
                CHUNK_TYPE_DONT_CARE => {
                    if chunk_payload_size != 0 {
                        return Err(GibbloxError::with_message(
                            GibbloxErrorKind::InvalidInput,
                            format!(
                                "chunk {chunk_index} DONT_CARE payload must be empty (got {chunk_payload_size})"
                            ),
                        ));
                    }

                    if let Some((output_start, output_end)) = claim_output_span(
                        &mut output_cursor,
                        chunk_output_bytes,
                        expanded_size_bytes,
                        chunk_index,
                    )? {
                        chunks.push(SparseChunk {
                            output_start,
                            output_end,
                            kind: SparseChunkKind::DontCare,
                        });
                    }
                }
                CHUNK_TYPE_CRC32 => {
                    if chunk_header.chunk_sz != 0 {
                        return Err(GibbloxError::with_message(
                            GibbloxErrorKind::InvalidInput,
                            format!("chunk {chunk_index} CRC32 chunk_sz must be zero"),
                        ));
                    }
                    if chunk_payload_size != 4 {
                        return Err(GibbloxError::with_message(
                            GibbloxErrorKind::InvalidInput,
                            format!(
                                "chunk {chunk_index} CRC32 payload size mismatch (expected 4, got {chunk_payload_size})"
                            ),
                        ));
                    }

                    let mut crc = [0u8; 4];
                    read_source_exact(
                        &source,
                        source_block_size,
                        source_size_bytes,
                        chunk_payload_offset,
                        &mut crc,
                        ReadContext::FOREGROUND,
                    )
                    .await?;
                }
                other => {
                    return Err(GibbloxError::with_message(
                        GibbloxErrorKind::Unsupported,
                        format!(
                            "unsupported sparse chunk type 0x{other:04X} at chunk {chunk_index}"
                        ),
                    ));
                }
            }

            chunk_cursor = chunk_end;
        }

        if output_cursor != expanded_size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                format!(
                    "sparse output size mismatch (mapped {output_cursor}, expected {expanded_size_bytes})"
                ),
            ));
        }

        debug!(
            source_block_size = source_block_size_u32,
            source_total_blocks,
            sparse_block_size,
            total_blocks,
            declared_chunks = sparse_header.total_chunks,
            mapped_chunks = chunks.len(),
            "android sparse reader initialized"
        );

        Ok(Self {
            source,
            source_block_size,
            source_size_bytes,
            block_size: sparse_block_size,
            total_blocks,
            expanded_size_bytes,
            declared_chunks: sparse_header.total_chunks,
            image_checksum: sparse_header.image_checksum,
            chunks,
        })
    }

    pub fn expanded_size_bytes(&self) -> u64 {
        self.expanded_size_bytes
    }

    fn chunk_index_for_offset(&self, offset: u64) -> Option<usize> {
        let index = self
            .chunks
            .partition_point(|chunk| chunk.output_end <= offset);
        if index < self.chunks.len() {
            Some(index)
        } else {
            None
        }
    }
}

#[async_trait]
impl<S> BlockReader for AndroidSparseBlockReader<S>
where
    S: BlockReader,
{
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        Ok(self.total_blocks)
    }

    fn write_identity(&self, out: &mut dyn fmt::Write) -> fmt::Result {
        out.write_str("android-sparse:(")?;
        self.source.write_identity(out)?;
        write!(
            out,
            "):blk_sz={}:total_blks={}:total_chunks={}:checksum={:08x}",
            self.block_size, self.total_blocks, self.declared_chunks, self.image_checksum
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

        let blocks = (buf.len() / self.block_size as usize) as u64;
        let end_lba = lba.checked_add(blocks).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
        })?;
        if end_lba > self.total_blocks {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "requested range exceeds sparse image",
            ));
        }

        let start_offset = lba.checked_mul(self.block_size as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "read start overflow")
        })?;
        let read_end = start_offset.checked_add(buf.len() as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "read end overflow")
        })?;

        let mut cursor = start_offset;
        let mut chunk_index = self.chunk_index_for_offset(cursor).ok_or_else(|| {
            GibbloxError::with_message(
                GibbloxErrorKind::Io,
                "sparse mapping does not cover requested offset",
            )
        })?;

        while cursor < read_end {
            let chunk = self.chunks.get(chunk_index).ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    "sparse mapping ended before requested range",
                )
            })?;
            if cursor < chunk.output_start || cursor >= chunk.output_end {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    "sparse mapping gap detected",
                ));
            }

            let segment_end = read_end.min(chunk.output_end);
            if segment_end <= cursor {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    "sparse mapping did not advance",
                ));
            }

            let dst_start = usize::try_from(cursor - start_offset).map_err(|_| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "destination slice offset overflow",
                )
            })?;
            let dst_len = usize::try_from(segment_end - cursor).map_err(|_| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "destination slice length overflow",
                )
            })?;
            let dst_end = dst_start.checked_add(dst_len).ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "destination slice end overflow",
                )
            })?;
            let dst = buf.get_mut(dst_start..dst_end).ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "destination slice out of bounds",
                )
            })?;

            let chunk_offset = cursor - chunk.output_start;
            match chunk.kind {
                SparseChunkKind::Raw { source_offset } => {
                    let source_offset =
                        source_offset.checked_add(chunk_offset).ok_or_else(|| {
                            GibbloxError::with_message(
                                GibbloxErrorKind::OutOfRange,
                                "raw chunk source offset overflow",
                            )
                        })?;
                    read_source_exact(
                        &self.source,
                        self.source_block_size,
                        self.source_size_bytes,
                        source_offset,
                        dst,
                        ctx,
                    )
                    .await?;
                }
                SparseChunkKind::Fill { pattern } => {
                    fill_pattern(dst, pattern, chunk_offset);
                }
                SparseChunkKind::DontCare => {
                    dst.fill(0);
                }
            }

            cursor = segment_end;
            if cursor == chunk.output_end {
                chunk_index += 1;
            }
        }

        trace!(lba, blocks, bytes = buf.len(), "served android sparse read");
        Ok(buf.len())
    }
}

#[derive(Clone, Copy)]
struct SparseHeader {
    magic: u32,
    major_version: u16,
    file_hdr_sz: u16,
    chunk_hdr_sz: u16,
    blk_sz: u32,
    total_blks: u32,
    total_chunks: u32,
    image_checksum: u32,
}

impl SparseHeader {
    fn parse(raw: &[u8; SPARSE_HEADER_LEN]) -> Self {
        Self {
            magic: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
            major_version: u16::from_le_bytes([raw[4], raw[5]]),
            file_hdr_sz: u16::from_le_bytes([raw[8], raw[9]]),
            chunk_hdr_sz: u16::from_le_bytes([raw[10], raw[11]]),
            blk_sz: u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]),
            total_blks: u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]),
            total_chunks: u32::from_le_bytes([raw[20], raw[21], raw[22], raw[23]]),
            image_checksum: u32::from_le_bytes([raw[24], raw[25], raw[26], raw[27]]),
        }
    }
}

#[derive(Clone, Copy)]
struct SparseChunkHeader {
    chunk_type: u16,
    chunk_sz: u32,
    total_sz: u32,
}

impl SparseChunkHeader {
    fn parse(raw: &[u8; CHUNK_HEADER_LEN]) -> Self {
        Self {
            chunk_type: u16::from_le_bytes([raw[0], raw[1]]),
            chunk_sz: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
            total_sz: u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]),
        }
    }
}

#[derive(Clone, Copy)]
struct SparseChunk {
    output_start: u64,
    output_end: u64,
    kind: SparseChunkKind,
}

#[derive(Clone, Copy)]
enum SparseChunkKind {
    Raw { source_offset: u64 },
    Fill { pattern: [u8; 4] },
    DontCare,
}

fn validate_sparse_header(header: &SparseHeader) -> GibbloxResult<()> {
    if header.magic != SPARSE_HEADER_MAGIC {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "invalid Android sparse magic",
        ));
    }
    if header.major_version != SPARSE_MAJOR_VERSION {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::Unsupported,
            format!(
                "unsupported Android sparse major version {}",
                header.major_version
            ),
        ));
    }
    if header.file_hdr_sz < SPARSE_HEADER_LEN as u16 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "sparse file header is smaller than minimum size",
        ));
    }
    if header.chunk_hdr_sz < CHUNK_HEADER_LEN as u16 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "sparse chunk header is smaller than minimum size",
        ));
    }
    if header.blk_sz == 0 || !header.blk_sz.is_power_of_two() || (header.blk_sz % 4) != 0 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "sparse block size must be a non-zero power of two and a multiple of 4",
        ));
    }
    Ok(())
}

fn claim_output_span(
    cursor: &mut u64,
    bytes: u64,
    expanded_size_bytes: u64,
    chunk_index: usize,
) -> GibbloxResult<Option<(u64, u64)>> {
    let start = *cursor;
    let end = start.checked_add(bytes).ok_or_else(|| {
        GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            format!("chunk {chunk_index} output range overflow"),
        )
    })?;
    if end > expanded_size_bytes {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            format!("chunk {chunk_index} output exceeds declared sparse image size"),
        ));
    }

    *cursor = end;
    if bytes == 0 {
        Ok(None)
    } else {
        Ok(Some((start, end)))
    }
}

async fn read_source_exact<S: BlockReader>(
    source: &S,
    source_block_size: usize,
    source_size_bytes: u64,
    offset: u64,
    out: &mut [u8],
    ctx: ReadContext,
) -> GibbloxResult<()> {
    if out.is_empty() {
        return Ok(());
    }

    let end = offset.checked_add(out.len() as u64).ok_or_else(|| {
        GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "source read range overflow")
    })?;
    if end > source_size_bytes {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            "source read range exceeds source size",
        ));
    }

    let bs = source_block_size as u64;
    if (offset % bs) == 0 && out.len().is_multiple_of(source_block_size) {
        read_source_full_blocks(source, source_block_size, offset / bs, out, ctx).await?;
        return Ok(());
    }

    let aligned_start = (offset / bs) * bs;
    let aligned_end = end.div_ceil(bs).checked_mul(bs).ok_or_else(|| {
        GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            "source aligned range overflow",
        )
    })?;
    let aligned_len = usize::try_from(aligned_end - aligned_start).map_err(|_| {
        GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            "source aligned read exceeds addressable memory",
        )
    })?;

    let mut scratch = vec![0u8; aligned_len];
    read_source_full_blocks(
        source,
        source_block_size,
        aligned_start / bs,
        &mut scratch,
        ctx,
    )
    .await?;

    let head = usize::try_from(offset - aligned_start).map_err(|_| {
        GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            "source aligned head offset overflow",
        )
    })?;
    let tail = head.checked_add(out.len()).ok_or_else(|| {
        GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            "source aligned tail offset overflow",
        )
    })?;
    let src = scratch.get(head..tail).ok_or_else(|| {
        GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            "source aligned slice out of bounds",
        )
    })?;
    out.copy_from_slice(src);
    Ok(())
}

async fn read_source_full_blocks<S: BlockReader>(
    source: &S,
    source_block_size: usize,
    lba: u64,
    out: &mut [u8],
    ctx: ReadContext,
) -> GibbloxResult<()> {
    if out.is_empty() {
        return Ok(());
    }
    if !out.len().is_multiple_of(source_block_size) {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "unaligned source block read requested",
        ));
    }

    let read = source.read_blocks(lba, out, ctx).await?;
    if read != out.len() {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::Io,
            format!(
                "short read from sparse source: expected {}, got {read}",
                out.len()
            ),
        ));
    }
    Ok(())
}

fn fill_pattern(out: &mut [u8], pattern: [u8; 4], start_offset: u64) {
    let mut idx = (start_offset & 3) as usize;
    for byte in out {
        *byte = pattern[idx];
        idx = (idx + 1) & 3;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        fn write_identity(&self, out: &mut dyn fmt::Write) -> fmt::Result {
            write!(out, "fake-sparse:{}:{}", self.block_size, self.data.len())
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
                    GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
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
    fn reads_mixed_raw_fill_and_dont_care_chunks() {
        let mut image = sparse_header(8, 3, 4, 28, 12);
        append_raw_chunk(&mut image, 1, b"ABCDEFGH", 12);
        append_fill_chunk(&mut image, 1, 0x4433_2211, 12);
        append_dont_care_chunk(&mut image, 1, 12);
        append_crc32_chunk(&mut image, 0xDEAD_BEEF, 12, 0);

        let source = FakeReader {
            block_size: 16,
            data: image,
        };
        let reader = block_on(AndroidSparseBlockReader::new(source)).expect("open sparse reader");

        assert_eq!(reader.block_size(), 8);
        assert_eq!(block_on(reader.total_blocks()).expect("total blocks"), 3);
        assert_eq!(reader.expanded_size_bytes(), 24);

        let mut out = vec![0u8; 24];
        let read = block_on(reader.read_blocks(0, &mut out, ReadContext::FOREGROUND))
            .expect("read blocks");
        assert_eq!(read, 24);

        let mut expected = Vec::new();
        expected.extend_from_slice(b"ABCDEFGH");
        expected.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44]);
        expected.extend_from_slice(&[0u8; 8]);
        assert_eq!(out, expected);
    }

    #[test]
    fn supports_extended_sparse_and_chunk_headers() {
        let mut image = sparse_header(4, 1, 1, 32, 16);
        append_raw_chunk(&mut image, 1, &[1, 2, 3, 4], 16);

        let source = FakeReader {
            block_size: 8,
            data: image,
        };
        let reader = block_on(AndroidSparseBlockReader::new(source)).expect("open sparse reader");

        let mut out = vec![0u8; 4];
        let read =
            block_on(reader.read_blocks(0, &mut out, ReadContext::FOREGROUND)).expect("read block");
        assert_eq!(read, 4);
        assert_eq!(out, vec![1, 2, 3, 4]);
    }

    #[test]
    fn rejects_raw_payload_size_mismatch_during_construction() {
        let mut image = sparse_header(4, 1, 1, 28, 12);
        append_chunk_header(&mut image, CHUNK_TYPE_RAW, 1, 15, 12);
        image.extend_from_slice(&[1, 2, 3]);

        let source = FakeReader {
            block_size: 8,
            data: image,
        };
        let err = block_on(AndroidSparseBlockReader::new(source))
            .err()
            .expect("construction should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_crc_chunk_with_non_zero_chunk_size() {
        let mut image = sparse_header(4, 0, 1, 28, 12);
        append_crc32_chunk(&mut image, 0xAABB_CCDD, 12, 1);

        let source = FakeReader {
            block_size: 8,
            data: image,
        };
        let err = block_on(AndroidSparseBlockReader::new(source))
            .err()
            .expect("construction should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_out_of_range_reads() {
        let mut image = sparse_header(8, 2, 2, 28, 12);
        append_raw_chunk(&mut image, 1, b"ABCDEFGH", 12);
        append_dont_care_chunk(&mut image, 1, 12);

        let source = FakeReader {
            block_size: 16,
            data: image,
        };
        let reader = block_on(AndroidSparseBlockReader::new(source)).expect("open sparse reader");

        let mut out = vec![0u8; 8];
        let err = block_on(reader.read_blocks(2, &mut out, ReadContext::FOREGROUND))
            .err()
            .expect("out-of-range read should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::OutOfRange);
    }

    fn sparse_header(
        blk_sz: u32,
        total_blks: u32,
        total_chunks: u32,
        file_hdr_sz: u16,
        chunk_hdr_sz: u16,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&SPARSE_HEADER_MAGIC.to_le_bytes());
        out.extend_from_slice(&SPARSE_MAJOR_VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&file_hdr_sz.to_le_bytes());
        out.extend_from_slice(&chunk_hdr_sz.to_le_bytes());
        out.extend_from_slice(&blk_sz.to_le_bytes());
        out.extend_from_slice(&total_blks.to_le_bytes());
        out.extend_from_slice(&total_chunks.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.resize(file_hdr_sz as usize, 0);
        out
    }

    fn append_raw_chunk(out: &mut Vec<u8>, blocks: u32, payload: &[u8], chunk_hdr_sz: u16) {
        append_chunk_header(
            out,
            CHUNK_TYPE_RAW,
            blocks,
            (chunk_hdr_sz as u32) + (payload.len() as u32),
            chunk_hdr_sz,
        );
        out.extend_from_slice(payload);
    }

    fn append_fill_chunk(out: &mut Vec<u8>, blocks: u32, fill: u32, chunk_hdr_sz: u16) {
        append_chunk_header(
            out,
            CHUNK_TYPE_FILL,
            blocks,
            (chunk_hdr_sz as u32) + 4,
            chunk_hdr_sz,
        );
        out.extend_from_slice(&fill.to_le_bytes());
    }

    fn append_dont_care_chunk(out: &mut Vec<u8>, blocks: u32, chunk_hdr_sz: u16) {
        append_chunk_header(
            out,
            CHUNK_TYPE_DONT_CARE,
            blocks,
            chunk_hdr_sz as u32,
            chunk_hdr_sz,
        );
    }

    fn append_crc32_chunk(out: &mut Vec<u8>, crc: u32, chunk_hdr_sz: u16, chunk_sz: u32) {
        append_chunk_header(
            out,
            CHUNK_TYPE_CRC32,
            chunk_sz,
            (chunk_hdr_sz as u32) + 4,
            chunk_hdr_sz,
        );
        out.extend_from_slice(&crc.to_le_bytes());
    }

    fn append_chunk_header(
        out: &mut Vec<u8>,
        chunk_type: u16,
        chunk_sz: u32,
        total_sz: u32,
        chunk_hdr_sz: u16,
    ) {
        out.extend_from_slice(&chunk_type.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&chunk_sz.to_le_bytes());
        out.extend_from_slice(&total_sz.to_le_bytes());
        out.resize(out.len() + (chunk_hdr_sz as usize - CHUNK_HEADER_LEN), 0);
    }
}
