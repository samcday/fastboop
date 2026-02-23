extern crate alloc;

use alloc::{boxed::Box, format, string::String, sync::Arc, vec};
use async_trait::async_trait;
use core::fmt;
use tracing::{info, trace};

use crate::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};

const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
const GPT_MIN_HEADER_SIZE: usize = 92;
const GPT_MIN_PARTITION_ENTRY_SIZE: usize = 128;
const GPT_MAX_PARTITION_TABLE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GptPartitionSelector {
    PartLabel(String),
    PartUuid(String),
    Index(u32),
}

impl GptPartitionSelector {
    pub fn part_label(value: impl Into<String>) -> Self {
        Self::PartLabel(value.into())
    }

    pub fn part_uuid(value: impl Into<String>) -> Self {
        Self::PartUuid(value.into())
    }

    pub const fn index(value: u32) -> Self {
        Self::Index(value)
    }
}

impl fmt::Display for GptPartitionSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PartLabel(value) => write!(f, "partlabel={value}"),
            Self::PartUuid(value) => write!(f, "partuuid={value}"),
            Self::Index(value) => write!(f, "index={value}"),
        }
    }
}

pub struct GptBlockReader {
    block_size: u32,
    partition_size_bytes: u64,
    partition_index: u32,
    partition_partuuid: String,
    source: Arc<dyn BlockReader>,
    source_block_size: usize,
    source_size_bytes: u64,
    partition_offset_bytes: u64,
    identity: String,
}

impl GptBlockReader {
    pub async fn new<S: BlockReader + 'static>(
        source: S,
        selector: GptPartitionSelector,
        block_size: u32,
    ) -> GibbloxResult<Self> {
        info!(%selector, block_size, "constructing GPT-backed reader");
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
        if source_total_blocks < 2 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "GPT image requires at least two logical blocks",
            ));
        }
        let source_size_bytes = source_total_blocks
            .checked_mul(source_block_size as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "image size overflow")
            })?;

        let source: Arc<dyn BlockReader> = Arc::new(source);
        let source_identity = crate::block_identity_string(source.as_ref());
        let byte_reader = SourceByteReader {
            inner: Arc::clone(&source),
            block_size: source_block_size as usize,
            size_bytes: source_size_bytes,
        };

        let mut header_block = vec![0u8; source_block_size as usize];
        byte_reader
            .read_exact_at(
                source_block_size as u64,
                &mut header_block,
                ReadContext::FOREGROUND,
            )
            .await?;
        let header = parse_gpt_header(&header_block, source_total_blocks)?;

        let partition_table_offset = header
            .partition_entries_lba
            .checked_mul(source_block_size as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "partition table offset overflow",
                )
            })?;
        let partition_table_bytes = (header.partition_entry_count as u64)
            .checked_mul(header.partition_entry_size as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "partition table size overflow",
                )
            })?;
        if partition_table_bytes == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "GPT partition table is empty",
            ));
        }
        if partition_table_bytes > GPT_MAX_PARTITION_TABLE_BYTES {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Unsupported,
                "GPT partition table is too large",
            ));
        }
        let partition_table_end = partition_table_offset
            .checked_add(partition_table_bytes)
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "partition table range overflow",
                )
            })?;
        if partition_table_end > source_size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "partition table exceeds image size",
            ));
        }

        let table_len = usize::try_from(partition_table_bytes).map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "partition table size exceeds addressable memory",
            )
        })?;
        let mut partition_table = vec![0u8; table_len];
        byte_reader
            .read_exact_at(
                partition_table_offset,
                &mut partition_table,
                ReadContext::FOREGROUND,
            )
            .await?;
        let partition_table_crc32 = crc32_ieee(&partition_table);
        if partition_table_crc32 != header.partition_entry_array_crc32 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "GPT partition table CRC mismatch",
            ));
        }

        let selected = select_partition_entry(
            &partition_table,
            header.partition_entry_size as usize,
            &selector,
        )?;
        validate_selected_partition(&header, &selected, source_total_blocks)?;

        let partition_offset_bytes = selected
            .first_lba
            .checked_mul(source_block_size as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "partition offset overflow",
                )
            })?;
        let partition_size_bytes = selected.partition_size_bytes(source_block_size as u64)?;
        let partition_end = partition_offset_bytes
            .checked_add(partition_size_bytes)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "partition range overflow")
            })?;
        if partition_end > source_size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "selected partition exceeds image size",
            ));
        }

        let partition_partuuid = format_guid_disk_bytes(&selected.unique_guid);
        info!(
            partition_index = selected.index,
            partuuid = %partition_partuuid,
            first_lba = selected.first_lba,
            last_lba = selected.last_lba,
            partition_size_bytes,
            "resolved GPT partition"
        );

        let identity = format!(
            "gpt-partition:({}):index={}:partuuid={}",
            source_identity, selected.index, partition_partuuid
        );

        Ok(Self {
            block_size,
            partition_size_bytes,
            partition_index: selected.index,
            partition_partuuid,
            source,
            source_block_size: source_block_size as usize,
            source_size_bytes,
            partition_offset_bytes,
            identity,
        })
    }

    pub fn partition_size_bytes(&self) -> u64 {
        self.partition_size_bytes
    }

    pub fn partition_index(&self) -> u32 {
        self.partition_index
    }

    pub fn partition_partuuid(&self) -> &str {
        &self.partition_partuuid
    }
}

#[async_trait]
impl BlockReader for GptBlockReader {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        Ok(self.partition_size_bytes.div_ceil(self.block_size as u64))
    }

    fn write_identity(&self, out: &mut dyn fmt::Write) -> fmt::Result {
        out.write_str(&self.identity)
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
        if offset >= self.partition_size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "requested block out of range",
            ));
        }

        let read_len = ((buf.len() as u64).min(self.partition_size_bytes - offset)) as usize;
        let source_offset = self
            .partition_offset_bytes
            .checked_add(offset)
            .ok_or_else(|| {
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
            read_len,
            "reading partition blocks from GPT"
        );
        byte_reader
            .read_exact_at(source_offset, &mut buf[..read_len], ctx)
            .await?;
        if read_len < buf.len() {
            buf[read_len..].fill(0);
        }
        Ok(buf.len())
    }
}

#[derive(Clone, Copy, Debug)]
struct GptHeader {
    first_usable_lba: u64,
    last_usable_lba: u64,
    partition_entries_lba: u64,
    partition_entry_count: u32,
    partition_entry_size: u32,
    partition_entry_array_crc32: u32,
}

#[derive(Clone, Copy, Debug)]
struct GptPartitionEntry {
    index: u32,
    type_guid: [u8; 16],
    unique_guid: [u8; 16],
    first_lba: u64,
    last_lba: u64,
}

impl GptPartitionEntry {
    fn is_unused(&self) -> bool {
        self.type_guid.iter().all(|byte| *byte == 0)
    }

    fn partition_size_bytes(&self, source_block_size: u64) -> GibbloxResult<u64> {
        let block_count = self
            .last_lba
            .checked_sub(self.first_lba)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "partition block range overflow",
                )
            })?;
        block_count.checked_mul(source_block_size).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "partition size overflow")
        })
    }
}

fn parse_gpt_header(raw: &[u8], total_blocks: u64) -> GibbloxResult<GptHeader> {
    if raw.len() < GPT_MIN_HEADER_SIZE {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "GPT header block is too short",
        ));
    }
    if raw[..8] != *GPT_SIGNATURE {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "GPT header signature not found at LBA1",
        ));
    }

    let header_size = read_u32_le(raw, 12)? as usize;
    if header_size < GPT_MIN_HEADER_SIZE || header_size > raw.len() {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "GPT header size is invalid",
        ));
    }
    let expected_header_crc32 = read_u32_le(raw, 16)?;
    let mut header_for_crc = raw[..header_size].to_vec();
    header_for_crc[16..20].fill(0);
    let actual_header_crc32 = crc32_ieee(&header_for_crc);
    if actual_header_crc32 != expected_header_crc32 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "GPT header CRC mismatch",
        ));
    }

    let current_lba = read_u64_le(raw, 24)?;
    let backup_lba = read_u64_le(raw, 32)?;
    let first_usable_lba = read_u64_le(raw, 40)?;
    let last_usable_lba = read_u64_le(raw, 48)?;
    let partition_entries_lba = read_u64_le(raw, 72)?;
    let partition_entry_count = read_u32_le(raw, 80)?;
    let partition_entry_size = read_u32_le(raw, 84)?;
    let partition_entry_array_crc32 = read_u32_le(raw, 88)?;

    if current_lba >= total_blocks {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            "GPT current LBA exceeds source bounds",
        ));
    }
    if backup_lba >= total_blocks {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            "GPT backup LBA exceeds source bounds",
        ));
    }
    if first_usable_lba > last_usable_lba {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "GPT usable LBA range is invalid",
        ));
    }
    if partition_entries_lba >= total_blocks {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            "GPT partition entry array LBA exceeds source bounds",
        ));
    }
    if partition_entry_count == 0 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "GPT partition entry count is zero",
        ));
    }
    if partition_entry_size < GPT_MIN_PARTITION_ENTRY_SIZE as u32 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "GPT partition entry size is too small",
        ));
    }

    Ok(GptHeader {
        first_usable_lba,
        last_usable_lba,
        partition_entries_lba,
        partition_entry_count,
        partition_entry_size,
        partition_entry_array_crc32,
    })
}

fn select_partition_entry(
    table: &[u8],
    partition_entry_size: usize,
    selector: &GptPartitionSelector,
) -> GibbloxResult<GptPartitionEntry> {
    if partition_entry_size == 0 || !table.len().is_multiple_of(partition_entry_size) {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "GPT partition table shape is invalid",
        ));
    }
    let entry_count = table.len() / partition_entry_size;

    match selector {
        GptPartitionSelector::PartLabel(raw_label) => {
            let target = raw_label.trim();
            if target.is_empty() {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "GPT partition label is empty",
                ));
            }

            for index in 0..entry_count {
                let entry_index = u32::try_from(index).map_err(|_| {
                    GibbloxError::with_message(
                        GibbloxErrorKind::OutOfRange,
                        "partition index exceeds u32 range",
                    )
                })?;
                let offset = index * partition_entry_size;
                let raw_entry = &table[offset..offset + partition_entry_size];
                let entry = parse_partition_entry(raw_entry, entry_index)?;
                if entry.is_unused() {
                    continue;
                }
                let label = parse_partition_label(raw_entry)?;
                if label == target {
                    if entry.last_lba < entry.first_lba {
                        return Err(GibbloxError::with_message(
                            GibbloxErrorKind::InvalidInput,
                            "selected GPT partition has invalid LBA range",
                        ));
                    }
                    return Ok(entry);
                }
            }

            Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "GPT partition label not found",
            ))
        }
        GptPartitionSelector::Index(index) => {
            let index_usize = usize::try_from(*index).map_err(|_| {
                GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "partition index exceeds addressable range",
                )
            })?;
            if index_usize >= entry_count {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "GPT partition index not found",
                ));
            }
            let offset = index_usize * partition_entry_size;
            let entry =
                parse_partition_entry(&table[offset..offset + partition_entry_size], *index)?;
            if entry.is_unused() {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "selected GPT partition entry is unused",
                ));
            }
            if entry.last_lba < entry.first_lba {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "selected GPT partition has invalid LBA range",
                ));
            }
            Ok(entry)
        }
        GptPartitionSelector::PartUuid(raw_uuid) => {
            let target = parse_guid_text_to_disk_bytes(raw_uuid)?;
            for index in 0..entry_count {
                let entry_index = u32::try_from(index).map_err(|_| {
                    GibbloxError::with_message(
                        GibbloxErrorKind::OutOfRange,
                        "partition index exceeds u32 range",
                    )
                })?;
                let offset = index * partition_entry_size;
                let entry = parse_partition_entry(
                    &table[offset..offset + partition_entry_size],
                    entry_index,
                )?;
                if entry.is_unused() {
                    continue;
                }
                if entry.unique_guid == target {
                    if entry.last_lba < entry.first_lba {
                        return Err(GibbloxError::with_message(
                            GibbloxErrorKind::InvalidInput,
                            "selected GPT partition has invalid LBA range",
                        ));
                    }
                    return Ok(entry);
                }
            }
            Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "GPT partition UUID not found",
            ))
        }
    }
}

fn parse_partition_entry(raw: &[u8], index: u32) -> GibbloxResult<GptPartitionEntry> {
    if raw.len() < GPT_MIN_PARTITION_ENTRY_SIZE {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "GPT partition entry is too short",
        ));
    }

    let mut type_guid = [0u8; 16];
    type_guid.copy_from_slice(&raw[..16]);
    let mut unique_guid = [0u8; 16];
    unique_guid.copy_from_slice(&raw[16..32]);

    let first_lba = read_u64_le(raw, 32)?;
    let last_lba = read_u64_le(raw, 40)?;

    Ok(GptPartitionEntry {
        index,
        type_guid,
        unique_guid,
        first_lba,
        last_lba,
    })
}

fn parse_partition_label(raw: &[u8]) -> GibbloxResult<String> {
    if raw.len() < GPT_MIN_PARTITION_ENTRY_SIZE {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "GPT partition entry is too short",
        ));
    }

    let name_raw = &raw[56..128];
    let mut units = [0u16; 36];
    for (idx, chunk) in name_raw.chunks_exact(2).enumerate() {
        units[idx] = u16::from_le_bytes([chunk[0], chunk[1]]);
    }

    let end = units
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(units.len());
    let mut out = String::new();
    for decoded in core::char::decode_utf16(units[..end].iter().copied()) {
        let ch = decoded.map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "GPT partition label is not valid UTF-16",
            )
        })?;
        out.push(ch);
    }
    Ok(out)
}

fn validate_selected_partition(
    header: &GptHeader,
    selected: &GptPartitionEntry,
    source_total_blocks: u64,
) -> GibbloxResult<()> {
    if selected.first_lba < header.first_usable_lba || selected.last_lba > header.last_usable_lba {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "selected GPT partition is outside usable LBA range",
        ));
    }
    if selected.last_lba >= source_total_blocks {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::OutOfRange,
            "selected GPT partition exceeds source bounds",
        ));
    }
    Ok(())
}

fn parse_guid_text_to_disk_bytes(value: &str) -> GibbloxResult<[u8; 16]> {
    let mut digits = [0u8; 32];
    let mut count = 0usize;
    for byte in value.as_bytes() {
        if *byte == b'-' {
            continue;
        }
        if count >= digits.len() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "invalid GPT UUID text",
            ));
        }
        digits[count] = *byte;
        count += 1;
    }
    if count != digits.len() {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "invalid GPT UUID text",
        ));
    }

    let mut canonical = [0u8; 16];
    for (idx, chunk) in digits.chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(chunk[0]).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::InvalidInput, "invalid GPT UUID text")
        })?;
        let low = decode_hex_nibble(chunk[1]).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::InvalidInput, "invalid GPT UUID text")
        })?;
        canonical[idx] = (high << 4) | low;
    }

    let mut disk = [0u8; 16];
    disk[0..4].copy_from_slice(&[canonical[3], canonical[2], canonical[1], canonical[0]]);
    disk[4..6].copy_from_slice(&[canonical[5], canonical[4]]);
    disk[6..8].copy_from_slice(&[canonical[7], canonical[6]]);
    disk[8..16].copy_from_slice(&canonical[8..16]);
    Ok(disk)
}

fn format_guid_disk_bytes(raw: &[u8; 16]) -> String {
    let a = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let b = u16::from_le_bytes([raw[4], raw[5]]);
    let c = u16::from_le_bytes([raw[6], raw[7]]);
    format!(
        "{a:08x}-{b:04x}-{c:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]
    )
}

fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320u32 & mask);
        }
    }
    !crc
}

fn read_u32_le(raw: &[u8], start: usize) -> GibbloxResult<u32> {
    let end = start.checked_add(4).ok_or_else(|| {
        GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "field offset overflow")
    })?;
    let data = raw.get(start..end).ok_or_else(|| {
        GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "field exceeds record bounds",
        )
    })?;
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(data);
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64_le(raw: &[u8], start: usize) -> GibbloxResult<u64> {
    let end = start.checked_add(8).ok_or_else(|| {
        GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "field offset overflow")
    })?;
    let data = raw.get(start..end).ok_or_else(|| {
        GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "field exceeds record bounds",
        )
    })?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(data);
    Ok(u64::from_le_bytes(bytes))
}

#[derive(Clone)]
struct SourceByteReader {
    inner: Arc<dyn BlockReader>,
    block_size: usize,
    size_bytes: u64,
}

impl SourceByteReader {
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
        let aligned_len = usize::try_from(aligned_end - aligned_start).map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "aligned read length exceeds addressable memory",
            )
        })?;

        let mut scratch = vec![0u8; aligned_len];
        let mut filled = 0usize;
        while filled < scratch.len() {
            let filled_u64 = u64::try_from(filled).map_err(|_| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "aligned read offset exceeds u64 range",
                )
            })?;
            let read_offset = aligned_start.checked_add(filled_u64).ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "aligned read offset overflow",
                )
            })?;
            let lba = read_offset / bs;
            let read = self
                .inner
                .read_blocks(lba, &mut scratch[filled..], ctx)
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
            filled = filled.checked_add(read).ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "aligned read progress overflow",
                )
            })?;
        }

        let head = usize::try_from(offset - aligned_start).map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "aligned read head offset exceeds addressable memory",
            )
        })?;
        out.copy_from_slice(&scratch[head..head + out.len()]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use futures::executor::block_on;

    const TEST_BLOCK_SIZE: usize = 512;
    const TEST_TOTAL_BLOCKS: usize = 160;
    const TEST_ENTRY_SIZE: usize = 128;
    const TEST_ENTRY_COUNT: usize = 128;
    const TEST_PART1_UUID: &str = "11111111-2222-3333-4444-555555555555";
    const TEST_PART2_UUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    struct FakeReader {
        block_size: u32,
        data: alloc::vec::Vec<u8>,
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
            write!(out, "fake-gpt:{}:{}", self.block_size, self.data.len())
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
    fn gpt_reader_selects_partition_by_partuuid() {
        let (disk, partition_one_data) = build_test_gpt_disk();
        let reader = FakeReader {
            block_size: TEST_BLOCK_SIZE as u32,
            data: disk,
        };

        let gpt = block_on(GptBlockReader::new(
            reader,
            GptPartitionSelector::part_uuid(TEST_PART1_UUID),
            1024,
        ))
        .expect("construct GPT partition reader");

        assert_eq!(gpt.partition_size_bytes(), 1536);
        assert_eq!(gpt.partition_index(), 0);
        assert_eq!(gpt.partition_partuuid(), TEST_PART1_UUID);
        assert_eq!(block_on(gpt.total_blocks()).expect("total blocks"), 2);

        let mut first = vec![0u8; 1024];
        block_on(gpt.read_blocks(0, &mut first, ReadContext::FOREGROUND)).expect("read first");
        assert_eq!(&first[..], &partition_one_data[..1024]);

        let mut second = vec![0u8; 1024];
        block_on(gpt.read_blocks(1, &mut second, ReadContext::FOREGROUND)).expect("read second");
        assert_eq!(&second[..512], &partition_one_data[1024..1536]);
        assert!(second[512..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn gpt_reader_selects_partition_by_index() {
        let (disk, _partition_one_data) = build_test_gpt_disk();
        let reader = FakeReader {
            block_size: TEST_BLOCK_SIZE as u32,
            data: disk,
        };

        let gpt = block_on(GptBlockReader::new(
            reader,
            GptPartitionSelector::index(1),
            TEST_BLOCK_SIZE as u32,
        ))
        .expect("construct GPT partition reader");

        assert_eq!(gpt.partition_index(), 1);
        assert_eq!(gpt.partition_partuuid(), TEST_PART2_UUID);
        assert_eq!(gpt.partition_size_bytes(), 1024);

        let mut block = vec![0u8; TEST_BLOCK_SIZE];
        block_on(gpt.read_blocks(0, &mut block, ReadContext::FOREGROUND)).expect("read block");
        assert!(block.iter().all(|byte| *byte == 0xAA));
    }

    #[test]
    fn gpt_reader_selects_partition_by_partlabel() {
        let (disk, partition_one_data) = build_test_gpt_disk();
        let reader = FakeReader {
            block_size: TEST_BLOCK_SIZE as u32,
            data: disk,
        };

        let gpt = block_on(GptBlockReader::new(
            reader,
            GptPartitionSelector::part_label("rootfs"),
            1024,
        ))
        .expect("construct GPT partition reader");

        assert_eq!(gpt.partition_index(), 0);
        assert_eq!(gpt.partition_partuuid(), TEST_PART1_UUID);

        let mut out = vec![0u8; 1024];
        block_on(gpt.read_blocks(0, &mut out, ReadContext::FOREGROUND)).expect("read block");
        assert_eq!(&out[..], &partition_one_data[..1024]);
    }

    #[test]
    fn gpt_reader_reports_missing_partuuid() {
        let (disk, _partition_one_data) = build_test_gpt_disk();
        let reader = FakeReader {
            block_size: TEST_BLOCK_SIZE as u32,
            data: disk,
        };

        let err = block_on(GptBlockReader::new(
            reader,
            GptPartitionSelector::part_uuid("00000000-0000-0000-0000-000000000000"),
            TEST_BLOCK_SIZE as u32,
        ))
        .err()
        .expect("missing uuid should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::InvalidInput);
    }

    #[test]
    fn gpt_reader_rejects_invalid_header_signature() {
        let (mut disk, _partition_one_data) = build_test_gpt_disk();
        let header_start = TEST_BLOCK_SIZE;
        disk[header_start..header_start + 8].copy_from_slice(b"NOT GPT!");

        let reader = FakeReader {
            block_size: TEST_BLOCK_SIZE as u32,
            data: disk,
        };

        let err = block_on(GptBlockReader::new(
            reader,
            GptPartitionSelector::index(0),
            TEST_BLOCK_SIZE as u32,
        ))
        .err()
        .expect("invalid header should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::InvalidInput);
    }

    #[test]
    fn gpt_reader_rejects_invalid_header_crc() {
        let (mut disk, _partition_one_data) = build_test_gpt_disk();
        let header_start = TEST_BLOCK_SIZE;
        disk[header_start + 16..header_start + 20].copy_from_slice(&0u32.to_le_bytes());

        let reader = FakeReader {
            block_size: TEST_BLOCK_SIZE as u32,
            data: disk,
        };

        let err = block_on(GptBlockReader::new(
            reader,
            GptPartitionSelector::index(0),
            TEST_BLOCK_SIZE as u32,
        ))
        .err()
        .expect("invalid header crc should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::InvalidInput);
    }

    #[test]
    fn gpt_reader_rejects_invalid_partition_table_crc() {
        let (mut disk, _partition_one_data) = build_test_gpt_disk();
        let table_start = TEST_BLOCK_SIZE * 2;
        disk[table_start] ^= 0x01;

        let reader = FakeReader {
            block_size: TEST_BLOCK_SIZE as u32,
            data: disk,
        };

        let err = block_on(GptBlockReader::new(
            reader,
            GptPartitionSelector::index(0),
            TEST_BLOCK_SIZE as u32,
        ))
        .err()
        .expect("invalid partition table crc should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::InvalidInput);
    }

    fn build_test_gpt_disk() -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>) {
        let mut disk = vec![0u8; TEST_BLOCK_SIZE * TEST_TOTAL_BLOCKS];

        let header_start = TEST_BLOCK_SIZE;
        let header_end = TEST_BLOCK_SIZE * 2;
        {
            let header = &mut disk[header_start..header_end];
            header[..8].copy_from_slice(GPT_SIGNATURE);
            header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
            header[12..16].copy_from_slice(&(GPT_MIN_HEADER_SIZE as u32).to_le_bytes());
            header[24..32].copy_from_slice(&1u64.to_le_bytes());
            header[32..40].copy_from_slice(&((TEST_TOTAL_BLOCKS - 1) as u64).to_le_bytes());
            header[40..48].copy_from_slice(&34u64.to_le_bytes());
            header[48..56].copy_from_slice(&((TEST_TOTAL_BLOCKS - 34) as u64).to_le_bytes());
            header[56..72].copy_from_slice(
                &parse_guid_text_to_disk_bytes("00112233-4455-6677-8899-aabbccddeeff")
                    .expect("disk guid"),
            );
            header[72..80].copy_from_slice(&2u64.to_le_bytes());
            header[80..84].copy_from_slice(&(TEST_ENTRY_COUNT as u32).to_le_bytes());
            header[84..88].copy_from_slice(&(TEST_ENTRY_SIZE as u32).to_le_bytes());
        }

        let table_start = TEST_BLOCK_SIZE * 2;
        let table_end = table_start + TEST_ENTRY_SIZE * TEST_ENTRY_COUNT;
        let table = &mut disk[table_start..table_end];
        write_partition_entry(table, 0, TEST_PART1_UUID, "rootfs", 40, 42);
        write_partition_entry(table, 1, TEST_PART2_UUID, "userdata", 50, 51);
        let table_crc32 = crc32_ieee(table);
        {
            let header = &mut disk[header_start..header_end];
            header[88..92].copy_from_slice(&table_crc32.to_le_bytes());

            let mut header_for_crc = header[..GPT_MIN_HEADER_SIZE].to_vec();
            header_for_crc[16..20].fill(0);
            let header_crc32 = crc32_ieee(&header_for_crc);
            header[16..20].copy_from_slice(&header_crc32.to_le_bytes());
        }

        let partition_one_offset = 40 * TEST_BLOCK_SIZE;
        let partition_one_data: alloc::vec::Vec<u8> =
            (0..1536).map(|idx| (idx % 251) as u8).collect();
        disk[partition_one_offset..partition_one_offset + partition_one_data.len()]
            .copy_from_slice(&partition_one_data);

        let partition_two_offset = 50 * TEST_BLOCK_SIZE;
        disk[partition_two_offset..partition_two_offset + 1024].fill(0xAA);

        (disk, partition_one_data)
    }

    fn write_partition_entry(
        table: &mut [u8],
        index: usize,
        partuuid: &str,
        partlabel: &str,
        first_lba: u64,
        last_lba: u64,
    ) {
        const TYPE_GUID: &str = "0fc63daf-8483-4772-8e79-3d69d8477de4";

        let start = index * TEST_ENTRY_SIZE;
        let entry = &mut table[start..start + TEST_ENTRY_SIZE];
        entry[..16].copy_from_slice(&parse_guid_text_to_disk_bytes(TYPE_GUID).expect("type guid"));
        entry[16..32].copy_from_slice(&parse_guid_text_to_disk_bytes(partuuid).expect("partuuid"));
        entry[32..40].copy_from_slice(&first_lba.to_le_bytes());
        entry[40..48].copy_from_slice(&last_lba.to_le_bytes());

        let encoded: alloc::vec::Vec<u16> = partlabel.encode_utf16().collect();
        assert!(
            encoded.len() <= 36,
            "partition label too long for GPT test entry"
        );
        for (idx, unit) in encoded.iter().enumerate() {
            let dst = 56 + idx * 2;
            entry[dst..dst + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
}
