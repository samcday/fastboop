#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::{boxed::Box, format, string::String, sync::Arc};
use async_trait::async_trait;
use bytemuck::try_from_bytes;
use core::fmt;
use gibblox_core::{
    BlockReader, ByteRangeReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext,
};
use hadris_part::mbr::MasterBootRecord;
use tracing::{info, trace};

const MBR_SECTOR_SIZE: usize = 512;
#[cfg(test)]
const MBR_SIGNATURE: [u8; 2] = [0x55, 0xaa];
#[cfg(test)]
const MBR_SIGNATURE_OFFSET: usize = 510;
const MBR_DISK_SIGNATURE_OFFSET: usize = 0x1b8;
#[cfg(test)]
const MBR_PARTITION_TABLE_OFFSET: usize = 0x1be;
#[cfg(test)]
const MBR_PARTITION_ENTRY_LEN: usize = 16;
const MBR_PRIMARY_PARTITION_COUNT: usize = 4;

const MBR_EXTENDED_TYPE_CHS: u8 = 0x05;
const MBR_EXTENDED_TYPE_LBA: u8 = 0x0f;
const MBR_EXTENDED_TYPE_LINUX: u8 = 0x85;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MbrPartitionSelector {
    PartUuid(String),
    Index(u32),
}

impl MbrPartitionSelector {
    pub fn part_uuid(value: impl Into<String>) -> Self {
        Self::PartUuid(value.into())
    }

    pub const fn index(value: u32) -> Self {
        Self::Index(value)
    }
}

impl fmt::Display for MbrPartitionSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PartUuid(value) => write!(f, "partuuid={value}"),
            Self::Index(value) => write!(f, "index={value}"),
        }
    }
}

pub struct MbrBlockReader {
    block_size: u32,
    partition_size_bytes: u64,
    partition_index: u32,
    partition_partuuid: String,
    byte_reader: ByteRangeReader,
    partition_offset_bytes: u64,
    identity: String,
}

impl MbrBlockReader {
    pub async fn new<S: BlockReader + 'static>(
        source: S,
        selector: MbrPartitionSelector,
        block_size: u32,
    ) -> GibbloxResult<Self> {
        info!(%selector, block_size, "constructing MBR-backed reader");
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
        if source_size_bytes < MBR_SECTOR_SIZE as u64 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "MBR image is smaller than one sector",
            ));
        }

        let source: Arc<dyn BlockReader> = Arc::new(source);
        let source_identity = gibblox_core::block_identity_string(source.as_ref());
        let byte_reader = ByteRangeReader::new(
            Arc::clone(&source),
            source_block_size as usize,
            source_size_bytes,
        );

        let mut mbr_sector = [0u8; MBR_SECTOR_SIZE];
        byte_reader
            .read_exact_at(0, &mut mbr_sector, ReadContext::FOREGROUND)
            .await?;
        let header = parse_mbr_header(&mbr_sector)?;
        let disk_signature = mbr_disk_signature(&header);

        let selected = select_partition_entry(&header, &selector)?;
        let partition_offset_bytes = u64::from(selected.first_lba)
            .checked_mul(MBR_SECTOR_SIZE as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "partition offset overflow",
                )
            })?;
        let partition_size_bytes = u64::from(selected.sector_count)
            .checked_mul(MBR_SECTOR_SIZE as u64)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "partition size overflow")
            })?;
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

        let partition_number = u8::try_from(selected.index + 1).map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "partition number exceeds addressable range",
            )
        })?;
        let partition_partuuid = format_mbr_partuuid(disk_signature, partition_number);

        info!(
            partition_index = selected.index,
            partuuid = %partition_partuuid,
            first_lba = selected.first_lba,
            sector_count = selected.sector_count,
            partition_size_bytes,
            "resolved MBR partition"
        );

        let identity = format!(
            "mbr-partition:({}):index={}:partuuid={}",
            source_identity, selected.index, partition_partuuid
        );

        Ok(Self {
            block_size,
            partition_size_bytes,
            partition_index: selected.index,
            partition_partuuid,
            byte_reader,
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
impl BlockReader for MbrBlockReader {
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

        trace!(
            lba,
            offset,
            requested = buf.len(),
            read_len,
            "reading partition blocks from MBR"
        );
        self.byte_reader
            .read_exact_at(source_offset, &mut buf[..read_len], ctx)
            .await?;
        if read_len < buf.len() {
            buf[read_len..].fill(0);
        }
        Ok(buf.len())
    }
}

#[derive(Clone, Copy, Debug)]
struct SelectedPartition {
    index: u32,
    partition_type: u8,
    first_lba: u32,
    sector_count: u32,
}

impl SelectedPartition {
    fn is_unused(&self) -> bool {
        self.partition_type == 0 || self.sector_count == 0
    }

    fn is_extended(&self) -> bool {
        matches!(
            self.partition_type,
            MBR_EXTENDED_TYPE_CHS | MBR_EXTENDED_TYPE_LBA | MBR_EXTENDED_TYPE_LINUX
        )
    }
}

fn parse_mbr_header(raw: &[u8]) -> GibbloxResult<MasterBootRecord> {
    if raw.len() < MBR_SECTOR_SIZE {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "MBR header block is too short",
        ));
    }

    let mbr = *try_from_bytes::<MasterBootRecord>(&raw[..MBR_SECTOR_SIZE]).map_err(|_| {
        GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "MBR header layout is invalid",
        )
    })?;
    if !mbr.has_valid_signature() {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "MBR signature not found at LBA0",
        ));
    }
    let partition_table = mbr.get_partition_table();
    if !partition_table.is_valid() {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "MBR partition entry has invalid boot indicator",
        ));
    }

    Ok(mbr)
}

fn mbr_disk_signature(mbr: &MasterBootRecord) -> u32 {
    let start = MBR_DISK_SIGNATURE_OFFSET;
    u32::from_le_bytes([
        mbr.bootstrap[start],
        mbr.bootstrap[start + 1],
        mbr.bootstrap[start + 2],
        mbr.bootstrap[start + 3],
    ])
}

fn select_partition_entry(
    header: &MasterBootRecord,
    selector: &MbrPartitionSelector,
) -> GibbloxResult<SelectedPartition> {
    let disk_signature = mbr_disk_signature(header);
    let partition_table = header.get_partition_table();

    let selected = match selector {
        MbrPartitionSelector::Index(index) => {
            let index_usize = usize::try_from(*index).map_err(|_| {
                GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "partition index exceeds addressable range",
                )
            })?;
            if index_usize >= MBR_PRIMARY_PARTITION_COUNT {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "MBR partition index not found",
                ));
            }
            let partition = partition_table.partitions[index_usize];
            SelectedPartition {
                index: *index,
                partition_type: partition.part_type,
                first_lba: partition.start_lba,
                sector_count: partition.sector_count,
            }
        }
        MbrPartitionSelector::PartUuid(raw_uuid) => {
            let (target_disk_signature, target_partition_number) =
                parse_mbr_partuuid_text(raw_uuid)?;
            if target_partition_number > MBR_PRIMARY_PARTITION_COUNT as u8 {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Unsupported,
                    "extended/logical MBR partitions are not supported",
                ));
            }
            if disk_signature != target_disk_signature {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "MBR partition UUID not found",
                ));
            }

            let index = usize::from(target_partition_number - 1);
            let partition = partition_table.partitions[index];
            SelectedPartition {
                index: u32::from(target_partition_number - 1),
                partition_type: partition.part_type,
                first_lba: partition.start_lba,
                sector_count: partition.sector_count,
            }
        }
    };

    if selected.is_unused() {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "selected MBR partition entry is unused",
        ));
    }
    if selected.is_extended() {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::Unsupported,
            "extended/logical MBR partitions are not supported",
        ));
    }
    Ok(selected)
}

fn parse_mbr_partuuid_text(value: &str) -> GibbloxResult<(u32, u8)> {
    let trimmed = value.trim();
    let (disk_signature_text, partition_number_text) = trimmed
        .split_once('-')
        .ok_or_else(invalid_mbr_partuuid_error)?;
    if disk_signature_text.len() != 8 || partition_number_text.len() != 2 {
        return Err(invalid_mbr_partuuid_error());
    }

    let disk_signature =
        u32::from_str_radix(disk_signature_text, 16).map_err(|_| invalid_mbr_partuuid_error())?;
    let partition_number =
        u8::from_str_radix(partition_number_text, 16).map_err(|_| invalid_mbr_partuuid_error())?;
    if partition_number == 0 {
        return Err(invalid_mbr_partuuid_error());
    }
    Ok((disk_signature, partition_number))
}

fn format_mbr_partuuid(disk_signature: u32, partition_number: u8) -> String {
    format!("{disk_signature:08x}-{partition_number:02x}")
}

fn invalid_mbr_partuuid_error() -> GibbloxError {
    GibbloxError::with_message(
        GibbloxErrorKind::InvalidInput,
        "invalid MBR partition UUID text",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use futures::executor::block_on;

    const TEST_BLOCK_SIZE: usize = 512;
    const TEST_TOTAL_BLOCKS: usize = 256;
    const TEST_DISK_SIGNATURE: u32 = 0x9439_af65;
    const TEST_PART1_UUID: &str = "9439af65-01";
    const TEST_PART2_UUID: &str = "9439af65-02";

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
            write!(out, "fake-mbr:{}:{}", self.block_size, self.data.len())
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

            let read_len = (self.data.len() - offset).min(buf.len());
            buf[..read_len].copy_from_slice(&self.data[offset..offset + read_len]);
            if read_len < buf.len() {
                buf[read_len..].fill(0);
            }
            Ok(buf.len())
        }
    }

    #[test]
    fn mbr_reader_selects_partition_by_partuuid() {
        let (disk, partition_one_data, _partition_two_data) = build_test_mbr_disk();
        let reader = FakeReader {
            block_size: TEST_BLOCK_SIZE as u32,
            data: disk,
        };

        let mbr = block_on(MbrBlockReader::new(
            reader,
            MbrPartitionSelector::part_uuid(TEST_PART1_UUID),
            1024,
        ))
        .expect("construct MBR partition reader");

        assert_eq!(mbr.partition_size_bytes(), 1536);
        assert_eq!(mbr.partition_index(), 0);
        assert_eq!(mbr.partition_partuuid(), TEST_PART1_UUID);
        assert_eq!(block_on(mbr.total_blocks()).expect("total blocks"), 2);

        let mut first = vec![0u8; 1024];
        block_on(mbr.read_blocks(0, &mut first, ReadContext::FOREGROUND)).expect("read first");
        assert_eq!(&first[..], &partition_one_data[..1024]);

        let mut second = vec![0u8; 1024];
        block_on(mbr.read_blocks(1, &mut second, ReadContext::FOREGROUND)).expect("read second");
        assert_eq!(&second[..512], &partition_one_data[1024..1536]);
        assert!(second[512..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn mbr_reader_selects_partition_by_index() {
        let (disk, _partition_one_data, partition_two_data) = build_test_mbr_disk();
        let reader = FakeReader {
            block_size: TEST_BLOCK_SIZE as u32,
            data: disk,
        };

        let mbr = block_on(MbrBlockReader::new(
            reader,
            MbrPartitionSelector::index(1),
            TEST_BLOCK_SIZE as u32,
        ))
        .expect("construct MBR partition reader");

        assert_eq!(mbr.partition_index(), 1);
        assert_eq!(mbr.partition_partuuid(), TEST_PART2_UUID);
        assert_eq!(mbr.partition_size_bytes(), 1024);

        let mut block = vec![0u8; TEST_BLOCK_SIZE];
        block_on(mbr.read_blocks(0, &mut block, ReadContext::FOREGROUND)).expect("read block");
        assert_eq!(&block[..], &partition_two_data[..TEST_BLOCK_SIZE]);
    }

    #[test]
    fn mbr_reader_reports_missing_partuuid() {
        let (disk, _partition_one_data, _partition_two_data) = build_test_mbr_disk();
        let reader = FakeReader {
            block_size: TEST_BLOCK_SIZE as u32,
            data: disk,
        };

        let err = block_on(MbrBlockReader::new(
            reader,
            MbrPartitionSelector::part_uuid("00000000-01"),
            TEST_BLOCK_SIZE as u32,
        ))
        .err()
        .expect("missing uuid should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::InvalidInput);
    }

    #[test]
    fn mbr_reader_rejects_extended_partition() {
        let (disk, _partition_one_data, _partition_two_data) = build_test_mbr_disk();
        let reader = FakeReader {
            block_size: TEST_BLOCK_SIZE as u32,
            data: disk,
        };

        let err = block_on(MbrBlockReader::new(
            reader,
            MbrPartitionSelector::index(2),
            TEST_BLOCK_SIZE as u32,
        ))
        .err()
        .expect("extended partition should be unsupported");
        assert_eq!(err.kind(), GibbloxErrorKind::Unsupported);
    }

    #[test]
    fn mbr_reader_rejects_linux_extended_partition_type() {
        let (mut disk, _partition_one_data, _partition_two_data) = build_test_mbr_disk();
        let entry_offset = MBR_PARTITION_TABLE_OFFSET + (2 * MBR_PARTITION_ENTRY_LEN);
        disk[entry_offset + 4] = MBR_EXTENDED_TYPE_LINUX;

        let reader = FakeReader {
            block_size: TEST_BLOCK_SIZE as u32,
            data: disk,
        };

        let err = block_on(MbrBlockReader::new(
            reader,
            MbrPartitionSelector::index(2),
            TEST_BLOCK_SIZE as u32,
        ))
        .err()
        .expect("linux extended partition should be unsupported");
        assert_eq!(err.kind(), GibbloxErrorKind::Unsupported);
    }

    fn build_test_mbr_disk() -> (
        alloc::vec::Vec<u8>,
        alloc::vec::Vec<u8>,
        alloc::vec::Vec<u8>,
    ) {
        let mut disk = vec![0u8; TEST_BLOCK_SIZE * TEST_TOTAL_BLOCKS];

        disk[MBR_DISK_SIGNATURE_OFFSET..MBR_DISK_SIGNATURE_OFFSET + 4]
            .copy_from_slice(&TEST_DISK_SIGNATURE.to_le_bytes());
        disk[MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 2].copy_from_slice(&MBR_SIGNATURE);

        write_partition_entry(&mut disk, 0, 0x80, 0x83, 2, 3);
        write_partition_entry(&mut disk, 1, 0x00, 0x83, 10, 2);
        write_partition_entry(&mut disk, 2, 0x00, MBR_EXTENDED_TYPE_LBA, 20, 64);

        let partition_one_offset = 2 * TEST_BLOCK_SIZE;
        let partition_one_data: alloc::vec::Vec<u8> =
            (0..1536).map(|idx| (idx % 251) as u8).collect();
        disk[partition_one_offset..partition_one_offset + partition_one_data.len()]
            .copy_from_slice(&partition_one_data);

        let partition_two_offset = 10 * TEST_BLOCK_SIZE;
        let partition_two_data = vec![0xAA; 1024];
        disk[partition_two_offset..partition_two_offset + partition_two_data.len()]
            .copy_from_slice(&partition_two_data);

        (disk, partition_one_data, partition_two_data)
    }

    fn write_partition_entry(
        disk: &mut [u8],
        index: usize,
        status: u8,
        partition_type: u8,
        first_lba: u32,
        sector_count: u32,
    ) {
        let offset = MBR_PARTITION_TABLE_OFFSET + index * MBR_PARTITION_ENTRY_LEN;
        let entry = &mut disk[offset..offset + MBR_PARTITION_ENTRY_LEN];
        entry.fill(0);
        entry[0] = status;
        entry[4] = partition_type;
        entry[8..12].copy_from_slice(&first_lba.to_le_bytes());
        entry[12..16].copy_from_slice(&sector_count.to_le_bytes());
    }
}
