#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::{
    collections::BTreeSet,
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use gibblox_core::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};
use tracing::info;

const BOOT_SECTOR_LEN: usize = 512;
const FAT_ENTRY_SIZE_BYTES: u64 = 4;

const FAT_ATTR_DIRECTORY: u8 = 0x10;
const FAT_ATTR_VOLUME_ID: u8 = 0x08;
const FAT_ATTR_LFN: u8 = 0x0f;

const FAT32_EOC_MIN: u32 = 0x0fff_fff8;
const FAT32_BAD_CLUSTER: u32 = 0x0fff_fff7;

const FAT32_CLUSTER_MIN: u32 = 2;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FatEntryType {
    File,
    Directory,
    Other,
}

#[derive(Clone)]
pub struct FatFs {
    source: Arc<dyn BlockReader>,
    source_block_size: usize,
    source_size_bytes: u64,
    source_identity: String,
    params: Fat32Params,
}

#[derive(Clone, Copy, Debug)]
struct Fat32Params {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sector_count: u16,
    first_data_sector: u32,
    cluster_count: u32,
    root_cluster: u32,
    filesystem_size_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

#[derive(Clone, Debug)]
struct DirectoryEntry {
    name: String,
    attr: u8,
    first_cluster: u32,
    size: u32,
}

impl DirectoryEntry {
    fn root(root_cluster: u32) -> Self {
        Self {
            name: "/".to_string(),
            attr: FAT_ATTR_DIRECTORY,
            first_cluster: root_cluster,
            size: 0,
        }
    }

    fn is_directory(&self) -> bool {
        (self.attr & FAT_ATTR_DIRECTORY) != 0
    }

    fn entry_type(&self) -> FatEntryType {
        if self.is_directory() {
            FatEntryType::Directory
        } else if (self.attr & FAT_ATTR_VOLUME_ID) == 0 {
            FatEntryType::File
        } else {
            FatEntryType::Other
        }
    }
}

impl FatFs {
    pub async fn open<S: BlockReader + 'static>(source: S) -> GibbloxResult<Self> {
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

        let source: Arc<dyn BlockReader> = Arc::new(source);
        let source_identity = gibblox_core::block_identity_string(source.as_ref());
        let source_block_size = source_block_size_u32 as usize;
        let byte_reader = SourceByteReader {
            inner: Arc::clone(&source),
            block_size: source_block_size,
            size_bytes: source_size_bytes,
        };

        let mut boot_sector = [0u8; BOOT_SECTOR_LEN];
        byte_reader
            .read_exact_at(0, &mut boot_sector, ReadContext::FOREGROUND)
            .await?;
        if boot_sector[510] != 0x55 || boot_sector[511] != 0xaa {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "FAT boot sector signature is missing",
            ));
        }

        let bytes_per_sector = le_u16(&boot_sector[11..13]);
        let sectors_per_cluster = boot_sector[13];
        let reserved_sector_count = le_u16(&boot_sector[14..16]);
        let fat_count = boot_sector[16];
        let root_entry_count = le_u16(&boot_sector[17..19]);
        let total_sectors_16 = le_u16(&boot_sector[19..21]);
        let sectors_per_fat_16 = le_u16(&boot_sector[22..24]);
        let total_sectors_32 = le_u32(&boot_sector[32..36]);
        let sectors_per_fat_32 = le_u32(&boot_sector[36..40]);
        let root_cluster = le_u32(&boot_sector[44..48]);

        if bytes_per_sector < 512 || !bytes_per_sector.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "FAT bytes-per-sector must be a power of two >= 512",
            ));
        }
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "FAT sectors-per-cluster must be a non-zero power of two",
            ));
        }
        if reserved_sector_count == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "FAT reserved-sector count must be non-zero",
            ));
        }
        if fat_count == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "FAT must contain at least one FAT table",
            ));
        }

        let total_sectors = if total_sectors_16 != 0 {
            u32::from(total_sectors_16)
        } else {
            total_sectors_32
        };
        if total_sectors == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "FAT total sector count is zero",
            ));
        }

        let sectors_per_fat = if sectors_per_fat_16 != 0 {
            u32::from(sectors_per_fat_16)
        } else {
            sectors_per_fat_32
        };
        if sectors_per_fat == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "FAT sectors-per-FAT is zero",
            ));
        }

        let bytes_per_sector_u32 = u32::from(bytes_per_sector);
        let root_dir_sectors = (u32::from(root_entry_count) * 32).div_ceil(bytes_per_sector_u32);
        let first_data_sector = u32::from(reserved_sector_count)
            .checked_add(
                u32::from(fat_count)
                    .checked_mul(sectors_per_fat)
                    .ok_or_else(|| {
                        GibbloxError::with_message(
                            GibbloxErrorKind::OutOfRange,
                            "FAT metadata sector range overflow",
                        )
                    })?,
            )
            .and_then(|v| v.checked_add(root_dir_sectors))
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "FAT first-data-sector overflow",
                )
            })?;
        if first_data_sector >= total_sectors {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "FAT first data sector is outside total sector range",
            ));
        }

        let data_sectors = total_sectors - first_data_sector;
        let cluster_count = data_sectors / u32::from(sectors_per_cluster);
        if cluster_count == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "FAT contains no data clusters",
            ));
        }

        let fat_type = determine_fat_type(
            root_entry_count,
            sectors_per_fat_16,
            sectors_per_fat_32,
            cluster_count,
        );
        if fat_type != FatType::Fat32 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Unsupported,
                "only FAT32 is currently supported",
            ));
        }
        if root_cluster < FAT32_CLUSTER_MIN {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "FAT32 root cluster is invalid",
            ));
        }

        let filesystem_size_bytes = u64::from(total_sectors)
            .checked_mul(u64::from(bytes_per_sector))
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "filesystem size overflow")
            })?;
        if filesystem_size_bytes > source_size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "filesystem size exceeds source size",
            ));
        }

        info!(
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sector_count,
            fat_count,
            sectors_per_fat,
            total_sectors,
            root_cluster,
            "opened FAT32 filesystem"
        );

        Ok(Self {
            source,
            source_block_size,
            source_size_bytes,
            source_identity,
            params: Fat32Params {
                bytes_per_sector,
                sectors_per_cluster,
                reserved_sector_count,
                first_data_sector,
                cluster_count,
                root_cluster,
                filesystem_size_bytes,
            },
        })
    }

    pub fn source_identity(&self) -> &str {
        self.source_identity.as_str()
    }

    pub async fn read_all(&self, path: &str) -> GibbloxResult<Vec<u8>> {
        let entry = self.resolve_required_entry(path).await?;
        if entry.entry_type() != FatEntryType::File {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                format!("FAT path is not a regular file: {path}"),
            ));
        }
        self.read_file_data(&entry).await
    }

    pub async fn read_range(&self, path: &str, offset: u64, len: usize) -> GibbloxResult<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        let full = self.read_all(path).await?;
        let offset = usize::try_from(offset).map_err(|_| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "range offset overflow")
        })?;
        if offset >= full.len() {
            return Ok(Vec::new());
        }
        let end = full.len().min(offset.saturating_add(len));
        Ok(full[offset..end].to_vec())
    }

    pub async fn read_dir(&self, path: &str) -> GibbloxResult<Vec<String>> {
        let entry = self.resolve_required_entry(path).await?;
        if entry.entry_type() != FatEntryType::Directory {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                format!("FAT path is not a directory: {path}"),
            ));
        }

        let entries = self.read_directory_entries(entry.first_cluster).await?;
        Ok(entries.into_iter().map(|entry| entry.name).collect())
    }

    pub async fn entry_type(&self, path: &str) -> GibbloxResult<Option<FatEntryType>> {
        Ok(self
            .resolve_entry(path)
            .await?
            .map(|entry| entry.entry_type()))
    }

    pub async fn exists(&self, path: &str) -> GibbloxResult<bool> {
        Ok(self.resolve_entry(path).await?.is_some())
    }

    async fn resolve_required_entry(&self, path: &str) -> GibbloxResult<DirectoryEntry> {
        self.resolve_entry(path).await?.ok_or_else(|| {
            GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                format!("FAT path not found: {path}"),
            )
        })
    }

    async fn resolve_entry(&self, path: &str) -> GibbloxResult<Option<DirectoryEntry>> {
        let components = split_path(path)?;
        if components.is_empty() {
            return Ok(Some(DirectoryEntry::root(self.params.root_cluster)));
        }

        let mut current = DirectoryEntry::root(self.params.root_cluster);
        for component in components {
            if current.entry_type() != FatEntryType::Directory {
                return Ok(None);
            }

            let entries = self.read_directory_entries(current.first_cluster).await?;
            let mut matched = None;
            for entry in entries {
                if fat_name_eq(entry.name.as_str(), component.as_str()) {
                    matched = Some(entry);
                    break;
                }
            }

            let Some(next) = matched else {
                return Ok(None);
            };
            current = next;
        }

        Ok(Some(current))
    }

    async fn read_file_data(&self, entry: &DirectoryEntry) -> GibbloxResult<Vec<u8>> {
        let file_size = entry.size as usize;
        if file_size == 0 {
            return Ok(Vec::new());
        }
        if entry.first_cluster < FAT32_CLUSTER_MIN {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "file has invalid start cluster",
            ));
        }

        let mut out = Vec::with_capacity(file_size);
        let mut remaining = file_size;
        let chain = self.read_cluster_chain(entry.first_cluster).await?;
        for cluster in chain {
            let data = self.read_cluster(cluster).await?;
            let take = remaining.min(data.len());
            out.extend_from_slice(&data[..take]);
            remaining -= take;
            if remaining == 0 {
                break;
            }
        }

        if remaining != 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Io,
                "file cluster chain ended before advertised size",
            ));
        }
        Ok(out)
    }

    async fn read_directory_entries(
        &self,
        start_cluster: u32,
    ) -> GibbloxResult<Vec<DirectoryEntry>> {
        if start_cluster < FAT32_CLUSTER_MIN {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "directory has invalid start cluster",
            ));
        }

        let chain = self.read_cluster_chain(start_cluster).await?;
        let mut entries = Vec::new();
        let mut pending_lfn = Vec::<[u8; 32]>::new();

        for cluster in chain {
            let data = self.read_cluster(cluster).await?;
            for raw in data.chunks_exact(32) {
                let first = raw[0];
                if first == 0x00 {
                    return Ok(entries);
                }
                if first == 0xe5 {
                    pending_lfn.clear();
                    continue;
                }

                let attr = raw[11];
                if attr == FAT_ATTR_LFN {
                    let mut entry = [0u8; 32];
                    entry.copy_from_slice(raw);
                    pending_lfn.push(entry);
                    continue;
                }

                if (attr & FAT_ATTR_VOLUME_ID) != 0 {
                    pending_lfn.clear();
                    continue;
                }

                let short_name = parse_short_name(raw)?;
                let name = decode_lfn_name(&pending_lfn).unwrap_or(short_name);
                pending_lfn.clear();

                if name == "." || name == ".." {
                    continue;
                }

                let first_cluster =
                    (u32::from(le_u16(&raw[20..22])) << 16) | u32::from(le_u16(&raw[26..28]));
                let size = le_u32(&raw[28..32]);
                entries.push(DirectoryEntry {
                    name,
                    attr,
                    first_cluster,
                    size,
                });
            }
        }

        Ok(entries)
    }

    async fn read_cluster_chain(&self, start_cluster: u32) -> GibbloxResult<Vec<u32>> {
        if start_cluster < FAT32_CLUSTER_MIN {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "invalid FAT32 cluster index",
            ));
        }

        let mut chain = Vec::new();
        let mut seen = BTreeSet::new();
        let max_cluster = self.max_cluster_index()?;
        let mut terminated = false;

        let mut cluster = start_cluster;
        for _ in 0..=usize::try_from(self.params.cluster_count).unwrap_or(usize::MAX) {
            if cluster < FAT32_CLUSTER_MIN || cluster > max_cluster {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "cluster chain points outside FAT data range",
                ));
            }
            if !seen.insert(cluster) {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    "cluster chain loop detected",
                ));
            }

            chain.push(cluster);
            let next = self.read_fat_entry(cluster).await?;
            if next >= FAT32_EOC_MIN {
                terminated = true;
                break;
            }
            if next == FAT32_BAD_CLUSTER {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    "cluster chain reached bad-cluster marker",
                ));
            }
            cluster = next;
        }

        if !terminated {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "cluster chain exceeds maximum expected length",
            ));
        }

        Ok(chain)
    }

    async fn read_fat_entry(&self, cluster: u32) -> GibbloxResult<u32> {
        let bps = u64::from(self.params.bytes_per_sector);
        let fat_start_sector = u64::from(self.params.reserved_sector_count);
        let fat_start = fat_start_sector.checked_mul(bps).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "FAT start offset overflow")
        })?;
        let entry_offset = u64::from(cluster)
            .checked_mul(FAT_ENTRY_SIZE_BYTES)
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "FAT entry offset overflow",
                )
            })?;
        let byte_offset = fat_start.checked_add(entry_offset).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "FAT byte offset overflow")
        })?;

        let mut raw = [0u8; 4];
        self.byte_reader()
            .read_exact_at(byte_offset, &mut raw, ReadContext::FOREGROUND)
            .await?;
        Ok(le_u32(&raw) & 0x0fff_ffff)
    }

    async fn read_cluster(&self, cluster: u32) -> GibbloxResult<Vec<u8>> {
        let cluster_size = self.cluster_size_bytes()?;
        let offset = self.cluster_offset_bytes(cluster)?;
        let mut out = vec![0u8; cluster_size];
        self.byte_reader()
            .read_exact_at(offset, &mut out, ReadContext::FOREGROUND)
            .await?;
        Ok(out)
    }

    fn cluster_offset_bytes(&self, cluster: u32) -> GibbloxResult<u64> {
        let max_cluster = self.max_cluster_index()?;
        if cluster < FAT32_CLUSTER_MIN || cluster > max_cluster {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "cluster index out of range",
            ));
        }

        let sector = u64::from(self.params.first_data_sector)
            .checked_add(
                u64::from(cluster - FAT32_CLUSTER_MIN)
                    .checked_mul(u64::from(self.params.sectors_per_cluster))
                    .ok_or_else(|| {
                        GibbloxError::with_message(
                            GibbloxErrorKind::OutOfRange,
                            "cluster sector offset overflow",
                        )
                    })?,
            )
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "cluster sector overflow")
            })?;
        let offset = sector
            .checked_mul(u64::from(self.params.bytes_per_sector))
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "cluster byte offset overflow",
                )
            })?;
        let end = offset
            .checked_add(u64::try_from(self.cluster_size_bytes()?).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "cluster end overflow")
            })?;
        if end > self.params.filesystem_size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "cluster extends past FAT filesystem bounds",
            ));
        }
        Ok(offset)
    }

    fn max_cluster_index(&self) -> GibbloxResult<u32> {
        self.params
            .cluster_count
            .checked_add(FAT32_CLUSTER_MIN - 1)
            .ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "max cluster index overflow",
                )
            })
    }

    fn cluster_size_bytes(&self) -> GibbloxResult<usize> {
        let bytes = u32::from(self.params.bytes_per_sector)
            .checked_mul(u32::from(self.params.sectors_per_cluster))
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "cluster size overflow")
            })?;
        usize::try_from(bytes).map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "cluster size does not fit usize",
            )
        })
    }

    fn byte_reader(&self) -> SourceByteReader {
        SourceByteReader {
            inner: Arc::clone(&self.source),
            block_size: self.source_block_size,
            size_bytes: self.source_size_bytes,
        }
    }
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
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "read range overflow")
        })?;
        if end > self.size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "read range exceeds source size",
            ));
        }

        let block_size = self.block_size as u64;
        let aligned_start = (offset / block_size) * block_size;
        let aligned_end = end
            .div_ceil(block_size)
            .checked_mul(block_size)
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "aligned read overflow")
            })?;
        let aligned_len = usize::try_from(aligned_end - aligned_start).map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "aligned read length exceeds addressable memory",
            )
        })?;

        let mut scratch = vec![0u8; aligned_len];
        let mut filled = 0usize;
        while filled < scratch.len() {
            let lba = (aligned_start as usize + filled) / self.block_size;
            let read = self
                .inner
                .read_blocks(lba as u64, &mut scratch[filled..], ctx)
                .await?;
            if read == 0 {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    "unexpected EOF during aligned block read",
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

fn determine_fat_type(
    root_entry_count: u16,
    sectors_per_fat_16: u16,
    sectors_per_fat_32: u32,
    cluster_count: u32,
) -> FatType {
    if sectors_per_fat_16 == 0 && root_entry_count == 0 && sectors_per_fat_32 != 0 {
        return FatType::Fat32;
    }
    if cluster_count < 4_085 {
        FatType::Fat12
    } else if cluster_count < 65_525 {
        FatType::Fat16
    } else {
        FatType::Fat32
    }
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
                "parent path traversal is not supported",
            ));
        }
        out.push(part.to_string());
    }
    Ok(out)
}

fn fat_name_eq(candidate: &str, wanted: &str) -> bool {
    if candidate.eq_ignore_ascii_case(wanted) {
        return true;
    }
    candidate
        .chars()
        .flat_map(char::to_lowercase)
        .eq(wanted.chars().flat_map(char::to_lowercase))
}

fn parse_short_name(raw: &[u8]) -> GibbloxResult<String> {
    if raw.len() < 32 {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "short directory entry is truncated",
        ));
    }

    let mut name_bytes = [0u8; 8];
    name_bytes.copy_from_slice(&raw[0..8]);
    if name_bytes[0] == 0x05 {
        name_bytes[0] = 0xe5;
    }

    let base = bytes_to_trimmed_ascii(&name_bytes);
    let ext = bytes_to_trimmed_ascii(&raw[8..11]);
    if base.is_empty() {
        return Err(GibbloxError::with_message(
            GibbloxErrorKind::InvalidInput,
            "short directory entry has empty filename",
        ));
    }
    if ext.is_empty() {
        Ok(base)
    } else {
        Ok(format!("{base}.{ext}"))
    }
}

fn decode_lfn_name(entries: &[[u8; 32]]) -> Option<String> {
    if entries.is_empty() {
        return None;
    }

    let mut units = Vec::new();
    for entry in entries.iter().rev() {
        append_lfn_units(entry, &mut units);
    }

    let end = units
        .iter()
        .position(|unit| *unit == 0x0000)
        .unwrap_or(units.len());
    let mut filtered = Vec::new();
    for unit in &units[..end] {
        if *unit == 0xffff {
            continue;
        }
        filtered.push(*unit);
    }
    if filtered.is_empty() {
        return None;
    }

    let mut out = String::new();
    for ch in core::char::decode_utf16(filtered.into_iter()) {
        match ch {
            Ok(ch) => out.push(ch),
            Err(_) => out.push('\u{fffd}'),
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn append_lfn_units(entry: &[u8; 32], out: &mut Vec<u16>) {
    append_utf16_pairs(&entry[1..11], out);
    append_utf16_pairs(&entry[14..26], out);
    append_utf16_pairs(&entry[28..32], out);
}

fn append_utf16_pairs(raw: &[u8], out: &mut Vec<u16>) {
    for chunk in raw.chunks_exact(2) {
        out.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
}

fn bytes_to_trimmed_ascii(raw: &[u8]) -> String {
    let mut out = String::new();
    for &byte in raw {
        if byte == b' ' {
            continue;
        }
        let ch = if byte.is_ascii_graphic() {
            byte as char
        } else {
            '_'
        };
        out.push(ch);
    }
    out
}

fn le_u16(raw: &[u8]) -> u16 {
    u16::from_le_bytes([raw[0], raw[1]])
}

fn le_u32(raw: &[u8]) -> u32 {
    u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use async_trait::async_trait;
    use core::fmt;
    use futures::executor::block_on;

    const TEST_BLOCK_SIZE: u32 = 512;
    const TEST_SECTOR_SIZE: usize = 512;
    const TEST_TOTAL_SECTORS: usize = 128;
    const TEST_RESERVED_SECTORS: usize = 32;
    const TEST_SECTORS_PER_FAT: usize = 1;
    const TEST_FIRST_DATA_SECTOR: usize = TEST_RESERVED_SECTORS + TEST_SECTORS_PER_FAT;
    const FAT32_NAME_UTF16_UNITS_PER_ENTRY: usize = 13;

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
            write!(out, "fake-fat:{}:{}", self.block_size, self.data.len())
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
    fn reads_short_and_long_fat_filenames() {
        let image = build_test_fat32_image();
        let fs = block_on(FatFs::open(FakeReader {
            block_size: TEST_BLOCK_SIZE,
            data: image,
        }))
        .expect("open FAT32 image");

        let kernel = block_on(fs.read_all("/vmlinuz")).expect("read /vmlinuz");
        assert_eq!(&kernel, b"hello kernel");

        let dtb = block_on(fs.read_all("/dtbs/qcom/sdm845-oneplus-fajita.dtb"))
            .expect("read dtb long filename");
        assert_eq!(&dtb, &[1, 2, 3, 4]);

        let dtb_upper = block_on(fs.exists("/DTBS/QCOM/SDM845-ONEPLUS-FAJITA.DTB"))
            .expect("case-insensitive exists");
        assert!(dtb_upper);

        let qcom_dir = block_on(fs.read_dir("/dtbs/qcom")).expect("list qcom dir");
        assert!(
            qcom_dir
                .iter()
                .any(|name| name == "sdm845-oneplus-fajita.dtb")
        );
    }

    #[test]
    fn reports_entry_types_and_missing_paths() {
        let image = build_test_fat32_image();
        let fs = block_on(FatFs::open(FakeReader {
            block_size: TEST_BLOCK_SIZE,
            data: image,
        }))
        .expect("open FAT32 image");

        assert_eq!(
            block_on(fs.entry_type("/")).expect("root type"),
            Some(FatEntryType::Directory)
        );
        assert_eq!(
            block_on(fs.entry_type("/vmlinuz")).expect("file type"),
            Some(FatEntryType::File)
        );
        assert_eq!(
            block_on(fs.entry_type("/missing")).expect("missing type"),
            None
        );

        let err = block_on(fs.read_all("/dtbs")).expect_err("read_all on dir must fail");
        assert_eq!(err.kind(), GibbloxErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_non_fat32_layouts() {
        let mut image = build_test_fat32_image();
        image[17..19].copy_from_slice(&512u16.to_le_bytes());
        image[22..24].copy_from_slice(&1u16.to_le_bytes());
        image[36..40].copy_from_slice(&0u32.to_le_bytes());

        let err = match block_on(FatFs::open(FakeReader {
            block_size: TEST_BLOCK_SIZE,
            data: image,
        })) {
            Ok(_) => panic!("FAT16-style layout should be unsupported"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), GibbloxErrorKind::Unsupported);
    }

    fn build_test_fat32_image() -> Vec<u8> {
        let mut image = vec![0u8; TEST_TOTAL_SECTORS * TEST_SECTOR_SIZE];

        let boot = &mut image[0..TEST_SECTOR_SIZE];
        boot[0] = 0xeb;
        boot[1] = 0x58;
        boot[2] = 0x90;
        boot[3..11].copy_from_slice(b"MSDOS5.0");
        boot[11..13].copy_from_slice(&(TEST_SECTOR_SIZE as u16).to_le_bytes());
        boot[13] = 1;
        boot[14..16].copy_from_slice(&(TEST_RESERVED_SECTORS as u16).to_le_bytes());
        boot[16] = 1;
        boot[17..19].copy_from_slice(&0u16.to_le_bytes());
        boot[19..21].copy_from_slice(&(TEST_TOTAL_SECTORS as u16).to_le_bytes());
        boot[21] = 0xf8;
        boot[22..24].copy_from_slice(&0u16.to_le_bytes());
        boot[24..26].copy_from_slice(&32u16.to_le_bytes());
        boot[26..28].copy_from_slice(&1u16.to_le_bytes());
        boot[28..32].copy_from_slice(&0u32.to_le_bytes());
        boot[32..36].copy_from_slice(&0u32.to_le_bytes());
        boot[36..40].copy_from_slice(&(TEST_SECTORS_PER_FAT as u32).to_le_bytes());
        boot[40..42].copy_from_slice(&0u16.to_le_bytes());
        boot[42..44].copy_from_slice(&0u16.to_le_bytes());
        boot[44..48].copy_from_slice(&2u32.to_le_bytes());
        boot[48..50].copy_from_slice(&1u16.to_le_bytes());
        boot[50..52].copy_from_slice(&6u16.to_le_bytes());
        boot[64] = 0x80;
        boot[66] = 0x29;
        boot[67..71].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        boot[71..82].copy_from_slice(b"NO NAME    ");
        boot[82..90].copy_from_slice(b"FAT32   ");
        boot[510] = 0x55;
        boot[511] = 0xaa;

        let fsinfo = &mut image[TEST_SECTOR_SIZE..TEST_SECTOR_SIZE * 2];
        fsinfo[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
        fsinfo[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
        fsinfo[488..492].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        fsinfo[492..496].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        fsinfo[508..512].copy_from_slice(&0xaa55_0000u32.to_le_bytes());

        let fat_offset = TEST_RESERVED_SECTORS * TEST_SECTOR_SIZE;
        let fat = &mut image[fat_offset..fat_offset + TEST_SECTOR_SIZE];
        set_fat_entry(fat, 0, 0x0fff_fff8);
        set_fat_entry(fat, 1, 0xffff_ffff);
        set_fat_entry(fat, 2, 0x0fff_ffff);
        set_fat_entry(fat, 3, 0x0fff_ffff);
        set_fat_entry(fat, 4, 0x0fff_ffff);
        set_fat_entry(fat, 5, 0x0fff_ffff);
        set_fat_entry(fat, 6, 0x0fff_ffff);

        let root = cluster_mut(&mut image, 2);
        write_short_entry(&mut root[0..32], short_name("VMLINUZ", ""), 0x20, 3, 12);
        write_short_entry(
            &mut root[32..64],
            short_name("DTBS", ""),
            FAT_ATTR_DIRECTORY,
            4,
            0,
        );
        root[64] = 0x00;

        let kernel_cluster = cluster_mut(&mut image, 3);
        kernel_cluster[..12].copy_from_slice(b"hello kernel");

        let dtbs_dir = cluster_mut(&mut image, 4);
        write_short_entry(
            &mut dtbs_dir[0..32],
            short_dot_name(true),
            FAT_ATTR_DIRECTORY,
            4,
            0,
        );
        write_short_entry(
            &mut dtbs_dir[32..64],
            short_dotdot_name(),
            FAT_ATTR_DIRECTORY,
            2,
            0,
        );
        write_short_entry(
            &mut dtbs_dir[64..96],
            short_name("QCOM", ""),
            FAT_ATTR_DIRECTORY,
            5,
            0,
        );
        dtbs_dir[96] = 0x00;

        let qcom_dir = cluster_mut(&mut image, 5);
        write_short_entry(
            &mut qcom_dir[0..32],
            short_dot_name(true),
            FAT_ATTR_DIRECTORY,
            5,
            0,
        );
        write_short_entry(
            &mut qcom_dir[32..64],
            short_dotdot_name(),
            FAT_ATTR_DIRECTORY,
            4,
            0,
        );

        let short = short_name("SDM845~1", "DTB");
        let lfn_entries = lfn_entries("sdm845-oneplus-fajita.dtb", &short);
        let mut offset = 64usize;
        for lfn in lfn_entries {
            qcom_dir[offset..offset + 32].copy_from_slice(&lfn);
            offset += 32;
        }
        write_short_entry(&mut qcom_dir[offset..offset + 32], short, 0x20, 6, 4);
        qcom_dir[offset + 32] = 0x00;

        let dtb_cluster = cluster_mut(&mut image, 6);
        dtb_cluster[..4].copy_from_slice(&[1, 2, 3, 4]);

        image
    }

    fn cluster_mut(image: &mut [u8], cluster: u32) -> &mut [u8] {
        let sector = TEST_FIRST_DATA_SECTOR + usize::try_from(cluster - 2).expect("cluster index");
        let start = sector * TEST_SECTOR_SIZE;
        let end = start + TEST_SECTOR_SIZE;
        &mut image[start..end]
    }

    fn set_fat_entry(fat: &mut [u8], index: usize, value: u32) {
        let start = index * 4;
        fat[start..start + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_short_entry(
        slot: &mut [u8],
        short: [u8; 11],
        attr: u8,
        first_cluster: u32,
        size: u32,
    ) {
        slot.fill(0);
        slot[0..11].copy_from_slice(&short);
        slot[11] = attr;
        slot[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
        slot[26..28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
        slot[28..32].copy_from_slice(&size.to_le_bytes());
    }

    fn short_name(base: &str, ext: &str) -> [u8; 11] {
        let mut out = [b' '; 11];
        for (idx, byte) in base.as_bytes().iter().take(8).enumerate() {
            out[idx] = byte.to_ascii_uppercase();
        }
        for (idx, byte) in ext.as_bytes().iter().take(3).enumerate() {
            out[8 + idx] = byte.to_ascii_uppercase();
        }
        out
    }

    fn short_dot_name(single: bool) -> [u8; 11] {
        let mut out = [b' '; 11];
        out[0] = b'.';
        if !single {
            out[1] = b'.';
        }
        out
    }

    fn short_dotdot_name() -> [u8; 11] {
        short_dot_name(false)
    }

    fn lfn_entries(name: &str, short: &[u8; 11]) -> Vec<[u8; 32]> {
        let checksum = lfn_checksum(short);
        let mut units: Vec<u16> = name.encode_utf16().collect();
        units.push(0x0000);
        while !units.len().is_multiple_of(FAT32_NAME_UTF16_UNITS_PER_ENTRY) {
            units.push(0xffff);
        }

        let chunks: Vec<&[u16]> = units.chunks(FAT32_NAME_UTF16_UNITS_PER_ENTRY).collect();
        let mut out = Vec::new();
        for index in (0..chunks.len()).rev() {
            let mut entry = [0xffu8; 32];
            let sequence = u8::try_from(index + 1).expect("lfn sequence fits u8");
            entry[0] = if index + 1 == chunks.len() {
                sequence | 0x40
            } else {
                sequence
            };
            entry[11] = FAT_ATTR_LFN;
            entry[12] = 0;
            entry[13] = checksum;
            entry[26] = 0;
            entry[27] = 0;

            let chunk = chunks[index];
            write_lfn_name_part(&mut entry[1..11], &chunk[0..5]);
            write_lfn_name_part(&mut entry[14..26], &chunk[5..11]);
            write_lfn_name_part(&mut entry[28..32], &chunk[11..13]);
            out.push(entry);
        }
        out
    }

    fn write_lfn_name_part(dst: &mut [u8], units: &[u16]) {
        for (idx, unit) in units.iter().enumerate() {
            let off = idx * 2;
            dst[off..off + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }

    fn lfn_checksum(short: &[u8; 11]) -> u8 {
        let mut sum = 0u8;
        for byte in short {
            sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(*byte);
        }
        sum
    }
}
