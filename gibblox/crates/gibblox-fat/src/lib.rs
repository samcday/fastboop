#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::{
    boxed::Box,
    format,
    rc::Rc,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use gibblox_core::{
    BlockReader, ByteRangeReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext,
    block_identity_string,
};
use hadris_fat::FatError as HFatError;
use hadris_fat::r#async::{
    dir::{DirectoryEntry as HDirectoryEntry, FileEntry as HFileEntry},
    fat_table::FatType as HFatType,
    fs::FatFs as HFatFs,
    io::{
        Error as HIoError, ErrorKind as HIoErrorKind, IoResult as HIoResult, Read as HIoRead,
        Seek as HIoSeek, SeekFrom as HIoSeekFrom,
    },
    read::FileReader as HFileReader,
};
use tracing::info;

const FAT_ATTR_DIRECTORY: u8 = 0x10;
const FAT_ATTR_VOLUME_ID: u8 = 0x08;
#[cfg(test)]
const FAT_ATTR_LFN: u8 = 0x0f;

type HFatDir<'a> = hadris_fat::r#async::dir::FatDir<'a, BlockReaderIo>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FatEntryType {
    File,
    Directory,
    Other,
}

#[derive(Clone)]
pub struct FatFs {
    inner: Rc<FatFsInner>,
}

struct FatFsInner {
    fs: HFatFs<BlockReaderIo>,
    source_identity: String,
}

enum ResolvedEntry {
    Root,
    Entry(Box<HFileEntry>),
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
            .checked_mul(u64::from(source_block_size_u32))
            .ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "source size overflow")
            })?;
        let source_identity = block_identity_string(&source);

        let source: Arc<dyn BlockReader> = Arc::new(source);
        let byte_reader = ByteRangeReader::new(
            Arc::clone(&source),
            source_block_size_u32 as usize,
            source_size_bytes,
        );
        let adapter = BlockReaderIo {
            byte_reader,
            size_bytes: source_size_bytes,
            position: 0,
        };

        let fs = HFatFs::open(adapter)
            .await
            .map_err(|err| map_fat_error("open FAT image", err))?;

        if fs.fat_type() != HFatType::Fat32 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::Unsupported,
                "only FAT32 is currently supported",
            ));
        }

        info!(
            source_block_size = source_block_size_u32,
            source_total_blocks, source_size_bytes, "opened FAT32 filesystem"
        );

        Ok(Self {
            inner: Rc::new(FatFsInner {
                fs,
                source_identity,
            }),
        })
    }

    pub fn source_identity(&self) -> &str {
        self.inner.source_identity.as_str()
    }

    pub async fn read_all(&self, path: &str) -> GibbloxResult<Vec<u8>> {
        let resolved = self.resolve_required_entry(path).await?;
        let entry = match resolved {
            ResolvedEntry::Root => {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::InvalidInput,
                    format!("FAT path is not a regular file: {path}"),
                ));
            }
            ResolvedEntry::Entry(entry) => *entry,
        };

        if classify_entry(&entry) != FatEntryType::File {
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
        let resolved = self.resolve_required_entry(path).await?;
        match resolved {
            ResolvedEntry::Root => {
                let root = self.inner.fs.root_dir();
                self.collect_dir_names(&root).await
            }
            ResolvedEntry::Entry(entry) => {
                if classify_entry(entry.as_ref()) != FatEntryType::Directory {
                    return Err(GibbloxError::with_message(
                        GibbloxErrorKind::InvalidInput,
                        format!("FAT path is not a directory: {path}"),
                    ));
                }

                let dir = self
                    .inner
                    .fs
                    .open_dir_entry(&entry)
                    .map_err(|err| map_fat_error("open FAT directory", err))?;
                self.collect_dir_names(&dir).await
            }
        }
    }

    pub async fn entry_type(&self, path: &str) -> GibbloxResult<Option<FatEntryType>> {
        Ok(match self.resolve_entry(path).await? {
            Some(ResolvedEntry::Root) => Some(FatEntryType::Directory),
            Some(ResolvedEntry::Entry(entry)) => Some(classify_entry(entry.as_ref())),
            None => None,
        })
    }

    pub async fn exists(&self, path: &str) -> GibbloxResult<bool> {
        Ok(self.resolve_entry(path).await?.is_some())
    }

    async fn read_file_data(&self, entry: &HFileEntry) -> GibbloxResult<Vec<u8>> {
        let mut reader = HFileReader::new(&self.inner.fs, entry)
            .map_err(|err| map_fat_error("open FAT file", err))?;
        reader
            .read_to_vec()
            .await
            .map_err(|err| map_fat_error("read FAT file", err))
    }

    async fn collect_dir_names(&self, dir: &HFatDir<'_>) -> GibbloxResult<Vec<String>> {
        let mut out = Vec::new();
        let mut iter = dir.entries();
        while let Some(next) = iter.next_entry().await {
            let HDirectoryEntry::Entry(entry) =
                next.map_err(|err| map_fat_error("read FAT directory entry", err))?;
            if is_dot_name(entry.name()) || is_volume_label(&entry) {
                continue;
            }
            out.push(entry.name().to_string());
        }
        Ok(out)
    }

    async fn resolve_required_entry(&self, path: &str) -> GibbloxResult<ResolvedEntry> {
        self.resolve_entry(path).await?.ok_or_else(|| {
            GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                format!("FAT path not found: {path}"),
            )
        })
    }

    async fn resolve_entry(&self, path: &str) -> GibbloxResult<Option<ResolvedEntry>> {
        let components = split_path(path)?;
        if components.is_empty() {
            return Ok(Some(ResolvedEntry::Root));
        }

        let mut current_dir = self.inner.fs.root_dir();
        for (index, component) in components.iter().enumerate() {
            let Some(entry) = self
                .find_entry_casefold(&current_dir, component.as_str())
                .await?
            else {
                return Ok(None);
            };

            let last = index + 1 == components.len();
            if last {
                return Ok(Some(ResolvedEntry::Entry(Box::new(entry))));
            }

            if classify_entry(&entry) != FatEntryType::Directory {
                return Ok(None);
            }

            current_dir = self
                .inner
                .fs
                .open_dir_entry(&entry)
                .map_err(|err| map_fat_error("open FAT directory", err))?;
        }

        Ok(Some(ResolvedEntry::Root))
    }

    async fn find_entry_casefold(
        &self,
        dir: &HFatDir<'_>,
        wanted: &str,
    ) -> GibbloxResult<Option<HFileEntry>> {
        let mut iter = dir.entries();
        while let Some(next) = iter.next_entry().await {
            let HDirectoryEntry::Entry(entry) =
                next.map_err(|err| map_fat_error("read FAT directory entry", err))?;

            if is_dot_name(entry.name()) || is_volume_label(&entry) {
                continue;
            }

            if fat_name_eq(entry.name(), wanted) || entry.short_name().matches(wanted) {
                return Ok(Some(entry));
            }
        }

        Ok(None)
    }
}

fn classify_entry(entry: &HFileEntry) -> FatEntryType {
    let attr = entry.attributes().bits();
    if (attr & FAT_ATTR_DIRECTORY) != 0 {
        FatEntryType::Directory
    } else if (attr & FAT_ATTR_VOLUME_ID) == 0 {
        FatEntryType::File
    } else {
        FatEntryType::Other
    }
}

fn is_volume_label(entry: &HFileEntry) -> bool {
    (entry.attributes().bits() & FAT_ATTR_VOLUME_ID) != 0
}

fn is_dot_name(name: &str) -> bool {
    name == "." || name == ".."
}

struct BlockReaderIo {
    byte_reader: ByteRangeReader,
    size_bytes: u64,
    position: u64,
}

impl HIoSeek for BlockReaderIo {
    async fn seek(&mut self, pos: HIoSeekFrom) -> HIoResult<u64> {
        let next = match pos {
            HIoSeekFrom::Start(offset) => i128::from(offset),
            HIoSeekFrom::End(offset) => i128::from(self.size_bytes)
                .checked_add(i128::from(offset))
                .ok_or_else(|| HIoError::from(HIoErrorKind::InvalidInput))?,
            HIoSeekFrom::Current(offset) => i128::from(self.position)
                .checked_add(i128::from(offset))
                .ok_or_else(|| HIoError::from(HIoErrorKind::InvalidInput))?,
        };

        if next < 0 {
            return Err(HIoErrorKind::InvalidInput.into());
        }

        let next = u64::try_from(next).map_err(|_| HIoErrorKind::InvalidInput)?;
        self.position = next;
        Ok(self.position)
    }
}

impl HIoRead for BlockReaderIo {
    async fn read(&mut self, out: &mut [u8]) -> HIoResult<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.position >= self.size_bytes {
            return Ok(0);
        }

        let remaining = self.size_bytes - self.position;
        let read_len = out
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        if read_len == 0 {
            return Ok(0);
        }

        self.byte_reader
            .read_exact_at(self.position, &mut out[..read_len], ReadContext::FOREGROUND)
            .await
            .map_err(map_block_error)?;

        self.position = self
            .position
            .checked_add(u64::try_from(read_len).unwrap_or(u64::MAX))
            .ok_or_else(|| HIoError::from(HIoErrorKind::InvalidInput))?;
        Ok(read_len)
    }
}

fn map_block_error(err: GibbloxError) -> HIoError {
    let kind = match err.kind() {
        GibbloxErrorKind::InvalidInput => HIoErrorKind::InvalidInput,
        GibbloxErrorKind::OutOfRange => HIoErrorKind::UnexpectedEof,
        GibbloxErrorKind::Io | GibbloxErrorKind::Unsupported | GibbloxErrorKind::Other => {
            HIoErrorKind::Other
        }
    };
    kind.into()
}

fn map_fat_error(op: &'static str, err: HFatError) -> GibbloxError {
    let kind = match &err {
        HFatError::UnsupportedFatType(_) => GibbloxErrorKind::Unsupported,
        HFatError::ClusterOutOfBounds { .. } => GibbloxErrorKind::OutOfRange,
        HFatError::BadCluster { .. } | HFatError::UnexpectedEndOfChain { .. } => {
            GibbloxErrorKind::Io
        }
        HFatError::Io(inner) => map_hio_error_kind(inner.kind()),
        HFatError::InvalidBootSignature { .. }
        | HFatError::InvalidFsInfoSignature { .. }
        | HFatError::InvalidShortFilename
        | HFatError::NotAFile
        | HFatError::NotADirectory
        | HFatError::EntryNotFound
        | HFatError::InvalidPath => GibbloxErrorKind::InvalidInput,
        #[allow(unreachable_patterns)]
        _ => GibbloxErrorKind::Other,
    };

    GibbloxError::with_message(kind, format!("{op}: {err}"))
}

fn map_hio_error_kind(kind: HIoErrorKind) -> GibbloxErrorKind {
    match kind {
        HIoErrorKind::InvalidInput => GibbloxErrorKind::InvalidInput,
        HIoErrorKind::UnexpectedEof => GibbloxErrorKind::OutOfRange,
        _ => GibbloxErrorKind::Io,
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec;
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
