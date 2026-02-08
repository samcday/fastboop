use core::mem::size_of;

#[cfg(feature = "std")]
use std::{
    fs::Permissions,
    os::unix::fs::PermissionsExt,
    time::{Duration, SystemTime},
};

#[cfg(feature = "std")]
use rustix::fs::FileType;

use crate::read::ReadCursor;
use crate::{Error, Result};

#[cfg(not(feature = "std"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileType(u32);

#[cfg(not(feature = "std"))]
impl FileType {
    pub fn from_raw_mode(mode: u32) -> Self {
        Self(mode)
    }

    pub fn is_dir(&self) -> bool {
        FileMode::from_bits_truncate(self.0 as u16).is_dir()
    }

    pub fn is_file(&self) -> bool {
        FileMode::from_bits_truncate(self.0 as u16).is_file()
    }

    pub fn is_symlink(&self) -> bool {
        FileMode::from_bits_truncate(self.0 as u16).contains(FileMode::SYMLINK)
    }
}

pub const MAGIC_NUMBER: u32 = 0xe0f5e1e2;
pub const SUPER_BLOCK_OFFSET: usize = 1024;

pub const LAYOUT_CHUNK_FORMAT_BITS: u16 = 0x001F;
pub const LAYOUT_CHUNK_FORMAT_INDEXES: u16 = 0x0020;

pub const SB_EXTSLOT_SIZE: usize = 16;

pub const FEATURE_INCOMPAT_ZERO_PADDING: u32 = 0x00000001;

pub const Z_EROFS_COMPRESSION_LZ4: u8 = 0;
pub const Z_EROFS_COMPRESSION_LZMA: u8 = 1;
pub const Z_EROFS_COMPRESSION_DEFLATE: u8 = 2;
pub const Z_EROFS_COMPRESSION_ZSTD: u8 = 3;

pub const Z_EROFS_ADVISE_COMPACTED_2B: u16 = 0x0001;
pub const Z_EROFS_ADVISE_EXTENTS: u16 = 0x0001;
pub const Z_EROFS_ADVISE_BIG_PCLUSTER_1: u16 = 0x0002;
pub const Z_EROFS_ADVISE_BIG_PCLUSTER_2: u16 = 0x0004;
pub const Z_EROFS_ADVISE_INLINE_PCLUSTER: u16 = 0x0008;
pub const Z_EROFS_ADVISE_INTERLACED_PCLUSTER: u16 = 0x0010;
pub const Z_EROFS_ADVISE_FRAGMENT_PCLUSTER: u16 = 0x0020;

pub const Z_EROFS_FRAGMENT_INODE_BIT: u8 = 7;

pub const Z_EROFS_LCLUSTER_TYPE_PLAIN: u8 = 0;
pub const Z_EROFS_LCLUSTER_TYPE_HEAD1: u8 = 1;
pub const Z_EROFS_LCLUSTER_TYPE_NONHEAD: u8 = 2;
pub const Z_EROFS_LCLUSTER_TYPE_HEAD2: u8 = 3;
pub const Z_EROFS_LI_LCLUSTER_TYPE_MASK: u16 = 0x0003;
pub const Z_EROFS_LI_PARTIAL_REF: u16 = 1 << 15;
pub const Z_EROFS_LI_D0_CBLKCNT: u16 = 1 << 11;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SuperBlock {
    pub magic: u32,
    pub checksum: u32,
    pub feature_compat: u32,
    pub blk_size_bits: u8,
    pub ext_slots: u8,
    pub root_nid: u16,
    pub inos: u64,
    pub build_time: u64,
    pub build_time_ns: u32,
    pub blocks: u32,
    pub meta_blk_addr: u32,
    pub xattr_blk_addr: u32,
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
    pub feature_incompat: u32,
    pub compr_algs: u16,
    pub extra_devices: u16,
    pub devt_slot_off: u16,
    pub dir_blk_bits: u8,
    pub xattr_prefix_count: u8,
    pub xattr_prefix_start: u32,
    pub packed_nid: u64,
    pub xattr_filter_res: u8,
    pub reserved: [u8; 23],
}

impl SuperBlock {
    #[inline]
    pub const fn size() -> usize {
        size_of::<Self>()
    }

    pub fn read_from(data: &[u8]) -> Result<Self> {
        let mut cursor = ReadCursor::new(data);
        Ok(Self {
            magic: cursor.read_u32_le()?,
            checksum: cursor.read_u32_le()?,
            feature_compat: cursor.read_u32_le()?,
            blk_size_bits: cursor.read_u8()?,
            ext_slots: cursor.read_u8()?,
            root_nid: cursor.read_u16_le()?,
            inos: cursor.read_u64_le()?,
            build_time: cursor.read_u64_le()?,
            build_time_ns: cursor.read_u32_le()?,
            blocks: cursor.read_u32_le()?,
            meta_blk_addr: cursor.read_u32_le()?,
            xattr_blk_addr: cursor.read_u32_le()?,
            uuid: cursor.read_array::<16>()?,
            volume_name: cursor.read_array::<16>()?,
            feature_incompat: cursor.read_u32_le()?,
            compr_algs: cursor.read_u16_le()?,
            extra_devices: cursor.read_u16_le()?,
            devt_slot_off: cursor.read_u16_le()?,
            dir_blk_bits: cursor.read_u8()?,
            xattr_prefix_count: cursor.read_u8()?,
            xattr_prefix_start: cursor.read_u32_le()?,
            packed_nid: cursor.read_u64_le()?,
            xattr_filter_res: cursor.read_u8()?,
            reserved: cursor.read_array::<23>()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Layout {
    FlatPlain = 0,
    CompressedFull = 1,
    FlatInline = 2,
    CompressedCompact = 3,
    ChunkBased = 4,
}

impl TryFrom<u8> for Layout {
    type Error = Error;
    fn try_from(x: u8) -> Result<Self> {
        use Layout::*;
        match x {
            0 => Ok(FlatPlain),
            1 => Ok(CompressedFull),
            2 => Ok(FlatInline),
            3 => Ok(CompressedCompact),
            4 => Ok(ChunkBased),
            x => Err(Error::InvalidLayout(x)),
        }
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FileMode: u16 {
        const READ = 0o400;
        const WRITE = 0o200;
        const EXEC = 0o100;
        const READ_GROUP = 0o040;
        const WRITE_GROUP = 0o020;
        const EXEC_GROUP = 0o010;
        const READ_OTHER = 0o004;
        const WRITE_OTHER = 0o002;
        const EXEC_OTHER = 0o001;
        const DIR = 0o040000;
        const CHAR_DEVICE = 0o020000;
        const BLOCK_DEVICE = 0o060000;
        const NAMED_PIPE = 0o010000;
        const SOCKET = 0o140000;
        const SYMLINK = 0o120000;
        const IRREGULAR = 0o100000;
        const SETUID = 0o004000;
        const SETGID = 0o002000;
        const STICKY = 0o001000;
    }
}

impl FileMode {
    pub fn is_dir(&self) -> bool {
        self.contains(Self::DIR)
    }

    pub fn is_file(&self) -> bool {
        !self.intersects(
            Self::DIR
                | Self::CHAR_DEVICE
                | Self::BLOCK_DEVICE
                | Self::NAMED_PIPE
                | Self::SOCKET
                | Self::SYMLINK
                | Self::IRREGULAR,
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Inode {
    Compact((u64, InodeCompact)),
    Extended((u64, InodeExtended)),
}

impl Inode {
    pub fn is_compact_format(layout: u16) -> bool {
        (layout & 0x01) == 0
    }

    pub fn id(&self) -> u64 {
        match self {
            Self::Compact((nid, _)) => *nid,
            Self::Extended((nid, _)) => *nid,
        }
    }

    pub fn layout(&self) -> Result<Layout> {
        let format_layout = match self {
            Self::Compact((_, n)) => n.format,
            Self::Extended((_, n)) => n.format,
        };

        let layout = ((format_layout & 0x0E) >> 1) as u8;
        layout.try_into()
    }

    pub fn size(&self) -> usize {
        match self {
            Self::Compact(_) => size_of::<InodeCompact>(),
            Self::Extended(_) => size_of::<InodeExtended>(),
        }
    }

    #[inline]
    pub fn data_size(&self) -> usize {
        match self {
            Self::Compact((_, n)) => n.size as usize,
            Self::Extended((_, n)) => n.size as usize,
        }
    }

    pub fn raw_block_addr(&self) -> u32 {
        match self {
            Self::Compact((_, n)) => n.inode_data,
            Self::Extended((_, n)) => n.inode_data,
        }
    }

    pub fn xattr_size(&self) -> usize {
        let count = match self {
            Self::Compact((_, n)) => n.xattr_count,
            Self::Extended((_, n)) => n.xattr_count,
        };
        if count == 0 {
            0
        } else {
            (count - 1) as usize * size_of::<XattrEntry>() + size_of::<XattrHeader>()
        }
    }

    pub fn file_type(&self) -> FileType {
        match self {
            Self::Compact((_, n)) => FileType::from_raw_mode(n.mode.into()),
            Self::Extended((_, n)) => FileType::from_raw_mode(n.mode.into()),
        }
    }

    pub fn is_dir(&self) -> bool {
        self.file_type().is_dir()
    }

    pub fn is_file(&self) -> bool {
        self.file_type().is_file()
    }

    pub fn is_symlink(&self) -> bool {
        self.file_type().is_symlink()
    }

    #[cfg(feature = "std")]
    pub fn permissions(&self) -> Permissions {
        match self {
            Self::Compact((_, n)) => Permissions::from_mode(n.mode.into()),
            Self::Extended((_, n)) => Permissions::from_mode(n.mode.into()),
        }
    }

    #[cfg(not(feature = "std"))]
    pub fn permissions(&self) -> u16 {
        match self {
            Self::Compact((_, n)) => n.mode,
            Self::Extended((_, n)) => n.mode,
        }
    }

    #[cfg(feature = "std")]
    pub fn modified(&self) -> Option<SystemTime> {
        match self {
            Self::Compact((_, _)) => None,
            Self::Extended((_, n)) => {
                let secs = n.mtime;
                let nanos = n.mtime_ns;
                Some(
                    SystemTime::UNIX_EPOCH
                        + Duration::from_secs(secs)
                        + Duration::from_nanos(nanos as u64),
                )
            }
        }
    }

    #[cfg(not(feature = "std"))]
    pub fn modified(&self) -> Option<(u64, u32)> {
        match self {
            Self::Compact((_, _)) => None,
            Self::Extended((_, n)) => Some((n.mtime, n.mtime_ns)),
        }
    }

    pub fn gid(&self) -> u32 {
        match self {
            Self::Compact((_, n)) => n.gid as u32,
            Self::Extended((_, n)) => n.gid,
        }
    }

    pub fn uid(&self) -> u32 {
        match self {
            Self::Compact((_, n)) => n.uid as u32,
            Self::Extended((_, n)) => n.uid,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InodeCompact {
    pub format: u16,
    pub xattr_count: u16,
    pub mode: u16,
    pub nlink: u16,
    pub size: u32,
    pub reserved: u32,
    pub inode_data: u32,
    pub inode: u32,
    pub uid: u16,
    pub gid: u16,
    pub reserved2: u32,
}

impl InodeCompact {
    #[inline]
    pub const fn size() -> usize {
        size_of::<Self>()
    }

    pub fn read_from(data: &[u8]) -> Result<Self> {
        let mut cursor = ReadCursor::new(data);
        Ok(Self {
            format: cursor.read_u16_le()?,
            xattr_count: cursor.read_u16_le()?,
            mode: cursor.read_u16_le()?,
            nlink: cursor.read_u16_le()?,
            size: cursor.read_u32_le()?,
            reserved: cursor.read_u32_le()?,
            inode_data: cursor.read_u32_le()?,
            inode: cursor.read_u32_le()?,
            uid: cursor.read_u16_le()?,
            gid: cursor.read_u16_le()?,
            reserved2: cursor.read_u32_le()?,
        })
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InodeExtended {
    pub format: u16,
    pub xattr_count: u16,
    pub mode: u16,
    pub reserved: u16,
    pub size: u64,
    pub inode_data: u32,
    pub inode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
    pub mtime_ns: u32,
    pub nlink: u32,
    pub reserved2: [u8; 16],
}

impl InodeExtended {
    #[inline]
    pub const fn size() -> usize {
        size_of::<Self>()
    }

    pub fn read_from(data: &[u8]) -> Result<Self> {
        let mut cursor = ReadCursor::new(data);
        Ok(Self {
            format: cursor.read_u16_le()?,
            xattr_count: cursor.read_u16_le()?,
            mode: cursor.read_u16_le()?,
            reserved: cursor.read_u16_le()?,
            size: cursor.read_u64_le()?,
            inode_data: cursor.read_u32_le()?,
            inode: cursor.read_u32_le()?,
            uid: cursor.read_u32_le()?,
            gid: cursor.read_u32_le()?,
            mtime: cursor.read_u64_le()?,
            mtime_ns: cursor.read_u32_le()?,
            nlink: cursor.read_u32_le()?,
            reserved2: cursor.read_array::<16>()?,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DirentFileType {
    Unknown = 0,
    RegularFile = 1,
    Directory = 2,
    CharacterDevice = 3,
    BlockDevice = 4,
    Fifo = 5,
    Socket = 6,
    Symlink = 7,
}

impl DirentFileType {
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Directory)
    }

    pub fn is_file(&self) -> bool {
        matches!(self, Self::RegularFile)
    }

    pub fn is_symlink(&self) -> bool {
        matches!(self, Self::Symlink)
    }
}

impl TryFrom<u8> for DirentFileType {
    type Error = Error;
    fn try_from(x: u8) -> Result<Self> {
        use DirentFileType::*;
        match x {
            0 => Ok(Unknown),
            1 => Ok(RegularFile),
            2 => Ok(Directory),
            3 => Ok(CharacterDevice),
            4 => Ok(BlockDevice),
            5 => Ok(Fifo),
            6 => Ok(Socket),
            7 => Ok(Symlink),
            _ => Err(Error::InvalidDirentFileType(x)),
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Dirent {
    pub nid: u64,
    pub name_off: u16,
    pub file_type: u8,
    pub reserved: u8,
}

impl Dirent {
    #[inline]
    pub const fn size() -> usize {
        size_of::<Self>()
    }

    pub fn read_from(data: &[u8]) -> Result<Self> {
        let mut cursor = ReadCursor::new(data);
        Ok(Self {
            nid: cursor.read_u64_le()?,
            name_off: cursor.read_u16_le()?,
            file_type: cursor.read_u8()?,
            reserved: cursor.read_u8()?,
        })
    }
}

pub struct ChunkBasedFormat(u16);

impl ChunkBasedFormat {
    pub fn new(format: u32) -> Self {
        Self(format as u16)
    }

    pub fn is_valid(&self) -> bool {
        let allowed_bits = LAYOUT_CHUNK_FORMAT_BITS | LAYOUT_CHUNK_FORMAT_INDEXES;
        (self.0 & !allowed_bits) == 0
    }

    pub fn is_indexes(&self) -> bool {
        (self.0 & LAYOUT_CHUNK_FORMAT_INDEXES) != 0
    }

    pub fn chunk_size_bits(&self) -> u8 {
        (self.0 & LAYOUT_CHUNK_FORMAT_BITS) as u8
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XattrHeader {
    pub name_filter: u32,
    pub shared_count: u8,
    pub reserved: [u8; 7],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XattrEntry {
    pub name_len: u8,
    pub name_index: u8,
    pub value_len: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct XattrLongPrefixItem {
    pub prefix_addr: u32,
    pub prefix_len: u8,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct XattrLongPrefix {
    pub base_index: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MapHeader {
    pub _reserved: u16,
    pub data_size: u16,
    pub advise: u16,
    // algorithm type (bit 0-3: HEAD1; bit 4-7: HEAD2)
    pub algorithmtype: u8,
    /*
     * bit 0-3 : logical cluster bits - blkszbits
     * bit 4-6 : reserved
     * bit 7   : pack the whole file into packed inode
     */
    pub clusterbits: u8,
}

impl MapHeader {
    #[inline]
    pub const fn size() -> usize {
        size_of::<Self>()
    }

    pub fn fragmentoff(&self) -> u32 {
        u32::from_le((self._reserved as u32) << 16 | u32::from(self.data_size))
    }

    pub fn read_from(data: &[u8]) -> Result<Self> {
        let mut cursor = ReadCursor::new(data);
        Ok(Self {
            _reserved: cursor.read_u16_le()?,
            data_size: cursor.read_u16_le()?,
            advise: cursor.read_u16_le()?,
            algorithmtype: cursor.read_u8()?,
            clusterbits: cursor.read_u8()?,
        })
    }

    pub fn lclusterbits(&self, sb_blk_bits: u8) -> u8 {
        sb_blk_bits + (self.clusterbits & 0x0F)
    }

    pub fn packed_inode(&self) -> bool {
        (self.clusterbits >> Z_EROFS_FRAGMENT_INODE_BIT) != 0
    }

    pub fn algorithm_head1(&self) -> u8 {
        self.algorithmtype & 0x0F
    }

    pub fn algorithm_head2(&self) -> u8 {
        self.algorithmtype >> 4
    }
}
