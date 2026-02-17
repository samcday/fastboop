pub(crate) const LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x0403_4b50;
pub(crate) const CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE: u32 = 0x0201_4b50;
pub(crate) const END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4b50;

pub(crate) const LOCAL_FILE_HEADER_LEN: usize = 30;
pub(crate) const CENTRAL_DIRECTORY_FILE_HEADER_LEN: usize = 46;
pub(crate) const END_OF_CENTRAL_DIRECTORY_LEN: usize = 22;

pub(crate) const MAX_EOCD_SEARCH_COMMENT_LEN: usize = 65_535;

pub(crate) const ZIP64_U16_SENTINEL: u16 = 0xffff;
pub(crate) const ZIP64_U32_SENTINEL: u32 = 0xffff_ffff;

#[derive(Clone, Copy, Debug)]
pub(crate) struct EndOfCentralDirectoryRecord {
    pub(crate) disk_number: u16,
    pub(crate) central_directory_disk: u16,
    pub(crate) entries_on_this_disk: u16,
    pub(crate) total_entries: u16,
    pub(crate) central_directory_size: u32,
    pub(crate) central_directory_offset: u32,
    pub(crate) comment_len: u16,
}

impl EndOfCentralDirectoryRecord {
    pub(crate) fn parse(raw: &[u8], offset: usize) -> Option<Self> {
        let sig = u32_at(raw, offset)?;
        if sig != END_OF_CENTRAL_DIRECTORY_SIGNATURE {
            return None;
        }
        Some(Self {
            disk_number: u16_at(raw, offset + 4)?,
            central_directory_disk: u16_at(raw, offset + 6)?,
            entries_on_this_disk: u16_at(raw, offset + 8)?,
            total_entries: u16_at(raw, offset + 10)?,
            central_directory_size: u32_at(raw, offset + 12)?,
            central_directory_offset: u32_at(raw, offset + 16)?,
            comment_len: u16_at(raw, offset + 20)?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CentralDirectoryFileHeader {
    pub(crate) flags: u16,
    pub(crate) compression_method: u16,
    pub(crate) compressed_size: u32,
    pub(crate) uncompressed_size: u32,
    pub(crate) file_name_len: u16,
    pub(crate) extra_len: u16,
    pub(crate) comment_len: u16,
    pub(crate) disk_number_start: u16,
    pub(crate) local_file_header_offset: u32,
}

impl CentralDirectoryFileHeader {
    pub(crate) fn parse(raw: &[u8], offset: usize) -> Option<Self> {
        let sig = u32_at(raw, offset)?;
        if sig != CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE {
            return None;
        }
        Some(Self {
            flags: u16_at(raw, offset + 8)?,
            compression_method: u16_at(raw, offset + 10)?,
            compressed_size: u32_at(raw, offset + 20)?,
            uncompressed_size: u32_at(raw, offset + 24)?,
            file_name_len: u16_at(raw, offset + 28)?,
            extra_len: u16_at(raw, offset + 30)?,
            comment_len: u16_at(raw, offset + 32)?,
            disk_number_start: u16_at(raw, offset + 34)?,
            local_file_header_offset: u32_at(raw, offset + 42)?,
        })
    }

    pub(crate) fn variable_len(&self) -> Option<usize> {
        (self.file_name_len as usize)
            .checked_add(self.extra_len as usize)?
            .checked_add(self.comment_len as usize)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LocalFileHeaderRecord {
    pub(crate) flags: u16,
    pub(crate) compression_method: u16,
    pub(crate) file_name_len: u16,
    pub(crate) extra_len: u16,
}

impl LocalFileHeaderRecord {
    pub(crate) fn parse(raw: &[u8], offset: usize) -> Option<Self> {
        let sig = u32_at(raw, offset)?;
        if sig != LOCAL_FILE_HEADER_SIGNATURE {
            return None;
        }
        Some(Self {
            flags: u16_at(raw, offset + 6)?,
            compression_method: u16_at(raw, offset + 8)?,
            file_name_len: u16_at(raw, offset + 26)?,
            extra_len: u16_at(raw, offset + 28)?,
        })
    }

    pub(crate) fn variable_len(&self) -> Option<usize> {
        (self.file_name_len as usize).checked_add(self.extra_len as usize)
    }
}

#[inline]
fn u16_at(raw: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes = raw.get(offset..end)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

#[inline]
fn u32_at(raw: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes = raw.get(offset..end)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn find_signature_from_end(raw: &[u8], signature: u32, before: usize) -> Option<usize> {
    let sig = signature.to_le_bytes();
    if raw.len() < 4 {
        return None;
    }
    let mut idx = before.min(raw.len().saturating_sub(4));
    loop {
        if raw[idx..idx + 4] == sig {
            return Some(idx);
        }
        if idx == 0 {
            return None;
        }
        idx -= 1;
    }
}
