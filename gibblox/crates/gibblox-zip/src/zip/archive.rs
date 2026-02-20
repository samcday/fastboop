extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec,
};
use core::cmp::min;

use gibblox_core::ReadContext;

use super::bytes::ByteReader;
use super::records::{
    CENTRAL_DIRECTORY_FILE_HEADER_LEN, CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE,
    END_OF_CENTRAL_DIRECTORY_LEN, END_OF_CENTRAL_DIRECTORY_SIGNATURE, LOCAL_FILE_HEADER_LEN,
    ZIP64_U16_SENTINEL, ZIP64_U32_SENTINEL,
};
use super::records::{
    CentralDirectoryFileHeader, EndOfCentralDirectoryRecord, LocalFileHeaderRecord,
    MAX_EOCD_SEARCH_COMMENT_LEN, find_signature_from_end,
};
use super::{ZipError, ZipResult};

const GP_FLAG_ENCRYPTED: u16 = 1 << 0;
const STORED_COMPRESSION_METHOD: u16 = 0;

#[derive(Clone, Debug)]
pub(crate) struct ZipEntryMeta {
    pub(crate) name: String,
    pub(crate) data_offset: u64,
    pub(crate) size_bytes: u64,
    pub(crate) compression_method: u16,
}

#[derive(Clone, Copy)]
struct LocatedEocd {
    record: EndOfCentralDirectoryRecord,
}

#[derive(Clone, Debug)]
struct SelectedCentralEntry {
    name: String,
    flags: u16,
    compression_method: u16,
    compressed_size: u32,
    uncompressed_size: u32,
    disk_number_start: u16,
    local_file_header_offset: u32,
}

pub(crate) async fn locate_entry(
    reader: &ByteReader,
    archive_size: u64,
    entry_name: &str,
) -> ZipResult<ZipEntryMeta> {
    let located = find_end_of_central_directory(reader, archive_size).await?;
    let selected =
        find_central_directory_entry(reader, archive_size, entry_name, &located.record).await?;
    validate_selected_entry(&selected)?;
    let data_offset = resolve_local_data_offset(reader, archive_size, &selected).await?;

    Ok(ZipEntryMeta {
        name: selected.name,
        data_offset,
        size_bytes: selected.uncompressed_size as u64,
        compression_method: selected.compression_method,
    })
}

async fn find_end_of_central_directory(
    reader: &ByteReader,
    archive_size: u64,
) -> ZipResult<LocatedEocd> {
    if archive_size < END_OF_CENTRAL_DIRECTORY_LEN as u64 {
        return Err(ZipError::invalid_input(
            "zip archive too small to contain EOCD",
        ));
    }

    let search_len = min(
        archive_size as usize,
        END_OF_CENTRAL_DIRECTORY_LEN + MAX_EOCD_SEARCH_COMMENT_LEN,
    );
    let start = archive_size - search_len as u64;
    let tail = reader
        .read_vec_at(start, search_len, ReadContext::FOREGROUND)
        .await?;

    let mut cursor = tail.len().saturating_sub(4);
    let mut unsupported: Option<ZipError> = None;

    while let Some(pos) = find_signature_from_end(&tail, END_OF_CENTRAL_DIRECTORY_SIGNATURE, cursor)
    {
        if let Some(record) = EndOfCentralDirectoryRecord::parse(&tail, pos)
            && let Some(located) =
                validate_eocd_candidate(start, pos, tail.len(), archive_size, record)
        {
            match located {
                Ok(located) => return Ok(located),
                Err(err) => {
                    if unsupported.is_none() {
                        unsupported = Some(err);
                    }
                }
            }
        }

        if pos == 0 {
            break;
        }
        cursor = pos - 1;
    }

    if let Some(err) = unsupported {
        return Err(err);
    }

    Err(ZipError::invalid_input(
        "failed to locate ZIP end-of-central-directory record",
    ))
}

fn validate_eocd_candidate(
    tail_start: u64,
    tail_offset: usize,
    tail_len: usize,
    archive_size: u64,
    record: EndOfCentralDirectoryRecord,
) -> Option<Result<LocatedEocd, ZipError>> {
    let comment_end = tail_offset
        .checked_add(END_OF_CENTRAL_DIRECTORY_LEN)?
        .checked_add(record.comment_len as usize)?;
    if comment_end > tail_len {
        return None;
    }

    if record.total_entries == ZIP64_U16_SENTINEL
        || record.entries_on_this_disk == ZIP64_U16_SENTINEL
        || record.central_directory_size == ZIP64_U32_SENTINEL
        || record.central_directory_offset == ZIP64_U32_SENTINEL
    {
        return Some(Err(ZipError::unsupported("zip64 archives are unsupported")));
    }

    if record.disk_number != 0
        || record.central_directory_disk != 0
        || record.disk_number != record.central_directory_disk
    {
        return Some(Err(ZipError::unsupported(
            "multi-disk ZIP archives are unsupported",
        )));
    }
    if record.entries_on_this_disk != record.total_entries {
        return Some(Err(ZipError::unsupported(
            "split ZIP central directory is unsupported",
        )));
    }

    let cd_offset = record.central_directory_offset as u64;
    let cd_size = record.central_directory_size as u64;
    let cd_end = cd_offset.checked_add(cd_size)?;
    if cd_end > archive_size {
        return None;
    }

    let eocd_offset = tail_start.checked_add(tail_offset as u64)?;
    if cd_end > eocd_offset {
        return None;
    }

    Some(Ok(LocatedEocd { record }))
}

async fn find_central_directory_entry(
    reader: &ByteReader,
    archive_size: u64,
    entry_name: &str,
    eocd: &EndOfCentralDirectoryRecord,
) -> ZipResult<SelectedCentralEntry> {
    let mut cursor = eocd.central_directory_offset as u64;
    let cd_end = cursor
        .checked_add(eocd.central_directory_size as u64)
        .ok_or_else(|| ZipError::out_of_range("central directory range overflow"))?;
    if cd_end > archive_size {
        return Err(ZipError::invalid_input(
            "central directory range exceeds archive size",
        ));
    }

    let mut selected: Option<SelectedCentralEntry> = None;

    for index in 0..(eocd.total_entries as usize) {
        let fixed_end = cursor
            .checked_add(CENTRAL_DIRECTORY_FILE_HEADER_LEN as u64)
            .ok_or_else(|| ZipError::out_of_range("central directory entry overflow"))?;
        if fixed_end > cd_end {
            return Err(ZipError::invalid_input(format!(
                "central directory entry {index} exceeds declared directory size"
            )));
        }

        let mut fixed = [0u8; CENTRAL_DIRECTORY_FILE_HEADER_LEN];
        reader
            .read_exact_at(cursor, &mut fixed, ReadContext::FOREGROUND)
            .await?;
        let header = CentralDirectoryFileHeader::parse(&fixed, 0).ok_or_else(|| {
            ZipError::invalid_input(format!(
                "central directory entry {index} has invalid signature (expected {CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE:08x})"
            ))
        })?;

        let variable_len = header
            .variable_len()
            .ok_or_else(|| ZipError::out_of_range("central directory variable length overflow"))?;
        let entry_len = (CENTRAL_DIRECTORY_FILE_HEADER_LEN as u64)
            .checked_add(variable_len as u64)
            .ok_or_else(|| ZipError::out_of_range("central directory entry length overflow"))?;
        let next_cursor = cursor
            .checked_add(entry_len)
            .ok_or_else(|| ZipError::out_of_range("central directory cursor overflow"))?;
        if next_cursor > cd_end {
            return Err(ZipError::invalid_input(format!(
                "central directory entry {index} overruns the declared central directory span"
            )));
        }

        let mut variable = vec![0u8; variable_len];
        if variable_len > 0 {
            reader
                .read_exact_at(fixed_end, &mut variable, ReadContext::FOREGROUND)
                .await?;
        }
        let name_end = header.file_name_len as usize;
        let name_bytes = &variable[..name_end];

        if name_bytes == entry_name.as_bytes() {
            if selected.is_some() {
                return Err(ZipError::invalid_input(format!(
                    "multiple entries named '{entry_name}' found in ZIP"
                )));
            }
            selected = Some(SelectedCentralEntry {
                name: entry_name.to_string(),
                flags: header.flags,
                compression_method: header.compression_method,
                compressed_size: header.compressed_size,
                uncompressed_size: header.uncompressed_size,
                disk_number_start: header.disk_number_start,
                local_file_header_offset: header.local_file_header_offset,
            });
        }

        cursor = next_cursor;
    }

    selected.ok_or_else(|| {
        ZipError::invalid_input(format!(
            "ZIP entry '{entry_name}' not found in central directory"
        ))
    })
}

fn validate_selected_entry(entry: &SelectedCentralEntry) -> ZipResult<()> {
    if entry.name.ends_with('/') {
        return Err(ZipError::invalid_input(format!(
            "ZIP entry '{}' is a directory",
            entry.name
        )));
    }
    if entry.disk_number_start != 0 {
        return Err(ZipError::unsupported(
            "entries on non-zero ZIP disks are unsupported",
        ));
    }
    if (entry.flags & GP_FLAG_ENCRYPTED) != 0 {
        return Err(ZipError::unsupported(format!(
            "ZIP entry '{}' is encrypted",
            entry.name
        )));
    }
    if entry.compression_method != STORED_COMPRESSION_METHOD {
        return Err(ZipError::unsupported(format!(
            "ZIP entry '{}' compression method {} is unsupported (required method: 0/store)",
            entry.name, entry.compression_method
        )));
    }
    if entry.compression_method == STORED_COMPRESSION_METHOD
        && entry.compressed_size != entry.uncompressed_size
    {
        return Err(ZipError::unsupported(format!(
            "ZIP entry '{}' uses unsupported stored-size mismatch",
            entry.name
        )));
    }
    if entry.compressed_size == ZIP64_U32_SENTINEL
        || entry.uncompressed_size == ZIP64_U32_SENTINEL
        || entry.local_file_header_offset == ZIP64_U32_SENTINEL
    {
        return Err(ZipError::unsupported("zip64 entry fields are unsupported"));
    }
    Ok(())
}

async fn resolve_local_data_offset(
    reader: &ByteReader,
    archive_size: u64,
    entry: &SelectedCentralEntry,
) -> ZipResult<u64> {
    let local_offset = entry.local_file_header_offset as u64;
    let header_end = local_offset
        .checked_add(LOCAL_FILE_HEADER_LEN as u64)
        .ok_or_else(|| ZipError::out_of_range("local header range overflow"))?;
    if header_end > archive_size {
        return Err(ZipError::invalid_input("local header exceeds archive size"));
    }

    let mut fixed = [0u8; LOCAL_FILE_HEADER_LEN];
    reader
        .read_exact_at(local_offset, &mut fixed, ReadContext::FOREGROUND)
        .await?;
    let local = LocalFileHeaderRecord::parse(&fixed, 0).ok_or_else(|| {
        ZipError::invalid_input(format!(
            "local file header for '{}' has invalid signature",
            entry.name
        ))
    })?;

    if local.compression_method != entry.compression_method {
        return Err(ZipError::invalid_input(format!(
            "local header compression method mismatch for '{}'",
            entry.name
        )));
    }
    if local.flags != entry.flags {
        return Err(ZipError::invalid_input(format!(
            "local header flags mismatch for '{}'",
            entry.name
        )));
    }

    let variable_len = local
        .variable_len()
        .ok_or_else(|| ZipError::out_of_range("local header variable length overflow"))?
        as u64;
    let data_offset = header_end
        .checked_add(variable_len)
        .ok_or_else(|| ZipError::out_of_range("local data offset overflow"))?;
    if data_offset > archive_size {
        return Err(ZipError::invalid_input(
            "local header variable section exceeds archive size",
        ));
    }

    let mut local_name = vec![0u8; local.file_name_len as usize];
    if !local_name.is_empty() {
        reader
            .read_exact_at(header_end, &mut local_name, ReadContext::FOREGROUND)
            .await?;
        if local_name != entry.name.as_bytes() {
            return Err(ZipError::invalid_input(format!(
                "local header file name mismatch for '{}'",
                entry.name
            )));
        }
    }

    let data_end = data_offset
        .checked_add(entry.compressed_size as u64)
        .ok_or_else(|| ZipError::out_of_range("local data end overflow"))?;
    if data_end > archive_size {
        return Err(ZipError::invalid_input("entry data exceeds archive size"));
    }

    Ok(data_offset)
}
