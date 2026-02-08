#[cfg(feature = "std")]
use core::{cmp, hint};

#[cfg(not(feature = "std"))]
use core::{cmp, hint};

#[cfg(feature = "std")]
use std::ffi::OsStr;

use alloc::string::{String, ToString};

use crate::types::{Dirent, DirentFileType};
use crate::{Error, Result};

#[cfg(feature = "std")]
pub fn find_nodeid_by_name(name: &OsStr, data: &[u8]) -> Result<Option<u64>> {
    let dirent = read_nth_dirent(data, 0)?;
    let n = dirent.name_off as usize / Dirent::size();
    if n <= 2 {
        return Ok(None);
    }

    let offset = 2;
    let mut size = n - offset;
    let mut base = 0usize;
    while size > 1 {
        let half = size / 2;
        let mid = base + half;

        let cmp = {
            let (_, entry_name) = read_nth_id_name(data, mid + offset, n)?;
            entry_name.as_str().cmp(&name.to_string_lossy())
        };
        base = hint::select_unpredictable(cmp == cmp::Ordering::Greater, base, mid);
        size -= half;
    }

    let (inner_nid, cmp) = {
        let (nid, entry_name) = read_nth_id_name(data, base + offset, n)?;
        let cmp = entry_name.as_str().cmp(&name.to_string_lossy());
        (nid, cmp)
    };
    if cmp != cmp::Ordering::Equal {
        return Ok(None);
    }

    Ok(Some(inner_nid))
}

#[cfg(not(feature = "std"))]
pub fn find_nodeid_by_name(name: &str, data: &[u8]) -> Result<Option<u64>> {
    let dirent = read_nth_dirent(data, 0)?;
    let n = dirent.name_off as usize / Dirent::size();
    if n <= 2 {
        return Ok(None);
    }

    let offset = 2;
    let mut size = n - offset;
    let mut base = 0usize;
    while size > 1 {
        let half = size / 2;
        let mid = base + half;

        let cmp = {
            let (_, entry_name) = read_nth_id_name(data, mid + offset, n)?;
            entry_name.as_str().cmp(name)
        };
        base = hint::select_unpredictable(cmp == cmp::Ordering::Greater, base, mid);
        size -= half;
    }

    let (inner_nid, cmp) = {
        let (nid, entry_name) = read_nth_id_name(data, base + offset, n)?;
        let cmp = entry_name.as_str().cmp(name);
        (nid, cmp)
    };
    if cmp != cmp::Ordering::Equal {
        return Ok(None);
    }

    Ok(Some(inner_nid))
}

fn read_nth_id_name(data: &[u8], n: usize, max: usize) -> Result<(u64, String)> {
    let dirent = read_nth_dirent(data, n)?;
    let name_start = dirent.name_off as usize;
    let name_end = if n < max - 1 {
        let dirent = read_nth_dirent(data, n + 1)?;
        dirent.name_off as usize
    } else {
        data.len()
    };

    if name_end < name_start || name_end > data.len() {
        return Err(Error::CorruptedData(
            "invalid directory entry name offset".to_string(),
        ));
    }
    let name = String::from_utf8_lossy(&data[name_start..name_end])
        .trim_end_matches('\0')
        .into();
    Ok((dirent.nid, name))
}

pub fn read_nth_dirent(data: &[u8], n: usize) -> Result<Dirent> {
    let start = n * Dirent::size();
    let slice = data
        .get(start..start + Dirent::size())
        .ok_or_else(|| Error::OutOfBounds("failed to parse directory entry".to_string()))?;
    Dirent::read_from(slice)
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub nid: u64,
    pub file_type: DirentFileType,
    pub file_name: String,
}
