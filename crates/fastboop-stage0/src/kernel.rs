extern crate alloc;

use alloc::vec::Vec;

use fastboop_core::{Compression, DeviceProfile};
use tracing::debug;

use crate::Stage0Error;

const GZIP_MAGIC: [u8; 3] = [0x1f, 0x8b, 0x08];
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
const MZ_MAGIC: [u8; 2] = [0x4d, 0x5a];
const MIN_KERNEL_BYTES: usize = 1024 * 1024;
const ARM64_MAGIC_OFFSET: usize = 0x38;
const ARM64_MAGIC: [u8; 4] = [0x41, 0x52, 0x4d, 0x64]; // "ARM\x64"
const GZIP_LEVEL_FAST: u8 = 1;

#[derive(Debug)]
enum KernelPayload {
    Raw(Vec<u8>),
    Gzip(Vec<u8>),
}

pub fn normalize_kernel(profile: &DeviceProfile, kernel: &[u8]) -> Result<Vec<u8>, Stage0Error> {
    debug!(bytes = kernel.len(), "kernel input");
    let payload = if kernel.starts_with(&GZIP_MAGIC) {
        debug!("kernel input already gzip");
        KernelPayload::Gzip(kernel.to_vec())
    } else if kernel.starts_with(&MZ_MAGIC) {
        debug!("kernel input is PE");
        extract_pe_recursive(kernel)?
    } else {
        debug!("kernel input treated as raw");
        KernelPayload::Raw(kernel.to_vec())
    };

    let desired = profile
        .boot
        .fastboot_boot
        .android_bootimg
        .kernel
        .encoding
        .compression();

    match (desired, payload) {
        (Compression::None, KernelPayload::Raw(data)) => Ok(data),
        (Compression::None, KernelPayload::Gzip(data)) => Ok(data),
        (Compression::Gzip, KernelPayload::Gzip(data)) => Ok(data),
        (Compression::Gzip, KernelPayload::Raw(data)) => gzip_compress(&data),
        (Compression::Lz4, _) => Err(Stage0Error::KernelFormat(
            "lz4 output compression not supported",
        )),
        (Compression::Zstd, _) => Err(Stage0Error::KernelFormat(
            "zstd output compression not supported",
        )),
    }
}

fn extract_pe_recursive(kernel: &[u8]) -> Result<KernelPayload, Stage0Error> {
    let mut current = kernel.to_vec();
    for _ in 0..4 {
        if is_arm64_image(&current) {
            debug!(bytes = current.len(), "arm64 image detected");
            return Ok(KernelPayload::Raw(current));
        }
        if !current.starts_with(&MZ_MAGIC) {
            return Ok(KernelPayload::Raw(current));
        }
        debug!(bytes = current.len(), "pe layer");
        match extract_pe_payload(&current)? {
            KernelPayload::Raw(next) => current = next,
            KernelPayload::Gzip(next) => return Ok(KernelPayload::Gzip(next)),
        }
    }
    Err(Stage0Error::KernelFormat(
        "PE extraction recursion limit reached",
    ))
}

fn extract_pe_payload(kernel: &[u8]) -> Result<KernelPayload, Stage0Error> {
    let pe_offset = read_u32_le(kernel, 0x3c)
        .ok_or(Stage0Error::KernelFormat("PE header offset out of range"))?
        as usize;
    let pe_magic = kernel
        .get(pe_offset..pe_offset + 4)
        .ok_or(Stage0Error::KernelFormat("PE header truncated"))?;
    if pe_magic != b"PE\0\0" {
        return Err(Stage0Error::KernelFormat("invalid PE signature"));
    }
    let coff = pe_offset + 4;
    let num_sections = read_u16_le(kernel, coff + 2)
        .ok_or(Stage0Error::KernelFormat("PE coff header truncated"))?
        as usize;
    let opt_size = read_u16_le(kernel, coff + 16)
        .ok_or(Stage0Error::KernelFormat("PE coff header truncated"))? as usize;
    let sections_offset = coff + 20 + opt_size;
    let sections = parse_sections(kernel, sections_offset, num_sections)?;
    debug!(sections = sections.len(), bytes = kernel.len(), "pe parsed");

    if let Some(payload) = search_sections_for_payload(kernel, &sections, Some(".text"))? {
        debug!("payload found in .text");
        return Ok(payload);
    }
    if let Some(payload) = search_sections_for_payload(kernel, &sections, None)? {
        debug!("payload found in other section");
        return Ok(payload);
    }
    if let Some(payload) = search_bytes_for_payload(kernel)? {
        debug!("payload found in full PE scan");
        return Ok(payload);
    }

    Err(Stage0Error::KernelFormat(
        "no compressed kernel payload found in PE",
    ))
}

#[derive(Debug)]
struct Section<'a> {
    name: &'a str,
    raw_offset: usize,
    raw_size: usize,
}

fn parse_sections<'a>(
    data: &'a [u8],
    offset: usize,
    count: usize,
) -> Result<Vec<Section<'a>>, Stage0Error> {
    let mut sections = Vec::new();
    for i in 0..count {
        let base = offset + i * 40;
        let name_bytes = data
            .get(base..base + 8)
            .ok_or(Stage0Error::KernelFormat("section header truncated"))?;
        let name_end = name_bytes.iter().position(|b| *b == 0).unwrap_or(8);
        let name = core::str::from_utf8(&name_bytes[..name_end])
            .map_err(|_| Stage0Error::KernelFormat("section name utf8"))?;
        let raw_size = read_u32_le(data, base + 16)
            .ok_or(Stage0Error::KernelFormat("section header truncated"))?
            as usize;
        let raw_offset = read_u32_le(data, base + 20)
            .ok_or(Stage0Error::KernelFormat("section header truncated"))?
            as usize;
        let end = match raw_offset.checked_add(raw_size) {
            Some(end) => end,
            None => return Err(Stage0Error::KernelFormat("section data out of range")),
        };
        if end > data.len() {
            return Err(Stage0Error::KernelFormat("section data out of range"));
        }
        sections.push(Section {
            name,
            raw_offset,
            raw_size,
        });
    }
    Ok(sections)
}

fn search_sections_for_payload(
    data: &[u8],
    sections: &[Section<'_>],
    preferred: Option<&str>,
) -> Result<Option<KernelPayload>, Stage0Error> {
    if let Some(name) = preferred {
        for section in sections.iter().filter(move |s| s.name == name) {
            if let Some(payload) = extract_section_payload(data, section)? {
                return Ok(Some(payload));
            }
        }
        return Ok(None);
    }

    for section in sections {
        if let Some(payload) = extract_section_payload(data, section)? {
            return Ok(Some(payload));
        }
    }
    Ok(None)
}

fn extract_section_payload(
    data: &[u8],
    section: &Section<'_>,
) -> Result<Option<KernelPayload>, Stage0Error> {
    let start = section.raw_offset;
    let end = start + section.raw_size;
    let bytes = &data[start..end];
    let result = search_bytes_for_payload(bytes)?;
    if result.is_some() {
        debug!(
            section = section.name,
            bytes = section.raw_size,
            "payload candidate"
        );
    }
    Ok(result)
}

fn search_bytes_for_payload(data: &[u8]) -> Result<Option<KernelPayload>, Stage0Error> {
    let zstd_hits = find_all_magics(data, &ZSTD_MAGIC);
    let gzip_hits = find_all_magics(data, &GZIP_MAGIC);
    debug!(
        zstd_hits = zstd_hits.len(),
        gzip_hits = gzip_hits.len(),
        bytes = data.len(),
        "payload scan"
    );
    let mut best_raw: Option<Vec<u8>> = None;
    let mut best_raw_len = 0usize;
    for idx in zstd_hits {
        if let Ok(payload) = decode_zstd(&data[idx..]) {
            debug!(bytes = payload.len(), "zstd decoded");
            if payload.starts_with(&MZ_MAGIC) || is_arm64_image(&payload) {
                return Ok(Some(KernelPayload::Raw(payload)));
            }
            if payload.len() > best_raw_len {
                best_raw_len = payload.len();
                best_raw = Some(payload);
            }
        }
    }
    if let Some(payload) = best_raw
        && payload.len() >= MIN_KERNEL_BYTES
    {
        return Ok(Some(KernelPayload::Raw(payload)));
    }

    for idx in gzip_hits {
        if let Some(prefix) = gzip_peek_header(&data[idx..])?
            && is_arm64_image(&prefix)
        {
            debug!("gzip header matches arm64 image");
            return Ok(Some(KernelPayload::Gzip(data[idx..].to_vec())));
        }
    }
    Ok(None)
}

fn decode_zstd(data: &[u8]) -> Result<Vec<u8>, Stage0Error> {
    let mut decoder =
        ruzstd::StreamingDecoder::new(data).map_err(|_| Stage0Error::KernelDecode("zstd init"))?;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = ruzstd::io::Read::read(&mut decoder, &mut buf)
            .map_err(|_| Stage0Error::KernelDecode("zstd decode failed"))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    debug!(bytes = out.len(), "zstd output");
    Ok(out)
}

fn gzip_peek_header(data: &[u8]) -> Result<Option<Vec<u8>>, Stage0Error> {
    if data.len() < 10 {
        return Ok(None);
    }
    if data[0] != 0x1f || data[1] != 0x8b || data[2] != 0x08 {
        return Ok(None);
    }
    let flg = data[3];
    if flg & 0xe0 != 0 {
        return Ok(None);
    }
    let mut offset = 10;
    if flg & 0x04 != 0 {
        if data.len() < offset + 2 {
            return Ok(None);
        }
        let xlen = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2 + xlen;
    }
    if flg & 0x08 != 0 {
        while offset < data.len() && data[offset] != 0 {
            offset += 1;
        }
        offset = offset.saturating_add(1);
    }
    if flg & 0x10 != 0 {
        while offset < data.len() && data[offset] != 0 {
            offset += 1;
        }
        offset = offset.saturating_add(1);
    }
    if flg & 0x02 != 0 {
        offset = offset.saturating_add(2);
    }
    if offset >= data.len() {
        return Ok(None);
    }
    if data.len().saturating_sub(offset) < 8 {
        return Ok(None);
    }
    let deflate_end = data.len() - 8;
    let deflate = &data[offset..deflate_end];
    let limit = ARM64_MAGIC_OFFSET + 8;
    match miniz_oxide::inflate::decompress_to_vec_with_limit(deflate, limit) {
        Ok(out) => Ok(Some(out)),
        Err(err) => Ok(Some(err.output)),
    }
}

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, Stage0Error> {
    debug!(bytes = data.len(), "gzip compress");
    let deflated = miniz_oxide::deflate::compress_to_vec(data, GZIP_LEVEL_FAST);
    let mut out = Vec::with_capacity(10 + deflated.len() + 8);
    out.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);
    out.extend_from_slice(&deflated);
    let crc = crc32(data);
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    Ok(out)
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320u32 & mask);
        }
    }
    !crc
}

fn find_all_magics(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx + needle.len() <= haystack.len() {
        if &haystack[idx..idx + needle.len()] == needle {
            out.push(idx);
        }
        idx += 1;
    }
    out
}

fn is_arm64_image(data: &[u8]) -> bool {
    data.len() > ARM64_MAGIC_OFFSET + ARM64_MAGIC.len()
        && data[ARM64_MAGIC_OFFSET..ARM64_MAGIC_OFFSET + ARM64_MAGIC.len()] == ARM64_MAGIC
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
