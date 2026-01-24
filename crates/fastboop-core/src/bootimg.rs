#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::DeviceProfile;

const ANDROID_MAGIC: &[u8; 8] = b"ANDROID!";
const NAME_LEN: usize = 16;
const CMDLINE_LEN: usize = 512;
const EXTRA_CMDLINE_LEN: usize = 1024;
const ID_LEN: usize = 32;
const HEADER_V0_SIZE: usize = 1632;
const HEADER_V1_SIZE: usize = 1648;
const HEADER_V2_SIZE: usize = 1660;

const DEFAULT_KERNEL_OFFSET: u64 = 0x00008000;
const DEFAULT_RAMDISK_OFFSET: u64 = 0x01000000;
const DEFAULT_SECOND_OFFSET: u64 = 0x00F00000;
const DEFAULT_TAGS_OFFSET: u64 = 0x00000100;

struct HeaderParams {
    header_version: u32,
    kernel_size: u32,
    kernel_addr: u32,
    ramdisk_size: u32,
    ramdisk_addr: u32,
    second_addr: u32,
    tags_addr: u32,
    page_size: u32,
    cmdline_main: String,
    cmdline_extra: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootImageError {
    UnsupportedHeaderVersion(u32),
    InvalidPageSize(u32),
    CmdlineTooLong(usize),
    AddressOverflow(&'static str),
    ExceedsKernelLimit { size: usize, limit: u64 },
    ExceedsInitrdLimit { size: usize, limit: u64 },
    ExceedsTotalLimit { size: usize, limit: u64 },
}

impl fmt::Display for BootImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHeaderVersion(v) => {
                write!(f, "unsupported android boot header version {v}")
            }
            Self::InvalidPageSize(size) => write!(f, "invalid page size {size}"),
            Self::CmdlineTooLong(len) => write!(f, "cmdline too long: {len} bytes"),
            Self::AddressOverflow(name) => write!(f, "{name} address overflows u32"),
            Self::ExceedsKernelLimit { size, limit } => {
                write!(f, "kernel size {size} exceeds limit {limit}")
            }
            Self::ExceedsInitrdLimit { size, limit } => {
                write!(f, "initrd size {size} exceeds limit {limit}")
            }
            Self::ExceedsTotalLimit { size, limit } => {
                write!(f, "total bootimg size {size} exceeds limit {limit}")
            }
        }
    }
}

pub fn build_android_bootimg(
    profile: &DeviceProfile,
    kernel: &[u8],
    ramdisk: &[u8],
    cmdline: &str,
) -> Result<Vec<u8>, BootImageError> {
    let boot = &profile.boot.fastboot_boot.android_bootimg;
    let header_version = boot.header_version;
    let page_size = boot.page_size;
    if page_size == 0 {
        return Err(BootImageError::InvalidPageSize(page_size));
    }

    if let Some(limit) = boot.limits.max_kernel_bytes
        && kernel.len() as u64 > limit
    {
        return Err(BootImageError::ExceedsKernelLimit {
            size: kernel.len(),
            limit,
        });
    }
    if let Some(limit) = boot.limits.max_initrd_bytes
        && ramdisk.len() as u64 > limit
    {
        return Err(BootImageError::ExceedsInitrdLimit {
            size: ramdisk.len(),
            limit,
        });
    }

    let (cmdline_main, cmdline_extra) = split_cmdline(cmdline)?;
    let (kernel_addr, ramdisk_addr, second_addr, tags_addr) =
        compute_addrs(boot.base, boot.kernel_offset)?;

    let params = HeaderParams {
        header_version,
        kernel_size: kernel.len() as u32,
        kernel_addr,
        ramdisk_size: ramdisk.len() as u32,
        ramdisk_addr,
        second_addr,
        tags_addr,
        page_size,
        cmdline_main,
        cmdline_extra,
    };

    let mut header = Vec::new();
    match header_version {
        0 => write_header_v0(&mut header, &params),
        1 => write_header_v1(&mut header, &params),
        2 => write_header_v2(&mut header, &params),
        _ => return Err(BootImageError::UnsupportedHeaderVersion(header_version)),
    }

    pad_to_page(&mut header, page_size);

    let mut image = header;
    push_section(&mut image, kernel, page_size);
    push_section(&mut image, ramdisk, page_size);

    if let Some(limit) = boot.limits.max_total_bytes
        && image.len() as u64 > limit
    {
        return Err(BootImageError::ExceedsTotalLimit {
            size: image.len(),
            limit,
        });
    }

    Ok(image)
}

fn compute_addrs(
    base: Option<u64>,
    kernel_offset: Option<u64>,
) -> Result<(u32, u32, u32, u32), BootImageError> {
    let base = base.unwrap_or(0);
    let kernel_offset = kernel_offset.unwrap_or(DEFAULT_KERNEL_OFFSET);
    let kernel_addr = base + kernel_offset;
    let ramdisk_addr = base + DEFAULT_RAMDISK_OFFSET;
    let second_addr = base + DEFAULT_SECOND_OFFSET;
    let tags_addr = base + DEFAULT_TAGS_OFFSET;

    Ok((
        u32::try_from(kernel_addr).map_err(|_| BootImageError::AddressOverflow("kernel"))?,
        u32::try_from(ramdisk_addr).map_err(|_| BootImageError::AddressOverflow("ramdisk"))?,
        u32::try_from(second_addr).map_err(|_| BootImageError::AddressOverflow("second"))?,
        u32::try_from(tags_addr).map_err(|_| BootImageError::AddressOverflow("tags"))?,
    ))
}

fn split_cmdline(cmdline: &str) -> Result<(String, String), BootImageError> {
    let bytes = cmdline.as_bytes();
    if bytes.len() <= CMDLINE_LEN {
        return Ok((cmdline.to_string(), String::new()));
    }
    if bytes.len() > CMDLINE_LEN + EXTRA_CMDLINE_LEN {
        return Err(BootImageError::CmdlineTooLong(bytes.len()));
    }
    let main = String::from_utf8_lossy(&bytes[..CMDLINE_LEN]).to_string();
    let extra = String::from_utf8_lossy(&bytes[CMDLINE_LEN..]).to_string();
    Ok((main, extra))
}

fn write_header_v0(out: &mut Vec<u8>, params: &HeaderParams) {
    out.extend_from_slice(ANDROID_MAGIC);
    write_u32(out, params.kernel_size);
    write_u32(out, params.kernel_addr);
    write_u32(out, params.ramdisk_size);
    write_u32(out, params.ramdisk_addr);
    write_u32(out, 0);
    write_u32(out, params.second_addr);
    write_u32(out, params.tags_addr);
    write_u32(out, params.page_size);
    write_u32(out, params.header_version);
    write_u32(out, 0);
    write_fixed(out, &[], NAME_LEN);
    write_fixed(out, params.cmdline_main.as_bytes(), CMDLINE_LEN);
    write_fixed(out, &[0; ID_LEN], ID_LEN);
    write_fixed(out, params.cmdline_extra.as_bytes(), EXTRA_CMDLINE_LEN);
    debug_assert_eq!(out.len(), HEADER_V0_SIZE);
}

fn write_header_v1(out: &mut Vec<u8>, params: &HeaderParams) {
    write_header_v0(out, params);
    write_u32(out, 0);
    write_u64(out, 0);
    write_u32(out, HEADER_V1_SIZE as u32);
    debug_assert_eq!(out.len(), HEADER_V1_SIZE);
}

fn write_header_v2(out: &mut Vec<u8>, params: &HeaderParams) {
    write_header_v1(out, params);
    write_u32(out, 0);
    write_u64(out, 0);
    debug_assert_eq!(out.len(), HEADER_V2_SIZE);
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_fixed(out: &mut Vec<u8>, data: &[u8], len: usize) {
    let mut buf = vec![0u8; len];
    let n = core::cmp::min(len, data.len());
    buf[..n].copy_from_slice(&data[..n]);
    out.extend_from_slice(&buf);
}

fn pad_to_page(out: &mut Vec<u8>, page_size: u32) {
    let page = page_size as usize;
    let rem = out.len() % page;
    if rem == 0 {
        return;
    }
    out.extend(core::iter::repeat_n(0, page - rem));
}

fn push_section(out: &mut Vec<u8>, data: &[u8], page_size: u32) {
    out.extend_from_slice(data);
    pad_to_page(out, page_size);
}
