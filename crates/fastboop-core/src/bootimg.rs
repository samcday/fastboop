extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::{AndroidBootImage, DeviceProfile};

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
const DEFAULT_DTB_OFFSET: u64 = 0x01F00000;

struct HeaderParams {
    header_version: u32,
    header_size: u32,
    kernel_size: u32,
    kernel_addr: u32,
    ramdisk_size: u32,
    ramdisk_addr: u32,
    second_addr: u32,
    tags_addr: u32,
    page_size: u32,
    cmdline_main: String,
    cmdline_extra: String,
    dtb_size: u32,
    dtb_addr: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootImageError {
    UnsupportedHeaderVersion(u32),
    InvalidPageSize(u32),
    CmdlineTooLong(usize),
    ReservedAblExorcistMarker,
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
            Self::ReservedAblExorcistMarker => write!(
                f,
                "ABLX command line must not contain <S> or <E>; fastboop adds these markers"
            ),
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
    dtb: Option<&[u8]>,
    cmdline: &str,
) -> Result<Vec<u8>, BootImageError> {
    let boot = &profile.boot.fastboot_boot.android_bootimg;
    let header_version = boot.header_version;
    let page_size = boot.page_size;
    if page_size == 0 {
        return Err(BootImageError::InvalidPageSize(page_size));
    }

    let limits = boot.limits.as_ref();
    if let Some(limit) = limits
        .and_then(|limits| limits.max_kernel_bytes)
        .filter(|limit| *limit > 0)
        && kernel.len() as u64 > limit
    {
        return Err(BootImageError::ExceedsKernelLimit {
            size: kernel.len(),
            limit,
        });
    }
    if let Some(limit) = limits
        .and_then(|limits| limits.max_initrd_bytes)
        .filter(|limit| *limit > 0)
        && ramdisk.len() as u64 > limit
    {
        return Err(BootImageError::ExceedsInitrdLimit {
            size: ramdisk.len(),
            limit,
        });
    }

    let (cmdline_main, cmdline_extra) = split_cmdline(cmdline)?;
    let (kernel_addr, ramdisk_addr, second_addr, tags_addr) = compute_addrs(boot)?;
    let dtb = if header_version >= 2 && !boot.kernel.encoding.append_dtb() {
        dtb
    } else {
        None
    };
    let (dtb_size, dtb_addr) = match dtb {
        Some(dtb) => (
            dtb.len() as u32,
            compute_dtb_addr(boot.base, boot.dtb_offset)?,
        ),
        None => (0, 0),
    };
    let header_size = match header_version {
        0 => HEADER_V0_SIZE as u32,
        1 => HEADER_V1_SIZE as u32,
        2 => HEADER_V2_SIZE as u32,
        _ => return Err(BootImageError::UnsupportedHeaderVersion(header_version)),
    };

    let params = HeaderParams {
        header_version,
        header_size,
        kernel_size: kernel.len() as u32,
        kernel_addr,
        ramdisk_size: ramdisk.len() as u32,
        ramdisk_addr,
        second_addr,
        tags_addr,
        page_size,
        cmdline_main,
        cmdline_extra,
        dtb_size,
        dtb_addr,
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
    if let Some(dtb) = dtb {
        push_section(&mut image, dtb, page_size);
    }

    if let Some(limit) = limits
        .and_then(|limits| limits.max_total_bytes)
        .filter(|limit| *limit > 0)
        && image.len() as u64 > limit
    {
        return Err(BootImageError::ExceedsTotalLimit {
            size: image.len(),
            limit,
        });
    }

    Ok(image)
}

fn compute_addrs(boot: &AndroidBootImage) -> Result<(u32, u32, u32, u32), BootImageError> {
    let base = boot.base.unwrap_or(0);
    let kernel_offset = boot.kernel_offset.unwrap_or(DEFAULT_KERNEL_OFFSET);
    let ramdisk_offset = boot.ramdisk_offset.unwrap_or(DEFAULT_RAMDISK_OFFSET);
    let second_offset = boot.second_offset.unwrap_or(DEFAULT_SECOND_OFFSET);
    let tags_offset = boot.tags_offset.unwrap_or(DEFAULT_TAGS_OFFSET);
    let addr = |offset: u64, name: &'static str| -> Result<u32, BootImageError> {
        base.checked_add(offset)
            .and_then(|addr| u32::try_from(addr).ok())
            .ok_or(BootImageError::AddressOverflow(name))
    };

    Ok((
        addr(kernel_offset, "kernel")?,
        addr(ramdisk_offset, "ramdisk")?,
        addr(second_offset, "second")?,
        addr(tags_offset, "tags")?,
    ))
}

fn compute_dtb_addr(base: Option<u64>, dtb_offset: Option<u64>) -> Result<u64, BootImageError> {
    let base = base.unwrap_or(0);
    let dtb_offset = dtb_offset.unwrap_or(DEFAULT_DTB_OFFSET);
    base.checked_add(dtb_offset)
        .ok_or(BootImageError::AddressOverflow("dtb"))
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
    write_u32(out, params.header_size);
    debug_assert_eq!(out.len(), HEADER_V1_SIZE);
}

fn write_header_v2(out: &mut Vec<u8>, params: &HeaderParams) {
    write_header_v1(out, params);
    write_u32(out, params.dtb_size);
    write_u64(out, params.dtb_addr);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AndroidKernel, Boot, BootPayload, KernelEncoding};

    fn bootimg_with_defaults() -> AndroidBootImage {
        AndroidBootImage {
            header_version: 2,
            page_size: 4096,
            base: None,
            kernel_offset: None,
            dtb_offset: None,
            ramdisk_offset: None,
            second_offset: None,
            tags_offset: None,
            limits: None,
            kernel: AndroidKernel {
                encoding: KernelEncoding::Image,
            },
            initrd: None,
            cmdline_append: None,
        }
    }

    fn profile_with_bootimg(android_bootimg: AndroidBootImage) -> DeviceProfile {
        DeviceProfile {
            id: "test".to_string(),
            display_name: None,
            devicetree_name: "test".to_string(),
            r#match: Vec::new(),
            probe: Vec::new(),
            boot: Boot {
                fastboot_boot: BootPayload { android_bootimg },
            },
        }
    }

    fn read_u32(image: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn default_offsets_match_legacy_addresses() {
        let profile = profile_with_bootimg(bootimg_with_defaults());
        let image = build_android_bootimg(&profile, &[0xAA; 16], &[0xBB; 16], None, "console=tty0")
            .expect("build boot image");

        assert_eq!(read_u32(&image, 12), 0x0000_8000);
        assert_eq!(read_u32(&image, 20), 0x0100_0000);
        assert_eq!(read_u32(&image, 28), 0x00F0_0000);
        assert_eq!(read_u32(&image, 32), 0x0000_0100);
    }

    #[test]
    fn a_base_plus_offset_that_wraps_u64_is_an_overflow_not_zero() {
        let mut bootimg = bootimg_with_defaults();
        bootimg.base = Some(u64::MAX);
        bootimg.ramdisk_offset = Some(1);
        let profile = profile_with_bootimg(bootimg);

        let err = build_android_bootimg(&profile, &[0xAA; 16], &[0xBB; 16], None, "")
            .expect_err("wrapping base + offset must not become address 0");
        assert!(matches!(err, BootImageError::AddressOverflow(_)), "{err}");
    }

    #[test]
    fn custom_offsets_are_written_to_header() {
        let mut bootimg = bootimg_with_defaults();
        bootimg.ramdisk_offset = Some(0x0400_0000);
        bootimg.second_offset = Some(0x0500_0000);
        bootimg.tags_offset = Some(0x0600_0000);
        let profile = profile_with_bootimg(bootimg);
        let image = build_android_bootimg(&profile, &[0xAA; 16], &[0xBB; 16], None, "")
            .expect("build boot image");

        assert_eq!(read_u32(&image, 12), 0x0000_8000);
        assert_eq!(read_u32(&image, 20), 0x0400_0000);
        assert_eq!(read_u32(&image, 28), 0x0500_0000);
        assert_eq!(read_u32(&image, 32), 0x0600_0000);
    }
}
