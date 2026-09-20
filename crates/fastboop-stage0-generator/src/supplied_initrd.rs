//! Prepare image-owned kernel/initramfs artifacts without synthesizing stage0.

use alloc::string::String;
use alloc::vec::Vec;
use dtoolkit::fdt::Fdt;
use fastboop_core::{BootImageComponents, DeviceProfile, InjectMac};

use crate::{Stage0Error, apply_dtbo_overlays, apply_mac_injection, kernel};

pub struct SuppliedInitrdOptions<'a> {
    pub kernel: &'a [u8],
    pub initrd: Vec<u8>,
    pub dtb: &'a [u8],
    pub overlays: &'a [Vec<u8>],
    pub inject_mac: &'a Option<InjectMac>,
    pub mac_seed: &'a str,
    pub cmdline: String,
}

/// Normalize the kernel for the device and prepare its DTB. The supplied
/// initramfs remains byte-for-byte unchanged, including any compression.
pub fn prepare_supplied_initrd(
    profile: &DeviceProfile,
    options: SuppliedInitrdOptions<'_>,
) -> Result<BootImageComponents, Stage0Error> {
    if options.kernel.is_empty() {
        return Err(Stage0Error::MissingFile(
            "boot profile kernel is empty".into(),
        ));
    }
    if options.initrd.is_empty() {
        return Err(Stage0Error::MissingFile(
            "boot profile initrd is empty".into(),
        ));
    }
    let needs_dtb = profile
        .boot
        .fastboot_boot
        .android_bootimg
        .kernel
        .encoding
        .append_dtb()
        || !options.overlays.is_empty()
        || options.inject_mac.is_some();
    if options.dtb.is_empty() && needs_dtb {
        return Err(Stage0Error::MissingFile(
            "boot profile dtbs or --dtb".into(),
        ));
    }
    let dtb = if options.dtb.is_empty() {
        Vec::new()
    } else {
        let dtb = apply_dtbo_overlays(options.dtb, options.overlays)?;
        let dtb = apply_mac_injection(&dtb, options.inject_mac, options.mac_seed)?;
        Fdt::new(&dtb).map_err(|_| Stage0Error::ParseError("dtb"))?;
        dtb
    };
    Ok(BootImageComponents {
        kernel_image: kernel::normalize_kernel(profile, options.kernel)?,
        initrd: options.initrd,
        dtb,
        kernel_cmdline_append: options.cmdline,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use fastboop_core::KernelEncoding;
    use fastboop_core::builtin::builtin_profiles;

    fn profile(encoding: KernelEncoding) -> DeviceProfile {
        let mut profile = builtin_profiles().unwrap().remove(0);
        profile.boot.fastboot_boot.android_bootimg.kernel.encoding = encoding;
        profile
    }

    #[test]
    fn preserves_compressed_initrd_and_normalizes_kernel_for_device() {
        let raw_kernel = vec![0x5a; 1024];
        let gzip_kernel = kernel::gzip_compress(&raw_kernel).unwrap();
        let initrd = kernel::gzip_compress(b"opaque image-owned initramfs").unwrap();
        for (encoding, input, expected) in [
            (
                KernelEncoding::Image,
                gzip_kernel.clone(),
                raw_kernel.clone(),
            ),
            (KernelEncoding::ImageGzip, raw_kernel, gzip_kernel),
        ] {
            let prepared = prepare_supplied_initrd(
                &profile(encoding),
                SuppliedInitrdOptions {
                    kernel: &input,
                    initrd: initrd.clone(),
                    dtb: &[],
                    overlays: &[],
                    inject_mac: &None,
                    mac_seed: "0",
                    cmdline: "image.cmdline=retained".into(),
                },
            )
            .unwrap();
            assert_eq!(prepared.kernel_image, expected);
            assert_eq!(prepared.initrd, initrd);
            assert_eq!(prepared.kernel_cmdline_append, "image.cmdline=retained");
        }
    }

    #[test]
    fn rejects_missing_initrd_and_required_dtb() {
        let initrd = vec![1, 2, 3];
        for (encoding, initrd) in [
            (KernelEncoding::Image, Vec::new()),
            (KernelEncoding::ImageGzipDtb, initrd),
        ] {
            assert!(
                prepare_supplied_initrd(
                    &profile(encoding),
                    SuppliedInitrdOptions {
                        kernel: &[1],
                        initrd,
                        dtb: &[],
                        overlays: &[],
                        inject_mac: &None,
                        mac_seed: "0",
                        cmdline: String::new(),
                    }
                )
                .is_err()
            );
        }
    }
}
