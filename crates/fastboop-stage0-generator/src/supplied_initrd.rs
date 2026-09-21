//! Prepare image-owned kernel/initramfs artifacts without synthesizing stage0.

use alloc::string::{String, ToString};
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
    /// Raw device-appropriate ABLX shim. When present, carry the Linux kernel
    /// and unchanged initramfs in an ABLXRD1 ramdisk container.
    pub abl_exorcist: Option<&'a [u8]>,
}

/// Normalize the kernel for the device and prepare its DTB. The supplied
/// initramfs remains byte-for-byte unchanged, including any compression, either
/// directly or inside an ABLXRD1 container. The caller must wrap the complete
/// Android command line in ABLX markers when a shim is supplied.
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
    let (kernel_image, initrd) = if let Some(shim) = options.abl_exorcist {
        abl_exorcist_assembler::arm64_image_size(shim, abl_exorcist_assembler::ImageKind::Shim)
            .map_err(|err| Stage0Error::AblExorcist(err.to_string()))?;
        let raw_kernel = kernel::prepare_ramdisk_kernel(options.kernel)?;
        tracing::debug!(
            kernel_bytes = raw_kernel.len(),
            shim_bytes = shim.len(),
            initrd_bytes = options.initrd.len(),
            "assembling ABLX ramdisk payload"
        );
        let ramdisk = abl_exorcist_assembler::assemble_ramdisk(&raw_kernel, &options.initrd)
            .map_err(|err| Stage0Error::AblExorcist(err.to_string()))?;
        (kernel::normalize_kernel(profile, shim)?, ramdisk)
    } else {
        (
            kernel::normalize_kernel(profile, options.kernel)?,
            options.initrd,
        )
    };
    Ok(BootImageComponents {
        kernel_image,
        initrd,
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
                    abl_exorcist: None,
                },
            )
            .unwrap();
            assert_eq!(prepared.kernel_image, expected);
            assert_eq!(prepared.initrd, initrd);
            assert_eq!(prepared.kernel_cmdline_append, "image.cmdline=retained");
        }
    }

    fn image(size: usize) -> Vec<u8> {
        let mut image = vec![0x5a; size];
        image[..2].copy_from_slice(b"MZ"); // EFI-stub ARM64 Image, not a wrapper
        image[16..24].copy_from_slice(&(size as u64).to_le_bytes());
        image[56..60].copy_from_slice(b"ARM\x64");
        image
    }

    fn compose(
        device: &DeviceProfile,
        kernel: &[u8],
        initrd: &[u8],
        shim: &[u8],
        dtb: &[u8],
    ) -> Result<BootImageComponents, Stage0Error> {
        prepare_supplied_initrd(
            device,
            SuppliedInitrdOptions {
                kernel,
                initrd: initrd.to_vec(),
                dtb,
                overlays: &[],
                inject_mac: &None,
                mac_seed: "0",
                cmdline: "root=/dev/smoo-root rd.smoo.root=42 rd.smoo.cow=1".into(),
                abl_exorcist: Some(shim),
            },
        )
    }

    #[test]
    fn ablx_ramdisk_roundtrips_kernel_and_opaque_initrd_with_device_geometry() {
        let mut device = builtin_profiles()
            .unwrap()
            .into_iter()
            .find(|p| p.id == "google-sargo")
            .unwrap();
        let kernel = image(16384);
        let gzip_kernel = kernel::gzip_compress(&kernel).unwrap();
        let shim = image(128);
        let dtb = dtoolkit::model::DeviceTree::new().to_dtb();
        let initrd = kernel::gzip_compress(b"opaque initrd, not a host-parsed cpio").unwrap();
        // Both the built-in appended-DTB layout and a v2 separate-DTB DevPro
        // must put the DTB outside ABLXRD1 and preserve its load geometry.
        for separate_dtb in [false, true] {
            if separate_dtb {
                let boot = &mut device.boot.fastboot_boot.android_bootimg;
                boot.header_version = 2;
                boot.kernel.encoding = KernelEncoding::ImageGzip;
                boot.dtb_offset = Some(0x03000000);
            }
            for input in [&kernel, &gzip_kernel] {
                let prepared = compose(&device, input, &initrd, &shim, &dtb).unwrap();
                assert_eq!(
                    kernel::normalize_kernel(
                        &profile(KernelEncoding::Image),
                        &prepared.kernel_image
                    )
                    .unwrap(),
                    shim
                );
                let ramdisk = &prepared.initrd;
                assert_eq!(&ramdisk[..8], b"ABLXRD1\0");
                let field = |offset| {
                    u64::from_le_bytes(ramdisk[offset..offset + 8].try_into().unwrap()) as usize
                };
                assert_eq!(u32::from_le_bytes(ramdisk[8..12].try_into().unwrap()), 72);
                assert_eq!(u32::from_le_bytes(ramdisk[12..16].try_into().unwrap()), 2);
                assert_eq!(field(16) % 4096, 0);
                assert_eq!(field(48) % 4096, 0);
                assert_eq!(field(32), kernel.len());
                assert_eq!(field(40), kernel.len());
                assert_eq!(field(56), initrd.len());
                let decoded = lz4_flex::block::decompress(
                    &ramdisk[field(16)..field(16) + field(24)],
                    field(32),
                )
                .unwrap();
                assert_eq!(decoded, kernel);
                assert_eq!(&ramdisk[field(48)..], initrd);
                let expected_ramdisk = ramdisk.clone();
                let compressed_shim = prepared.kernel_image.clone();
                let payload =
                    fastboop_core::build_android_boot_payload_with_options(&device, prepared, true)
                        .unwrap();
                let u32_at = |offset| {
                    u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize
                };
                let page = u32_at(36);
                assert_eq!(u32_at(12), 0x8000);
                assert_eq!(u32_at(20), 0x04000000);
                assert_eq!(u32_at(32), 0x100);
                assert_eq!(
                    &payload[page..page + compressed_shim.len()],
                    compressed_shim
                );
                let ramdisk_start = page + u32_at(8).div_ceil(page) * page;
                assert_eq!(
                    &payload[ramdisk_start..ramdisk_start + u32_at(16)],
                    expected_ramdisk
                );
                if separate_dtb {
                    assert_eq!(
                        u64::from_le_bytes(payload[1652..1660].try_into().unwrap()),
                        0x03000000
                    );
                    let dtb_start = ramdisk_start + u32_at(16).div_ceil(page) * page;
                    assert_eq!(&payload[dtb_start..dtb_start + dtb.len()], dtb);
                } else {
                    assert_eq!(
                        &payload[page + compressed_shim.len()..page + u32_at(8)],
                        dtb
                    );
                }
            }
        }
    }

    #[test]
    fn ablx_limits_apply_to_shim_and_complete_ramdisk_container() {
        let mut device = profile(KernelEncoding::Image);
        let kernel = image(16384);
        let shim = image(128);
        let initrd = b"unchanged initrd";
        device.boot.fastboot_boot.android_bootimg.limits = Some(fastboop_core::BootLimits {
            max_kernel_bytes: Some(128),
            max_initrd_bytes: None,
            max_total_bytes: None,
        });
        // The Linux kernel is much larger than the Android kernel section's
        // limit, which now applies to the shim. This must still succeed.
        let gzip_kernel = kernel::gzip_compress(&kernel).unwrap();
        let prepared = compose(&device, &gzip_kernel, initrd, &shim, &[]).unwrap();
        fastboop_core::build_android_boot_payload_with_options(&device, prepared, true).unwrap();
        device
            .boot
            .fastboot_boot
            .android_bootimg
            .limits
            .as_mut()
            .unwrap()
            .max_initrd_bytes = Some(initrd.len() as u64);
        let prepared = compose(&device, &kernel, initrd, &shim, &[]).unwrap();
        assert!(matches!(
            fastboop_core::build_android_boot_payload_with_options(&device, prepared, true),
            Err(fastboop_core::bootimg::BootImageError::ExceedsInitrdLimit { .. })
        ));
        device
            .boot
            .fastboot_boot
            .android_bootimg
            .limits
            .as_mut()
            .unwrap()
            .max_initrd_bytes = None;
        device
            .boot
            .fastboot_boot
            .android_bootimg
            .limits
            .as_mut()
            .unwrap()
            .max_kernel_bytes = Some(127);
        let prepared = compose(&device, &kernel, initrd, &shim, &[]).unwrap();
        assert!(matches!(
            fastboop_core::build_android_boot_payload_with_options(&device, prepared, true),
            Err(fastboop_core::bootimg::BootImageError::ExceedsKernelLimit { .. })
        ));
    }

    #[test]
    fn ablx_rejects_invalid_images_and_caller_supplied_markers() {
        let device = profile(KernelEncoding::ImageGzip);
        let raw = image(128);
        let mut zero_size = raw.clone();
        zero_size[16..24].fill(0);
        let compressed = kernel::gzip_compress(&raw).unwrap();
        for invalid in [&[][..], &b"wrong file"[..], &zero_size, &compressed] {
            assert!(compose(&device, &raw, b"initrd", invalid, &[]).is_err());
        }
        assert!(compose(&device, b"not a kernel", b"initrd", &raw, &[]).is_err());
        assert!(compose(&device, &zero_size, b"initrd", &raw, &[]).is_err());
        for marker in ["<S>", "<E>"] {
            let mut prepared = compose(&device, &raw, b"initrd", &raw, &[]).unwrap();
            prepared.kernel_cmdline_append = marker.into();
            assert!(matches!(
                fastboop_core::build_android_boot_payload_with_options(&device, prepared, true),
                Err(fastboop_core::bootimg::BootImageError::ReservedAblExorcistMarker)
            ));
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
                        abl_exorcist: None,
                    }
                )
                .is_err()
            );
        }
    }
}
