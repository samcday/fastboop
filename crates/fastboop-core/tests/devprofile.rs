use fastboop_core::{
    AndroidBootImage, AndroidKernel, Boot, BootPayload, DeviceProfile, FastbootMatch,
    KernelEncoding, MatchRule, decode_dev_profile, encode_dev_profile,
};

fn sample_profile() -> DeviceProfile {
    DeviceProfile {
        id: "pocketfed".to_string(),
        display_name: Some("PocketFed".to_string()),
        devicetree_name: "qcom/sdm845-shift-axolotl".to_string(),
        r#match: vec![MatchRule {
            fastboot: FastbootMatch {
                vid: 0x18d1,
                pid: 0x4ee1,
            },
        }],
        probe: Vec::new(),
        boot: Boot {
            fastboot_boot: BootPayload {
                android_bootimg: AndroidBootImage {
                    header_version: 2,
                    page_size: 4096,
                    base: None,
                    kernel_offset: None,
                    dtb_offset: None,
                    ramdisk_offset: Some(0x0400_0000),
                    second_offset: Some(0x00F0_0000),
                    tags_offset: Some(0x0000_0100),
                    limits: None,
                    kernel: AndroidKernel {
                        encoding: KernelEncoding::Image,
                    },
                    initrd: None,
                    cmdline_append: None,
                },
            },
        },
    }
}

#[test]
fn device_profile_roundtrips_offsets_binary_codec() {
    let profile = sample_profile();
    let encoded = encode_dev_profile(&profile).expect("encode device profile");
    let decoded = decode_dev_profile(&encoded).expect("decode device profile");

    assert_eq!(decoded.id, profile.id);
    let bootimg = &decoded.boot.fastboot_boot.android_bootimg;
    assert_eq!(bootimg.ramdisk_offset, Some(0x0400_0000));
    assert_eq!(bootimg.second_offset, Some(0x00F0_0000));
    assert_eq!(bootimg.tags_offset, Some(0x0000_0100));
}

#[test]
fn device_profile_without_new_fields_roundtrips_as_none_binary_codec() {
    let mut profile = sample_profile();
    let bootimg = &mut profile.boot.fastboot_boot.android_bootimg;
    bootimg.ramdisk_offset = None;
    bootimg.second_offset = None;
    bootimg.tags_offset = None;

    let encoded = encode_dev_profile(&profile).expect("encode device profile");
    let decoded = decode_dev_profile(&encoded).expect("decode device profile");

    let bootimg = &decoded.boot.fastboot_boot.android_bootimg;
    assert_eq!(bootimg.ramdisk_offset, None);
    assert_eq!(bootimg.second_offset, None);
    assert_eq!(bootimg.tags_offset, None);
}
