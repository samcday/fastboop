use fastboop_core::{
    AndroidBootImage, AndroidKernel, Boot, BootPayload, DevProfileCodecError, DeviceProfile,
    FastbootMatch, KernelEncoding, MatchRule, decode_dev_profile, decode_dev_profile_prefix,
    encode_dev_profile,
};
use fastboop_schema::bin::DEV_PROFILE_BIN_FORMAT_VERSION;

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

#[test]
fn encodes_current_device_profile_format_version() {
    let encoded = encode_dev_profile(&sample_profile()).expect("encode device profile");
    assert_eq!(&encoded[..8], b"FBOODEVP");
    assert_eq!(
        u16::from_le_bytes([encoded[8], encoded[9]]),
        DEV_PROFILE_BIN_FORMAT_VERSION
    );
}

#[test]
fn rejects_device_profile_with_previous_format_version() {
    // v0.0.1-rc.21 wrote format version 0 records, whose Android boot image
    // payload has no ramdisk/second/tags offsets.
    let mut stale = encode_dev_profile(&sample_profile()).expect("encode device profile");
    stale[8..10].copy_from_slice(&0u16.to_le_bytes());

    let err = decode_dev_profile(&stale).expect_err("stale format version should fail decode");
    assert!(matches!(
        err,
        DevProfileCodecError::UnsupportedFormatVersion(0)
    ));
    let err = decode_dev_profile_prefix(&stale)
        .expect_err("stale format version should fail prefix decode");
    assert!(matches!(
        err,
        DevProfileCodecError::UnsupportedFormatVersion(0)
    ));

    let message = err.to_string();
    assert!(message.contains("format version 0"), "{message}");
    assert!(
        message.contains(&format!(
            "supports version {DEV_PROFILE_BIN_FORMAT_VERSION}"
        )),
        "{message}"
    );
    assert!(
        message.contains("recompile the device profile with this fastboop version"),
        "{message}"
    );
}
