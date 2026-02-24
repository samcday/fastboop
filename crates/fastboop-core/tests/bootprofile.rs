use std::collections::BTreeMap;

use fastboop_core::{
    BootProfile, BootProfileArtifactSource, BootProfileArtifactSourceCasync,
    BootProfileArtifactSourceCasyncSource, BootProfileArtifactSourceFileSource,
    BootProfileArtifactSourceGpt, BootProfileArtifactSourceGptSource,
    BootProfileArtifactSourceHttpSource, BootProfileArtifactSourceMbr,
    BootProfileArtifactSourceMbrSource, BootProfileCodecError, BootProfileDevice,
    BootProfileDeviceStage0, BootProfileRootfs, BootProfileRootfsErofsSource,
    BootProfileRootfsExt4Source, BootProfileRootfsFatSource, BootProfileStage0,
    BootProfileValidationError, decode_boot_profile, decode_boot_profile_prefix,
    encode_boot_profile, resolve_effective_boot_profile_stage0, validate_boot_profile,
};

#[test]
fn boot_profile_roundtrip_binary_codec() {
    let profile = sample_profile();
    let encoded = encode_boot_profile(&profile).expect("encode boot profile");
    let decoded = decode_boot_profile(&encoded).expect("decode boot profile");
    assert_eq!(decoded, profile);
}

#[test]
fn boot_profile_prefix_decode_returns_consumed_length() {
    let profile = sample_profile();
    let mut encoded = encode_boot_profile(&profile).expect("encode boot profile");
    encoded.extend_from_slice(b"TAIL");

    let (decoded, consumed) =
        decode_boot_profile_prefix(&encoded).expect("decode boot profile prefix");
    assert_eq!(decoded, profile);
    assert_eq!(consumed, encoded.len() - 4);
}

#[test]
fn boot_profile_ext4_roundtrip_binary_codec() {
    let profile = BootProfile {
        id: "ext4-roundtrip".to_string(),
        display_name: Some("Ext4 Roundtrip".to_string()),
        rootfs: BootProfileRootfs::Ext4(BootProfileRootfsExt4Source {
            ext4: BootProfileArtifactSource::Http(BootProfileArtifactSourceHttpSource {
                http: "https://example.invalid/rootfs.ext4".to_string(),
            }),
        }),
        kernel: None,
        dtbs: None,
        dt_overlays: Vec::new(),
        extra_cmdline: None,
        stage0: BootProfileStage0::default(),
    };

    let encoded = encode_boot_profile(&profile).expect("encode boot profile");
    let decoded = decode_boot_profile(&encoded).expect("decode boot profile");
    assert_eq!(decoded, profile);
}

#[test]
fn rejects_boot_profile_with_invalid_magic() {
    let profile = sample_profile();
    let mut tampered = encode_boot_profile(&profile).expect("encode boot profile");
    tampered[0..8].copy_from_slice(b"NOTMAGIC");

    let err = decode_boot_profile(&tampered).expect_err("invalid magic should fail decode");
    assert!(matches!(err, BootProfileCodecError::InvalidMagic));
}

#[test]
fn resolves_effective_stage0_for_device_override() {
    let profile = sample_profile();
    let resolved = resolve_effective_boot_profile_stage0(&profile, "oneplus-fajita");
    assert_eq!(resolved.extra_modules, vec!["erofs", "qcom-foo"]);
    assert_eq!(
        resolved.extra_cmdline,
        Some("selinux=0 console=ttyMSM0,115200n8".to_string())
    );
    assert_eq!(resolved.dt_overlays, vec![vec![0xAA], vec![0xBB]]);
}

#[test]
fn rejects_casync_archive_indexes() {
    let profile = BootProfile {
        id: "bad".to_string(),
        display_name: None,
        rootfs: BootProfileRootfs::Erofs(BootProfileRootfsErofsSource {
            erofs: BootProfileArtifactSource::Casync(BootProfileArtifactSourceCasyncSource {
                casync: BootProfileArtifactSourceCasync {
                    index: "https://example.invalid/image.caidx".to_string(),
                    chunk_store: None,
                },
            }),
        }),
        kernel: None,
        dtbs: None,
        dt_overlays: Vec::new(),
        extra_cmdline: None,
        stage0: BootProfileStage0::default(),
    };

    assert!(validate_boot_profile(&profile).is_err());
}

#[test]
fn rejects_gpt_step_without_selector() {
    let profile = BootProfile {
        id: "bad-gpt".to_string(),
        display_name: None,
        rootfs: BootProfileRootfs::Erofs(BootProfileRootfsErofsSource {
            erofs: BootProfileArtifactSource::Gpt(BootProfileArtifactSourceGptSource {
                gpt: BootProfileArtifactSourceGpt {
                    partlabel: None,
                    partuuid: None,
                    index: None,
                    source: Box::new(BootProfileArtifactSource::Http(
                        BootProfileArtifactSourceHttpSource {
                            http: "https://example.invalid/rootfs.img".to_string(),
                        },
                    )),
                },
            }),
        }),
        kernel: None,
        dtbs: None,
        dt_overlays: Vec::new(),
        extra_cmdline: None,
        stage0: BootProfileStage0::default(),
    };

    let err = validate_boot_profile(&profile).expect_err("gpt selector validation should fail");
    assert_eq!(
        err,
        BootProfileValidationError::InvalidGptSelectorCount { selectors: 0 }
    );
}

#[test]
fn rejects_mbr_step_without_selector() {
    let profile = BootProfile {
        id: "bad-mbr".to_string(),
        display_name: None,
        rootfs: BootProfileRootfs::Erofs(BootProfileRootfsErofsSource {
            erofs: BootProfileArtifactSource::Mbr(BootProfileArtifactSourceMbrSource {
                mbr: BootProfileArtifactSourceMbr {
                    partuuid: None,
                    index: None,
                    source: Box::new(BootProfileArtifactSource::Http(
                        BootProfileArtifactSourceHttpSource {
                            http: "https://example.invalid/rootfs.img".to_string(),
                        },
                    )),
                },
            }),
        }),
        kernel: None,
        dtbs: None,
        dt_overlays: Vec::new(),
        extra_cmdline: None,
        stage0: BootProfileStage0::default(),
    };

    let err = validate_boot_profile(&profile).expect_err("mbr selector validation should fail");
    assert_eq!(
        err,
        BootProfileValidationError::InvalidMbrSelectorCount { selectors: 0 }
    );
}

#[test]
fn accepts_file_artifact_source() {
    let profile = BootProfile {
        id: "file-source".to_string(),
        display_name: None,
        rootfs: BootProfileRootfs::Erofs(BootProfileRootfsErofsSource {
            erofs: BootProfileArtifactSource::File(BootProfileArtifactSourceFileSource {
                file: "./rootfs.ero".to_string(),
            }),
        }),
        kernel: None,
        dtbs: None,
        dt_overlays: Vec::new(),
        extra_cmdline: None,
        stage0: BootProfileStage0::default(),
    };

    validate_boot_profile(&profile).expect("file source should validate");
}

#[test]
fn accepts_ext4_rootfs_source() {
    let profile = BootProfile {
        id: "ext4-source".to_string(),
        display_name: None,
        rootfs: BootProfileRootfs::Ext4(BootProfileRootfsExt4Source {
            ext4: BootProfileArtifactSource::File(BootProfileArtifactSourceFileSource {
                file: "./rootfs.img".to_string(),
            }),
        }),
        kernel: None,
        dtbs: None,
        dt_overlays: Vec::new(),
        extra_cmdline: None,
        stage0: BootProfileStage0::default(),
    };

    validate_boot_profile(&profile).expect("ext4 source should validate");
}

#[test]
fn rejects_fat_rootfs_for_stage0_switchroot() {
    let profile = BootProfile {
        id: "fat-rootfs".to_string(),
        display_name: None,
        rootfs: BootProfileRootfs::Fat(BootProfileRootfsFatSource {
            fat: BootProfileArtifactSource::File(BootProfileArtifactSourceFileSource {
                file: "./rootfs.fat".to_string(),
            }),
        }),
        kernel: None,
        dtbs: None,
        dt_overlays: Vec::new(),
        extra_cmdline: None,
        stage0: BootProfileStage0::default(),
    };

    let err = validate_boot_profile(&profile).expect_err("fat rootfs should be rejected");
    assert_eq!(
        err,
        BootProfileValidationError::UnsupportedRootfsFilesystem { filesystem: "fat" }
    );
}

#[test]
fn rejects_empty_kernel_path() {
    let mut profile = sample_profile();
    profile.kernel = Some(fastboop_core::BootProfileArtifactPathSource {
        path: "   ".to_string(),
        source: BootProfileRootfs::Erofs(BootProfileRootfsErofsSource {
            erofs: BootProfileArtifactSource::Http(BootProfileArtifactSourceHttpSource {
                http: "https://example.invalid/kernel.img".to_string(),
            }),
        }),
    });

    let err = validate_boot_profile(&profile).expect_err("empty kernel path should fail");
    assert_eq!(err, BootProfileValidationError::EmptyKernelPath);
}

fn sample_profile() -> BootProfile {
    let mut devices = BTreeMap::new();
    devices.insert(
        "oneplus-fajita".to_string(),
        BootProfileDevice {
            dt_overlays: vec![vec![0xBB]],
            extra_cmdline: Some("console=ttyMSM0,115200n8".to_string()),
            stage0: BootProfileDeviceStage0 {
                extra_modules: vec!["qcom-foo".to_string()],
            },
        },
    );

    BootProfile {
        id: "live-pocket-fedora".to_string(),
        display_name: Some("Live Pocket Fedora".to_string()),
        rootfs: BootProfileRootfs::Erofs(BootProfileRootfsErofsSource {
            erofs: BootProfileArtifactSource::Casync(BootProfileArtifactSourceCasyncSource {
                casync: BootProfileArtifactSourceCasync {
                    index: "https://example.invalid/image.caibx".to_string(),
                    chunk_store: Some("https://example.invalid/chunks/".to_string()),
                },
            }),
        }),
        kernel: None,
        dtbs: None,
        dt_overlays: vec![vec![0xAA]],
        extra_cmdline: Some("selinux=0".to_string()),
        stage0: BootProfileStage0 {
            extra_modules: vec!["erofs".to_string()],
            devices,
        },
    }
}
