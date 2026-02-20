use std::collections::BTreeMap;

use fastboop_core::{
    BootProfile, BootProfileDevice, BootProfileDeviceStage0, BootProfileRootfs,
    BootProfileRootfsCasync, BootProfileRootfsCasyncSource, BootProfileStage0, decode_boot_profile,
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
        rootfs: BootProfileRootfs::Casync(BootProfileRootfsCasyncSource {
            casync: BootProfileRootfsCasync {
                index: "https://example.invalid/image.caidx".to_string(),
                chunk_store: None,
            },
        }),
        dt_overlays: Vec::new(),
        extra_cmdline: None,
        stage0: BootProfileStage0::default(),
    };

    assert!(validate_boot_profile(&profile).is_err());
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
        rootfs: BootProfileRootfs::Casync(BootProfileRootfsCasyncSource {
            casync: BootProfileRootfsCasync {
                index: "https://example.invalid/image.caibx".to_string(),
                chunk_store: Some("https://example.invalid/chunks/".to_string()),
            },
        }),
        dt_overlays: vec![vec![0xAA]],
        extra_cmdline: Some("selinux=0".to_string()),
        stage0: BootProfileStage0 {
            extra_modules: vec!["erofs".to_string()],
            devices,
        },
    }
}
