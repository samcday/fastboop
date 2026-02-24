use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use fastboop_core::{CHANNEL_SNIFF_PREFIX_LEN, ChannelStreamKind, classify_channel_prefix};

#[test]
fn generated_fixtures_match_expected_stream_kinds() {
    let fixtures_dir = fixtures_dir();
    if !fixtures_dir.exists() {
        eprintln!(
            "skipping channel stream fixture harness: missing {} (run tools/channels/generate-fixtures.sh)",
            fixtures_dir.display()
        );
        return;
    }

    let cases = [
        ("profile-bundle-v1.bin", ChannelStreamKind::ProfileBundleV1),
        ("android-sparse.img", ChannelStreamKind::AndroidSparse),
        ("gpt.img", ChannelStreamKind::Gpt),
        ("mbr.img", ChannelStreamKind::Mbr),
        ("iso9660.img", ChannelStreamKind::Iso9660),
        ("rootfs.erofs", ChannelStreamKind::Erofs),
        ("rootfs.ext4", ChannelStreamKind::Ext4),
        ("boot.vfat", ChannelStreamKind::Fat),
        ("rootfs.erofs.xz", ChannelStreamKind::Xz),
        ("rootfs.erofs.zip", ChannelStreamKind::Zip),
    ];

    for (fixture_name, expected_kind) in cases {
        let fixture_path = fixtures_dir.join(fixture_name);
        assert!(
            fixture_path.exists(),
            "missing fixture {}; run tools/channels/generate-fixtures.sh",
            fixture_path.display()
        );
        let prefix = read_prefix(&fixture_path, CHANNEL_SNIFF_PREFIX_LEN);
        let actual_kind = classify_channel_prefix(&prefix);
        assert_eq!(
            actual_kind, expected_kind,
            "fixture {} classified incorrectly",
            fixture_name
        );
    }
}

fn fixtures_dir() -> PathBuf {
    if let Some(path) = env::var_os("FASTBOOP_CHANNEL_FIXTURES_DIR") {
        return PathBuf::from(path);
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("build/channels-fixtures")
}

fn read_prefix(path: &Path, cap: usize) -> Vec<u8> {
    let mut file = File::open(path).unwrap_or_else(|err| {
        panic!("open fixture {}: {err}", path.display());
    });
    let mut buf = vec![0u8; cap];
    let read = file.read(&mut buf).unwrap_or_else(|err| {
        panic!("read fixture {}: {err}", path.display());
    });
    buf.truncate(read);
    buf
}
