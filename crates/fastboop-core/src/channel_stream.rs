use crate::channel_index::CHANNEL_INDEX_RECORD_MAGIC;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelStreamKind {
    /// `FBCH` profile bundle of any format version; the bundle codec rejects
    /// versions other than [`CHANNEL_PROFILE_BUNDLE_FORMAT_VERSION`].
    ProfileBundle,
    Xz,
    Zip,
    AndroidSparse,
    Gpt,
    Iso9660,
    Erofs,
    Ext4,
    Fat,
    Mbr,
    Unknown,
}

pub const CHANNEL_PROFILE_BUNDLE_MAGIC: [u8; 4] = *b"FBCH";
/// Version 2: the payload switched to the binary-safe `DeviceProfileBin` /
/// `BootProfileBin` representations (v0.0.1-rc.22). Bump it whenever the
/// payload layout changes, including through those profile types.
pub const CHANNEL_PROFILE_BUNDLE_FORMAT_VERSION: u16 = 2;

// 64 KiB covers current known signatures, including ISO9660 (offset 0x8001).
pub const CHANNEL_SNIFF_PREFIX_LEN: usize = 64 * 1024;

pub fn classify_channel_prefix(prefix: &[u8]) -> ChannelStreamKind {
    if is_profile_bundle(prefix) {
        return ChannelStreamKind::ProfileBundle;
    }
    if is_xz(prefix) {
        return ChannelStreamKind::Xz;
    }
    if is_zip(prefix) {
        return ChannelStreamKind::Zip;
    }
    if is_android_sparse(prefix) {
        return ChannelStreamKind::AndroidSparse;
    }
    if is_gpt(prefix) {
        return ChannelStreamKind::Gpt;
    }
    if is_iso9660(prefix) {
        return ChannelStreamKind::Iso9660;
    }
    if is_erofs(prefix) {
        return ChannelStreamKind::Erofs;
    }
    if is_ext4(prefix) {
        return ChannelStreamKind::Ext4;
    }
    if is_fat(prefix) {
        return ChannelStreamKind::Fat;
    }
    if is_mbr(prefix) {
        return ChannelStreamKind::Mbr;
    }
    ChannelStreamKind::Unknown
}

fn is_profile_bundle(prefix: &[u8]) -> bool {
    // Any version matches, so a bundle from another fastboop version is
    // reported as a bundle rather than as an unrecognized format. Channel
    // index records share the `FBCH` prefix but are not bundles.
    prefix.len() >= CHANNEL_PROFILE_BUNDLE_MAGIC.len() + 2
        && has_at(prefix, 0, &CHANNEL_PROFILE_BUNDLE_MAGIC)
        && !has_at(prefix, 0, &CHANNEL_INDEX_RECORD_MAGIC)
}

fn is_xz(prefix: &[u8]) -> bool {
    has_at(prefix, 0, &[0xFD, b'7', b'z', b'X', b'Z', 0x00])
}

fn is_zip(prefix: &[u8]) -> bool {
    has_at(prefix, 0, b"PK\x03\x04")
        || has_at(prefix, 0, b"PK\x05\x06")
        || has_at(prefix, 0, b"PK\x07\x08")
}

fn is_android_sparse(prefix: &[u8]) -> bool {
    has_u32_le(prefix, 0, 0xED26_FF3A)
}

fn is_gpt(prefix: &[u8]) -> bool {
    has_at(prefix, 512, b"EFI PART")
}

fn is_iso9660(prefix: &[u8]) -> bool {
    if !has_at(prefix, 32769, b"CD001") {
        return false;
    }
    matches!(prefix.get(32768), Some(1 | 2 | 255))
}

fn is_erofs(prefix: &[u8]) -> bool {
    has_u32_le(prefix, 1024, 0xE0F5_E1E2)
}

fn is_ext4(prefix: &[u8]) -> bool {
    has_u16_le(prefix, 1080, 0xEF53)
}

fn is_fat(prefix: &[u8]) -> bool {
    if !has_at(prefix, 510, &[0x55, 0xAA]) {
        return false;
    }
    has_at(prefix, 54, b"FAT12") || has_at(prefix, 54, b"FAT16") || has_at(prefix, 82, b"FAT32")
}

fn is_mbr(prefix: &[u8]) -> bool {
    if !has_at(prefix, 510, &[0x55, 0xAA]) {
        return false;
    }

    for index in 0..4 {
        let type_offset = 446 + (index * 16) + 4;
        if let Some(partition_type) = prefix.get(type_offset)
            && *partition_type != 0
        {
            return true;
        }
    }

    false
}

fn has_u16_le(prefix: &[u8], offset: usize, expected: u16) -> bool {
    let Some(bytes) = prefix.get(offset..offset + 2) else {
        return false;
    };
    u16::from_le_bytes([bytes[0], bytes[1]]) == expected
}

fn has_u32_le(prefix: &[u8], offset: usize, expected: u32) -> bool {
    let Some(bytes) = prefix.get(offset..offset + 4) else {
        return false;
    };
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) == expected
}

fn has_at(prefix: &[u8], offset: usize, expected: &[u8]) -> bool {
    let Some(bytes) = prefix.get(offset..offset + expected.len()) else {
        return false;
    };
    bytes == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_profile_bundle_before_other_formats() {
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&CHANNEL_PROFILE_BUNDLE_MAGIC);
        buf[4..6].copy_from_slice(&CHANNEL_PROFILE_BUNDLE_FORMAT_VERSION.to_le_bytes());
        assert_eq!(
            classify_channel_prefix(&buf),
            ChannelStreamKind::ProfileBundle
        );
    }

    #[test]
    fn detects_profile_bundle_with_unsupported_version() {
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&CHANNEL_PROFILE_BUNDLE_MAGIC);
        buf[4..6].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            classify_channel_prefix(&buf),
            ChannelStreamKind::ProfileBundle
        );
    }

    #[test]
    fn channel_index_record_is_not_a_profile_bundle() {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&CHANNEL_INDEX_RECORD_MAGIC);
        assert_eq!(classify_channel_prefix(&buf), ChannelStreamKind::Unknown);
    }

    #[test]
    fn detects_xz_magic() {
        let buf = [0xFD, b'7', b'z', b'X', b'Z', 0x00];
        assert_eq!(classify_channel_prefix(&buf), ChannelStreamKind::Xz);
    }

    #[test]
    fn fat_wins_before_mbr_when_both_signatures_exist() {
        let mut buf = [0u8; 512];
        buf[510] = 0x55;
        buf[511] = 0xAA;
        buf[82..87].copy_from_slice(b"FAT32");
        buf[446 + 4] = 0x83;
        assert_eq!(classify_channel_prefix(&buf), ChannelStreamKind::Fat);
    }

    #[test]
    fn returns_unknown_for_short_or_invalid_prefix() {
        assert_eq!(classify_channel_prefix(&[]), ChannelStreamKind::Unknown);
        assert_eq!(
            classify_channel_prefix(&[1, 2, 3, 4]),
            ChannelStreamKind::Unknown
        );
    }
}
