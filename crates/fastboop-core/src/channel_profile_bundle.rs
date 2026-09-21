extern crate alloc;

use alloc::vec::Vec;

use fastboop_schema::bin::{BootProfileBin, DeviceProfileBin};
use fastboop_schema::{BootProfile, DeviceProfile};
use serde::{Deserialize, Serialize};

use crate::channel_stream::{CHANNEL_PROFILE_BUNDLE_FORMAT_V1, CHANNEL_PROFILE_BUNDLE_MAGIC};

pub const CHANNEL_PROFILE_BUNDLE_HEADER_LEN: usize = 6;

#[derive(Clone, Debug, Default)]
pub struct ChannelProfileBundle {
    pub devprofiles: Vec<DeviceProfile>,
    pub bootprofiles: Vec<BootProfile>,
}

#[derive(Debug)]
pub enum ChannelProfileBundleCodecError {
    Decode(postcard::Error),
    InvalidMagic,
    UnsupportedFormatVersion(u16),
}

impl core::fmt::Display for ChannelProfileBundleCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(err) => write!(f, "decode channel profile bundle: {err}"),
            Self::InvalidMagic => {
                write!(f, "invalid channel profile bundle magic")
            }
            Self::UnsupportedFormatVersion(version) => write!(
                f,
                "unsupported channel profile bundle format version {version} (expected {CHANNEL_PROFILE_BUNDLE_FORMAT_V1})"
            ),
        }
    }
}

impl From<postcard::Error> for ChannelProfileBundleCodecError {
    fn from(err: postcard::Error) -> Self {
        Self::Decode(err)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ChannelProfileBundleV1Bin {
    devprofiles: Vec<DeviceProfileBin>,
    bootprofiles: Vec<BootProfileBin>,
}

pub fn decode_channel_profile_bundle(
    bytes: &[u8],
) -> Result<ChannelProfileBundle, ChannelProfileBundleCodecError> {
    let Some(format_version) = channel_profile_bundle_header_version(bytes) else {
        return Err(ChannelProfileBundleCodecError::InvalidMagic);
    };
    if format_version != CHANNEL_PROFILE_BUNDLE_FORMAT_V1 {
        return Err(ChannelProfileBundleCodecError::UnsupportedFormatVersion(
            format_version,
        ));
    }

    let payload = &bytes[CHANNEL_PROFILE_BUNDLE_HEADER_LEN..];
    let payload: ChannelProfileBundleV1Bin = postcard::from_bytes(payload)?;
    Ok(ChannelProfileBundle {
        devprofiles: payload.devprofiles.into_iter().map(Into::into).collect(),
        bootprofiles: payload.bootprofiles.into_iter().map(Into::into).collect(),
    })
}

pub fn encode_channel_profile_bundle(
    bundle: &ChannelProfileBundle,
) -> Result<Vec<u8>, postcard::Error> {
    let payload = postcard::to_allocvec(&ChannelProfileBundleV1Bin {
        devprofiles: bundle.devprofiles.iter().cloned().map(Into::into).collect(),
        bootprofiles: bundle
            .bootprofiles
            .iter()
            .cloned()
            .map(Into::into)
            .collect(),
    })?;
    let mut out = Vec::with_capacity(CHANNEL_PROFILE_BUNDLE_HEADER_LEN + payload.len());
    out.extend_from_slice(&CHANNEL_PROFILE_BUNDLE_MAGIC);
    out.extend_from_slice(&CHANNEL_PROFILE_BUNDLE_FORMAT_V1.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn channel_profile_bundle_header_version(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < CHANNEL_PROFILE_BUNDLE_HEADER_LEN {
        return None;
    }
    if bytes[..CHANNEL_PROFILE_BUNDLE_MAGIC.len()] != CHANNEL_PROFILE_BUNDLE_MAGIC {
        return None;
    }
    Some(u16::from_le_bytes([
        bytes[CHANNEL_PROFILE_BUNDLE_MAGIC.len()],
        bytes[CHANNEL_PROFILE_BUNDLE_MAGIC.len() + 1],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn roundtrips_empty_bundle() {
        let bundle = ChannelProfileBundle::default();
        let encoded = encode_channel_profile_bundle(&bundle).unwrap();
        let decoded = decode_channel_profile_bundle(&encoded).unwrap();
        assert!(decoded.devprofiles.is_empty());
        assert!(decoded.bootprofiles.is_empty());
    }

    fn boot_profile() -> BootProfile {
        let rootfs = crate::BootProfileRootfs::Ext4(crate::BootProfileRootfsExt4Source {
            ext4: crate::BootProfileArtifactSource::File(
                crate::BootProfileArtifactSourceFileSource {
                    file: "root.ext4".into(),
                    content: Some(gibblox_pipeline::PipelineSourceContent {
                        digest: format!("sha512:{}", "11".repeat(64)),
                        size_bytes: 4096,
                    }),
                },
            ),
        });
        BootProfile {
            id: "supplied-initrd".into(),
            display_name: Some("Supplied initrd".into()),
            rootfs: rootfs.clone(),
            kernel: Some(crate::BootProfileArtifactPathSource {
                path: "/boot/vmlinuz".into(),
                source: rootfs.clone(),
            }),
            initrd: Some(crate::BootProfileArtifactPathSource {
                path: "/boot/initrd".into(),
                source: rootfs,
            }),
            boot: crate::BootStrategy::Initrd,
            dtbs: None,
            dt_overlays: alloc::vec![alloc::vec![1, 2, 3]],
            extra_cmdline: Some("console=tty0".into()),
            stage0: crate::BootProfileStage0::default(),
        }
    }

    fn assert_roundtrip(bundle: ChannelProfileBundle) {
        let encoded = encode_channel_profile_bundle(&bundle).expect("encode nonempty bundle");
        let decoded = decode_channel_profile_bundle(&encoded).expect("decode nonempty bundle");
        assert_eq!(decoded.bootprofiles, bundle.bootprofiles);
        assert_eq!(decoded.devprofiles.len(), bundle.devprofiles.len());
        let mut stream = Vec::new();
        for (actual, expected) in decoded.devprofiles.iter().zip(&bundle.devprofiles) {
            let record = crate::encode_dev_profile(actual).unwrap();
            assert_eq!(record, crate::encode_dev_profile(expected).unwrap());
            stream.extend(record);
        }
        for profile in &decoded.bootprofiles {
            stream.extend(crate::encode_boot_profile(profile).unwrap());
        }
        // Bundles have a standalone codec. Boot intake consumes profile records.
        let head = crate::read_channel_stream_head(&stream, stream.len() as u64).unwrap();
        assert_eq!(head.boot_profiles, bundle.bootprofiles);
        assert_eq!(head.dev_profiles.len(), bundle.devprofiles.len());
        assert_eq!(head.consumed_bytes, stream.len() as u64);
        assert_eq!(head.warning_count, 0);
    }

    #[test]
    fn roundtrips_device_profiles() {
        assert_roundtrip(ChannelProfileBundle {
            devprofiles: crate::builtin::builtin_profiles().unwrap(),
            bootprofiles: Vec::new(),
        });
    }

    #[test]
    fn roundtrips_boot_profiles() {
        assert_roundtrip(ChannelProfileBundle {
            devprofiles: Vec::new(),
            bootprofiles: alloc::vec![boot_profile()],
        });
    }

    #[test]
    fn roundtrips_mixed_profiles() {
        assert_roundtrip(ChannelProfileBundle {
            devprofiles: crate::builtin::builtin_profiles().unwrap(),
            bootprofiles: alloc::vec![boot_profile()],
        });
    }

    #[test]
    fn rejects_invalid_magic() {
        let err = decode_channel_profile_bundle(b"xxxx\x01\x00payload").unwrap_err();
        assert!(matches!(err, ChannelProfileBundleCodecError::InvalidMagic));
    }
}
