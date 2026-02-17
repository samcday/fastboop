use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::{
    Boot, BootProfile, BootProfileDevice, BootProfileDeviceStage0, BootProfileRootfs,
    BootProfileRootfsCasync, BootProfileRootfsCasyncSource, BootProfileRootfsHttpSource,
    BootProfileStage0, DeviceProfile, ExistsFlag, FastbootGetvarEq, FastbootGetvarExists,
    FastbootGetvarNotEq, FastbootGetvarNotExists, InjectMac, MatchRule, NotExistsFlag, ProbeStep,
    Stage0,
};

pub const BOOT_PROFILE_BIN_FORMAT_VERSION: u16 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BootProfileEnvelopeBin {
    pub format_version: u16,
    pub profile: BootProfileBin,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BootProfileBin {
    pub id: String,
    pub display_name: Option<String>,
    pub rootfs: BootProfileRootfsBin,
    pub dt_overlays: Vec<Vec<u8>>,
    pub extra_cmdline: Option<String>,
    pub stage0: BootProfileStage0Bin,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum BootProfileRootfsBin {
    Casync {
        index: String,
        chunk_store: Option<String>,
    },
    Http {
        url: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BootProfileStage0Bin {
    pub extra_modules: Vec<String>,
    pub devices: BTreeMap<String, BootProfileDeviceBin>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BootProfileDeviceBin {
    pub dt_overlays: Vec<Vec<u8>>,
    pub extra_cmdline: Option<String>,
    pub stage0: BootProfileDeviceStage0Bin,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BootProfileDeviceStage0Bin {
    pub extra_modules: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceProfileBin {
    pub id: String,
    pub display_name: Option<String>,
    pub devicetree_name: String,
    pub r#match: Vec<MatchRule>,
    pub probe: Vec<ProbeStepBin>,
    pub boot: Boot,
    pub stage0: Stage0Bin,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ProbeStepBin {
    FastbootGetvarEq { name: String, equals: String },
    FastbootGetvarNotEq { name: String, not_equals: String },
    FastbootGetvarExists { name: String },
    FastbootGetvarNotExists { name: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Stage0Bin {
    pub kernel_modules: Vec<String>,
    pub inject_mac: Option<InjectMacBin>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InjectMacBin {
    pub wifi: Option<String>,
    pub bluetooth: Option<String>,
}

impl From<DeviceProfile> for DeviceProfileBin {
    fn from(profile: DeviceProfile) -> Self {
        Self {
            id: profile.id,
            display_name: profile.display_name,
            devicetree_name: profile.devicetree_name,
            r#match: profile.r#match,
            probe: profile.probe.into_iter().map(ProbeStepBin::from).collect(),
            boot: profile.boot,
            stage0: Stage0Bin::from(profile.stage0),
        }
    }
}

impl From<DeviceProfileBin> for DeviceProfile {
    fn from(profile: DeviceProfileBin) -> Self {
        Self {
            id: profile.id,
            display_name: profile.display_name,
            devicetree_name: profile.devicetree_name,
            r#match: profile.r#match,
            probe: profile.probe.into_iter().map(ProbeStep::from).collect(),
            boot: profile.boot,
            stage0: Stage0::from(profile.stage0),
        }
    }
}

impl From<ProbeStep> for ProbeStepBin {
    fn from(step: ProbeStep) -> Self {
        match step {
            ProbeStep::FastbootGetvarEq(FastbootGetvarEq { name, equals }) => {
                ProbeStepBin::FastbootGetvarEq { name, equals }
            }
            ProbeStep::FastbootGetvarNotEq(FastbootGetvarNotEq { name, not_equals }) => {
                ProbeStepBin::FastbootGetvarNotEq { name, not_equals }
            }
            ProbeStep::FastbootGetvarExists(FastbootGetvarExists { name, .. }) => {
                ProbeStepBin::FastbootGetvarExists { name }
            }
            ProbeStep::FastbootGetvarNotExists(FastbootGetvarNotExists { name, .. }) => {
                ProbeStepBin::FastbootGetvarNotExists { name }
            }
        }
    }
}

impl From<ProbeStepBin> for ProbeStep {
    fn from(step: ProbeStepBin) -> Self {
        match step {
            ProbeStepBin::FastbootGetvarEq { name, equals } => {
                ProbeStep::FastbootGetvarEq(FastbootGetvarEq { name, equals })
            }
            ProbeStepBin::FastbootGetvarNotEq { name, not_equals } => {
                ProbeStep::FastbootGetvarNotEq(FastbootGetvarNotEq { name, not_equals })
            }
            ProbeStepBin::FastbootGetvarExists { name } => {
                ProbeStep::FastbootGetvarExists(FastbootGetvarExists {
                    name,
                    exists: Some(ExistsFlag),
                })
            }
            ProbeStepBin::FastbootGetvarNotExists { name } => {
                ProbeStep::FastbootGetvarNotExists(FastbootGetvarNotExists {
                    name,
                    not_exists: Some(NotExistsFlag),
                })
            }
        }
    }
}

impl From<Stage0> for Stage0Bin {
    fn from(stage0: Stage0) -> Self {
        Self {
            kernel_modules: stage0.kernel_modules,
            inject_mac: stage0.inject_mac.map(InjectMacBin::from),
        }
    }
}

impl From<Stage0Bin> for Stage0 {
    fn from(stage0: Stage0Bin) -> Self {
        Self {
            kernel_modules: stage0.kernel_modules,
            inject_mac: stage0.inject_mac.map(InjectMac::from),
        }
    }
}

impl From<InjectMac> for InjectMacBin {
    fn from(mac: InjectMac) -> Self {
        Self {
            wifi: mac.wifi,
            bluetooth: mac.bluetooth,
        }
    }
}

impl From<InjectMacBin> for InjectMac {
    fn from(mac: InjectMacBin) -> Self {
        Self {
            wifi: mac.wifi,
            bluetooth: mac.bluetooth,
        }
    }
}

impl From<BootProfile> for BootProfileBin {
    fn from(profile: BootProfile) -> Self {
        Self {
            id: profile.id,
            display_name: profile.display_name,
            rootfs: BootProfileRootfsBin::from(profile.rootfs),
            dt_overlays: profile.dt_overlays,
            extra_cmdline: profile.extra_cmdline,
            stage0: BootProfileStage0Bin::from(profile.stage0),
        }
    }
}

impl From<BootProfileBin> for BootProfile {
    fn from(profile: BootProfileBin) -> Self {
        Self {
            id: profile.id,
            display_name: profile.display_name,
            rootfs: BootProfileRootfs::from(profile.rootfs),
            dt_overlays: profile.dt_overlays,
            extra_cmdline: profile.extra_cmdline,
            stage0: BootProfileStage0::from(profile.stage0),
        }
    }
}

impl From<BootProfileRootfs> for BootProfileRootfsBin {
    fn from(rootfs: BootProfileRootfs) -> Self {
        match rootfs {
            BootProfileRootfs::Casync(BootProfileRootfsCasyncSource {
                casync: BootProfileRootfsCasync { index, chunk_store },
            }) => Self::Casync { index, chunk_store },
            BootProfileRootfs::Http(BootProfileRootfsHttpSource { http }) => {
                Self::Http { url: http }
            }
        }
    }
}

impl From<BootProfileRootfsBin> for BootProfileRootfs {
    fn from(rootfs: BootProfileRootfsBin) -> Self {
        match rootfs {
            BootProfileRootfsBin::Casync { index, chunk_store } => {
                Self::Casync(BootProfileRootfsCasyncSource {
                    casync: BootProfileRootfsCasync { index, chunk_store },
                })
            }
            BootProfileRootfsBin::Http { url } => {
                Self::Http(BootProfileRootfsHttpSource { http: url })
            }
        }
    }
}

impl From<BootProfileStage0> for BootProfileStage0Bin {
    fn from(stage0: BootProfileStage0) -> Self {
        Self {
            extra_modules: stage0.extra_modules,
            devices: stage0
                .devices
                .into_iter()
                .map(|(device_id, device)| (device_id, BootProfileDeviceBin::from(device)))
                .collect(),
        }
    }
}

impl From<BootProfileStage0Bin> for BootProfileStage0 {
    fn from(stage0: BootProfileStage0Bin) -> Self {
        Self {
            extra_modules: stage0.extra_modules,
            devices: stage0
                .devices
                .into_iter()
                .map(|(device_id, device)| (device_id, BootProfileDevice::from(device)))
                .collect(),
        }
    }
}

impl From<BootProfileDevice> for BootProfileDeviceBin {
    fn from(device: BootProfileDevice) -> Self {
        Self {
            dt_overlays: device.dt_overlays,
            extra_cmdline: device.extra_cmdline,
            stage0: BootProfileDeviceStage0Bin::from(device.stage0),
        }
    }
}

impl From<BootProfileDeviceBin> for BootProfileDevice {
    fn from(device: BootProfileDeviceBin) -> Self {
        Self {
            dt_overlays: device.dt_overlays,
            extra_cmdline: device.extra_cmdline,
            stage0: BootProfileDeviceStage0::from(device.stage0),
        }
    }
}

impl From<BootProfileDeviceStage0> for BootProfileDeviceStage0Bin {
    fn from(stage0: BootProfileDeviceStage0) -> Self {
        Self {
            extra_modules: stage0.extra_modules,
        }
    }
}

impl From<BootProfileDeviceStage0Bin> for BootProfileDeviceStage0 {
    fn from(stage0: BootProfileDeviceStage0Bin) -> Self {
        Self {
            extra_modules: stage0.extra_modules,
        }
    }
}
