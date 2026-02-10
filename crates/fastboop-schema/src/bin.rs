use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::{
    Boot, DeviceProfile, ExistsFlag, FastbootGetvarEq, FastbootGetvarExists, FastbootGetvarNotEq,
    FastbootGetvarNotExists, InjectMac, MatchRule, NotExistsFlag, ProbeStep, Stage0,
};

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
