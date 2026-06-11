use std::sync::Arc;

use fastboop_core::{BootProfile, DeviceProfile};
use fastboop_fastboot_rusb::RusbDeviceHandle;
use gibblox_core::BlockReader;
use ui::SmooStatsHandle;
pub use ui::{next_session_id, update_session_boot_config, update_session_phase, BootConfig};

#[derive(Clone)]
pub struct ProbedDevice {
    pub handle: RusbDeviceHandle,
    pub profile: DeviceProfile,
    pub name: String,
    pub vid: u16,
    pub pid: u16,
    pub serial: Option<String>,
}

#[derive(Clone)]
pub struct SessionChannelIntake {
    pub compatible_boot_profiles: Vec<BootProfile>,
}

#[derive(Clone)]
pub struct BootRuntime {
    pub reader: Arc<dyn BlockReader>,
    pub size_bytes: u64,
    pub identity: String,
    pub smoo_stats: SmooStatsHandle,
}

pub type SessionPhase = ui::SessionPhase<BootRuntime>;
pub type DeviceSession = ui::DeviceSession<ProbedDevice, SessionChannelIntake, BootRuntime>;
pub type SessionStore = ui::SessionStore<ProbedDevice, SessionChannelIntake, BootRuntime>;
