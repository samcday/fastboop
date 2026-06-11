use std::rc::Rc;

use fastboop_core::{BootProfile, ChannelPipelineHintsRecord, DeviceProfile};
#[cfg(target_arch = "wasm32")]
use fastboop_environment_web::LocalReaderBridge;
use fastboop_environment_web::WebUsbDeviceHandle;
#[cfg(target_arch = "wasm32")]
use ui::SmooStatsHandle;
pub use ui::{next_session_id, update_session_boot_config, update_session_phase, BootConfig};

#[derive(Clone)]
pub struct ProbedDevice {
    pub handle: WebUsbDeviceHandle,
    pub profile: DeviceProfile,
    pub name: String,
    pub vid: u16,
    pub pid: u16,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct SessionChannelIntake {
    pub exact_total_bytes: u64,
    pub consumed_bytes: u64,
    pub warning_count: usize,
    pub has_artifact_payload: bool,
    pub compatible_boot_profiles: Vec<BootProfile>,
    pub pipeline_hint_records: Vec<ChannelPipelineHintsRecord>,
}

#[allow(dead_code)]
pub struct BootRuntime {
    pub size_bytes: u64,
    pub identity: String,
    pub channel: String,
    pub channel_offset_bytes: u64,
    #[cfg(target_arch = "wasm32")]
    pub local_reader_bridge: Option<LocalReaderBridge>,
    #[cfg(target_arch = "wasm32")]
    pub smoo_stats: SmooStatsHandle,
}

pub type SessionPhase = ui::SessionPhase<Rc<BootRuntime>>;
pub type DeviceSession = ui::DeviceSession<ProbedDevice, SessionChannelIntake, Rc<BootRuntime>>;
pub type SessionStore = ui::SessionStore<ProbedDevice, SessionChannelIntake, Rc<BootRuntime>>;
