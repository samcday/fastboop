use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use dioxus::prelude::{Signal, WritableExt};
use fastboop_core::{BootProfile, ChannelPipelineHintsRecord, DeviceProfile};
#[cfg(target_arch = "wasm32")]
use fastboop_environment_web::LocalReaderBridge;
use fastboop_environment_web::WebUsbDeviceHandle;
#[cfg(target_arch = "wasm32")]
use ui::SmooStatsHandle;

#[derive(Clone)]
pub struct ProbedDevice {
    pub handle: WebUsbDeviceHandle,
    pub profile: DeviceProfile,
    pub name: String,
    pub vid: u16,
    pub pid: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootConfig {
    pub channel: String,
    pub selected_boot_profile_id: Option<String>,
    pub extra_kargs: String,
    pub enable_serial: bool,
}

impl BootConfig {
    pub fn new(
        channel: impl Into<String>,
        selected_boot_profile_id: Option<String>,
        extra_kargs: impl Into<String>,
        enable_serial: bool,
    ) -> Self {
        Self {
            channel: channel.into(),
            selected_boot_profile_id,
            extra_kargs: extra_kargs.into(),
            enable_serial,
        }
    }
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

#[derive(Clone)]
pub enum SessionPhase {
    Configuring,
    Booting {
        step: String,
    },
    Active {
        runtime: Rc<BootRuntime>,
        host_started: bool,
        host_connected: bool,
    },
    Error {
        summary: String,
    },
}

#[derive(Clone)]
pub struct DeviceSession {
    pub id: String,
    pub device: ProbedDevice,
    pub channel_intake: SessionChannelIntake,
    pub boot_config: BootConfig,
    pub phase: SessionPhase,
}

pub type SessionStore = Signal<Vec<DeviceSession>>;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn next_session_id() -> String {
    let n = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("device-{n}")
}

pub fn update_session_phase(store: &mut SessionStore, session_id: &str, phase: SessionPhase) {
    if let Some(session) = store.write().iter_mut().find(|s| s.id == session_id) {
        session.phase = phase;
    }
}

pub fn update_session_boot_config(
    store: &mut SessionStore,
    session_id: &str,
    update: impl FnOnce(&mut BootConfig),
) {
    if let Some(session) = store.write().iter_mut().find(|s| s.id == session_id) {
        update(&mut session.boot_config);
    }
}

#[cfg(target_arch = "wasm32")]
pub fn update_session_active_host_state(
    store: &mut SessionStore,
    session_id: &str,
    host_started: Option<bool>,
    host_connected: Option<bool>,
) {
    if let Some(session) = store.write().iter_mut().find(|s| s.id == session_id) {
        if let SessionPhase::Active {
            host_started: started,
            host_connected: connected,
            ..
        } = &mut session.phase
        {
            if let Some(v) = host_started {
                *started = v;
            }
            if let Some(v) = host_connected {
                *connected = v;
            }
        }
    }
}
