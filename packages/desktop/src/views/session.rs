use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dioxus::prelude::{Signal, WritableExt};
use fastboop_core::DeviceProfile;
use fastboop_fastboot_rusb::RusbDeviceHandle;
use gibblox_core::BlockReader;
use ui::SmooStatsHandle;

#[derive(Clone)]
pub struct ProbedDevice {
    pub handle: RusbDeviceHandle,
    pub profile: DeviceProfile,
    pub name: String,
    pub vid: u16,
    pub pid: u16,
    pub serial: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootConfig {
    pub rootfs_artifact: String,
    pub extra_kargs: String,
    pub enable_serial: bool,
}

impl BootConfig {
    pub fn new(
        rootfs_artifact: impl Into<String>,
        extra_kargs: impl Into<String>,
        enable_serial: bool,
    ) -> Self {
        Self {
            rootfs_artifact: rootfs_artifact.into(),
            extra_kargs: extra_kargs.into(),
            enable_serial,
        }
    }
}

#[derive(Clone)]
pub struct BootRuntime {
    pub reader: Arc<dyn BlockReader>,
    pub size_bytes: u64,
    pub identity: String,
    pub smoo_stats: SmooStatsHandle,
}

#[derive(Clone)]
pub enum SessionPhase {
    Configuring,
    Booting {
        step: String,
    },
    Active {
        runtime: BootRuntime,
        host_started: bool,
    },
    Error {
        summary: String,
    },
}

#[derive(Clone)]
pub struct DeviceSession {
    pub id: String,
    pub device: ProbedDevice,
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
