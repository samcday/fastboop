use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dioxus::prelude::{Signal, WritableExt};
use fastboop_core::DeviceProfile;
use fastboop_erofs_rootfs::CacheStatsHandle;
use fastboop_fastboot_rusb::RusbDeviceHandle;
use gibblox_core::BlockReader;
use ui::{CacheStatsViewModel, SmooStatsHandle};

#[derive(Clone)]
pub struct ProbedDevice {
    pub handle: RusbDeviceHandle,
    pub profile: DeviceProfile,
    pub name: String,
    pub vid: u16,
    pub pid: u16,
}

#[derive(Clone)]
pub struct BootRuntime {
    pub reader: Arc<dyn BlockReader>,
    pub size_bytes: u64,
    pub identity: String,
    pub cache_stats: Option<CacheStatsHandle>,
    pub smoo_stats: SmooStatsHandle,
}

#[derive(Clone)]
pub enum SessionPhase {
    Booting {
        step: String,
        cache_stats: Option<CacheStatsViewModel>,
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
