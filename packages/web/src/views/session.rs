use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dioxus::prelude::{Signal, WritableExt};
use fastboop_core::DeviceProfile;
use fastboop_fastboot_webusb::WebUsbDeviceHandle;
use gibblox_core::BlockReader;

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
pub struct BootRuntime {
    pub reader: Arc<dyn BlockReader>,
    pub size_bytes: u64,
    pub identity: String,
}

#[derive(Clone)]
pub enum SessionPhase {
    Booting {
        step: String,
    },
    Active {
        runtime: BootRuntime,
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
