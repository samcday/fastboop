use std::sync::atomic::{AtomicU64, Ordering};

use dioxus::prelude::{Signal, WritableExt};

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
pub enum SessionPhase<Runtime> {
    Configuring,
    Booting {
        step: String,
    },
    Active {
        runtime: Runtime,
        host_started: bool,
        host_connected: bool,
    },
    Error {
        summary: String,
    },
}

#[derive(Clone)]
pub struct DeviceSession<Device, ChannelIntake, Runtime> {
    pub id: String,
    pub device: Device,
    pub channel_intake: ChannelIntake,
    pub boot_config: BootConfig,
    pub phase: SessionPhase<Runtime>,
}

pub type SessionStore<Device, ChannelIntake, Runtime> =
    Signal<Vec<DeviceSession<Device, ChannelIntake, Runtime>>>;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn next_session_id() -> String {
    let n = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("device-{n}")
}

pub fn update_session_phase<Device, ChannelIntake, Runtime>(
    store: &mut SessionStore<Device, ChannelIntake, Runtime>,
    session_id: &str,
    phase: SessionPhase<Runtime>,
) where
    Device: 'static,
    ChannelIntake: 'static,
    Runtime: 'static,
{
    if let Some(session) = store.write().iter_mut().find(|s| s.id == session_id) {
        session.phase = phase;
    }
}

pub fn update_session_boot_config<Device, ChannelIntake, Runtime>(
    store: &mut SessionStore<Device, ChannelIntake, Runtime>,
    session_id: &str,
    update: impl FnOnce(&mut BootConfig),
) where
    Device: 'static,
    ChannelIntake: 'static,
    Runtime: 'static,
{
    if let Some(session) = store.write().iter_mut().find(|s| s.id == session_id) {
        update(&mut session.boot_config);
    }
}

pub fn update_session_active_host_state<Device, ChannelIntake, Runtime>(
    store: &mut SessionStore<Device, ChannelIntake, Runtime>,
    session_id: &str,
    host_started: Option<bool>,
    host_connected: Option<bool>,
) where
    Device: 'static,
    ChannelIntake: 'static,
    Runtime: 'static,
{
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
