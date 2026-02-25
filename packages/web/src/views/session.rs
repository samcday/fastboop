#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_arch = "wasm32")]
use std::sync::Arc;

#[cfg(target_arch = "wasm32")]
use anyhow::Context;
use dioxus::prelude::{Signal, WritableExt};
use fastboop_core::DeviceProfile;
use fastboop_fastboot_webusb::WebUsbDeviceHandle;
#[cfg(target_arch = "wasm32")]
use gibblox_blockreader_messageport::{MessagePortBlockReaderClient, MessagePortBlockReaderServer};
#[cfg(target_arch = "wasm32")]
use gibblox_core::BlockReader;
#[cfg(target_arch = "wasm32")]
use gibblox_web_worker::GibbloxWebWorker;
#[cfg(target_arch = "wasm32")]
use ui::SmooStatsHandle;
#[cfg(target_arch = "wasm32")]
use web_sys::MessageChannel;

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
    pub extra_kargs: String,
    pub enable_serial: bool,
}

impl BootConfig {
    pub fn new(
        channel: impl Into<String>,
        extra_kargs: impl Into<String>,
        enable_serial: bool,
    ) -> Self {
        Self {
            channel: channel.into(),
            extra_kargs: extra_kargs.into(),
            enable_serial,
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
pub struct LocalReaderBridge {
    reader: Arc<dyn BlockReader>,
    servers: Rc<RefCell<Vec<MessagePortBlockReaderServer>>>,
}

#[cfg(target_arch = "wasm32")]
impl LocalReaderBridge {
    pub fn new(reader: Arc<dyn BlockReader>) -> Self {
        Self {
            reader,
            servers: Rc::new(RefCell::new(Vec::new())),
        }
    }

    pub async fn create_reader(&self) -> anyhow::Result<MessagePortBlockReaderClient> {
        let channel = MessageChannel::new().map_err(|err| {
            anyhow::anyhow!(
                "create local channel reader bridge message channel: {}",
                js_value_to_string(err)
            )
        })?;
        let server = MessagePortBlockReaderServer::serve(channel.port2(), self.reader.clone())
            .map_err(|err| anyhow::anyhow!("serve local channel reader bridge: {err}"))?;
        let client = MessagePortBlockReaderClient::connect(channel.port1())
            .await
            .map_err(|err| anyhow::anyhow!("connect local channel reader bridge: {err}"))
            .with_context(|| "attach local channel reader bridge")?;
        self.servers.borrow_mut().push(server);
        Ok(client)
    }
}

#[cfg(target_arch = "wasm32")]
fn js_value_to_string(value: wasm_bindgen::JsValue) -> String {
    js_sys::JSON::stringify(&value)
        .ok()
        .and_then(|s| s.as_string())
        .unwrap_or_else(|| format!("{value:?}"))
}

#[allow(dead_code)]
pub struct BootRuntime {
    pub size_bytes: u64,
    pub identity: String,
    pub channel: String,
    pub channel_offset_bytes: u64,
    #[cfg(target_arch = "wasm32")]
    pub gibblox_worker: Option<GibbloxWebWorker>,
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
