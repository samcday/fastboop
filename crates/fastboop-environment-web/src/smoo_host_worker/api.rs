use smoo_host_webusb::WebUsbTransportConfig;

#[derive(Clone, Debug)]
pub struct HostWorkerConfig {
    pub transport: WebUsbTransportConfig,
    pub status_retry_attempts: usize,
    pub heartbeat_interval_ms: u32,
    pub size_bytes: u64,
    pub identity: String,
}

impl Default for HostWorkerConfig {
    fn default() -> Self {
        Self {
            transport: WebUsbTransportConfig::default(),
            status_retry_attempts: 5,
            heartbeat_interval_ms: 1000,
            size_bytes: 0,
            identity: "gibblox".to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostWorkerState {
    Idle,
    Running,
}

#[derive(Clone, Debug)]
pub enum HostWorkerEvent {
    Starting,
    TransportConnected,
    Configured,
    Counters {
        ios_up: u64,
        ios_down: u64,
        bytes_up: u64,
        bytes_down: u64,
    },
    SessionChanged {
        previous: u64,
        current: u64,
    },
    TransportLost,
    Error {
        message: String,
    },
    Stopped,
}

impl HostWorkerEvent {
    pub(crate) fn event_name(&self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::TransportConnected => "transport_connected",
            Self::Configured => "configured",
            Self::Counters { .. } => "counters",
            Self::SessionChanged { .. } => "session_changed",
            Self::TransportLost => "transport_lost",
            Self::Error { .. } => "error",
            Self::Stopped => "stopped",
        }
    }
}
