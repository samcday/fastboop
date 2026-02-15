//! This crate contains all shared UI for the workspace.

mod hero;
pub use hero::Hero;
mod dtbo;
pub use dtbo::oneplus_fajita_dtbo_overlays;
mod cache_stats;
pub use cache_stats::{CacheStatsPanel, CacheStatsViewModel};
mod smoo_stats;
pub use smoo_stats::{SmooStatsHandle, SmooStatsPanel, SmooStatsSnapshot, SmooStatsViewModel};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    WebUsb,
    NativeUsb,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectedProfileOption {
    pub profile_id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectedDevice {
    pub vid: u16,
    pub pid: u16,
    pub name: String,
    pub profile_options: Vec<DetectedProfileOption>,
    pub selected_profile: Option<usize>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProbeState {
    Loading,
    Unsupported,
    Ready {
        transport: TransportKind,
        devices: Vec<DetectedDevice>,
    },
}
