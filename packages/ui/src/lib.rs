//! This crate contains all shared UI for the workspace.

mod hero;
pub use hero::Hero;
mod dtbo;
pub use dtbo::oneplus_fajita_dtbo_overlays;
mod cache_stats;
pub use cache_stats::{CacheStatsPanel, CacheStatsViewModel};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    WebUsb,
    NativeUsb,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectedDevice {
    pub vid: u16,
    pub pid: u16,
    pub name: String,
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
