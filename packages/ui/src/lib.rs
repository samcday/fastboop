//! This crate contains all shared UI for the workspace.

mod hero;
pub use hero::Hero;

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
