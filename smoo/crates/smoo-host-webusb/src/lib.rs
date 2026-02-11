//! WebUSB-backed smoo host transport.
//!
//! This crate provides a [`Transport`](smoo_host_core::transport::Transport) implementation
//! suitable for use from WebAssembly targets where WebUSB is available.

#[cfg(not(target_arch = "wasm32"))]
compile_error!("smoo-host-webusb is only available on wasm32 targets");

/// Transport configuration for WebUSB.
#[derive(Clone, Copy, Debug, Default)]
pub struct WebUsbTransportConfig {
    /// Interface number to claim before issuing transfers.
    pub interface: u8,
    /// Interrupt endpoint number used to receive Request messages (device → host).
    pub interrupt_in: Option<u8>,
    /// Interrupt endpoint number used to send Response messages (host → device).
    pub interrupt_out: Option<u8>,
    /// Bulk endpoint number used to read payloads (device → host).
    pub bulk_in: Option<u8>,
    /// Bulk endpoint number used to write payloads (host → device).
    pub bulk_out: Option<u8>,
}

mod webusb;

pub use webusb::{WebUsbControl, WebUsbTransport};
