use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;

use fastboop_serial::{NativeSerialEvent, NativeSerialSelector, spawn_native_serial_reader};

use crate::boot_ui::BootEvent;

pub(crate) fn start_cdc_acm_monitor(
    vid: u16,
    pid: u16,
    serial: Option<String>,
    events: Sender<BootEvent>,
) -> Arc<AtomicBool> {
    let selector = NativeSerialSelector::new(vid, pid, serial);
    spawn_native_serial_reader(selector, move |event| {
        let mapped = match event {
            NativeSerialEvent::Status(message) => BootEvent::Log(format!("serial: {message}")),
            NativeSerialEvent::Connected { port } => {
                BootEvent::Log(format!("serial: connected on {port}"))
            }
            NativeSerialEvent::Disconnected { port } => {
                BootEvent::Log(format!("serial: disconnected from {port}"))
            }
            NativeSerialEvent::Error(message) => BootEvent::Log(format!("serial: {message}")),
            NativeSerialEvent::Bytes(bytes) => BootEvent::SerialBytes(bytes),
        };
        let _ = events.send(mapped);
    })
}
