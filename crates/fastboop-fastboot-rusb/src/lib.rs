use std::fmt;
use std::time::Duration;

use fastboop_core::device::{DeviceEvent, DeviceWatcher as DeviceWatcherTrait};
use fastboop_core::fastboot::{FastbootWire, Response};
use fastboop_core::prober::FastbootCandidate;
use rusb::{Context, Device, DeviceHandle, Direction, TransferType, UsbContext as _};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use tracing::{trace, warn};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const HOTPLUG_POLL_INTERVAL: Duration = Duration::from_millis(250);
const RESPONSE_BUFFER_LEN: usize = 4096;

#[derive(Clone, Copy, Debug)]
pub struct FastbootInterface {
    pub interface: u8,
    pub ep_in: u8,
    pub ep_out: u8,
}

pub struct FastbootRusb {
    handle: DeviceHandle<Context>,
    interface: u8,
    ep_in: u8,
    ep_out: u8,
    timeout: Duration,
}

pub struct FastbootRusbCandidate {
    device: rusb::Device<Context>,
    vid: u16,
    pid: u16,
}

pub struct DeviceWatcher {
    _context: Arc<Context>,
    _registration: rusb::Registration<Context>,
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Debug)]
pub enum FastbootRusbError {
    Usb(rusb::Error),
    NoFastbootInterface,
    InvalidResponse,
    Fail(String),
    DownloadTooLarge(usize),
    UnexpectedStatus(String),
    ShortWrite,
    Utf8(std::string::FromUtf8Error),
}

#[derive(Debug)]
pub enum DeviceWatcherError {
    HotplugUnsupported,
    Usb(rusb::Error),
    ThreadSpawn(std::io::Error),
}

impl fmt::Display for FastbootRusbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usb(err) => write!(f, "usb error: {err}"),
            Self::NoFastbootInterface => write!(f, "no fastboot bulk endpoints found"),
            Self::InvalidResponse => write!(f, "invalid fastboot response"),
            Self::Fail(msg) => write!(f, "fastboot failure: {msg}"),
            Self::DownloadTooLarge(size) => write!(f, "download too large: {size} bytes"),
            Self::UnexpectedStatus(status) => write!(f, "unexpected status: {status}"),
            Self::ShortWrite => write!(f, "short write while sending data"),
            Self::Utf8(err) => write!(f, "utf8 error: {err}"),
        }
    }
}

impl std::error::Error for FastbootRusbError {}

impl std::error::Error for DeviceWatcherError {}

impl From<rusb::Error> for FastbootRusbError {
    fn from(value: rusb::Error) -> Self {
        Self::Usb(value)
    }
}

impl From<rusb::Error> for DeviceWatcherError {
    fn from(value: rusb::Error) -> Self {
        Self::Usb(value)
    }
}

impl From<std::string::FromUtf8Error> for FastbootRusbError {
    fn from(value: std::string::FromUtf8Error) -> Self {
        Self::Utf8(value)
    }
}

impl std::fmt::Display for DeviceWatcherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HotplugUnsupported => write!(f, "usb hotplug not supported"),
            Self::Usb(err) => write!(f, "usb error: {err}"),
            Self::ThreadSpawn(err) => write!(f, "failed to spawn hotplug thread: {err}"),
        }
    }
}

struct HotplugCallback {
    handler: Arc<dyn Fn(DeviceEvent) + Send + Sync + 'static>,
}

impl rusb::Hotplug<Context> for HotplugCallback {
    fn device_arrived(&mut self, _device: Device<Context>) {
        (self.handler)(DeviceEvent::Arrived);
    }

    fn device_left(&mut self, _device: Device<Context>) {
        (self.handler)(DeviceEvent::Left);
    }
}

impl DeviceWatcher {
    pub fn new(
        handler: Box<dyn Fn(DeviceEvent) + Send + Sync + 'static>,
    ) -> Result<Self, DeviceWatcherError> {
        <Self as DeviceWatcherTrait>::new(handler)
    }
}

impl DeviceWatcherTrait for DeviceWatcher {
    type Error = DeviceWatcherError;
    type Handler = Box<dyn Fn(DeviceEvent) + Send + Sync + 'static>;

    fn new(handler: Self::Handler) -> Result<Self, Self::Error> {
        if !rusb::has_hotplug() {
            return Err(DeviceWatcherError::HotplugUnsupported);
        }
        let context = Arc::new(Context::new()?);
        let handler = Arc::from(handler);
        let callback = HotplugCallback {
            handler: Arc::clone(&handler),
        };
        let registration = rusb::HotplugBuilder::new()
            .enumerate(true)
            .register(context.as_ref(), Box::new(callback))?;
        let running = Arc::new(AtomicBool::new(true));
        let thread_context = Arc::clone(&context);
        let thread_running = Arc::clone(&running);
        let thread = std::thread::Builder::new()
            .name("fastboop-rusb-hotplug".to_string())
            .spawn(move || {
                while thread_running.load(Ordering::Relaxed) {
                    if let Err(err) = thread_context.handle_events(Some(HOTPLUG_POLL_INTERVAL)) {
                        if !matches!(err, rusb::Error::Interrupted) {
                            warn!(%err, "rusb hotplug event loop error");
                        }
                    }
                }
            })
            .map_err(DeviceWatcherError::ThreadSpawn)?;
        Ok(Self {
            _context: context,
            _registration: registration,
            running,
            thread: Some(thread),
        })
    }
}

impl Drop for DeviceWatcher {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl FastbootRusb {
    pub fn open(device: &Device<Context>) -> Result<Self, FastbootRusbError> {
        let iface = find_fastboot_interface(device)?;
        let handle = device.open()?;
        Self::from_handle(handle, iface, DEFAULT_TIMEOUT)
    }

    pub fn from_handle(
        handle: DeviceHandle<Context>,
        iface: FastbootInterface,
        timeout: Duration,
    ) -> Result<Self, FastbootRusbError> {
        let _ = handle.set_auto_detach_kernel_driver(true);
        if let Ok(true) = handle.kernel_driver_active(iface.interface) {
            let _ = handle.detach_kernel_driver(iface.interface);
        }
        handle.claim_interface(iface.interface)?;
        Ok(Self {
            handle,
            interface: iface.interface,
            ep_in: iface.ep_in,
            ep_out: iface.ep_out,
            timeout,
        })
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub fn interface(&self) -> FastbootInterface {
        FastbootInterface {
            interface: self.interface,
            ep_in: self.ep_in,
            ep_out: self.ep_out,
        }
    }

    fn send_command(&mut self, cmd: &str) -> Result<Response, FastbootRusbError> {
        trace!(command = %cmd, "fastboot send");
        self.handle
            .write_bulk(self.ep_out, cmd.as_bytes(), self.timeout)?;
        self.read_response_inner()
    }

    fn read_response_inner(&mut self) -> Result<Response, FastbootRusbError> {
        let mut buf = vec![0u8; RESPONSE_BUFFER_LEN];
        let n = self.handle.read_bulk(self.ep_in, &mut buf, self.timeout)?;
        if n < 4 {
            return Err(FastbootRusbError::InvalidResponse);
        }
        buf.truncate(n);
        let status = String::from_utf8(buf[0..4].to_vec())?;
        let payload = String::from_utf8(buf[4..].to_vec())?;
        trace!(
            status = %status,
            payload = %truncate_payload(&payload),
            "fastboot recv"
        );
        Ok(Response { status, payload })
    }
}

impl FastbootRusbCandidate {
    pub fn new(device: rusb::Device<Context>, vid: u16, pid: u16) -> Self {
        Self { device, vid, pid }
    }

    pub fn device(&self) -> &rusb::Device<Context> {
        &self.device
    }
}

impl Drop for FastbootRusb {
    fn drop(&mut self) {
        let _ = self.handle.release_interface(self.interface);
    }
}

impl FastbootWire for FastbootRusb {
    type Error = FastbootRusbError;
    type SendCommandFuture<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, Self::Error>> + 'a>>;
    type SendDataFuture<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Self::Error>> + 'a>>;
    type ReadResponseFuture<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, Self::Error>> + 'a>>;

    fn send_command<'a>(&'a mut self, cmd: &'a str) -> Self::SendCommandFuture<'a> {
        Box::pin(async move { self.send_command(cmd) })
    }

    fn send_data<'a>(&'a mut self, data: &'a [u8]) -> Self::SendDataFuture<'a> {
        Box::pin(async move {
            let mut remaining = data;
            while !remaining.is_empty() {
                let written = self
                    .handle
                    .write_bulk(self.ep_out, remaining, self.timeout)?;
                if written == 0 {
                    return Err(FastbootRusbError::ShortWrite);
                }
                remaining = &remaining[written..];
            }
            Ok(())
        })
    }

    fn read_response<'a>(&'a mut self) -> Self::ReadResponseFuture<'a> {
        Box::pin(async move { self.read_response_inner() })
    }
}

impl FastbootCandidate for FastbootRusbCandidate {
    type Wire = FastbootRusb;
    type Error = FastbootRusbError;
    type OpenFuture<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Wire, Self::Error>> + 'a>>;

    fn vid(&self) -> u16 {
        self.vid
    }

    fn pid(&self) -> u16 {
        self.pid
    }

    fn open<'a>(&'a self) -> Self::OpenFuture<'a> {
        Box::pin(async move { FastbootRusb::open(&self.device) })
    }
}

pub fn find_fastboot_interface(
    device: &Device<Context>,
) -> Result<FastbootInterface, FastbootRusbError> {
    let device_desc = device.device_descriptor()?;
    for config_index in 0..device_desc.num_configurations() {
        let config = device.config_descriptor(config_index)?;
        for interface in config.interfaces() {
            for alt in interface.descriptors() {
                let mut ep_in = None;
                let mut ep_out = None;
                for endpoint in alt.endpoint_descriptors() {
                    if endpoint.transfer_type() != TransferType::Bulk {
                        continue;
                    }
                    match endpoint.direction() {
                        Direction::In => ep_in = Some(endpoint.address()),
                        Direction::Out => ep_out = Some(endpoint.address()),
                    }
                }
                if let (Some(ep_in), Some(ep_out)) = (ep_in, ep_out) {
                    trace!(
                        interface = alt.interface_number(),
                        ep_in = ep_in,
                        ep_out = ep_out,
                        "fastboot interface selected"
                    );
                    return Ok(FastbootInterface {
                        interface: alt.interface_number(),
                        ep_in,
                        ep_out,
                    });
                }
            }
        }
    }
    Err(FastbootRusbError::NoFastbootInterface)
}

fn truncate_payload(payload: &str) -> String {
    const MAX: usize = 96;
    if payload.len() <= MAX {
        payload.to_string()
    } else {
        format!("{}…", &payload[..MAX])
    }
}
