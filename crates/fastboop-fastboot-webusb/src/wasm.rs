use fastboop_core::device::{
    DeviceEvent, DeviceFilter, DeviceHandle as DeviceHandleTrait,
    DeviceWatcher as DeviceWatcherTrait,
};
use fastboop_core::fastboot::{FastbootWire, Response};
use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures_core::Stream;
use js_sys::{Array, Reflect, Uint8Array};
use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tracing::{debug, trace};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{
    Usb, UsbDevice, UsbDeviceFilter, UsbDeviceRequestOptions, UsbDirection, UsbEndpoint,
    UsbEndpointType, UsbTransferStatus,
};

const RESPONSE_BUFFER_LEN: u32 = 4096;

#[derive(Clone)]
struct SendSyncUsbDevice(UsbDevice);

unsafe impl Send for SendSyncUsbDevice {}
unsafe impl Sync for SendSyncUsbDevice {}

impl SendSyncUsbDevice {
    fn clone_inner(&self) -> UsbDevice {
        self.0.clone()
    }
}

impl std::fmt::Debug for SendSyncUsbDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SendSyncUsbDevice")
    }
}

#[derive(Debug)]
pub struct FastbootWebUsb {
    device: UsbDevice,
    interface: u8,
    ep_in: u8,
    ep_out: u8,
    claimed: Cell<bool>,
}

#[derive(Debug, Clone)]
pub struct WebUsbDeviceHandle {
    device: SendSyncUsbDevice,
    vid: u16,
    pid: u16,
}

pub type FastbootWebUsbCandidate = WebUsbDeviceHandle;

pub struct DeviceWatcher {
    usb: Usb,
    receiver: UnboundedReceiver<DeviceEvent<WebUsbDeviceHandle>>,
    on_connect: wasm_bindgen::closure::Closure<dyn FnMut(JsValue)>,
    on_disconnect: wasm_bindgen::closure::Closure<dyn FnMut(JsValue)>,
}

#[derive(Debug)]
pub enum FastbootWebUsbError {
    Js(JsValue),
    InvalidResponse,
    NoFastbootInterface,
    Fail(String),
    UnexpectedStatus(String),
    DownloadTooLarge(usize),
}

#[derive(Debug)]
pub enum DeviceWatcherError {
    Unsupported,
    Js(JsValue),
    ChannelClosed,
}

impl std::fmt::Display for FastbootWebUsbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Js(err) => write!(f, "js error: {:?}", err),
            Self::InvalidResponse => write!(f, "invalid fastboot response"),
            Self::NoFastbootInterface => write!(f, "no fastboot bulk endpoints found"),
            Self::Fail(msg) => write!(f, "fastboot failure: {msg}"),
            Self::UnexpectedStatus(status) => write!(f, "unexpected status: {status}"),
            Self::DownloadTooLarge(size) => write!(f, "download too large: {size} bytes"),
        }
    }
}

impl std::error::Error for FastbootWebUsbError {}

impl std::error::Error for DeviceWatcherError {}

impl From<JsValue> for FastbootWebUsbError {
    fn from(value: JsValue) -> Self {
        Self::Js(value)
    }
}

impl From<JsValue> for DeviceWatcherError {
    fn from(value: JsValue) -> Self {
        Self::Js(value)
    }
}

impl std::fmt::Display for DeviceWatcherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => write!(f, "webusb is not available"),
            Self::Js(err) => write!(f, "js error: {:?}", err),
            Self::ChannelClosed => write!(f, "device watcher event stream closed"),
        }
    }
}

impl FastbootWebUsb {
    pub fn new(device: UsbDevice, interface: u8, ep_in: u8, ep_out: u8) -> Self {
        Self {
            device,
            interface,
            ep_in,
            ep_out,
            claimed: Cell::new(false),
        }
    }

    pub async fn ensure_open(&self) -> Result<(), FastbootWebUsbError> {
        if self.device.opened() {
            trace!(interface = self.interface, "fastboot webusb already open");
        } else {
            debug!(interface = self.interface, "fastboot webusb opening");
            JsFuture::from(self.device.open()).await?;
        }
        if self.device.configuration().is_none() {
            debug!("fastboot webusb select configuration");
            JsFuture::from(self.device.select_configuration(1)).await?;
        }
        if !self.claimed.get() {
            debug!(
                interface = self.interface,
                "fastboot webusb claim interface"
            );
            JsFuture::from(self.device.claim_interface(self.interface)).await?;
            self.claimed.set(true);
        }
        Ok(())
    }

    async fn send_command_inner(&self, cmd: &str) -> Result<Response, FastbootWebUsbError> {
        trace!(command = %cmd, "fastboot send");
        let out = Uint8Array::from(cmd.as_bytes());
        trace!(
            len = out.length(),
            ep_out = self.ep_out,
            "fastboot transfer_out command"
        );
        let promise = self
            .device
            .transfer_out_with_u8_array(self.ep_out, &out)
            .map_err(FastbootWebUsbError::Js)?;
        JsFuture::from(promise).await?;
        self.read_response_inner().await
    }

    async fn read_response_inner(&self) -> Result<Response, FastbootWebUsbError> {
        trace!(
            ep_in = self.ep_in,
            len = RESPONSE_BUFFER_LEN,
            "fastboot transfer_in response"
        );
        let result =
            JsFuture::from(self.device.transfer_in(self.ep_in, RESPONSE_BUFFER_LEN)).await?;
        let result: web_sys::UsbInTransferResult =
            result.dyn_into().map_err(FastbootWebUsbError::Js)?;
        if result.status() != UsbTransferStatus::Ok {
            debug!(status = ?result.status(), "fastboot transfer_in status");
            return Err(FastbootWebUsbError::InvalidResponse);
        }
        let data = result.data().ok_or(FastbootWebUsbError::InvalidResponse)?;
        let start: u32 = data
            .byte_offset()
            .try_into()
            .map_err(|_| FastbootWebUsbError::InvalidResponse)?;
        let len: u32 = data
            .byte_length()
            .try_into()
            .map_err(|_| FastbootWebUsbError::InvalidResponse)?;
        trace!(start, len, "fastboot response buffer view");
        let end: u32 = start
            .checked_add(len)
            .ok_or(FastbootWebUsbError::InvalidResponse)?;
        let view = Uint8Array::new(&data.buffer()).subarray(start, end);
        let buf = view.to_vec();
        if buf.len() < 4 {
            debug!(len = buf.len(), "fastboot response too short");
            return Err(FastbootWebUsbError::InvalidResponse);
        }
        let status = String::from_utf8_lossy(&buf[..4]).to_string();
        let payload = String::from_utf8_lossy(&buf[4..]).to_string();
        trace!(
            status = %status,
            payload = %truncate_payload(&payload),
            "fastboot recv"
        );
        Ok(Response { status, payload })
    }

    pub async fn shutdown(&mut self) -> Result<(), FastbootWebUsbError> {
        if self.claimed.get() {
            if let Err(err) = JsFuture::from(self.device.release_interface(self.interface)).await {
                debug!(?err, "fastboot release_interface failed during shutdown");
            }
            self.claimed.set(false);
        }

        if self.device.opened() {
            if let Err(err) = JsFuture::from(self.device.close()).await {
                debug!(?err, "fastboot close failed during shutdown");
            }
        }

        Ok(())
    }
}

impl WebUsbDeviceHandle {
    pub fn new(device: UsbDevice) -> Self {
        Self {
            vid: device.vendor_id(),
            pid: device.product_id(),
            device: SendSyncUsbDevice(device),
        }
    }

    pub fn device(&self) -> UsbDevice {
        self.device.clone_inner()
    }
}

impl DeviceHandleTrait for WebUsbDeviceHandle {
    type FastbootWire = FastbootWebUsb;
    type OpenFastbootError = FastbootWebUsbError;
    type OpenFastbootFuture<'a> =
        Pin<Box<dyn Future<Output = Result<Self::FastbootWire, Self::OpenFastbootError>> + 'a>>;

    fn vid(&self) -> u16 {
        self.vid
    }

    fn pid(&self) -> u16 {
        self.pid
    }

    fn open_fastboot<'a>(&'a self) -> Self::OpenFastbootFuture<'a> {
        let device = self.device.clone_inner();
        Box::pin(async move {
            ensure_configured(&device).await?;
            let (interface, ep_in, ep_out) = find_fastboot_interface(&device)?;
            Ok(FastbootWebUsb::new(device, interface, ep_in, ep_out))
        })
    }
}

impl FastbootWire for FastbootWebUsb {
    type Error = FastbootWebUsbError;
    type SendCommandFuture<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, Self::Error>> + 'a>>;
    type SendDataFuture<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Self::Error>> + 'a>>;
    type ReadResponseFuture<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, Self::Error>> + 'a>>;

    fn send_command<'a>(&'a mut self, cmd: &'a str) -> Self::SendCommandFuture<'a> {
        Box::pin(async move {
            self.ensure_open().await?;
            self.send_command_inner(cmd).await
        })
    }

    fn send_data<'a>(&'a mut self, data: &'a [u8]) -> Self::SendDataFuture<'a> {
        Box::pin(async move {
            self.ensure_open().await?;
            let out = Uint8Array::from(data);
            trace!(
                len = out.length(),
                ep_out = self.ep_out,
                "fastboot transfer_out data"
            );
            let promise = self
                .device
                .transfer_out_with_u8_array(self.ep_out, &out)
                .map_err(FastbootWebUsbError::Js)?;
            JsFuture::from(promise).await?;
            Ok(())
        })
    }

    fn read_response<'a>(&'a mut self) -> Self::ReadResponseFuture<'a> {
        Box::pin(async move {
            self.ensure_open().await?;
            self.read_response_inner().await
        })
    }
}

impl Drop for FastbootWebUsb {
    fn drop(&mut self) {
        self.claimed.set(false);
    }
}

impl DeviceWatcher {
    pub fn new(filters: &[DeviceFilter]) -> Result<Self, DeviceWatcherError> {
        let usb = webusb_handle()?;
        let filters = std::rc::Rc::new(filters.to_vec());
        let (sender, receiver) = unbounded();

        enqueue_authorized_devices(usb.clone(), std::rc::Rc::clone(&filters), sender.clone());

        let on_connect = {
            let filters = std::rc::Rc::clone(&filters);
            let sender = sender.clone();
            wasm_bindgen::closure::Closure::wrap(Box::new(move |evt: JsValue| {
                trace!(target: "fastboop::webusb::watcher", "webusb connect event");
                if let Some(device) = event_device(&evt) {
                    enqueue_arrived_if_matching(&filters, &sender, device);
                }
            }) as Box<dyn FnMut(JsValue)>)
        };

        let on_disconnect = {
            let filters = std::rc::Rc::clone(&filters);
            let sender = sender.clone();
            wasm_bindgen::closure::Closure::wrap(Box::new(move |evt: JsValue| {
                trace!(target: "fastboop::webusb::watcher", "webusb disconnect event");
                if let Some(device) = event_device(&evt) {
                    enqueue_left_if_matching(&filters, &sender, device);
                }
            }) as Box<dyn FnMut(JsValue)>)
        };

        usb.add_event_listener_with_callback("connect", on_connect.as_ref().unchecked_ref())?;
        usb.add_event_listener_with_callback("disconnect", on_disconnect.as_ref().unchecked_ref())?;

        Ok(Self {
            usb,
            receiver,
            on_connect,
            on_disconnect,
        })
    }
}

impl DeviceWatcherTrait for DeviceWatcher {
    type Device = WebUsbDeviceHandle;
    type Error = DeviceWatcherError;

    fn poll_next_event(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<DeviceEvent<Self::Device>, Self::Error>> {
        match Pin::new(&mut self.receiver).poll_next(cx) {
            Poll::Ready(Some(event)) => Poll::Ready(Ok(event)),
            Poll::Ready(None) => Poll::Ready(Err(DeviceWatcherError::ChannelClosed)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for DeviceWatcher {
    fn drop(&mut self) {
        let _ = self.usb.remove_event_listener_with_callback(
            "connect",
            self.on_connect.as_ref().unchecked_ref(),
        );
        let _ = self.usb.remove_event_listener_with_callback(
            "disconnect",
            self.on_disconnect.as_ref().unchecked_ref(),
        );
    }
}

pub async fn request_device(
    filters: &[DeviceFilter],
) -> Result<WebUsbDeviceHandle, DeviceWatcherError> {
    let usb = webusb_handle()?;
    let options = UsbDeviceRequestOptions::new(&JsValue::from(build_filters(filters)));
    let device = JsFuture::from(usb.request_device(&options)).await?;
    let device = device
        .dyn_into::<UsbDevice>()
        .map_err(DeviceWatcherError::Js)?;
    Ok(WebUsbDeviceHandle::new(device))
}

fn enqueue_authorized_devices(
    usb: Usb,
    filters: std::rc::Rc<Vec<DeviceFilter>>,
    sender: UnboundedSender<DeviceEvent<WebUsbDeviceHandle>>,
) {
    spawn_local(async move {
        let devices = match JsFuture::from(usb.get_devices()).await {
            Ok(devices) => devices,
            Err(err) => {
                debug!(target: "fastboop::webusb::watcher", ?err, "webusb getDevices failed");
                return;
            }
        };
        let devices: Array = match devices.dyn_into() {
            Ok(devices) => devices,
            Err(err) => {
                debug!(target: "fastboop::webusb::watcher", ?err, "webusb getDevices cast failed");
                return;
            }
        };
        for value in devices.iter() {
            if let Ok(device) = value.dyn_into::<UsbDevice>() {
                enqueue_arrived_if_matching(&filters, &sender, device);
            }
        }
    });
}

fn event_device(evt: &JsValue) -> Option<UsbDevice> {
    let value = Reflect::get(evt, &JsValue::from_str("device")).ok()?;
    value.dyn_into::<UsbDevice>().ok()
}

fn enqueue_arrived_if_matching(
    filters: &[DeviceFilter],
    sender: &UnboundedSender<DeviceEvent<WebUsbDeviceHandle>>,
    device: UsbDevice,
) {
    let vid = device.vendor_id();
    let pid = device.product_id();
    if !matches_filters(filters, vid, pid) {
        return;
    }
    let _ = sender.unbounded_send(DeviceEvent::Arrived {
        device: WebUsbDeviceHandle::new(device),
    });
}

fn enqueue_left_if_matching(
    filters: &[DeviceFilter],
    sender: &UnboundedSender<DeviceEvent<WebUsbDeviceHandle>>,
    device: UsbDevice,
) {
    let vid = device.vendor_id();
    let pid = device.product_id();
    if !matches_filters(filters, vid, pid) {
        return;
    }
    let _ = sender.unbounded_send(DeviceEvent::Left {
        device: WebUsbDeviceHandle::new(device),
    });
}

fn matches_filters(filters: &[DeviceFilter], vid: u16, pid: u16) -> bool {
    if filters.is_empty() {
        return true;
    }
    filters
        .iter()
        .any(|filter| filter.vid == vid && filter.pid == pid)
}

fn build_filters(filters: &[DeviceFilter]) -> Array {
    let array = Array::new();
    let mut deduped = Vec::new();
    for filter in filters {
        if deduped.contains(filter) {
            continue;
        }
        deduped.push(*filter);
        let usb_filter = UsbDeviceFilter::new();
        usb_filter.set_vendor_id(filter.vid);
        usb_filter.set_product_id(filter.pid);
        array.push(&usb_filter);
    }
    array
}

fn truncate_payload(payload: &str) -> String {
    const MAX: usize = 96;
    if payload.len() <= MAX {
        payload.to_string()
    } else {
        format!("{}…", &payload[..MAX])
    }
}

fn webusb_handle() -> Result<Usb, DeviceWatcherError> {
    let window = web_sys::window().ok_or(DeviceWatcherError::Unsupported)?;
    let navigator = window.navigator();
    let has_usb = Reflect::has(&navigator, &JsValue::from_str("usb"))?;
    if !has_usb {
        return Err(DeviceWatcherError::Unsupported);
    }
    let usb = Reflect::get(&navigator, &JsValue::from_str("usb"))?;
    usb.dyn_into::<Usb>().map_err(DeviceWatcherError::Js)
}

async fn ensure_configured(device: &UsbDevice) -> Result<(), FastbootWebUsbError> {
    if !device.opened() {
        debug!("fastboot webusb open device for discovery");
        JsFuture::from(device.open()).await?;
    }
    if device.configuration().is_none() {
        debug!("fastboot webusb select configuration for discovery");
        JsFuture::from(device.select_configuration(1)).await?;
    }
    Ok(())
}

fn find_fastboot_interface(device: &UsbDevice) -> Result<(u8, u8, u8), FastbootWebUsbError> {
    let configuration = device
        .configuration()
        .ok_or(FastbootWebUsbError::InvalidResponse)?;
    for interface in configuration.interfaces().iter() {
        let interface: web_sys::UsbInterface =
            interface.dyn_into().map_err(FastbootWebUsbError::Js)?;
        let alt = interface.alternate();
        let mut ep_in = None;
        let mut ep_out = None;
        for endpoint in alt.endpoints().iter() {
            let endpoint: UsbEndpoint = endpoint.dyn_into().map_err(FastbootWebUsbError::Js)?;
            trace!(
                interface = interface.interface_number(),
                ep = endpoint.endpoint_number(),
                direction = ?endpoint.direction(),
                kind = ?endpoint.type_(),
                "fastboot endpoint"
            );
            if endpoint.type_() != UsbEndpointType::Bulk {
                continue;
            }
            match endpoint.direction() {
                UsbDirection::In => ep_in = Some(endpoint.endpoint_number()),
                UsbDirection::Out => ep_out = Some(endpoint.endpoint_number()),
                _ => {}
            }
        }
        if let (Some(ep_in), Some(ep_out)) = (ep_in, ep_out) {
            debug!(
                interface = interface.interface_number(),
                ep_in, ep_out, "fastboot interface selected"
            );
            return Ok((interface.interface_number(), ep_in, ep_out));
        }
    }
    Err(FastbootWebUsbError::NoFastbootInterface)
}
