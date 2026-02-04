use fastboop_core::fastboot::{FastbootWire, Response};
use fastboop_core::prober::FastbootCandidate;
use js_sys::Uint8Array;
use tracing::trace;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{UsbDevice, UsbDirection, UsbEndpoint, UsbEndpointType, UsbTransferStatus};

const RESPONSE_BUFFER_LEN: u32 = 4096;

#[derive(Debug)]
pub struct FastbootWebUsb {
    device: UsbDevice,
    interface: u8,
    ep_in: u8,
    ep_out: u8,
}

#[derive(Debug, Clone)]
pub struct FastbootWebUsbCandidate {
    device: UsbDevice,
    interface: u8,
    ep_in: u8,
    ep_out: u8,
    vid: u16,
    pid: u16,
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

impl From<JsValue> for FastbootWebUsbError {
    fn from(value: JsValue) -> Self {
        Self::Js(value)
    }
}

impl FastbootWebUsb {
    pub fn new(device: UsbDevice, interface: u8, ep_in: u8, ep_out: u8) -> Self {
        Self {
            device,
            interface,
            ep_in,
            ep_out,
        }
    }

    pub async fn ensure_open(&self) -> Result<(), FastbootWebUsbError> {
        if self.device.opened() {
            return Ok(());
        }
        JsFuture::from(self.device.open()).await?;
        if self.device.configuration().is_none() {
            JsFuture::from(self.device.select_configuration(1)).await?;
        }
        JsFuture::from(self.device.claim_interface(self.interface)).await?;
        Ok(())
    }

    async fn send_command(&self, cmd: &str) -> Result<Response, FastbootWebUsbError> {
        trace!(command = %cmd, "fastboot send");
        let out = Uint8Array::from(cmd.as_bytes());
        let promise = self
            .device
            .transfer_out_with_u8_array(self.ep_out, &out)
            .map_err(FastbootWebUsbError::Js)?;
        JsFuture::from(promise).await?;
        self.read_response_inner().await
    }

    async fn read_response_inner(&self) -> Result<Response, FastbootWebUsbError> {
        let result =
            JsFuture::from(self.device.transfer_in(self.ep_in, RESPONSE_BUFFER_LEN)).await?;
        let result: web_sys::UsbInTransferResult =
            result.dyn_into().map_err(FastbootWebUsbError::Js)?;
        if result.status() != UsbTransferStatus::Ok {
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
        let end: u32 = start
            .checked_add(len)
            .ok_or(FastbootWebUsbError::InvalidResponse)?;
        let view = Uint8Array::new(&data.buffer()).subarray(start, end);
        let buf = view.to_vec();
        if buf.len() < 4 {
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
}

impl FastbootWebUsbCandidate {
    pub fn new(device: UsbDevice, interface: u8, ep_in: u8, ep_out: u8) -> Self {
        let vid = device.vendor_id();
        let pid = device.product_id();
        Self {
            device,
            interface,
            ep_in,
            ep_out,
            vid,
            pid,
        }
    }

    pub async fn from_device(device: UsbDevice) -> Result<Self, FastbootWebUsbError> {
        ensure_configured(&device).await?;
        let (interface, ep_in, ep_out) = find_fastboot_interface(&device)?;
        Ok(Self::new(device, interface, ep_in, ep_out))
    }

    pub fn device(&self) -> &UsbDevice {
        &self.device
    }
}

impl FastbootCandidate for FastbootWebUsbCandidate {
    type Wire = FastbootWebUsb;
    type Error = FastbootWebUsbError;
    type OpenFuture<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Wire, Self::Error>> + 'a>>;

    fn vid(&self) -> u16 {
        self.vid
    }

    fn pid(&self) -> u16 {
        self.pid
    }

    fn open<'a>(&'a self) -> Self::OpenFuture<'a> {
        let device = self.device.clone();
        let interface = self.interface;
        let ep_in = self.ep_in;
        let ep_out = self.ep_out;
        Box::pin(async move { Ok(FastbootWebUsb::new(device, interface, ep_in, ep_out)) })
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
            self.send_command(cmd).await
        })
    }

    fn send_data<'a>(&'a mut self, data: &'a [u8]) -> Self::SendDataFuture<'a> {
        Box::pin(async move {
            self.ensure_open().await?;
            let out = Uint8Array::from(data);
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

pub async fn fastboot_candidates_from_devices(
    devices: &[UsbDevice],
) -> Vec<FastbootWebUsbCandidate> {
    let mut candidates = Vec::new();
    for device in devices {
        let device = device.clone();
        if let Ok(candidate) = FastbootWebUsbCandidate::from_device(device).await {
            candidates.push(candidate);
        }
    }
    candidates
}

fn truncate_payload(payload: &str) -> String {
    const MAX: usize = 96;
    if payload.len() <= MAX {
        payload.to_string()
    } else {
        format!("{}…", &payload[..MAX])
    }
}

async fn ensure_configured(device: &UsbDevice) -> Result<(), FastbootWebUsbError> {
    if !device.opened() {
        JsFuture::from(device.open()).await?;
    }
    if device.configuration().is_none() {
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
            return Ok((interface.interface_number(), ep_in, ep_out));
        }
    }
    Err(FastbootWebUsbError::NoFastbootInterface)
}
