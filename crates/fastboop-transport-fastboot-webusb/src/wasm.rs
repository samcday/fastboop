use fastboop_core::fastboot::{FastbootWire, Response};
use js_sys::Uint8Array;
use tracing::trace;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{UsbDevice, UsbTransferStatus};

const RESPONSE_BUFFER_LEN: u32 = 4096;

#[derive(Debug)]
pub struct FastbootWebUsb {
    device: UsbDevice,
    interface: u8,
    ep_in: u8,
    ep_out: u8,
}

#[derive(Debug)]
pub enum FastbootWebUsbError {
    Js(JsValue),
    InvalidResponse,
    Fail(String),
    UnexpectedStatus(String),
    DownloadTooLarge(usize),
}

impl std::fmt::Display for FastbootWebUsbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Js(err) => write!(f, "js error: {:?}", err),
            Self::InvalidResponse => write!(f, "invalid fastboot response"),
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
        JsFuture::from(self.device.transfer_out_with_u8_array(self.ep_out, &out)).await?;
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
        let view = Uint8Array::new(&data.buffer())
            .subarray(data.byte_offset(), data.byte_offset() + data.byte_length());
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
            JsFuture::from(self.device.transfer_out_with_u8_array(self.ep_out, &out)).await?;
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

#[derive(Debug)]
fn truncate_payload(payload: &str) -> String {
    const MAX: usize = 96;
    if payload.len() <= MAX {
        payload.to_string()
    } else {
        format!("{}…", &payload[..MAX])
    }
}
