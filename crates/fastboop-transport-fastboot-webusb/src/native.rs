use std::fmt;

use fastboop_core::fastboot::{FastbootWire, Response};
use fastboop_core::prober::FastbootCandidate;

#[derive(Debug)]
pub struct FastbootWebUsb;

#[derive(Debug, Clone, Copy)]
pub struct FastbootWebUsbCandidate;

#[derive(Debug, Clone, Copy)]
pub struct FastbootWebUsbError;

impl fmt::Display for FastbootWebUsbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "webusb is only available on wasm32")
    }
}

impl std::error::Error for FastbootWebUsbError {}

impl FastbootWebUsb {
    pub fn new() -> Self {
        Self
    }
}

impl FastbootWebUsbCandidate {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FastbootWebUsbCandidate {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for FastbootWebUsb {
    fn default() -> Self {
        Self::new()
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

    fn send_command<'a>(&'a mut self, _cmd: &'a str) -> Self::SendCommandFuture<'a> {
        Box::pin(async { Err(FastbootWebUsbError) })
    }

    fn send_data<'a>(&'a mut self, _data: &'a [u8]) -> Self::SendDataFuture<'a> {
        Box::pin(async { Err(FastbootWebUsbError) })
    }

    fn read_response<'a>(&'a mut self) -> Self::ReadResponseFuture<'a> {
        Box::pin(async { Err(FastbootWebUsbError) })
    }
}

impl FastbootCandidate for FastbootWebUsbCandidate {
    type Wire = FastbootWebUsb;
    type Error = FastbootWebUsbError;
    type OpenFuture<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Wire, Self::Error>> + 'a>>;

    fn vid(&self) -> u16 {
        0
    }

    fn pid(&self) -> u16 {
        0
    }

    fn open<'a>(&'a self) -> Self::OpenFuture<'a> {
        Box::pin(async { Err(FastbootWebUsbError) })
    }
}
