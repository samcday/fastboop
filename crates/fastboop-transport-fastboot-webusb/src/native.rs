use std::fmt;

use fastboop_core::fastboot::{FastbootWire, Response};

#[derive(Debug)]
pub struct FastbootWebUsb;

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
