use std::fmt;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use fastboop_core::device::{
    DeviceEvent, DeviceFilter, DeviceHandle as DeviceHandleTrait,
    DeviceWatcher as DeviceWatcherTrait,
};
use fastboop_core::fastboot::{FastbootWire, Response};

#[derive(Debug)]
pub struct FastbootWebUsb;

#[derive(Debug, Clone, Copy)]
pub struct WebUsbDeviceHandle;

pub type FastbootWebUsbCandidate = WebUsbDeviceHandle;

#[derive(Debug, Clone, Copy)]
pub struct DeviceWatcher;

#[derive(Debug, Clone, Copy)]
pub struct FastbootWebUsbError;

#[derive(Debug, Clone, Copy)]
pub struct DeviceWatcherError;

impl fmt::Display for FastbootWebUsbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "webusb is only available on wasm32")
    }
}

impl std::error::Error for FastbootWebUsbError {}

impl fmt::Display for DeviceWatcherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "webusb is only available on wasm32")
    }
}

impl std::error::Error for DeviceWatcherError {}

impl FastbootWebUsb {
    pub fn new() -> Self {
        Self
    }

    pub async fn shutdown(&mut self) -> Result<(), FastbootWebUsbError> {
        Ok(())
    }
}

impl Default for FastbootWebUsb {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceHandleTrait for WebUsbDeviceHandle {
    type FastbootWire = FastbootWebUsb;
    type OpenFastbootError = FastbootWebUsbError;
    type OpenFastbootFuture<'a> =
        core::future::Ready<Result<Self::FastbootWire, Self::OpenFastbootError>>;

    fn vid(&self) -> u16 {
        0
    }

    fn pid(&self) -> u16 {
        0
    }

    fn open_fastboot<'a>(&'a self) -> Self::OpenFastbootFuture<'a> {
        core::future::ready(Err(FastbootWebUsbError))
    }
}

impl DeviceWatcher {
    pub fn new(_filters: &[DeviceFilter]) -> Result<Self, DeviceWatcherError> {
        Err(DeviceWatcherError)
    }
}

impl DeviceWatcherTrait for DeviceWatcher {
    type Device = WebUsbDeviceHandle;
    type Error = DeviceWatcherError;

    fn poll_next_event(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<DeviceEvent<Self::Device>, Self::Error>> {
        let _ = self;
        Poll::Ready(Err(DeviceWatcherError))
    }
}

pub async fn request_device(
    _filters: &[DeviceFilter],
) -> Result<WebUsbDeviceHandle, DeviceWatcherError> {
    Err(DeviceWatcherError)
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
