use crate::WebUsbTransportConfig;
use async_trait::async_trait;
use smoo_host_core::{
    ControlTransport, Transport, TransportError, TransportErrorKind, TransportResult,
};

/// Stub control handle for non-wasm targets.
#[derive(Clone)]
pub struct WebUsbControl;

/// Stub WebUSB transport that always reports unsupported.
#[derive(Clone, Copy)]
pub struct WebUsbTransport;

impl WebUsbTransport {
    pub async fn new(_cfg: WebUsbTransportConfig) -> TransportResult<Self> {
        Err(TransportError::new(TransportErrorKind::Unsupported))
    }
}

#[async_trait]
impl ControlTransport for WebUsbControl {
    async fn control_in(
        &self,
        _request_type: u8,
        _request: u8,
        _buf: &mut [u8],
    ) -> TransportResult<usize> {
        Err(TransportError::new(TransportErrorKind::Unsupported))
    }

    async fn control_out(
        &self,
        _request_type: u8,
        _request: u8,
        _data: &[u8],
    ) -> TransportResult<usize> {
        Err(TransportError::new(TransportErrorKind::Unsupported))
    }
}

#[async_trait]
impl ControlTransport for WebUsbTransport {
    async fn control_in(
        &self,
        _request_type: u8,
        _request: u8,
        _buf: &mut [u8],
    ) -> TransportResult<usize> {
        Err(TransportError::new(TransportErrorKind::Unsupported))
    }

    async fn control_out(
        &self,
        _request_type: u8,
        _request: u8,
        _data: &[u8],
    ) -> TransportResult<usize> {
        Err(TransportError::new(TransportErrorKind::Unsupported))
    }
}

#[async_trait]
impl Transport for WebUsbTransport {
    async fn read_interrupt(&self, _buf: &mut [u8]) -> TransportResult<usize> {
        Err(TransportError::new(TransportErrorKind::Unsupported))
    }

    async fn write_interrupt(&self, _buf: &[u8]) -> TransportResult<usize> {
        Err(TransportError::new(TransportErrorKind::Unsupported))
    }

    async fn read_bulk(&self, _buf: &mut [u8]) -> TransportResult<usize> {
        Err(TransportError::new(TransportErrorKind::Unsupported))
    }

    async fn write_bulk(&self, _buf: &[u8]) -> TransportResult<usize> {
        Err(TransportError::new(TransportErrorKind::Unsupported))
    }
}
