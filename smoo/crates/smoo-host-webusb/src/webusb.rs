use crate::WebUsbTransportConfig;
use async_trait::async_trait;
use futures_util::future::FutureExt;
use js_sys::{Promise, Uint8Array};
use smoo_host_core::{
    ControlTransport, Transport, TransportError, TransportErrorKind, TransportResult,
};
use tracing::{debug, trace};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    UsbAlternateInterface, UsbConfiguration, UsbControlTransferParameters, UsbDevice, UsbDirection,
    UsbEndpoint, UsbEndpointType, UsbInTransferResult, UsbInterface, UsbOutTransferResult,
    UsbRecipient, UsbRequestType, UsbTransferStatus,
};

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Wrapper to mark `JsFuture` as `Send` on wasm (single-threaded).
struct SendJsFuture(JsFuture);

unsafe impl Send for SendJsFuture {}

impl From<Promise> for SendJsFuture {
    fn from(promise: Promise) -> Self {
        Self(JsFuture::from(promise))
    }
}

impl Future for SendJsFuture {
    type Output = Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        FutureExt::poll_unpin(&mut self.0, cx)
    }
}

/// Clonable control handle for issuing vendor requests alongside the transport.
#[derive(Clone)]
pub struct WebUsbControl {
    device: UsbDevice,
    interface: u8,
}

impl WebUsbControl {
    pub fn new(device: UsbDevice, interface: u8) -> Self {
        Self { device, interface }
    }

    fn ensure_open(&self) -> TransportResult<()> {
        if !self.device.opened() {
            return Err(TransportError::new(TransportErrorKind::NotReady));
        }
        Ok(())
    }
}

/// [`Transport`] implementation backed by WebUSB.
#[derive(Clone)]
pub struct WebUsbTransport {
    device: SendUsbDevice,
    config: WebUsbTransportConfig,
    control: WebUsbControl,
}

impl WebUsbTransport {
    /// Construct a transport from an already obtained `UsbDevice`.
    ///
    /// This will `open()` the device and `claim_interface()` using the supplied config.
    pub async fn new(device: UsbDevice, config: WebUsbTransportConfig) -> TransportResult<Self> {
        open_and_claim(&device, config.interface).await?;
        let resolved = resolve_endpoints(&device, config)?;
        debug!(
            interface = resolved.interface,
            interrupt_in = resolved.interrupt_in,
            interrupt_out = resolved.interrupt_out,
            bulk_in = resolved.bulk_in,
            bulk_out = resolved.bulk_out,
            "webusb: endpoints resolved"
        );
        let control = WebUsbControl::new(device.clone(), config.interface);
        Ok(Self {
            device: SendUsbDevice(device),
            config: resolved,
            control,
        })
    }

    /// Returns a clonable control handle for issuing vendor requests alongside the transport.
    pub fn control_handle(&self) -> WebUsbControl {
        self.control.clone()
    }
}

#[async_trait]
impl ControlTransport for WebUsbControl {
    async fn control_in(
        &self,
        request_type: u8,
        request: u8,
        buf: &mut [u8],
    ) -> TransportResult<usize> {
        self.ensure_open()?;
        let len: u16 = buf.len().try_into().map_err(|_| {
            TransportError::with_message(
                TransportErrorKind::Protocol,
                "control_in length exceeds u16",
            )
        })?;
        trace!(
            req_type = request_type,
            request,
            len = buf.len(),
            interface = self.interface,
            "webusb: control_in"
        );
        let promise = {
            let params = control_params(request_type, request, self.interface);
            self.device.control_transfer_in(&params, len)
        };
        let result = SendJsFuture::from(promise)
            .await
            .map_err(|err| js_error("control_in", err))?;
        let result: UsbInTransferResult = result
            .dyn_into()
            .map_err(|err| js_error("control_in cast", err))?;
        let status = result.status();
        match status {
            UsbTransferStatus::Ok => {
                let data = result
                    .data()
                    .ok_or_else(|| TransportError::new(TransportErrorKind::Protocol))?;
                let read = data.byte_length() as usize;
                let offset: u32 = data.byte_offset().try_into().map_err(|_| {
                    TransportError::with_message(
                        TransportErrorKind::Protocol,
                        "control_in data offset exceeds u32",
                    )
                })?;
                let view = Uint8Array::new_with_byte_offset_and_length(
                    &data.buffer(),
                    offset,
                    read as u32,
                );
                trace!(
                    status = ?status,
                    req_type = request_type,
                    request,
                    expected = buf.len(),
                    read,
                    "webusb: control_in status OK"
                );
                if read != buf.len() {
                    return Err(TransportError::with_message(
                        TransportErrorKind::Protocol,
                        format!(
                            "control_in length mismatch (status={status:?}, expected {}, got {})",
                            buf.len(),
                            read
                        ),
                    ));
                }
                view.copy_to(buf);
                Ok(read)
            }
            _ => Err(TransportError::with_message(
                map_transfer_status(status),
                format!("control_in status {:?}, len=0", status),
            )),
        }
    }

    async fn control_out(
        &self,
        request_type: u8,
        request: u8,
        data: &[u8],
    ) -> TransportResult<usize> {
        self.ensure_open()?;
        trace!(
            req_type = request_type,
            request,
            len = data.len(),
            interface = self.interface,
            "webusb: control_out"
        );
        let promise = {
            let params = control_params(request_type, request, self.interface);
            let payload = Uint8Array::from(data);
            self.device
                .control_transfer_out_with_u8_array(&params, &payload)
                .map_err(|err| js_error("control_out", err))?
        };
        let result = SendJsFuture::from(promise)
            .await
            .map_err(|err| js_error("control_out", err))?;
        let result: UsbOutTransferResult = result
            .dyn_into()
            .map_err(|err| js_error("control_out cast", err))?;
        match result.status() {
            UsbTransferStatus::Ok => Ok(result.bytes_written() as usize),
            status => Err(TransportError::with_message(
                map_transfer_status(status),
                format!("control_out status {:?}", status),
            )),
        }
    }
}

#[async_trait]
impl ControlTransport for WebUsbTransport {
    async fn control_in(
        &self,
        request_type: u8,
        request: u8,
        buf: &mut [u8],
    ) -> TransportResult<usize> {
        self.control.control_in(request_type, request, buf).await
    }

    async fn control_out(
        &self,
        request_type: u8,
        request: u8,
        data: &[u8],
    ) -> TransportResult<usize> {
        self.control.control_out(request_type, request, data).await
    }
}

#[async_trait]
impl Transport for WebUsbTransport {
    async fn read_interrupt(&self, buf: &mut [u8]) -> TransportResult<usize> {
        transfer_in(
            self.device.clone(),
            self.config
                .interrupt_in
                .expect("interrupt_in resolved during construction"),
            buf,
        )
        .await
    }

    async fn write_interrupt(&self, buf: &[u8]) -> TransportResult<usize> {
        transfer_out(
            self.device.clone(),
            self.config
                .interrupt_out
                .expect("interrupt_out resolved during construction"),
            buf,
        )
        .await
    }

    async fn read_bulk(&self, buf: &mut [u8]) -> TransportResult<usize> {
        transfer_in(
            self.device.clone(),
            self.config
                .bulk_in
                .expect("bulk_in resolved during construction"),
            buf,
        )
        .await
    }

    async fn write_bulk(&self, buf: &[u8]) -> TransportResult<usize> {
        transfer_out(
            self.device.clone(),
            self.config
                .bulk_out
                .expect("bulk_out resolved during construction"),
            buf,
        )
        .await
    }
}

unsafe impl Send for WebUsbTransport {}
unsafe impl Sync for WebUsbTransport {}
unsafe impl Send for WebUsbControl {}
unsafe impl Sync for WebUsbControl {}
unsafe impl Send for SendUsbDevice {}
unsafe impl Sync for SendUsbDevice {}

#[derive(Clone)]
struct SendUsbDevice(UsbDevice);

impl SendUsbDevice {
    fn clone_inner(&self) -> UsbDevice {
        self.0.clone()
    }
}

impl std::ops::Deref for SendUsbDevice {
    type Target = UsbDevice;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn control_params(request_type: u8, request: u8, interface: u8) -> UsbControlTransferParameters {
    let (req_type, recipient) = decode_request_type(request_type);
    UsbControlTransferParameters::new(
        interface as u16,
        recipient.unwrap_or(UsbRecipient::Interface),
        request,
        req_type,
        0,
    )
}

fn decode_request_type(bm_request_type: u8) -> (UsbRequestType, Option<UsbRecipient>) {
    let ty = match (bm_request_type >> 5) & 0x03 {
        0 => UsbRequestType::Standard,
        1 => UsbRequestType::Class,
        2 => UsbRequestType::Vendor,
        _ => UsbRequestType::Vendor,
    };
    let recipient = match bm_request_type & 0x1f {
        0 => Some(UsbRecipient::Device),
        1 => Some(UsbRecipient::Interface),
        2 => Some(UsbRecipient::Endpoint),
        3 => Some(UsbRecipient::Other),
        _ => None,
    };
    (ty, recipient)
}

async fn open_and_claim(device: &UsbDevice, interface: u8) -> TransportResult<()> {
    if !device.opened() {
        let promise = device.open();
        SendJsFuture::from(promise)
            .await
            .map_err(|err| js_error("open await", err))?;
    }
    if device.configuration().is_none() {
        let promise = device.select_configuration(1);
        SendJsFuture::from(promise)
            .await
            .map_err(|err| js_error("select_configuration await", err))?;
    }
    let promise = device.claim_interface(interface as u8);
    SendJsFuture::from(promise)
        .await
        .map_err(|err| js_error("claim_interface await", err))?;
    Ok(())
}

async fn transfer_in(
    device: SendUsbDevice,
    endpoint: u8,
    buf: &mut [u8],
) -> TransportResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    if !device.opened() {
        return Err(TransportError::new(TransportErrorKind::NotReady));
    }
    trace!(endpoint, len = buf.len(), "webusb: transfer_in");
    let len: u32 = buf.len().try_into().map_err(|_| {
        TransportError::with_message(
            TransportErrorKind::Protocol,
            "transfer_in length exceeds u32",
        )
    })?;
    let promise = device.clone_inner().transfer_in(endpoint, len);
    let result = SendJsFuture::from(promise)
        .await
        .map_err(|err| js_error("transfer_in await", err))?;
    let result: UsbInTransferResult = result
        .dyn_into()
        .map_err(|err| js_error("transfer_in cast", err))?;
    let status = result.status();
    match status {
        UsbTransferStatus::Ok => {
            let data = result
                .data()
                .ok_or_else(|| TransportError::new(TransportErrorKind::Protocol))?;
            let read = data.byte_length() as usize;
            let offset: u32 = data.byte_offset().try_into().map_err(|_| {
                TransportError::with_message(
                    TransportErrorKind::Protocol,
                    "transfer_in data offset exceeds u32",
                )
            })?;
            let view =
                Uint8Array::new_with_byte_offset_and_length(&data.buffer(), offset, read as u32);
            let copy_len = buf.len().min(read);
            view.slice(0, copy_len as u32).copy_to(buf);
            trace!(
                endpoint,
                requested = buf.len(),
                read,
                copied = copy_len,
                "webusb: transfer_in status OK"
            );
            Ok(copy_len)
        }
        _ => Err(TransportError::with_message(
            map_transfer_status(status),
            format!("transfer_in status {:?}", status),
        )),
    }
}

async fn transfer_out(device: SendUsbDevice, endpoint: u8, buf: &[u8]) -> TransportResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    if !device.opened() {
        return Err(TransportError::new(TransportErrorKind::NotReady));
    }
    trace!(endpoint, len = buf.len(), "webusb: transfer_out");
    let promise = {
        let payload = Uint8Array::from(buf);
        let promise = device
            .transfer_out_with_u8_array(endpoint, &payload)
            .map_err(|err| js_error("transfer_out", err))?;
        drop(payload);
        promise
    };
    let result = SendJsFuture::from(promise)
        .await
        .map_err(|err| js_error("transfer_out await", err))?;
    let result: UsbOutTransferResult = result
        .dyn_into()
        .map_err(|err| js_error("transfer_out cast", err))?;
    match result.status() {
        UsbTransferStatus::Ok => Ok(result.bytes_written() as usize),
        status => Err(TransportError::with_message(
            map_transfer_status(status),
            format!("transfer_out status {:?}", status),
        )),
    }
}

fn map_transfer_status(status: UsbTransferStatus) -> TransportErrorKind {
    match status {
        UsbTransferStatus::Ok => TransportErrorKind::Other,
        UsbTransferStatus::Stall | UsbTransferStatus::Babble => TransportErrorKind::Protocol,
        _ => TransportErrorKind::Other,
    }
}

fn js_error(op: &str, err: impl Into<wasm_bindgen::JsValue>) -> TransportError {
    let js: wasm_bindgen::JsValue = err.into();
    let msg = js_as_string(&js).unwrap_or_else(|| format!("{:?}", js));
    TransportError::with_message(TransportErrorKind::Other, format!("{op}: {msg}"))
}

fn js_as_string(js: &wasm_bindgen::JsValue) -> Option<String> {
    js.as_string().or_else(|| {
        js.dyn_ref::<js_sys::Error>()
            .and_then(|e| e.message().as_string())
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EndpointInfo {
    number: u8,
    direction: UsbDirection,
    kind: UsbEndpointType,
}

fn resolve_endpoints(
    device: &UsbDevice,
    preferred: WebUsbTransportConfig,
) -> TransportResult<WebUsbTransportConfig> {
    let configuration = device
        .configuration()
        .ok_or_else(|| TransportError::new(TransportErrorKind::NotReady))?;
    let interface = find_interface(&configuration, preferred.interface)?.ok_or_else(|| {
        TransportError::with_message(
            TransportErrorKind::NotReady,
            format!("interface {} not present", preferred.interface),
        )
    })?;
    let active = interface.alternate();
    let endpoints = collect_endpoints(&active)?;
    trace!(
        interface = interface.interface_number(),
        endpoints = %describe_endpoints(&endpoints),
        "webusb: discovered endpoints"
    );

    let interrupt_in = choose_endpoint(
        &endpoints,
        preferred.interrupt_in,
        UsbDirection::In,
        UsbEndpointType::Interrupt,
        "interrupt_in",
    )?;
    let interrupt_out = choose_endpoint(
        &endpoints,
        preferred.interrupt_out,
        UsbDirection::Out,
        UsbEndpointType::Interrupt,
        "interrupt_out",
    )?;
    let bulk_in = choose_endpoint(
        &endpoints,
        preferred.bulk_in,
        UsbDirection::In,
        UsbEndpointType::Bulk,
        "bulk_in",
    )?;
    let bulk_out = choose_endpoint(
        &endpoints,
        preferred.bulk_out,
        UsbDirection::Out,
        UsbEndpointType::Bulk,
        "bulk_out",
    )?;

    Ok(WebUsbTransportConfig {
        interface: preferred.interface,
        interrupt_in: Some(interrupt_in),
        interrupt_out: Some(interrupt_out),
        bulk_in: Some(bulk_in),
        bulk_out: Some(bulk_out),
    })
}

fn find_interface(
    configuration: &UsbConfiguration,
    interface_number: u8,
) -> TransportResult<Option<UsbInterface>> {
    let mut found = None;
    for iface in configuration.interfaces().iter() {
        let iface: UsbInterface = iface
            .dyn_into()
            .map_err(|err| js_error("interface cast", err))?;
        if iface.interface_number() == interface_number {
            found = Some(iface);
            break;
        }
    }
    Ok(found)
}

fn collect_endpoints(alternate: &UsbAlternateInterface) -> TransportResult<Vec<EndpointInfo>> {
    let mut endpoints = Vec::new();
    for ep in alternate.endpoints().iter() {
        let ep: UsbEndpoint = ep
            .dyn_into()
            .map_err(|err| js_error("endpoint cast", err))?;
        endpoints.push(EndpointInfo {
            number: ep.endpoint_number(),
            direction: ep.direction(),
            kind: ep.type_(),
        });
    }
    Ok(endpoints)
}

fn choose_endpoint(
    endpoints: &[EndpointInfo],
    preferred: Option<u8>,
    direction: UsbDirection,
    kind: UsbEndpointType,
    label: &str,
) -> TransportResult<u8> {
    if let Some(pref) = preferred {
        if let Some(ep) = endpoints
            .iter()
            .find(|ep| ep.number == pref && ep.direction == direction && ep.kind == kind)
        {
            return Ok(ep.number);
        }
    }
    if let Some(ep) = endpoints
        .iter()
        .find(|ep| ep.direction == direction && ep.kind == kind)
    {
        return Ok(ep.number);
    }

    Err(TransportError::with_message(
        TransportErrorKind::Protocol,
        format!(
            "{label} endpoint not found (direction={direction:?}, type={kind:?}); available={}",
            describe_endpoints(endpoints)
        ),
    ))
}

fn describe_endpoints(endpoints: &[EndpointInfo]) -> String {
    if endpoints.is_empty() {
        return "[]".to_string();
    }
    let parts: Vec<String> = endpoints
        .iter()
        .map(|ep| format!("#{}:{:?}/{:?}", ep.number, ep.direction, ep.kind))
        .collect();
    format!("[{}]", parts.join(", "))
}
