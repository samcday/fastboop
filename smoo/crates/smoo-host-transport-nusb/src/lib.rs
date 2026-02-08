use async_trait::async_trait;
use nusb::{
    Device,
    descriptors::TransferType,
    io::{EndpointRead, EndpointWrite},
    transfer::{
        Bulk, ControlIn, ControlOut, ControlType, Direction, In, Interrupt, Out, Recipient,
        TransferError,
    },
};
use smoo_host_core::{
    ControlTransport, Transport, TransportError, TransportErrorKind, TransportResult,
};
use std::{io, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

/// Configuration for [`NusbTransport`].
#[derive(Clone, Copy, Debug)]
pub struct NusbTransportConfig {
    pub vendor_id: u16,
    pub product_id: u16,
    pub interface: u8,
    pub interrupt_in: u8,
    pub interrupt_out: u8,
    pub bulk_in: u8,
    pub bulk_out: u8,
    pub timeout: Duration,
}

impl Default for NusbTransportConfig {
    fn default() -> Self {
        Self {
            vendor_id: 0,
            product_id: 0,
            interface: 0,
            interrupt_in: 0x81,
            interrupt_out: 0x01,
            bulk_in: 0x82,
            bulk_out: 0x02,
            timeout: Duration::from_millis(100),
        }
    }
}

/// Clonable control handle for issuing vendor requests alongside the transport.
#[derive(Clone)]
pub struct NusbControl {
    device: Arc<Device>,
    interface: u8,
}

impl NusbControl {
    pub fn new(device: Arc<Device>, interface: u8) -> Self {
        Self { device, interface }
    }
}

/// [`Transport`] implementation backed by `nusb`.
#[derive(Clone)]
pub struct NusbTransport {
    control: NusbControl,
    interrupt_in: Arc<Mutex<EndpointRead<Interrupt>>>,
    interrupt_out: Arc<Mutex<EndpointWrite<Interrupt>>>,
    bulk_in: Arc<Mutex<EndpointRead<Bulk>>>,
    bulk_out: Arc<Mutex<EndpointWrite<Bulk>>>,
    timeout: Duration,
}

impl NusbTransport {
    pub async fn new(device: Device, config: NusbTransportConfig) -> TransportResult<Self> {
        let iface = device
            .claim_interface(config.interface)
            .await
            .map_err(|err| map_nusb_error("claim usb interface", err))?;

        let interrupt_in_ep = iface
            .endpoint::<Interrupt, In>(config.interrupt_in)
            .map_err(|err| map_nusb_error("open interrupt_in endpoint", err))?;
        let interrupt_out_ep = iface
            .endpoint::<Interrupt, Out>(config.interrupt_out)
            .map_err(|err| map_nusb_error("open interrupt_out endpoint", err))?;
        let bulk_in_ep = iface
            .endpoint::<Bulk, In>(config.bulk_in)
            .map_err(|err| map_nusb_error("open bulk_in endpoint", err))?;
        let bulk_out_ep = iface
            .endpoint::<Bulk, Out>(config.bulk_out)
            .map_err(|err| map_nusb_error("open bulk_out endpoint", err))?;

        let interrupt_in_mps = interrupt_in_ep.max_packet_size();
        let _interrupt_out_mps = interrupt_out_ep.max_packet_size();
        let bulk_in_mps = bulk_in_ep.max_packet_size();
        let _bulk_out_mps = bulk_out_ep.max_packet_size();
        let interrupt_transfer_size = interrupt_in_mps.max(1024);
        let bulk_transfer_size = bulk_in_mps.max(64 * 1024);

        let interrupt_in = Arc::new(Mutex::new(EndpointRead::new(
            interrupt_in_ep,
            interrupt_transfer_size,
        )));
        let interrupt_out = Arc::new(Mutex::new(EndpointWrite::new(
            interrupt_out_ep,
            interrupt_transfer_size,
        )));
        let bulk_in = Arc::new(Mutex::new(EndpointRead::new(
            bulk_in_ep,
            bulk_transfer_size,
        )));
        let bulk_out = Arc::new(Mutex::new(EndpointWrite::new(
            bulk_out_ep,
            bulk_transfer_size,
        )));

        let control = NusbControl::new(Arc::new(device), config.interface);

        Ok(Self {
            control,
            interrupt_in,
            interrupt_out,
            bulk_in,
            bulk_out,
            timeout: config.timeout,
        })
    }

    /// Returns a clonable control handle for issuing vendor requests alongside the transport.
    pub fn control_handle(&self) -> NusbControl {
        self.control.clone()
    }

    /// Discover and open the first device matching filters and the desired interface class tuple.
    pub async fn open_matching(
        vendor_id: Option<u16>,
        product_id: Option<u16>,
        class: u8,
        subclass: u8,
        protocol: u8,
        timeout: Duration,
    ) -> TransportResult<(Self, NusbControl)> {
        let devices = nusb::list_devices()
            .await
            .map_err(|err| map_nusb_error("list devices", err))?;
        let mut selected = None;
        for info in devices {
            if let Some(v) = vendor_id
                && info.vendor_id() != v
            {
                continue;
            }
            if let Some(p) = product_id
                && info.product_id() != p
            {
                continue;
            }
            if info.interfaces().any(|iface| {
                iface.class() == class
                    && iface.subclass() == subclass
                    && iface.protocol() == protocol
            }) {
                selected = Some(info);
                break;
            }
        }

        let info = selected.ok_or_else(|| TransportError::new(TransportErrorKind::NotReady))?;
        let interface_number = info
            .interfaces()
            .find(|iface| {
                iface.class() == class
                    && iface.subclass() == subclass
                    && iface.protocol() == protocol
            })
            .map(|iface| iface.interface_number())
            .ok_or_else(|| TransportError::new(TransportErrorKind::NotReady))?;

        let device = info
            .open()
            .await
            .map_err(|err| map_nusb_error("open device", err))?;
        let config = device.active_configuration().map_err(|err| {
            TransportError::with_message(
                TransportErrorKind::Other,
                format!("read active configuration: {err}"),
            )
        })?;
        let iface_desc = config
            .interfaces()
            .find(|iface| iface.interface_number() == interface_number)
            .ok_or_else(|| TransportError::new(TransportErrorKind::NotReady))?;
        let alt = iface_desc
            .alt_settings()
            .next()
            .ok_or_else(|| TransportError::new(TransportErrorKind::NotReady))?;

        let mut interrupt_in = None;
        let mut interrupt_out = None;
        let mut bulk_in = None;
        let mut bulk_out = None;
        for ep in alt.endpoints() {
            match (ep.transfer_type(), ep.direction()) {
                (TransferType::Interrupt, Direction::In) if interrupt_in.is_none() => {
                    interrupt_in = Some(ep.address());
                }
                (TransferType::Interrupt, Direction::Out) if interrupt_out.is_none() => {
                    interrupt_out = Some(ep.address());
                }
                (TransferType::Bulk, Direction::In) if bulk_in.is_none() => {
                    bulk_in = Some(ep.address());
                }
                (TransferType::Bulk, Direction::Out) if bulk_out.is_none() => {
                    bulk_out = Some(ep.address());
                }
                _ => {}
            }
        }

        let (interrupt_in, interrupt_out, bulk_in, bulk_out) = (
            interrupt_in.ok_or_else(|| TransportError::new(TransportErrorKind::NotReady))?,
            interrupt_out.ok_or_else(|| TransportError::new(TransportErrorKind::NotReady))?,
            bulk_in.ok_or_else(|| TransportError::new(TransportErrorKind::NotReady))?,
            bulk_out.ok_or_else(|| TransportError::new(TransportErrorKind::NotReady))?,
        );

        let transport = NusbTransport::new(
            device,
            NusbTransportConfig {
                vendor_id: info.vendor_id(),
                product_id: info.product_id(),
                interface: interface_number,
                interrupt_in,
                interrupt_out,
                bulk_in,
                bulk_out,
                timeout,
            },
        )
        .await?;
        let control = transport.control_handle();
        Ok((transport, control))
    }

    /// Find the first device matching VID/PID.
    pub async fn discover(vid: u16, pid: u16) -> TransportResult<Device> {
        let devices = nusb::list_devices()
            .await
            .map_err(|err| map_nusb_error("list devices", err))?;
        for info in devices {
            if info.vendor_id() == vid && info.product_id() == pid {
                return info
                    .open()
                    .await
                    .map_err(|err| map_nusb_error("open device", err));
            }
        }
        Err(TransportError::new(TransportErrorKind::NotReady))
    }
}

#[async_trait]
impl ControlTransport for NusbControl {
    async fn control_in(
        &self,
        request_type: u8,
        request: u8,
        buf: &mut [u8],
    ) -> TransportResult<usize> {
        let result = self
            .device
            .control_in(
                ControlIn {
                    control_type: decode_control_type(request_type),
                    recipient: decode_recipient(request_type),
                    request,
                    value: 0,
                    index: self.interface as u16,
                    length: buf.len() as u16,
                },
                Duration::from_millis(100),
            )
            .await
            .map_err(|err| map_transfer_error("control-in transfer", err))?;
        let len = result.len().min(buf.len());
        buf[..len].copy_from_slice(&result[..len]);
        Ok(len)
    }

    async fn control_out(
        &self,
        request_type: u8,
        request: u8,
        data: &[u8],
    ) -> TransportResult<usize> {
        self.device
            .control_out(
                ControlOut {
                    control_type: decode_control_type(request_type),
                    recipient: decode_recipient(request_type),
                    request,
                    value: 0,
                    index: self.interface as u16,
                    data,
                },
                Duration::from_millis(100),
            )
            .await
            .map_err(|err| map_transfer_error("control-out transfer", err))?;
        Ok(data.len())
    }
}

#[async_trait]
impl ControlTransport for NusbTransport {
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
impl Transport for NusbTransport {
    async fn read_interrupt(&self, buf: &mut [u8]) -> TransportResult<usize> {
        let mut reader = self.interrupt_in.lock().await;
        reader
            .read_exact(buf)
            .await
            .map_err(|err| map_io_error("interrupt-in read", err))?;
        Ok(buf.len())
    }

    async fn write_interrupt(&self, buf: &[u8]) -> TransportResult<usize> {
        let mut writer = self.interrupt_out.lock().await;
        writer
            .write_all(buf)
            .await
            .map_err(|err| map_io_error("interrupt-out write", err))?;
        writer
            .flush()
            .await
            .map_err(|err| map_io_error("interrupt-out flush", err))?;
        Ok(buf.len())
    }

    async fn read_bulk(&self, buf: &mut [u8]) -> TransportResult<usize> {
        let mut reader = self.bulk_in.lock().await;
        reader.set_read_timeout(self.timeout);
        reader
            .read_exact(buf)
            .await
            .map_err(|err| map_io_error("bulk-in read", err))?;
        Ok(buf.len())
    }

    async fn write_bulk(&self, buf: &[u8]) -> TransportResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut writer = self.bulk_out.lock().await;
        writer
            .write_all(buf)
            .await
            .map_err(|err| map_io_error("bulk-out write", err))?;
        writer
            .flush()
            .await
            .map_err(|err| map_io_error("bulk-out flush", err))?;
        Ok(buf.len())
    }
}

fn map_nusb_error(op: &str, err: nusb::Error) -> TransportError {
    let kind = match err.kind() {
        nusb::ErrorKind::Disconnected => TransportErrorKind::Disconnected,
        nusb::ErrorKind::NotFound => TransportErrorKind::NotReady,
        nusb::ErrorKind::PermissionDenied | nusb::ErrorKind::Busy => TransportErrorKind::Other,
        nusb::ErrorKind::Unsupported => TransportErrorKind::Unsupported,
        nusb::ErrorKind::Other => TransportErrorKind::Other,
        _ => TransportErrorKind::Other,
    };
    TransportError::with_message(kind, format!("{op}: {err}"))
}

fn map_transfer_error(op: &str, err: TransferError) -> TransportError {
    let kind = match err {
        TransferError::Cancelled => TransportErrorKind::Timeout,
        TransferError::Stall => TransportErrorKind::Protocol,
        TransferError::Disconnected => TransportErrorKind::Disconnected,
        TransferError::Fault => TransportErrorKind::Other,
        TransferError::InvalidArgument => TransportErrorKind::Unsupported,
        TransferError::Unknown(_) => TransportErrorKind::Other,
    };
    TransportError::with_message(kind, format!("{op}: {err}"))
}

fn map_io_error(op: &str, err: io::Error) -> TransportError {
    let kind = match err.kind() {
        io::ErrorKind::TimedOut => TransportErrorKind::Timeout,
        io::ErrorKind::NotFound => TransportErrorKind::Disconnected,
        io::ErrorKind::BrokenPipe => TransportErrorKind::Protocol,
        io::ErrorKind::Unsupported => TransportErrorKind::Unsupported,
        _ => TransportErrorKind::Other,
    };
    TransportError::with_message(kind, format!("{op}: {err}"))
}

fn decode_control_type(request_type: u8) -> ControlType {
    match (request_type >> 5) & 0x03 {
        0 => ControlType::Standard,
        1 => ControlType::Class,
        2 => ControlType::Vendor,
        _ => ControlType::Vendor,
    }
}

fn decode_recipient(request_type: u8) -> Recipient {
    match request_type & 0x1F {
        0 => Recipient::Device,
        1 => Recipient::Interface,
        2 => Recipient::Endpoint,
        _ => Recipient::Other,
    }
}
