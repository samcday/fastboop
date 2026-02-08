use async_trait::async_trait;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TrySendError, bounded};
use rusb::{Context, Device, DeviceHandle, Direction, TransferType, UsbContext};
use smoo_host_core::{
    ControlTransport, Transport, TransportError, TransportErrorKind, TransportResult,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::{sync::oneshot, task};
use tracing::{debug, trace, warn};

const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(50);
const DEFAULT_QUEUE_DEPTH: usize = 32;
const DEFAULT_TRANSFER_TIMEOUT: Duration = Duration::from_millis(200);

/// Configuration for [`RusbTransport`].
#[derive(Clone, Debug)]
pub struct RusbTransportConfig {
    /// Interface number to claim before issuing transfers.
    pub interface: u8,
    /// Interrupt endpoint address used to receive Request messages (device → host).
    pub interrupt_in: u8,
    /// Interrupt endpoint address used to send Response messages (host → device).
    pub interrupt_out: u8,
    /// Bulk endpoint address used to read payloads (device → host).
    pub bulk_in: u8,
    /// Bulk endpoint address used to write payloads (host → device).
    pub bulk_out: u8,
    /// Timeout applied to each blocking transfer attempt before checking for cancellation/shutdown.
    pub transfer_timeout: Duration,
    /// Maximum queued transfers per worker.
    pub queue_depth: usize,
}

impl Default for RusbTransportConfig {
    fn default() -> Self {
        Self {
            interface: 0,
            interrupt_in: 0x81,
            interrupt_out: 0x01,
            bulk_in: 0x82,
            bulk_out: 0x02,
            transfer_timeout: DEFAULT_TRANSFER_TIMEOUT,
            queue_depth: DEFAULT_QUEUE_DEPTH,
        }
    }
}

/// [`Transport`] implementation backed by `rusb` worker threads.
#[derive(Clone)]
pub struct RusbTransport {
    inner: Arc<Inner>,
}

/// Clonable control handle for issuing vendor requests alongside the transport.
#[derive(Clone)]
pub struct RusbControl {
    inner: Arc<Inner>,
}

struct Inner {
    shutdown: Arc<AtomicBool>,
    control: ControlWorker,
    interrupt_in: ReadWorker,
    interrupt_out: WriteWorker,
    bulk_in: ReadWorker,
    bulk_out: WriteWorker,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.control.shutdown();
        self.interrupt_in.shutdown();
        self.interrupt_out.shutdown();
        self.bulk_in.shutdown();
        self.bulk_out.shutdown();
    }
}

impl RusbTransport {
    pub(crate) fn new(
        handle: DeviceHandle<Context>,
        config: RusbTransportConfig,
    ) -> TransportResult<Self> {
        let RusbTransportConfig {
            interface,
            interrupt_in,
            interrupt_out,
            bulk_in,
            bulk_out,
            transfer_timeout,
            queue_depth,
        } = config;

        if let Err(err) = handle.set_auto_detach_kernel_driver(true) {
            debug!(%err, "rusb: failed to enable kernel driver auto-detach; continuing");
        }

        handle
            .claim_interface(interface)
            .map_err(|err| map_rusb_error("claim usb interface", err))?;

        let handle = Arc::new(handle);
        let shutdown = Arc::new(AtomicBool::new(false));

        let control = ControlWorker::spawn(
            handle.clone(),
            shutdown.clone(),
            interface,
            queue_depth,
            transfer_timeout,
        )?;

        let interrupt_in_worker = ReadWorker::spawn(
            "rusb-interrupt-in",
            handle.clone(),
            shutdown.clone(),
            queue_depth,
            move |h, buf| h.read_interrupt(interrupt_in, buf, transfer_timeout),
        )?;

        let interrupt_out_worker = WriteWorker::spawn(
            "rusb-interrupt-out",
            handle.clone(),
            shutdown.clone(),
            queue_depth,
            move |h, data| h.write_interrupt(interrupt_out, data, transfer_timeout),
        )?;

        let bulk_in_worker = ReadWorker::spawn(
            "rusb-bulk-in",
            handle.clone(),
            shutdown.clone(),
            queue_depth,
            move |h, buf| h.read_bulk(bulk_in, buf, transfer_timeout),
        )?;

        let bulk_out_worker = WriteWorker::spawn(
            "rusb-bulk-out",
            handle,
            shutdown.clone(),
            queue_depth,
            move |h, data| h.write_bulk(bulk_out, data, transfer_timeout),
        )?;

        let inner = Inner {
            shutdown,
            control,
            interrupt_in: interrupt_in_worker,
            interrupt_out: interrupt_out_worker,
            bulk_in: bulk_in_worker,
            bulk_out: bulk_out_worker,
        };

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Returns a clonable control handle for issuing vendor requests alongside the transport.
    pub fn control_handle(&self) -> RusbControl {
        RusbControl {
            inner: self.inner.clone(),
        }
    }
}

impl RusbTransport {
    /// Discover and open the first device matching filters and the desired interface class tuple.
    pub async fn open_matching(
        vendor_id: Option<u16>,
        product_id: Option<u16>,
        class: u8,
        subclass: u8,
        protocol: u8,
        transfer_timeout: Duration,
    ) -> TransportResult<(Self, RusbControl)> {
        let discovery = task::spawn_blocking(move || {
            find_matching_device(vendor_id, product_id, class, subclass, protocol)
        })
        .await
        .map_err(|err| join_error("device discovery", err))??;

        let transport = RusbTransport::new(
            discovery.handle,
            RusbTransportConfig {
                interface: discovery.interface,
                interrupt_in: discovery.interrupt_in,
                interrupt_out: discovery.interrupt_out,
                bulk_in: discovery.bulk_in,
                bulk_out: discovery.bulk_out,
                transfer_timeout,
                queue_depth: DEFAULT_QUEUE_DEPTH,
            },
        )?;
        let control = transport.control_handle();
        Ok((transport, control))
    }
}

#[async_trait]
impl ControlTransport for RusbControl {
    async fn control_in(
        &self,
        request_type: u8,
        request: u8,
        buf: &mut [u8],
    ) -> TransportResult<usize> {
        let pending = self
            .inner
            .control
            .submit_in(request_type, request, buf.len())?;
        let data = await_with_abort(pending, "control-in").await?;
        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        Ok(len)
    }

    async fn control_out(
        &self,
        request_type: u8,
        request: u8,
        data: &[u8],
    ) -> TransportResult<usize> {
        let pending = self
            .inner
            .control
            .submit_out(request_type, request, data.to_vec())?;
        await_with_abort(pending, "control-out").await
    }
}

#[async_trait]
impl ControlTransport for RusbTransport {
    async fn control_in(
        &self,
        request_type: u8,
        request: u8,
        buf: &mut [u8],
    ) -> TransportResult<usize> {
        self.control_handle()
            .control_in(request_type, request, buf)
            .await
    }

    async fn control_out(
        &self,
        request_type: u8,
        request: u8,
        data: &[u8],
    ) -> TransportResult<usize> {
        self.control_handle()
            .control_out(request_type, request, data)
            .await
    }
}

#[async_trait]
impl Transport for RusbTransport {
    async fn read_interrupt(&self, buf: &mut [u8]) -> TransportResult<usize> {
        let pending = self.inner.interrupt_in.submit(vec![0u8; buf.len()])?;
        let data = await_with_abort(pending, "interrupt-in").await?;
        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        Ok(len)
    }

    async fn write_interrupt(&self, buf: &[u8]) -> TransportResult<usize> {
        let pending = self.inner.interrupt_out.submit(buf.to_vec())?;
        await_with_abort(pending, "interrupt-out").await
    }

    async fn read_bulk(&self, buf: &mut [u8]) -> TransportResult<usize> {
        let pending = self.inner.bulk_in.submit(vec![0u8; buf.len()])?;
        let data = await_with_abort(pending, "bulk-in").await?;
        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        Ok(len)
    }

    async fn write_bulk(&self, buf: &[u8]) -> TransportResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let pending = self.inner.bulk_out.submit(buf.to_vec())?;
        await_with_abort(pending, "bulk-out").await
    }
}

struct ReadWorker {
    label: &'static str,
    tx: Sender<ReadWork>,
    join: Option<thread::JoinHandle<()>>,
}

impl ReadWorker {
    fn spawn<F>(
        label: &'static str,
        handle: Arc<DeviceHandle<Context>>,
        shutdown: Arc<AtomicBool>,
        queue_depth: usize,
        op: F,
    ) -> TransportResult<Self>
    where
        F: Fn(&DeviceHandle<Context>, &mut [u8]) -> Result<usize, rusb::Error> + Send + 'static,
    {
        let (tx, rx) = bounded(queue_depth);
        let join = thread::Builder::new()
            .name(label.to_string())
            .spawn(move || run_read_worker(label, rx, handle, shutdown, op))
            .map_err(|err| worker_spawn_error(label, err))?;

        Ok(Self {
            label,
            tx,
            join: Some(join),
        })
    }

    fn submit(&self, buf: Vec<u8>) -> TransportResult<Pending<Vec<u8>>> {
        let abort = Arc::new(AtomicBool::new(false));
        let (reply, rx) = oneshot::channel();
        match self.tx.try_send(ReadWork::Transfer {
            buf,
            reply,
            abort: abort.clone(),
        }) {
            Ok(()) => Ok(Pending { abort, rx }),
            Err(TrySendError::Full(_)) => Err(queue_full_error(self.label)),
            Err(TrySendError::Disconnected(_)) => Err(disconnected_err(self.label)),
        }
    }

    fn shutdown(&mut self) {
        let _ = self.tx.try_send(ReadWork::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct WriteWorker {
    label: &'static str,
    tx: Sender<WriteWork>,
    join: Option<thread::JoinHandle<()>>,
}

impl WriteWorker {
    fn spawn<F>(
        label: &'static str,
        handle: Arc<DeviceHandle<Context>>,
        shutdown: Arc<AtomicBool>,
        queue_depth: usize,
        op: F,
    ) -> TransportResult<Self>
    where
        F: Fn(&DeviceHandle<Context>, &[u8]) -> Result<usize, rusb::Error> + Send + 'static,
    {
        let (tx, rx) = bounded(queue_depth);
        let join = thread::Builder::new()
            .name(label.to_string())
            .spawn(move || run_write_worker(label, rx, handle, shutdown, op))
            .map_err(|err| worker_spawn_error(label, err))?;
        Ok(Self {
            label,
            tx,
            join: Some(join),
        })
    }

    fn submit(&self, buf: Vec<u8>) -> TransportResult<Pending<usize>> {
        let abort = Arc::new(AtomicBool::new(false));
        let (reply, rx) = oneshot::channel();
        match self.tx.try_send(WriteWork::Transfer {
            buf,
            reply,
            abort: abort.clone(),
        }) {
            Ok(()) => Ok(Pending { abort, rx }),
            Err(TrySendError::Full(_)) => Err(queue_full_error(self.label)),
            Err(TrySendError::Disconnected(_)) => Err(disconnected_err(self.label)),
        }
    }

    fn shutdown(&mut self) {
        let _ = self.tx.try_send(WriteWork::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct ControlWorker {
    label: &'static str,
    tx: Sender<ControlWork>,
    join: Option<thread::JoinHandle<()>>,
}

impl ControlWorker {
    fn spawn(
        handle: Arc<DeviceHandle<Context>>,
        shutdown: Arc<AtomicBool>,
        interface: u8,
        queue_depth: usize,
        transfer_timeout: Duration,
    ) -> TransportResult<Self> {
        let (tx, rx) = bounded(queue_depth);
        let join = thread::Builder::new()
            .name("rusb-control".to_string())
            .spawn(move || run_control_worker(rx, handle, shutdown, interface, transfer_timeout))
            .map_err(|err| worker_spawn_error("rusb-control", err))?;
        Ok(Self {
            label: "control",
            tx,
            join: Some(join),
        })
    }

    fn submit_in(
        &self,
        request_type: u8,
        request: u8,
        len: usize,
    ) -> TransportResult<Pending<Vec<u8>>> {
        let abort = Arc::new(AtomicBool::new(false));
        let (reply, rx) = oneshot::channel();
        match self.tx.try_send(ControlWork::In {
            request_type,
            request,
            buf: vec![0u8; len],
            reply,
            abort: abort.clone(),
        }) {
            Ok(()) => Ok(Pending { abort, rx }),
            Err(TrySendError::Full(_)) => Err(queue_full_error(self.label)),
            Err(TrySendError::Disconnected(_)) => Err(disconnected_err(self.label)),
        }
    }

    fn submit_out(
        &self,
        request_type: u8,
        request: u8,
        data: Vec<u8>,
    ) -> TransportResult<Pending<usize>> {
        let abort = Arc::new(AtomicBool::new(false));
        let (reply, rx) = oneshot::channel();
        match self.tx.try_send(ControlWork::Out {
            request_type,
            request,
            data,
            reply,
            abort: abort.clone(),
        }) {
            Ok(()) => Ok(Pending { abort, rx }),
            Err(TrySendError::Full(_)) => Err(queue_full_error(self.label)),
            Err(TrySendError::Disconnected(_)) => Err(disconnected_err(self.label)),
        }
    }

    fn shutdown(&mut self) {
        let _ = self.tx.try_send(ControlWork::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

enum ReadWork {
    Transfer {
        buf: Vec<u8>,
        reply: oneshot::Sender<TransportResult<Vec<u8>>>,
        abort: Arc<AtomicBool>,
    },
    Shutdown,
}

enum WriteWork {
    Transfer {
        buf: Vec<u8>,
        reply: oneshot::Sender<TransportResult<usize>>,
        abort: Arc<AtomicBool>,
    },
    Shutdown,
}

enum ControlWork {
    In {
        request_type: u8,
        request: u8,
        buf: Vec<u8>,
        reply: oneshot::Sender<TransportResult<Vec<u8>>>,
        abort: Arc<AtomicBool>,
    },
    Out {
        request_type: u8,
        request: u8,
        data: Vec<u8>,
        reply: oneshot::Sender<TransportResult<usize>>,
        abort: Arc<AtomicBool>,
    },
    Shutdown,
}

struct Pending<T> {
    abort: Arc<AtomicBool>,
    rx: oneshot::Receiver<TransportResult<T>>,
}

fn run_read_worker<F>(
    label: &'static str,
    rx: Receiver<ReadWork>,
    handle: Arc<DeviceHandle<Context>>,
    shutdown: Arc<AtomicBool>,
    op: F,
) where
    F: Fn(&DeviceHandle<Context>, &mut [u8]) -> Result<usize, rusb::Error> + Send + 'static,
{
    while !shutdown.load(Ordering::SeqCst) {
        match rx.recv_timeout(WORKER_POLL_INTERVAL) {
            Ok(ReadWork::Transfer { buf, reply, abort }) => {
                trace!(op = label, bytes = buf.len(), "rusb worker: start");
                let result = run_read_loop(label, buf, &handle, &shutdown, &abort, &op);
                match &result {
                    Ok(data) => trace!(op = label, bytes = data.len(), "rusb worker: done"),
                    Err(err) => warn!(op = label, %err, "rusb worker: transfer failed"),
                }
                let _ = reply.send(result);
            }
            Ok(ReadWork::Shutdown) => break,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    drain_read_queue(label, rx);
}

fn run_write_worker<F>(
    label: &'static str,
    rx: Receiver<WriteWork>,
    handle: Arc<DeviceHandle<Context>>,
    shutdown: Arc<AtomicBool>,
    op: F,
) where
    F: Fn(&DeviceHandle<Context>, &[u8]) -> Result<usize, rusb::Error> + Send + 'static,
{
    while !shutdown.load(Ordering::SeqCst) {
        match rx.recv_timeout(WORKER_POLL_INTERVAL) {
            Ok(WriteWork::Transfer { buf, reply, abort }) => {
                trace!(op = label, bytes = buf.len(), "rusb worker: start");
                let result = run_write_loop(label, buf, &handle, &shutdown, &abort, &op);
                match &result {
                    Ok(bytes) => trace!(op = label, bytes, "rusb worker: done"),
                    Err(err) => warn!(op = label, %err, "rusb worker: transfer failed"),
                }
                let _ = reply.send(result);
            }
            Ok(WriteWork::Shutdown) => break,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    drain_write_queue(label, rx);
}

fn run_control_worker(
    rx: Receiver<ControlWork>,
    handle: Arc<DeviceHandle<Context>>,
    shutdown: Arc<AtomicBool>,
    interface: u8,
    transfer_timeout: Duration,
) {
    while !shutdown.load(Ordering::SeqCst) {
        match rx.recv_timeout(WORKER_POLL_INTERVAL) {
            Ok(ControlWork::In {
                request_type,
                request,
                buf,
                reply,
                abort,
            }) => {
                trace!(op = "control-in", bytes = buf.len(), "rusb worker: start");
                let result =
                    run_read_loop("control-in", buf, &handle, &shutdown, &abort, &|h, data| {
                        h.read_control(
                            request_type,
                            request,
                            0,
                            interface as u16,
                            data,
                            transfer_timeout,
                        )
                    });
                match &result {
                    Ok(data) => trace!(op = "control-in", bytes = data.len(), "rusb worker: done"),
                    Err(err) => warn!(op = "control-in", %err, "rusb worker: transfer failed"),
                }
                let _ = reply.send(result);
            }
            Ok(ControlWork::Out {
                request_type,
                request,
                data,
                reply,
                abort,
            }) => {
                trace!(op = "control-out", bytes = data.len(), "rusb worker: start");
                let result = run_write_loop(
                    "control-out",
                    data,
                    &handle,
                    &shutdown,
                    &abort,
                    &|h, payload| {
                        h.write_control(
                            request_type,
                            request,
                            0,
                            interface as u16,
                            payload,
                            transfer_timeout,
                        )
                    },
                );
                match &result {
                    Ok(bytes) => trace!(op = "control-out", bytes, "rusb worker: done"),
                    Err(err) => warn!(op = "control-out", %err, "rusb worker: transfer failed"),
                }
                let _ = reply.send(result);
            }
            Ok(ControlWork::Shutdown) => break,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    drain_control_queue(rx);
}

fn run_read_loop<F>(
    op_label: &'static str,
    mut buf: Vec<u8>,
    handle: &DeviceHandle<Context>,
    shutdown: &AtomicBool,
    abort: &AtomicBool,
    op: &F,
) -> TransportResult<Vec<u8>>
where
    F: Fn(&DeviceHandle<Context>, &mut [u8]) -> Result<usize, rusb::Error>,
{
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return Err(disconnected_err(op_label));
        }
        match op(handle, &mut buf[..]) {
            Ok(read) => {
                if read > buf.len() {
                    return Err(protocol_error(format!(
                        "{op_label} reported too many bytes ({read} > {})",
                        buf.len()
                    )));
                }
                buf.truncate(read);
                return Ok(buf);
            }
            Err(rusb::Error::Timeout | rusb::Error::Interrupted) => {
                if abort.load(Ordering::SeqCst) || shutdown.load(Ordering::SeqCst) {
                    return Err(timeout_err(op_label));
                }
            }
            Err(err) => return Err(map_rusb_error(op_label, err)),
        }
    }
}

fn run_write_loop<F>(
    op_label: &'static str,
    buf: Vec<u8>,
    handle: &DeviceHandle<Context>,
    shutdown: &AtomicBool,
    abort: &AtomicBool,
    op: &F,
) -> TransportResult<usize>
where
    F: Fn(&DeviceHandle<Context>, &[u8]) -> Result<usize, rusb::Error>,
{
    if buf.is_empty() {
        return Ok(0);
    }
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return Err(disconnected_err(op_label));
        }
        match op(handle, &buf) {
            Ok(written) => return Ok(written),
            Err(rusb::Error::Timeout | rusb::Error::Interrupted) => {
                if abort.load(Ordering::SeqCst) || shutdown.load(Ordering::SeqCst) {
                    return Err(timeout_err(op_label));
                }
            }
            Err(err) => return Err(map_rusb_error(op_label, err)),
        }
    }
}

async fn await_with_abort<T>(pending: Pending<T>, op: &'static str) -> TransportResult<T> {
    let Pending { abort, rx } = pending;
    let mut guard = AbortGuard::new(abort);
    let result = rx.await.unwrap_or_else(|_| Err(disconnected_err(op)));
    guard.disarm();
    result
}

struct AbortGuard {
    flag: Option<Arc<AtomicBool>>,
}

impl AbortGuard {
    fn new(flag: Arc<AtomicBool>) -> Self {
        Self { flag: Some(flag) }
    }

    fn disarm(&mut self) {
        self.flag.take();
    }
}

impl Drop for AbortGuard {
    fn drop(&mut self) {
        if let Some(flag) = &self.flag {
            flag.store(true, Ordering::SeqCst);
        }
    }
}

fn drain_read_queue(label: &'static str, rx: Receiver<ReadWork>) {
    for work in rx.try_iter() {
        if let ReadWork::Transfer { reply, .. } = work {
            let _ = reply.send(Err(disconnected_err(label)));
        }
    }
}

fn drain_write_queue(label: &'static str, rx: Receiver<WriteWork>) {
    for work in rx.try_iter() {
        if let WriteWork::Transfer { reply, .. } = work {
            let _ = reply.send(Err(disconnected_err(label)));
        }
    }
}

fn drain_control_queue(rx: Receiver<ControlWork>) {
    for work in rx.try_iter() {
        match work {
            ControlWork::In { reply, .. } => {
                let _ = reply.send(Err(disconnected_err("control-in")));
            }
            ControlWork::Out { reply, .. } => {
                let _ = reply.send(Err(disconnected_err("control-out")));
            }
            ControlWork::Shutdown => {}
        }
    }
}

struct DiscoveredDevice {
    handle: DeviceHandle<Context>,
    interface: u8,
    interrupt_in: u8,
    interrupt_out: u8,
    bulk_in: u8,
    bulk_out: u8,
}

struct EndpointAddresses {
    interface: u8,
    interrupt_in: u8,
    interrupt_out: u8,
    bulk_in: u8,
    bulk_out: u8,
}

fn find_matching_device(
    vendor_id: Option<u16>,
    product_id: Option<u16>,
    class: u8,
    subclass: u8,
    protocol: u8,
) -> TransportResult<DiscoveredDevice> {
    let context = Context::new().map_err(|err| map_rusb_error("create libusb context", err))?;
    let devices = context
        .devices()
        .map_err(|err| map_rusb_error("list devices", err))?;

    for device in devices.iter() {
        let desc = device
            .device_descriptor()
            .map_err(|err| map_rusb_error("read device descriptor", err))?;
        if let Some(v) = vendor_id {
            if desc.vendor_id() != v {
                continue;
            }
        }
        if let Some(p) = product_id {
            if desc.product_id() != p {
                continue;
            }
        }

        if let Some(endpoints) = select_endpoints(&device, class, subclass, protocol)? {
            let handle = device
                .open()
                .map_err(|err| map_rusb_error("open device", err))?;
            return Ok(DiscoveredDevice {
                handle,
                interface: endpoints.interface,
                interrupt_in: endpoints.interrupt_in,
                interrupt_out: endpoints.interrupt_out,
                bulk_in: endpoints.bulk_in,
                bulk_out: endpoints.bulk_out,
            });
        }
    }

    Err(TransportError::new(TransportErrorKind::NotReady))
}

fn select_endpoints(
    device: &Device<Context>,
    class: u8,
    subclass: u8,
    protocol: u8,
) -> TransportResult<Option<EndpointAddresses>> {
    let config = device
        .active_config_descriptor()
        .map_err(|err| map_rusb_error("read active configuration", err))?;
    for interface in config.interfaces() {
        for desc in interface.descriptors() {
            if desc.class_code() != class
                || desc.sub_class_code() != subclass
                || desc.protocol_code() != protocol
            {
                continue;
            }

            let mut interrupt_in = None;
            let mut interrupt_out = None;
            let mut bulk_in = None;
            let mut bulk_out = None;

            for ep in desc.endpoint_descriptors() {
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

            if let (Some(interrupt_in), Some(interrupt_out), Some(bulk_in), Some(bulk_out)) =
                (interrupt_in, interrupt_out, bulk_in, bulk_out)
            {
                return Ok(Some(EndpointAddresses {
                    interface: desc.interface_number(),
                    interrupt_in,
                    interrupt_out,
                    bulk_in,
                    bulk_out,
                }));
            }
        }
    }

    Ok(None)
}

fn map_rusb_error(op: &str, err: rusb::Error) -> TransportError {
    let kind = match err {
        rusb::Error::Timeout => TransportErrorKind::Timeout,
        rusb::Error::NoDevice => TransportErrorKind::Disconnected,
        rusb::Error::Pipe | rusb::Error::Overflow => TransportErrorKind::Protocol,
        rusb::Error::NotSupported => TransportErrorKind::Unsupported,
        _ => TransportErrorKind::Other,
    };
    TransportError::with_message(kind, format!("{op}: {err}"))
}

fn join_error(op: &str, err: task::JoinError) -> TransportError {
    TransportError::with_message(
        TransportErrorKind::Other,
        format!("{op} task join failed: {err}"),
    )
}

fn protocol_error(message: impl Into<String>) -> TransportError {
    TransportError::with_message(TransportErrorKind::Protocol, message)
}

fn disconnected_err(op: &str) -> TransportError {
    TransportError::with_message(
        TransportErrorKind::Disconnected,
        format!("{op} worker not running"),
    )
}

fn timeout_err(op: &str) -> TransportError {
    TransportError::with_message(
        TransportErrorKind::Timeout,
        format!("{op} transfer aborted"),
    )
}

fn queue_full_error(op: &str) -> TransportError {
    TransportError::with_message(TransportErrorKind::Timeout, format!("{op} queue is full"))
}

fn worker_spawn_error(op: &str, err: std::io::Error) -> TransportError {
    TransportError::with_message(
        TransportErrorKind::Other,
        format!("{op} worker spawn failed: {err}"),
    )
}
