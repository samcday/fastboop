use anyhow::{anyhow, ensure, Context, Result};
use clap::{Parser, ValueEnum};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request as HttpRequest, Response as HttpResponse, Server, StatusCode};
use metrics_exporter_prometheus::PrometheusBuilder;
use smoo_gadget_core::{
    ConfigExport, ConfigExportsV0, ControlIo, DeviceHandle, DmaHeap, ExportController, ExportFlags,
    ExportReconcileContext, ExportSpec, ExportState, FunctionfsEndpoints, GadgetConfig,
    GadgetControl, GadgetStatusReport, IoPumpHandle, IoWork, LinkCommand, LinkController,
    LinkState, PersistedExportRecord, RuntimeTunables, SetupCommand, SetupPacket, SmooGadget,
    SmooUblk, SmooUblkDevice, StateStore, UblkIoRequest, UblkOp, UblkQueueRuntime,
};
use smoo_proto::{Ident, OpCode, Request, Response, SMOO_STATUS_REQUEST, SMOO_STATUS_REQ_TYPE};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    fs::File,
    io,
    net::SocketAddr,
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncReadExt,
    signal,
    signal::unix::{signal as unix_signal, SignalKind},
    sync::{
        mpsc,
        mpsc::error::{TryRecvError, TrySendError},
        oneshot, watch, Mutex, Notify, RwLock,
    },
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};
use usb_gadget::{
    function::custom::{
        CtrlReceiver, CtrlReq, CtrlSender, Custom, CustomBuilder, Endpoint, EndpointDirection,
        Event, Interface, TransferType,
    },
    Class, Config, Gadget, Id, RegGadget, Strings,
};

const SMOO_CLASS: u8 = 0xFF;
const SMOO_SUBCLASS: u8 = 0x53;
const SMOO_PROTOCOL: u8 = 0x4D;
const FASTBOOT_SUBCLASS: u8 = 0x42;
const FASTBOOT_PROTOCOL: u8 = 0x03;
const DEFAULT_MAX_IO_BYTES: usize = 4 * 1024 * 1024;
const CONFIG_CHANNEL_DEPTH: usize = 32;
const QUEUE_CHANNEL_DEPTH: usize = 128;
const QUEUE_BATCH_MAX: usize = 32;
const OUTSTANDING_BATCH_MAX: usize = 32;
const IDLE_INTERVAL_MS: u64 = 10;
const LIVENESS_INTERVAL_MS: u64 = 500;
const MAINTENANCE_SLICE_MS: u64 = 200;
const RECONCILE_TIMEOUT_MS: u64 = 200;
const GRACEFUL_SHUTDOWN_TIMEOUT_MS: u64 = 5_000;

#[derive(Debug, Parser)]
#[command(name = "smoo-gadget-cli", version)]
#[command(about = "Expose a smoo gadget backed by FunctionFS + ublk", long_about = None)]
pub struct Args {
    /// USB vendor ID for the gadget (hex).
    #[arg(long, value_name = "HEX", default_value = "0xDEAD", value_parser = parse_hex_u16)]
    pub vendor_id: u16,
    /// USB product ID for the gadget (hex).
    #[arg(long, value_name = "HEX", default_value = "0xBEEF", value_parser = parse_hex_u16)]
    pub product_id: u16,
    /// Number of ublk queues to configure.
    #[arg(long, default_value_t = 1)]
    pub queue_count: u16,
    /// Depth of each ublk queue.
    #[arg(long, default_value_t = 16)]
    pub queue_depth: u16,
    /// Maximum per-I/O size in bytes to advertise to ublk (block-aligned).
    #[arg(long = "max-io", value_name = "BYTES")]
    pub max_io_bytes: Option<usize>,
    /// Opt-in to the experimental DMA-BUF fast path when supported by the kernel.
    #[arg(long)]
    pub experimental_dma_buf: bool,
    /// DMA-HEAP to allocate from when DMA-BUF mode is enabled.
    #[arg(long, value_enum, default_value_t = DmaHeapSelection::System)]
    pub dma_heap: DmaHeapSelection,
    /// Path to the recovery state file. When unset, crash recovery is disabled.
    #[arg(long, value_name = "PATH")]
    pub state_file: Option<PathBuf>,
    /// Adopt existing ublk devices via user recovery.
    #[arg(long)]
    pub adopt: bool,
    /// Expose Prometheus metrics on this TCP port (0 disables).
    #[arg(long, default_value_t = 0)]
    pub metrics_port: u16,
    /// Use an existing FunctionFS directory and skip configfs management.
    #[arg(long, value_name = "PATH")]
    pub ffs_dir: Option<PathBuf>,
    /// Use fastboot-style interface subclass/protocol for restrictive WebUSB flows.
    #[arg(long)]
    pub mimic_fastboot: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum DmaHeapSelection {
    System,
    Cma,
    Reserved,
}

impl From<DmaHeapSelection> for DmaHeap {
    fn from(value: DmaHeapSelection) -> Self {
        match value {
            DmaHeapSelection::System => DmaHeap::System,
            DmaHeapSelection::Cma => DmaHeap::Cma,
            DmaHeapSelection::Reserved => DmaHeap::Reserved,
        }
    }
}

impl Default for Args {
    fn default() -> Self {
        Self {
            vendor_id: 0xDEAD,
            product_id: 0xBEEF,
            queue_count: 1,
            queue_depth: 16,
            max_io_bytes: None,
            experimental_dma_buf: false,
            dma_heap: DmaHeapSelection::System,
            state_file: None,
            adopt: false,
            metrics_port: 0,
            ffs_dir: None,
            mimic_fastboot: false,
        }
    }
}

pub async fn run_from_env() -> Result<()> {
    let args = Args::parse();
    let result = run_impl(args).await;
    if let Err(err) = &result {
        error!(error = ?err, "smoo-gadget-cli exiting with error");
    }
    result
}

pub async fn run_with_args(args: Args) -> Result<()> {
    run_impl(args).await
}

async fn run_impl(args: Args) -> Result<()> {
    let metrics_shutdown = CancellationToken::new();
    let metrics_task = spawn_metrics_listener(args.metrics_port, metrics_shutdown.clone())?;
    let mut ublk = SmooUblk::new().context("init ublk")?;
    let mut state_store = if let Some(path) = args.state_file.as_ref() {
        info!(path = ?path, "state file configured");
        match StateStore::load(path.clone()) {
            Ok(store) => store,
            Err(err) => {
                warn!(path = ?path, error = ?err, "failed to load state file; starting new session");
                StateStore::new_with_path(path.clone())
            }
        }
    } else {
        debug!("state file disabled; crash recovery off");
        StateStore::new()
    };

    initialize_session(&mut ublk, &mut state_store).await?;
    if args.adopt {
        adopt_prepare(&mut ublk, &mut state_store).await?;
    }

    let (custom, endpoints, _gadget_guard, ffs_dir) =
        setup_configfs(&args).context("setup ConfigFS")?;

    let ident = Ident::new(0, 1);
    let dma_heap = args.experimental_dma_buf.then(|| args.dma_heap.into());
    let max_io_bytes = args.max_io_bytes.unwrap_or(DEFAULT_MAX_IO_BYTES);
    let gadget_config = GadgetConfig::new(
        ident,
        args.queue_count,
        args.queue_depth,
        max_io_bytes,
        dma_heap,
    );
    let gadget =
        Arc::new(SmooGadget::new(endpoints, gadget_config).context("init smoo gadget core")?);
    info!(
        ident_major = ident.major,
        ident_minor = ident.minor,
        queues = args.queue_count,
        depth = args.queue_depth,
        max_io_bytes = max_io_bytes,
        "smoo gadget initialized"
    );

    let control_handler = gadget.control_handler();
    let (control_tx, control_rx) = mpsc::channel(CONFIG_CHANNEL_DEPTH);
    let (control_stop_tx, control_stop_rx) = watch::channel(false);

    let exports = build_initial_exports(&state_store);
    let initial_export_count = count_active_exports(&exports);
    let status = GadgetStatusShared::new(GadgetStatus::new(
        state_store.session_id(),
        initial_export_count,
    ));
    let ep0_signals = Ep0Signals::new();
    let control_task = tokio::spawn(control_loop(
        custom,
        control_handler,
        status.clone(),
        ep0_signals.clone(),
        control_stop_rx,
        control_tx,
    ));
    let tunables = RuntimeTunables {
        queue_count: args.queue_count,
        queue_depth: args.queue_depth,
        max_io_bytes: args.max_io_bytes,
        dma_heap,
    };
    let link = LinkController::new(Duration::from_secs(3));
    let io_pump_capacity = args.queue_count as usize * args.queue_depth as usize;
    let runtime = RuntimeState {
        state_store,
        status,
        exports,
        queue_tasks: HashMap::new(),
        tunables,
        gadget: Some(gadget),
        io_pump: None,
        io_pump_task: None,
        io_pump_capacity,
        gadget_config,
        ffs_dir,
        reconcile_queue: VecDeque::new(),
        data_plane_epoch: 0,
    };
    let result = run_event_loop(
        &mut ublk,
        runtime,
        control_rx,
        link,
        ep0_signals,
        control_stop_tx.clone(),
    )
    .await;
    metrics_shutdown.cancel();
    if let Some(task) = metrics_task {
        let _ = task.await;
    }
    let _ = control_stop_tx.send(true);
    control_task.abort();
    let _ = control_task.await;
    result
}

fn spawn_metrics_listener(
    port: u16,
    shutdown: CancellationToken,
) -> Result<Option<JoinHandle<()>>> {
    if port == 0 {
        return Ok(None);
    }
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .context("install Prometheus metrics recorder")?;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let task = tokio::spawn(async move {
        let make_svc = make_service_fn(move |_conn| {
            let handle = handle.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req: HttpRequest<Body>| {
                    let handle = handle.clone();
                    async move {
                        if req.uri().path() != "/metrics" {
                            return Ok::<_, Infallible>(
                                HttpResponse::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Body::from("not found"))
                                    .unwrap(),
                            );
                        }
                        let body = handle.render();
                        Ok::<_, Infallible>(
                            HttpResponse::builder()
                                .status(StatusCode::OK)
                                .header(hyper::header::CONTENT_TYPE, "text/plain; version=0.0.4")
                                .body(Body::from(body))
                                .unwrap(),
                        )
                    }
                }))
            }
        });

        let server = Server::bind(&addr).serve(make_svc);
        let graceful = server.with_graceful_shutdown(async {
            shutdown.cancelled().await;
        });

        if let Err(err) = graceful.await {
            warn!(error = %err, %addr, "metrics server error");
        }
    });

    info!(%addr, "metrics listener started");
    Ok(Some(task))
}

#[derive(Clone, Copy, Debug)]
struct GadgetStatus {
    session_id: u64,
    export_count: u32,
}

impl GadgetStatus {
    fn new(session_id: u64, export_count: u32) -> Self {
        Self {
            session_id,
            export_count,
        }
    }
}

#[derive(Clone)]
struct GadgetStatusShared {
    inner: Arc<RwLock<GadgetStatus>>,
}

impl GadgetStatusShared {
    fn new(initial: GadgetStatus) -> Self {
        Self {
            inner: Arc::new(RwLock::new(initial)),
        }
    }

    async fn snapshot(&self) -> GadgetStatus {
        *self.inner.read().await
    }

    async fn report(&self) -> GadgetStatusReport {
        let snapshot = self.snapshot().await;
        GadgetStatusReport::new(snapshot.session_id, snapshot.export_count)
    }

    async fn set_export_count(&self, export_count: u32) {
        let mut guard = self.inner.write().await;
        guard.export_count = export_count;
    }
}

#[derive(Clone)]
struct Ep0Signals {
    status_seq: Arc<AtomicU64>,
    lifecycle_seq: Arc<AtomicU64>,
    lifecycle: Arc<Mutex<Vec<Event<'static>>>>,
    notify: Arc<Notify>,
}

impl Ep0Signals {
    fn new() -> Self {
        Self {
            status_seq: Arc::new(AtomicU64::new(0)),
            lifecycle_seq: Arc::new(AtomicU64::new(0)),
            lifecycle: Arc::new(Mutex::new(Vec::new())),
            notify: Arc::new(Notify::new()),
        }
    }

    fn status_seq(&self) -> u64 {
        self.status_seq.load(Ordering::Relaxed)
    }

    fn lifecycle_seq(&self) -> u64 {
        self.lifecycle_seq.load(Ordering::Relaxed)
    }

    fn mark_status_ping(&self) {
        self.status_seq.fetch_add(1, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    async fn push_lifecycle(&self, event: Event<'static>) {
        let mut guard = self.lifecycle.lock().await;
        guard.push(event);
        self.lifecycle_seq.fetch_add(1, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    async fn take_lifecycle(&self) -> Vec<Event<'static>> {
        let mut guard = self.lifecycle.lock().await;
        guard.drain(..).collect()
    }

    fn notifier(&self) -> Arc<Notify> {
        self.notify.clone()
    }
}

struct RuntimeState {
    state_store: StateStore,
    status: GadgetStatusShared,
    exports: HashMap<u32, ExportController>,
    queue_tasks: HashMap<u32, QueueTaskSet>,
    tunables: RuntimeTunables,
    gadget: Option<Arc<SmooGadget>>,
    io_pump: Option<IoPumpHandle>,
    io_pump_task: Option<JoinHandle<()>>,
    io_pump_capacity: usize,
    gadget_config: GadgetConfig,
    ffs_dir: PathBuf,
    reconcile_queue: VecDeque<u32>,
    data_plane_epoch: u64,
}

impl RuntimeState {
    fn status(&self) -> &GadgetStatusShared {
        &self.status
    }

    fn state_store(&mut self) -> &mut StateStore {
        &mut self.state_store
    }
}

type QueueSender = mpsc::Sender<QueueEvent>;

struct QueueTaskSet {
    stop: watch::Sender<bool>,
    handles: Vec<JoinHandle<()>>,
}

impl QueueTaskSet {
    async fn shutdown(self) {
        let _ = self.stop.send(true);
        for handle in self.handles {
            let _ = handle.await;
        }
    }

    fn abort(self) {
        let _ = self.stop.send(true);
        for handle in self.handles {
            handle.abort();
        }
    }
}

enum QueueEvent {
    Request {
        export_id: u32,
        dev_id: u32,
        request: UblkIoRequest,
        queues: Arc<UblkQueueRuntime>,
    },
    QueueError {
        export_id: u32,
        dev_id: u32,
        error: anyhow::Error,
    },
}

#[derive(Debug)]
enum DataPlaneEvent {
    IoError { epoch: u64, error: io::Error },
}

fn notify_data_plane_error(tx: &mpsc::UnboundedSender<DataPlaneEvent>, epoch: u64, err: io::Error) {
    let _ = tx.send(DataPlaneEvent::IoError { epoch, error: err });
}

struct OutstandingRequest {
    dev_id: u32,
    request: UblkIoRequest,
    queues: Arc<UblkQueueRuntime>,
}

#[derive(Clone)]
struct InflightRequest {
    export_id: u32,
    request_id: u32,
    request: UblkIoRequest,
    queues: Arc<UblkQueueRuntime>,
    req_len: usize,
    block_size: usize,
    sent: bool,
    response_seen: bool,
}

fn update_request_gauges(map: &HashMap<u32, HashMap<u32, InflightRequest>>) {
    let pending = map.values().map(|m| m.len()).sum::<usize>();
    let inflight = map
        .values()
        .map(|m| m.values().filter(|req| req.sent).count())
        .sum::<usize>();
    smoo_gadget_core::record_pending_requests(pending);
    smoo_gadget_core::record_inflight_requests(inflight);
}

async fn take_inflight_entry(
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    export_id: u32,
    request_id: u32,
) -> Option<InflightRequest> {
    let mut guard = inflight.lock().await;
    let entry = guard
        .get_mut(&export_id)
        .and_then(|map| map.remove(&request_id));
    if let Some(map) = guard.get(&export_id) {
        if map.is_empty() {
            guard.remove(&export_id);
        }
    }
    update_request_gauges(&guard);
    entry
}

enum ResponseLookup {
    Unknown,
    Duplicate,
    Fresh(InflightRequest),
}

async fn mark_response_seen(
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    export_id: u32,
    request_id: u32,
) -> ResponseLookup {
    let mut guard = inflight.lock().await;
    let Some(entry) = guard
        .get_mut(&export_id)
        .and_then(|map| map.get_mut(&request_id))
    else {
        return ResponseLookup::Unknown;
    };
    if entry.response_seen {
        return ResponseLookup::Duplicate;
    }
    entry.response_seen = true;
    ResponseLookup::Fresh(entry.clone())
}

async fn mark_request_sent(
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    export_id: u32,
    request_id: u32,
) {
    let mut guard = inflight.lock().await;
    if let Some(entry) = guard
        .get_mut(&export_id)
        .and_then(|map| map.get_mut(&request_id))
    {
        entry.sent = true;
    }
    update_request_gauges(&guard);
}

fn build_initial_exports(state_store: &StateStore) -> HashMap<u32, ExportController> {
    let mut exports = HashMap::new();
    for record in state_store.records() {
        if exports.contains_key(&record.export_id) {
            warn!(
                export_id = record.export_id,
                "duplicate export_id in state store; skipping"
            );
            continue;
        }
        let state = match record.assigned_dev_id {
            Some(dev_id) => ExportState::RecoveringPending { dev_id },
            None => ExportState::New,
        };
        exports.insert(
            record.export_id,
            ExportController::new(record.export_id, record.spec.clone(), state),
        );
    }
    exports
}

fn spawn_queue_tasks(
    export_id: u32,
    dev_id: u32,
    queues: Arc<UblkQueueRuntime>,
    tx: QueueSender,
) -> QueueTaskSet {
    let (stop, stop_rx) = watch::channel(false);
    let mut handles = Vec::new();
    for queue_id in 0..queues.queue_count() {
        let mut stop_rx = stop_rx.clone();
        let queues = queues.clone();
        let tx = tx.clone();
        handles.push(tokio::spawn(async move {
            queue_task_loop(export_id, dev_id, queue_id, queues, &mut stop_rx, tx).await;
        }));
    }
    QueueTaskSet { stop, handles }
}

async fn queue_task_loop(
    export_id: u32,
    dev_id: u32,
    queue_id: u16,
    queues: Arc<UblkQueueRuntime>,
    stop: &mut watch::Receiver<bool>,
    tx: QueueSender,
) {
    loop {
        tokio::select! {
            _changed = stop.changed() => {
                break;
            }
            req = queues.next_io(queue_id) => {
                match req {
                    Ok(request) => {
                        let send_fut = tx.send(QueueEvent::Request { export_id, dev_id, request, queues: queues.clone() });
                        tokio::select! {
                            res = send_fut => {
                                if res.is_err() {
                                    break;
                                }
                            }
                            _ = stop.changed() => break,
                        }
                    }
                    Err(err) => {
                        if !*stop.borrow() {
                            let send_fut = tx.send(QueueEvent::QueueError { export_id, dev_id, error: err });
                            let _ = tokio::select! {
                                res = send_fut => res,
                                _ = stop.changed() => Ok(()),
                            };
                        }
                        break;
                    }
                }
            }
        }
    }
}

async fn sync_queue_tasks(runtime: &mut RuntimeState, queue_tx: &QueueSender) {
    if runtime.io_pump.is_none() {
        stop_all_queue_tasks(runtime).await;
        return;
    }
    let mut to_stop: Vec<u32> = runtime
        .queue_tasks
        .keys()
        .cloned()
        .filter(|export_id| !runtime.exports.contains_key(export_id))
        .collect();

    for (&export_id, controller) in runtime.exports.iter() {
        let should_run = controller
            .device_handle()
            .map(|h| {
                matches!(
                    h,
                    DeviceHandle::Online { .. } | DeviceHandle::Starting { .. }
                )
            })
            .unwrap_or(false);
        let running = runtime.queue_tasks.contains_key(&export_id);
        if should_run && runtime.io_pump.is_some() && !running {
            if let Some(handle) = controller.device_handle() {
                if let Some(queues) = handle.queues() {
                    let tasks =
                        spawn_queue_tasks(export_id, handle.dev_id(), queues, queue_tx.clone());
                    runtime.queue_tasks.insert(export_id, tasks);
                }
            }
        } else if !should_run && running {
            to_stop.push(export_id);
        }
    }

    for export_id in to_stop {
        if let Some(tasks) = runtime.queue_tasks.remove(&export_id) {
            tasks.shutdown().await;
        }
    }
}

async fn stop_all_queue_tasks(runtime: &mut RuntimeState) {
    let mut tasks = std::mem::take(&mut runtime.queue_tasks);
    for (_, taskset) in tasks.drain() {
        taskset.shutdown().await;
    }
}

async fn ensure_data_plane(
    runtime: &mut RuntimeState,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    response_task: &mut Option<JoinHandle<()>>,
    data_plane_tx: &mpsc::UnboundedSender<DataPlaneEvent>,
) {
    if runtime.gadget.is_none() {
        if let Some(pump) = runtime.io_pump.take() {
            drop(pump);
        }
        if let Some(task) = runtime.io_pump_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(handle) = response_task.take() {
            handle.abort();
            let _ = handle.await;
        }
        return;
    }

    if runtime.io_pump.is_none() {
        if let Some(gadget) = runtime.gadget.clone() {
            let (handle, task) = IoPumpHandle::spawn(gadget, runtime.io_pump_capacity);
            runtime.io_pump = Some(handle);
            runtime.io_pump_task = Some(task);
        }
    }
    if response_task.is_none() {
        if let Some(gadget) = runtime.gadget.clone() {
            let inflight_map = inflight.clone();
            let interrupt_out = gadget.response_reader();
            *response_task = Some(tokio::spawn(response_loop(
                gadget,
                interrupt_out,
                inflight_map,
                data_plane_tx.clone(),
                runtime.data_plane_epoch,
            )));
        }
    }
}

async fn drain_ep0_signals(
    ep0_signals: &Ep0Signals,
    last_status_seq: &mut u64,
    last_lifecycle_seq: &mut u64,
    link: &mut LinkController,
) {
    let status_seq = ep0_signals.status_seq();
    if status_seq != *last_status_seq {
        *last_status_seq = status_seq;
        link.on_status_ping();
    }
    if ep0_signals.lifecycle_seq() != *last_lifecycle_seq {
        let events = ep0_signals.take_lifecycle().await;
        *last_lifecycle_seq = ep0_signals.lifecycle_seq();
        for event in events {
            link.on_ep0_event(event);
        }
    }
}

async fn drain_queue_batch(
    runtime: &mut RuntimeState,
    link: &mut LinkController,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    data_plane_tx: &mpsc::UnboundedSender<DataPlaneEvent>,
    queue_rx: &mut mpsc::Receiver<QueueEvent>,
) -> Result<()> {
    let mut processed = 0;
    while processed < QUEUE_BATCH_MAX.saturating_sub(1) {
        match queue_rx.try_recv() {
            Ok(evt) => {
                handle_queue_event(runtime, link, inflight, outstanding, data_plane_tx, evt)
                    .await?;
                processed += 1;
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
        }
    }
    if processed >= QUEUE_BATCH_MAX.saturating_sub(1) {
        trace!(processed, "queue batch truncated; will continue next tick");
    }
    Ok(())
}

fn pop_next_outstanding(
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
) -> Option<(u32, u16, u16, OutstandingRequest)> {
    let (export_id, (queue_id, tag)) = outstanding.iter().find_map(|(export_id, reqs)| {
        reqs.keys()
            .next()
            .map(|(queue, tag)| (*export_id, (*queue, *tag)))
    })?;
    let pending = outstanding
        .get_mut(&export_id)
        .and_then(|map| map.remove(&(queue_id, tag)))?;
    if let Some(map) = outstanding.get(&export_id) {
        if map.is_empty() {
            outstanding.remove(&export_id);
        }
    }
    Some((export_id, queue_id, tag, pending))
}

async fn drain_outstanding_bounded(
    runtime: &mut RuntimeState,
    link: &mut LinkController,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    data_plane_tx: &mpsc::UnboundedSender<DataPlaneEvent>,
    deadline: Instant,
) -> Result<()> {
    if outstanding.is_empty() {
        return Ok(());
    }
    if link.state() != LinkState::Online {
        trace!(
            outstanding_exports = outstanding.len(),
            "link not online; deferring outstanding IO drain"
        );
        return Ok(());
    }
    let Some(pump) = runtime.io_pump.as_ref() else {
        trace!(
            outstanding_exports = outstanding.len(),
            "no gadget endpoints available; deferring outstanding IO drain"
        );
        return Ok(());
    };

    let mut processed = 0usize;
    while processed < OUTSTANDING_BATCH_MAX && Instant::now() < deadline {
        let Some((export_id, _queue_id, _tag, pending)) = pop_next_outstanding(outstanding) else {
            break;
        };
        let Some(ctrl) = runtime.exports.get(&export_id) else {
            let _ = pending.queues.complete_io(pending.request, -libc::ENODEV);
            continue;
        };
        let Some(handle) = ctrl.device_handle() else {
            park_request(
                outstanding,
                export_id,
                pending.dev_id,
                pending.queues.clone(),
                pending.request,
            );
            break;
        };
        if handle.dev_id() != pending.dev_id {
            trace!(
                export_id,
                stale_dev = pending.dev_id,
                current_dev = handle.dev_id(),
                "dropping outstanding for stale device"
            );
            continue;
        }
        if !handle.is_online() {
            park_request(
                outstanding,
                export_id,
                pending.dev_id,
                pending.queues.clone(),
                pending.request,
            );
            break;
        }
        let Some(queues) = handle.queues() else {
            park_request(
                outstanding,
                export_id,
                pending.dev_id,
                pending.queues.clone(),
                pending.request,
            );
            break;
        };
        let req = pending.request;
        trace!(
            export_id,
            dev_id = pending.dev_id,
            queue = req.queue_id,
            tag = req.tag,
            "replaying outstanding IO to host"
        );
        if let Err(err) = handle_request(
            pump.clone(),
            data_plane_tx.clone(),
            runtime.data_plane_epoch,
            inflight,
            export_id,
            queues.clone(),
            req,
        )
        .await
        {
            let io_err = io_error_from_anyhow(&err);
            link.on_io_error(&io_err);
            park_request(
                outstanding,
                export_id,
                pending.dev_id,
                pending.queues.clone(),
                req,
            );
            warn!(
                export_id,
                queue = req.queue_id,
                tag = req.tag,
                error = ?err,
                "link error replaying outstanding IO; parked again"
            );
            break;
        }
        processed += 1;
    }

    if !outstanding.is_empty() {
        trace!(
            remaining_exports = outstanding.len(),
            processed,
            "outstanding drain truncated"
        );
    }
    Ok(())
}

async fn run_reconcile_slice(
    ublk: &mut SmooUblk,
    runtime: &mut RuntimeState,
    deadline: Instant,
) -> Result<()> {
    let now = Instant::now();
    for (&export_id, ctrl) in runtime.exports.iter() {
        if ctrl.needs_reconcile(now) && !runtime.reconcile_queue.contains(&export_id) {
            runtime.reconcile_queue.push_back(export_id);
        }
    }

    while Instant::now() < deadline {
        let Some(export_id) = runtime.reconcile_queue.pop_front() else {
            break;
        };
        let now = Instant::now();
        let needs_reconcile = runtime
            .exports
            .get(&export_id)
            .is_some_and(|ctrl| ctrl.needs_reconcile(now));
        if !needs_reconcile {
            continue;
        }

        let tunables = runtime.tunables;
        let mut controller = match runtime.exports.remove(&export_id) {
            Some(ctrl) => ctrl,
            None => continue,
        };
        {
            let mut cx = ExportReconcileContext {
                ublk,
                state_store: runtime.state_store(),
                tunables,
            };
            match tokio::time::timeout(
                Duration::from_millis(RECONCILE_TIMEOUT_MS),
                controller.reconcile(&mut cx),
            )
            .await
            {
                Ok(res) => res?,
                Err(_) => {
                    warn!(export_id, "reconcile timed out; backing off");
                    controller.fail_device("reconcile timed out".to_string());
                }
            }
        }
        let needs_more = controller.needs_reconcile(Instant::now());
        runtime.exports.insert(export_id, controller);
        if needs_more {
            runtime.reconcile_queue.push_back(export_id);
        }

        if Instant::now() >= deadline {
            break;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn drive_runtime(
    ublk: &mut SmooUblk,
    runtime: &mut RuntimeState,
    link: &mut LinkController,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    queue_tx: Option<&QueueSender>,
    response_task: &mut Option<JoinHandle<()>>,
    data_plane_tx: &mpsc::UnboundedSender<DataPlaneEvent>,
    allow_reconcile: bool,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_millis(MAINTENANCE_SLICE_MS);
    link.tick(Instant::now());
    process_link_commands(runtime, link, inflight, outstanding, response_task).await?;
    ensure_data_plane(runtime, inflight, response_task, data_plane_tx).await;
    if let Some(tx) = queue_tx {
        sync_queue_tasks(runtime, tx).await;
    }
    drain_outstanding_bounded(
        runtime,
        link,
        inflight,
        outstanding,
        data_plane_tx,
        deadline,
    )
    .await?;
    if allow_reconcile {
        run_reconcile_slice(ublk, runtime, deadline).await?;
    }
    let active_count = count_active_exports(&runtime.exports);
    runtime.status().set_export_count(active_count).await;
    Ok(())
}

async fn handle_config_message(
    ublk: &mut SmooUblk,
    runtime: &mut RuntimeState,
    link: &mut LinkController,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    response_task: &mut Option<JoinHandle<()>>,
    config: ConfigExportsV0,
) -> Result<()> {
    park_inflight_requests(inflight, outstanding).await;
    apply_config(ublk, runtime, config).await?;
    prune_outstanding_for_missing_exports(outstanding, &runtime.exports);
    process_link_commands(runtime, link, inflight, outstanding, response_task).await?;
    Ok(())
}

async fn stop_accepting_new_io(runtime: &mut RuntimeState, queue_tx: &mut Option<QueueSender>) {
    stop_all_queue_tasks(runtime).await;
    *queue_tx = None;
}

enum ShutdownState {
    Running,
    Graceful { deadline: Instant },
    Forceful,
}

async fn run_event_loop(
    ublk: &mut SmooUblk,
    mut runtime: RuntimeState,
    mut control_rx: mpsc::Receiver<ConfigExportsV0>,
    mut link: LinkController,
    ep0_signals: Ep0Signals,
    control_stop: watch::Sender<bool>,
) -> Result<()> {
    let mut shutdown = Some(Box::pin(signal::ctrl_c()));
    let mut hup = unix_signal(SignalKind::hangup()).context("install SIGHUP handler")?;
    let idle_sleep = tokio::time::sleep(Duration::from_millis(IDLE_INTERVAL_MS));
    tokio::pin!(idle_sleep);
    let mut liveness_tick = tokio::time::interval(Duration::from_millis(LIVENESS_INTERVAL_MS));
    liveness_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut outstanding: HashMap<u32, HashMap<(u16, u16), OutstandingRequest>> = HashMap::new();
    let (queue_tx_init, mut queue_rx) = mpsc::channel::<QueueEvent>(QUEUE_CHANNEL_DEPTH);
    let mut queue_tx: Option<QueueSender> = Some(queue_tx_init);
    let inflight: Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut response_task: Option<JoinHandle<()>> = None;
    let (data_plane_tx, mut data_plane_rx) = mpsc::unbounded_channel::<DataPlaneEvent>();
    let ep0_notify = ep0_signals.notifier();

    let mut io_error = None;
    let mut recovery_exit = false;
    let mut shutdown_state = ShutdownState::Running;
    let mut last_status_seq = ep0_signals.status_seq();
    let mut last_lifecycle_seq = ep0_signals.lifecycle_seq();

    loop {
        idle_sleep
            .as_mut()
            .reset(tokio::time::Instant::now() + Duration::from_millis(IDLE_INTERVAL_MS));

        drain_ep0_signals(
            &ep0_signals,
            &mut last_status_seq,
            &mut last_lifecycle_seq,
            &mut link,
        )
        .await;
        process_link_commands(
            &mut runtime,
            &mut link,
            &inflight,
            &mut outstanding,
            &mut response_task,
        )
        .await?;
        // Make sure the data plane (io pump + response reader) is up before we
        // start draining queue events so early responses can't be missed.
        ensure_data_plane(&mut runtime, &inflight, &mut response_task, &data_plane_tx).await;

        if response_task
            .as_ref()
            .is_some_and(|task| task.is_finished())
        {
            if let Some(task) = response_task.take() {
                let _ = task.await;
            }
            notify_data_plane_error(
                &data_plane_tx,
                runtime.data_plane_epoch,
                io::Error::other("response loop exited"),
            );
        }
        if runtime
            .io_pump_task
            .as_ref()
            .is_some_and(|task| task.is_finished())
        {
            if let Some(task) = runtime.io_pump_task.take() {
                let _ = task.await;
            }
            notify_data_plane_error(
                &data_plane_tx,
                runtime.data_plane_epoch,
                io::Error::other("io pump exited"),
            );
        }

        if let ShutdownState::Graceful { deadline } = shutdown_state {
            if Instant::now() >= deadline {
                warn!("graceful shutdown timed out; forcing shutdown");
                shutdown_state = ShutdownState::Forceful;
            }
        }

        if matches!(shutdown_state, ShutdownState::Forceful) {
            break;
        }

        let ep0_notified = ep0_notify.notified();
        tokio::pin!(ep0_notified);
        tokio::select! { biased;
            _ = async {
                if let Some(fut) = shutdown.as_mut() {
                    let _ = fut.as_mut().await;
                }
            }, if shutdown.is_some() => {
                shutdown = None;
                match shutdown_state {
                    ShutdownState::Running => {
                        info!("shutdown signal received; entering graceful shutdown");
                        shutdown_state = ShutdownState::Graceful {
                            deadline: Instant::now() + Duration::from_millis(GRACEFUL_SHUTDOWN_TIMEOUT_MS),
                        };
                        stop_accepting_new_io(&mut runtime, &mut queue_tx).await;
                        let _ = control_stop.send(true);
                    }
                    ShutdownState::Graceful { .. } => {
                        warn!("second shutdown signal; forcing shutdown");
                        shutdown_state = ShutdownState::Forceful;
                        break;
                    }
                    ShutdownState::Forceful => break,
                }
            }
            Some(_) = hup.recv() => {
                info!("SIGHUP received; initiating user recovery");
                let _ = control_stop.send(true);
                begin_user_recovery(ublk, &mut runtime).await?;
                recovery_exit = true;
                break;
            }
            event = data_plane_rx.recv() => {
                if let Some(event) = event {
                    if let Err(err) = handle_data_plane_event(
                        &mut runtime,
                        &mut link,
                        &inflight,
                        &mut outstanding,
                        &mut response_task,
                        event,
                    )
                    .await
                    {
                        io_error = Some(err);
                        break;
                    }
                }
            }
            Some(config) = control_rx.recv(), if matches!(shutdown_state, ShutdownState::Running) => {
                if let Err(err) = handle_config_message(
                    ublk,
                    &mut runtime,
                    &mut link,
                    &mut outstanding,
                    &inflight,
                    &mut response_task,
                    config,
                )
                .await
                {
                    warn!(error = ?err, "CONFIG_EXPORTS application failed");
                }
            }
            _ = ep0_notified.as_mut() => {
                continue;
            }
            maybe_evt = queue_rx.recv(), if !matches!(shutdown_state, ShutdownState::Forceful) && runtime.io_pump.is_some() => {
                if let Some(evt) = maybe_evt {
                    if let Err(err) = handle_queue_event(
                        &mut runtime,
                        &mut link,
                        &inflight,
                        &mut outstanding,
                        &data_plane_tx,
                        evt,
                    )
                    .await
                    {
                        io_error = Some(err);
                        break;
                    }
                    if let Err(err) = drain_queue_batch(
                        &mut runtime,
                        &mut link,
                        &inflight,
                        &mut outstanding,
                        &data_plane_tx,
                        &mut queue_rx,
                    )
                    .await
                    {
                        io_error = Some(err);
                        break;
                    }
                    if let Err(err) = drive_runtime(
                        ublk,
                        &mut runtime,
                        &mut link,
                        &inflight,
                        &mut outstanding,
                        queue_tx.as_ref(),
                        &mut response_task,
                        &data_plane_tx,
                        false,
                    ).await {
                        io_error = Some(err);
                        break;
                    }
                }
            }
            _ = liveness_tick.tick() => {
                if let Err(err) = drive_runtime(
                    ublk,
                    &mut runtime,
                    &mut link,
                    &inflight,
                    &mut outstanding,
                    queue_tx.as_ref(),
                    &mut response_task,
                    &data_plane_tx,
                    false,
                ).await {
                    io_error = Some(err);
                    break;
                }
            }
            _ = &mut idle_sleep => {
                let allow_reconcile = matches!(shutdown_state, ShutdownState::Running);
                if let Err(err) = drive_runtime(
                    ublk,
                    &mut runtime,
                    &mut link,
                    &inflight,
                    &mut outstanding,
                    queue_tx.as_ref(),
                    &mut response_task,
                    &data_plane_tx,
                    allow_reconcile,
                ).await {
                    io_error = Some(err);
                    break;
                }
            }
        }

        if let ShutdownState::Graceful { deadline } = shutdown_state {
            if let Err(err) = drive_runtime(
                ublk,
                &mut runtime,
                &mut link,
                &inflight,
                &mut outstanding,
                queue_tx.as_ref(),
                &mut response_task,
                &data_plane_tx,
                false,
            )
            .await
            {
                io_error = Some(err);
                break;
            }
            let inflight_empty = inflight.lock().await.is_empty();
            let outstanding_empty = outstanding.is_empty();
            let queue_drained = queue_rx.is_closed() && queue_rx.is_empty();
            if inflight_empty && outstanding_empty && queue_drained {
                info!("graceful shutdown complete; exiting");
                break;
            }
            if Instant::now() >= deadline {
                warn!("graceful shutdown deadline reached; forcing shutdown");
                shutdown_state = ShutdownState::Forceful;
                shutdown = None;
            }
        }
    }

    if let Some(pump) = runtime.io_pump.take() {
        drop(pump);
    }
    if let Some(task) = runtime.io_pump_task.take() {
        task.abort();
        let _ = task.await;
    }
    if let Some(handle) = response_task.take() {
        handle.abort();
        let _ = handle.await;
    }
    drain_inflight(&inflight).await;

    if recovery_exit {
        return Ok(());
    }

    let _ = control_stop.send(true);
    cleanup_ublk_devices(
        ublk,
        &mut runtime,
        matches!(shutdown_state, ShutdownState::Forceful),
    )
    .await?;
    runtime.status().set_export_count(0).await;

    if let Err(err) = runtime.state_store().remove_file() {
        warn!(error = ?err, "failed to remove state file on shutdown");
    } else {
        debug!("state file removed on shutdown");
    }

    if let Some(err) = io_error {
        Err(err)
    } else {
        Ok(())
    }
}

async fn handle_request(
    pump: IoPumpHandle,
    data_plane_tx: mpsc::UnboundedSender<DataPlaneEvent>,
    data_plane_epoch: u64,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    export_id: u32,
    queues: Arc<UblkQueueRuntime>,
    req: UblkIoRequest,
) -> Result<()> {
    let block_size = queues.block_size();
    let req_len = match request_byte_len(&req, block_size) {
        Ok(len) => len,
        Err(err) => {
            let errno = errno_from_io(&err);
            warn!(
                queue = req.queue_id,
                tag = req.tag,
                errno = errno,
                ?req.op,
                "invalid request length: {err}"
            );
            queues
                .complete_io(req, -errno)
                .context("complete invalid request")?;
            return Ok(());
        }
    };

    let opcode = match opcode_from_ublk(req.op) {
        Some(op) => op,
        None => {
            warn!(
                queue = req.queue_id,
                tag = req.tag,
                op = ?req.op,
                "unsupported ublk opcode"
            );
            queues
                .complete_io(req, -libc::EOPNOTSUPP)
                .context("complete unsupported opcode")?;
            return Ok(());
        }
    };

    trace!(
        export_id,
        dev_id = queues.dev_id(),
        queue = req.queue_id,
        tag = req.tag,
        op = ?req.op,
        req_bytes = req_len,
        block_size,
        "handle_request begin"
    );

    if matches!(opcode, OpCode::Read | OpCode::Write) && req_len > 0 {
        let capacity = queues.buffer_len();
        if req_len > capacity {
            warn!(
                queue = req.queue_id,
                tag = req.tag,
                req_bytes = req_len,
                buf_cap = capacity,
                "request exceeds buffer capacity"
            );
            queues
                .complete_io(req, -libc::EINVAL)
                .context("complete oversized request")?;
            return Ok(());
        }
    }

    let num_blocks = u32::try_from(req_len / block_size)
        .context("request block count exceeds protocol limit")?;
    let request_id = make_request_id(req.queue_id, req.tag);
    let proto_req = Request::new(export_id, request_id, opcode, req.sector, num_blocks, 0);
    {
        // Track the request before sending it so early Responses can't be dropped as unknown.
        let mut guard = inflight.lock().await;
        let entry = InflightRequest {
            export_id,
            request_id,
            request: req,
            queues: queues.clone(),
            req_len,
            block_size,
            sent: false,
            response_seen: false,
        };
        guard
            .entry(export_id)
            .or_default()
            .insert(request_id, entry);
        update_request_gauges(&guard);
    }
    trace!(
        export_id,
        dev_id = queues.dev_id(),
        queue = req.queue_id,
        tag = req.tag,
        op = ?opcode,
        num_blocks,
        req_bytes = req_len,
        "queueing smoo Request through pump"
    );

    let inflight_for_sent = inflight.clone();
    let (sent_tx, sent_rx) = oneshot::channel();
    let sent_marker = tokio::spawn(async move {
        if sent_rx.await.is_ok() {
            mark_request_sent(&inflight_for_sent, export_id, request_id).await;
        }
    });
    tokio::spawn(async move {
        let work = IoWork {
            request: proto_req,
            req_len,
            queue_id: req.queue_id,
            tag: req.tag,
            op: opcode,
            queues: queues.clone(),
            on_request_sent: Some(sent_tx),
        };
        if let Err(err) = pump.submit(work).await {
            notify_data_plane_error(
                &data_plane_tx,
                data_plane_epoch,
                io::Error::other(format!("io pump submit failed: {err:#}")),
            );
            warn!(
                export_id,
                queue = req.queue_id,
                tag = req.tag,
                error = ?err,
                "io pump error dispatching request"
            );
        }
        let _ = sent_marker.await;
    });

    Ok(())
}

async fn control_loop(
    mut custom: Custom,
    handler: GadgetControl,
    status: GadgetStatusShared,
    signals: Ep0Signals,
    mut stop: watch::Receiver<bool>,
    tx: mpsc::Sender<ConfigExportsV0>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = stop.changed() => {
                debug!("control loop stopping on shutdown signal");
                return Ok(());
            }
            result = custom.wait_event() => {
                result.context("wait for FunctionFS event")?;
            }
        }
        let event = custom.event().context("read FunctionFS event")?;
        match event {
            usb_gadget::function::custom::Event::Bind => {
                debug!("FunctionFS bind event (control loop)");
                signals.push_lifecycle(Event::Bind).await;
            }
            usb_gadget::function::custom::Event::Unbind => {
                debug!("FunctionFS unbind event (control loop)");
                signals.push_lifecycle(Event::Unbind).await;
            }
            usb_gadget::function::custom::Event::Enable => {
                debug!("FunctionFS enable event (control loop)");
                signals.push_lifecycle(Event::Enable).await;
            }
            usb_gadget::function::custom::Event::Disable => {
                debug!("FunctionFS disable event (control loop)");
                signals.push_lifecycle(Event::Disable).await;
            }
            usb_gadget::function::custom::Event::Suspend => {
                debug!("FunctionFS suspend event (control loop)");
                signals.push_lifecycle(Event::Suspend).await;
            }
            usb_gadget::function::custom::Event::Resume => {
                debug!("FunctionFS resume event (control loop)");
                signals.push_lifecycle(Event::Resume).await;
            }
            usb_gadget::function::custom::Event::SetupDeviceToHost(sender) => {
                let report = status.report().await;
                let setup = setup_from_ctrl_req(sender.ctrl_req());
                let mut io = UsbControlIo::from_sender(sender);
                if let Err(err) = handler.handle_setup_packet(&mut io, setup, &report).await {
                    warn!(error = ?err, "vendor setup handling failed");
                    let _ = io.stall().await;
                } else if is_status_setup(&setup) {
                    signals.mark_status_ping();
                }
            }
            usb_gadget::function::custom::Event::SetupHostToDevice(receiver) => {
                let report = status.report().await;
                let setup = setup_from_ctrl_req(receiver.ctrl_req());
                let mut io = UsbControlIo::from_receiver(receiver);
                match handler.handle_setup_packet(&mut io, setup, &report).await {
                    Ok(Some(SetupCommand::Config(payload))) => match tx.try_send(payload) {
                        Ok(()) => {}
                        Err(TrySendError::Closed(_)) => {
                            warn!("CONFIG_EXPORTS channel closed; dropping payload");
                        }
                        Err(TrySendError::Full(_)) => {
                            warn!("CONFIG_EXPORTS channel full; dropping payload");
                        }
                    },
                    Ok(None) => {
                        if is_status_setup(&setup) {
                            signals.mark_status_ping();
                        }
                    }
                    Err(err) => {
                        warn!(error = ?err, "vendor setup handling failed");
                        let _ = io.stall().await;
                    }
                }
            }
            usb_gadget::function::custom::Event::Unknown(code) => {
                debug!(event = code, "FunctionFS unknown event");
            }
            _ => {}
        }
    }
}

fn opcode_from_ublk(op: UblkOp) -> Option<OpCode> {
    match op {
        UblkOp::Read => Some(OpCode::Read),
        UblkOp::Write => Some(OpCode::Write),
        UblkOp::Flush => Some(OpCode::Flush),
        UblkOp::Discard => Some(OpCode::Discard),
        UblkOp::Unknown(_) => None,
    }
}

fn make_request_id(queue_id: u16, tag: u16) -> u32 {
    ((queue_id as u32) << 16) | tag as u32
}

fn response_status(resp: &Response, expected_len: usize, block_size: usize) -> Result<i32> {
    if resp.status != 0 {
        let errno = i32::from(resp.status);
        return Ok(-errno);
    }
    let len = resp.num_blocks as usize * block_size;
    i32::try_from(len)
        .or_else(|_| i32::try_from(expected_len))
        .map_err(|_| anyhow!("response length exceeds i32"))
}

struct BulkOutWork {
    entry: InflightRequest,
    read_len: usize,
    status: i32,
    completion: oneshot::Sender<BulkOutResult>,
}

struct BulkOutResult {
    entry: InflightRequest,
    status: i32,
    result: Result<()>,
}

async fn response_loop(
    gadget: Arc<SmooGadget>,
    interrupt_out: Arc<Mutex<tokio::fs::File>>,
    inflight: Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    data_plane_tx: mpsc::UnboundedSender<DataPlaneEvent>,
    data_plane_epoch: u64,
) {
    let (bulk_tx, mut bulk_rx) = mpsc::channel::<BulkOutWork>(64);
    let bulk_gadget = gadget.clone();
    let bulk_task = tokio::spawn(async move {
        while let Some(work) = bulk_rx.recv().await {
            let result = async {
                let mut buffer = work
                    .entry
                    .queues
                    .checkout_buffer(work.entry.request.queue_id, work.entry.request.tag)
                    .map_err(|err| anyhow!("checkout buffer for bulk out: {err:#}"))?;
                bulk_gadget
                    .read_bulk_buffer(&mut buffer.as_mut_slice()[..work.read_len])
                    .await
                    .map_err(|err| anyhow!("bulk OUT read failed: {err:#}"))?;
                Ok(())
            }
            .await;
            let _ = work.completion.send(BulkOutResult {
                entry: work.entry,
                status: work.status,
                result,
            });
        }
    });
    loop {
        let response = {
            let mut buf = [0u8; smoo_proto::RESPONSE_LEN];
            let start = Instant::now();
            let read_res = {
                let mut lock = interrupt_out.lock().await;
                lock.read_exact(&mut buf).await
            };
            if let Err(err) = read_res {
                warn!(error = ?err, "response reader exiting after error");
                notify_data_plane_error(
                    &data_plane_tx,
                    data_plane_epoch,
                    io::Error::new(err.kind(), format!("interrupt OUT read failed: {err}")),
                );
                break;
            }
            smoo_gadget_core::observe_interrupt_out(buf.len(), start.elapsed());
            match Response::try_from(buf.as_slice()) {
                Ok(resp) => resp,
                Err(err) => {
                    warn!(error = ?err, "response reader failed to decode Response");
                    continue;
                }
            }
        };
        let entry =
            match mark_response_seen(&inflight, response.export_id, response.request_id).await {
                ResponseLookup::Unknown => {
                    warn!(
                        request_id = response.request_id,
                        export_id = response.export_id,
                        op = ?response.op,
                        "response for unknown request; dropping"
                    );
                    continue;
                }
                ResponseLookup::Duplicate => {
                    trace!(
                        request_id = response.request_id,
                        export_id = response.export_id,
                        op = ?response.op,
                        "duplicate response; dropping"
                    );
                    continue;
                }
                ResponseLookup::Fresh(entry) => entry,
            };
        let status = match response_status(&response, entry.req_len, entry.block_size) {
            Ok(status) => status,
            Err(err) => {
                warn!(
                    request_id = response.request_id,
                    export_id = response.export_id,
                    error = %err,
                    "failed to interpret response"
                );
                -libc::EIO
            }
        };
        if status >= 0 && (status as usize) != entry.req_len {
            warn!(
                request_id = response.request_id,
                export_id = response.export_id,
                expected = entry.req_len,
                reported = status,
                "response byte count mismatch"
            );
        }
        if response.op == OpCode::Read && status > 0 {
            let read_len = usize::try_from(status).unwrap_or(entry.req_len);
            let read_len = read_len.min(entry.req_len);
            let (completion_tx, completion_rx) = oneshot::channel();
            if bulk_tx
                .send(BulkOutWork {
                    entry,
                    read_len,
                    status,
                    completion: completion_tx,
                })
                .await
                .is_err()
            {
                warn!(
                    request_id = response.request_id,
                    export_id = response.export_id,
                    "bulk OUT worker stopped"
                );
                notify_data_plane_error(
                    &data_plane_tx,
                    data_plane_epoch,
                    io::Error::other("bulk OUT worker stopped"),
                );
                continue;
            }
            let inflight_for_complete = inflight.clone();
            let data_plane_tx = data_plane_tx.clone();
            tokio::spawn(async move {
                match completion_rx.await {
                    Ok(result) => match result.result {
                        Ok(()) => {
                            if let Some(entry) = take_inflight_entry(
                                &inflight_for_complete,
                                result.entry.export_id,
                                result.entry.request_id,
                            )
                            .await
                            {
                                if let Err(err) =
                                    entry.queues.complete_io(entry.request, result.status)
                                {
                                    warn!(
                                        request_id = entry.request_id,
                                        export_id = entry.export_id,
                                        error = ?err,
                                        "failed to complete ublk request after bulk OUT"
                                    );
                                }
                            } else {
                                trace!(
                                    request_id = result.entry.request_id,
                                    export_id = result.entry.export_id,
                                    "inflight entry cleared before bulk OUT completion"
                                );
                            }
                        }
                        Err(err) => {
                            warn!(error = ?err, "bulk OUT worker error");
                            notify_data_plane_error(
                                &data_plane_tx,
                                data_plane_epoch,
                                io::Error::other(format!("bulk OUT read failed: {err:#}")),
                            );
                        }
                    },
                    Err(_) => {
                        warn!("bulk OUT completion channel dropped");
                    }
                }
            });
            continue;
        }
        if let Some(entry) =
            take_inflight_entry(&inflight, response.export_id, response.request_id).await
        {
            if let Err(err) = entry.queues.complete_io(entry.request, status) {
                warn!(
                    request_id = response.request_id,
                    export_id = response.export_id,
                    error = ?err,
                    "failed to complete ublk request from response"
                );
            }
        } else {
            trace!(
                request_id = response.request_id,
                export_id = response.export_id,
                "inflight entry cleared before response completion"
            );
        }
    }
    drop(bulk_tx);
    let _ = bulk_task.await;
}

fn request_byte_len(req: &UblkIoRequest, block_size: usize) -> io::Result<usize> {
    let sectors = usize::try_from(req.num_sectors)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sector count overflow"))?;
    sectors
        .checked_mul(block_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "request byte length overflow"))
}

fn errno_from_io(err: &io::Error) -> i32 {
    err.raw_os_error().unwrap_or_else(|| match err.kind() {
        io::ErrorKind::Unsupported => libc::EOPNOTSUPP,
        io::ErrorKind::PermissionDenied => libc::EACCES,
        io::ErrorKind::UnexpectedEof => libc::EIO,
        io::ErrorKind::NotFound => libc::ENOENT,
        io::ErrorKind::InvalidInput => libc::EINVAL,
        _ => libc::EIO,
    })
}

fn setup_from_ctrl_req(ctrl: &CtrlReq) -> SetupPacket {
    SetupPacket::from_fields(
        ctrl.request_type,
        ctrl.request,
        ctrl.value,
        ctrl.index,
        ctrl.length,
    )
}

fn is_status_setup(setup: &SetupPacket) -> bool {
    setup.request() == SMOO_STATUS_REQUEST && setup.request_type() == SMOO_STATUS_REQ_TYPE
}

enum UsbControlInner<'a> {
    In(Option<CtrlSender<'a>>),
    Out(Option<CtrlReceiver<'a>>),
}

struct UsbControlIo<'a> {
    inner: UsbControlInner<'a>,
}

impl<'a> UsbControlIo<'a> {
    fn from_sender(sender: CtrlSender<'a>) -> Self {
        Self {
            inner: UsbControlInner::In(Some(sender)),
        }
    }

    fn from_receiver(receiver: CtrlReceiver<'a>) -> Self {
        Self {
            inner: UsbControlInner::Out(Some(receiver)),
        }
    }
}

#[async_trait::async_trait]
impl ControlIo for UsbControlIo<'_> {
    async fn write_in(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.inner {
            UsbControlInner::In(sender) => {
                let sender = sender.take().context("control sender already used")?;
                sender
                    .send(data)
                    .with_context(|| format!("send control response of {} bytes", data.len()))
                    .map(|_| ())
            }
            UsbControlInner::Out(_) => Ok(()),
        }
    }

    async fn read_out(&mut self, buf: &mut [u8]) -> Result<()> {
        match &mut self.inner {
            UsbControlInner::Out(receiver) => {
                let receiver = receiver.take().context("control receiver already used")?;
                let read = receiver
                    .recv(buf)
                    .with_context(|| format!("read control payload of {} bytes", buf.len()))?;
                ensure!(read == buf.len(), "control payload truncated");
                Ok(())
            }
            UsbControlInner::In(_) => Err(anyhow!("attempted to read_out on IN control transfer")),
        }
    }

    async fn stall(&mut self) -> Result<()> {
        match &mut self.inner {
            UsbControlInner::In(sender) => {
                let sender = sender.take().context("control sender already used")?;
                sender.halt().context("stall control sender")
            }
            UsbControlInner::Out(receiver) => {
                let receiver = receiver.take().context("control receiver already used")?;
                receiver.halt().context("stall control receiver")
            }
        }
    }
}
async fn initialize_session(_ublk: &mut SmooUblk, state_store: &mut StateStore) -> Result<()> {
    if state_store.records().is_empty() {
        if state_store.path().is_some() {
            debug!("state file present but no exports recorded; nothing to recover");
        }
        return Ok(());
    }

    let mut seen = HashSet::new();
    let mut reset = false;
    for record in state_store.records() {
        if !seen.insert(record.export_id) {
            warn!(
                export_id = record.export_id,
                "state file contains duplicate export_id; clearing state"
            );
            reset = true;
            break;
        }
        if let Err(err) = validate_persisted_record(record) {
            warn!(
                export_id = record.export_id,
                error = ?err,
                "state file entry invalid; clearing state"
            );
            reset = true;
            break;
        }
    }

    if reset {
        reset_state_store(state_store);
        let _ = state_store.persist();
    }
    Ok(())
}

async fn adopt_prepare(ublk: &mut SmooUblk, state_store: &mut StateStore) -> Result<()> {
    let mut dev_ids = Vec::new();
    let mut owner_pids = HashSet::new();
    let mut stale_devices = false;
    for record in state_store.records() {
        if let Some(dev_id) = record.assigned_dev_id {
            dev_ids.push(dev_id);
            match ublk.owner_pid(dev_id).await {
                Ok(pid) => {
                    let alive = pid_is_alive(pid);
                    debug!(dev_id, pid, alive, "queried ublk owner");
                    if pid > 0 && pid != unsafe { libc::getpid() } && alive {
                        owner_pids.insert(pid);
                    } else if pid > 0 && !alive {
                        stale_devices = true;
                    }
                }
                Err(err) => {
                    let missing = error_is_missing(&err);
                    warn!(dev_id, error = ?err, missing, "query owner pid failed");
                    if missing {
                        stale_devices = true;
                    }
                }
            }
        }
    }

    if stale_devices && owner_pids.is_empty() {
        warn!("no surviving owners and stale devices detected; resetting state for fresh session");
        reset_state_store(state_store);
        if let Err(err) = state_store.persist() {
            warn!(error = ?err, "persist state reset failed");
        }
        return Ok(());
    }

    if owner_pids.len() > 1 {
        warn!(
            owners = ?owner_pids,
            "multiple ublk owners detected; resetting state for clean session"
        );
        reset_state_store(state_store);
        if let Err(err) = state_store.persist() {
            warn!(error = ?err, "persist state reset failed");
        }
        anyhow::bail!("multiple ublk owners detected during adopt");
    }

    if let Some(pid) = owner_pids.into_iter().next() {
        info!(pid, "signaling existing smoo-gadget owner for recovery");
        unsafe {
            libc::kill(pid, libc::SIGHUP);
        }
        info!(pid, "waiting for prior owner to exit before adopting");
        wait_for_owner_exit(ublk, &dev_ids, pid, Duration::from_secs(3)).await?;
    }

    Ok(())
}

async fn wait_for_owner_exit(
    ublk: &mut SmooUblk,
    dev_ids: &[u32],
    target_pid: i32,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut still_owned = false;
        for dev_id in dev_ids {
            match ublk.owner_pid(*dev_id).await {
                Ok(pid) => {
                    debug!(dev_id, pid, target_pid, "owner check during adopt wait");
                    if pid == target_pid {
                        still_owned = true;
                    } else if pid > 0 && pid != target_pid {
                        anyhow::bail!(
                            "device {dev_id} now owned by unexpected pid {pid} during adopt"
                        );
                    }
                }
                Err(err) => {
                    warn!(dev_id, error = ?err, "owner pid query failed during adopt wait");
                }
            }
        }
        if !still_owned {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("owner pid {target_pid} still active after adopt wait");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn reset_state_store(state_store: &mut StateStore) {
    let path = state_store.path().map(Path::to_path_buf);
    *state_store = match path {
        Some(path) => StateStore::new_with_path(path),
        None => StateStore::new(),
    };
}

fn count_active_exports(exports: &HashMap<u32, ExportController>) -> u32 {
    exports
        .values()
        .filter(|ctrl| ctrl.is_active_for_status())
        .count() as u32
}

async fn apply_config(
    ublk: &mut SmooUblk,
    runtime: &mut RuntimeState,
    config: ConfigExportsV0,
) -> Result<()> {
    let entries = config.entries();
    let desired_records = if entries.is_empty() {
        Vec::new()
    } else {
        config_entries_to_records(entries)?
    };

    // Fast-path: zero exports means tear everything down.
    if desired_records.is_empty() {
        for controller in runtime.exports.values_mut() {
            if let Some((ctrl, queues)) = controller.take_device_handles() {
                ublk.stop_dev(SmooUblkDevice::from_parts(ctrl, queues), true)
                    .await
                    .context("stop ublk device before applying CONFIG_EXPORTS")?;
            }
        }
        runtime.exports.clear();
        runtime.reconcile_queue.clear();
        runtime.state_store().replace_all(Vec::new());
        if let Err(err) = runtime.state_store().persist() {
            warn!(error = ?err, "failed to clear state file");
        }
        runtime.status().set_export_count(0).await;
        return Ok(());
    }

    let desired_specs: HashMap<u32, ExportSpec> = desired_records
        .iter()
        .map(|record| (record.export_id, record.spec.clone()))
        .collect();

    // Stop and remove exports that are missing or whose geometry changed.
    let mut to_remove = Vec::new();
    for (export_id, controller) in runtime.exports.iter() {
        match desired_specs.get(export_id) {
            Some(spec) if spec == &controller.spec => {}
            _ => to_remove.push(*export_id),
        }
    }
    for export_id in to_remove {
        if let Some(mut controller) = runtime.exports.remove(&export_id) {
            if let Some((ctrl, queues)) = controller.take_device_handles() {
                ublk.stop_dev(SmooUblkDevice::from_parts(ctrl, queues), true)
                    .await
                    .with_context(|| format!("stop ublk device for export {export_id}"))?;
            }
        }
    }

    // Create controllers for any new exports.
    for record in &desired_records {
        runtime.exports.entry(record.export_id).or_insert_with(|| {
            ExportController::new(record.export_id, record.spec.clone(), ExportState::New)
        });
    }

    // Rebuild state store with the desired exports, keeping any assigned dev_ids
    // for controllers we kept alive.
    let mut new_records = Vec::with_capacity(desired_records.len());
    for mut record in desired_records {
        if let Some(ctrl) = runtime.exports.get(&record.export_id) {
            record.assigned_dev_id = ctrl.dev_id();
        }
        new_records.push(record);
    }

    runtime.state_store().replace_all(new_records);
    if let Err(err) = runtime.state_store().persist() {
        warn!(error = ?err, "failed to write state store");
    }
    runtime
        .reconcile_queue
        .retain(|export_id| runtime.exports.contains_key(export_id));
    runtime
        .status()
        .set_export_count(count_active_exports(&runtime.exports))
        .await;
    Ok(())
}

struct GadgetGuard {
    _registration: RegGadget,
}

fn setup_configfs(
    args: &Args,
) -> Result<(Custom, FunctionfsEndpoints, Option<GadgetGuard>, PathBuf)> {
    if let Some(ffs_dir) = args.ffs_dir.as_ref() {
        info!(
            ffs_dir = %ffs_dir.display(),
            "using existing FunctionFS directory; skipping configfs setup"
        );
        let custom = configfs_builder(args)
            .existing(ffs_dir)
            .context("initialize FunctionFS in existing directory")?;
        let endpoints = open_data_endpoints(ffs_dir)?;
        return Ok((custom, endpoints, None, ffs_dir.clone()));
    }

    usb_gadget::remove_all().context("remove existing USB gadgets")?;
    let (mut custom, handle) = configfs_builder(args).build();

    let (subclass, protocol) = interface_identity(args);
    let klass = Class::new(SMOO_CLASS, subclass, protocol);
    let id = Id::new(args.vendor_id, args.product_id);
    let strings = Strings::new("smoo", "smoo gadget", "0001");
    let udc = usb_gadget::default_udc().context("locate UDC")?;
    let gadget =
        Gadget::new(klass, id, strings).with_config(Config::new("config").with_function(handle));
    let reg = gadget.register().context("register gadget")?;

    let ffs_dir = custom.ffs_dir().context("resolve FunctionFS dir")?;
    reg.bind(Some(&udc)).context("bind gadget to UDC")?;

    let endpoints = open_data_endpoints(&ffs_dir)?;

    Ok((
        custom,
        endpoints,
        Some(GadgetGuard { _registration: reg }),
        ffs_dir,
    ))
}

fn configfs_builder(args: &Args) -> CustomBuilder {
    let (subclass, protocol) = interface_identity(args);
    Custom::builder().with_interface(
        Interface::new(Class::vendor_specific(subclass, protocol), "smoo")
            .with_endpoint(interrupt_in_ep())
            .with_endpoint(interrupt_out_ep())
            .with_endpoint(bulk_in_ep())
            .with_endpoint(bulk_out_ep()),
    )
}

fn interface_identity(args: &Args) -> (u8, u8) {
    if args.mimic_fastboot {
        (FASTBOOT_SUBCLASS, FASTBOOT_PROTOCOL)
    } else {
        (SMOO_SUBCLASS, SMOO_PROTOCOL)
    }
}

fn open_data_endpoints(ffs_dir: &Path) -> Result<FunctionfsEndpoints> {
    let interrupt_in = open_endpoint_fd(ffs_dir.join("ep1")).context("open interrupt IN")?;
    let interrupt_out = open_endpoint_fd(ffs_dir.join("ep2")).context("open interrupt OUT")?;
    let bulk_in = open_endpoint_fd(ffs_dir.join("ep3")).context("open bulk IN")?;
    let bulk_out = open_endpoint_fd(ffs_dir.join("ep4")).context("open bulk OUT")?;
    Ok(FunctionfsEndpoints::new(
        interrupt_in,
        interrupt_out,
        bulk_in,
        bulk_out,
    ))
}

fn interrupt_in_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::device_to_host();
    make_ep(dir, TransferType::Interrupt, 1024)
}

fn interrupt_out_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::host_to_device();
    make_ep(dir, TransferType::Interrupt, 1024)
}

fn bulk_in_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::device_to_host();
    make_ep(dir, TransferType::Bulk, 512)
}

fn bulk_out_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::host_to_device();
    make_ep(dir, TransferType::Bulk, 512)
}

fn make_ep(direction: EndpointDirection, ty: TransferType, packet_size: u16) -> Endpoint {
    let mut ep = match ty {
        TransferType::Bulk => Endpoint::bulk(direction),
        _ => Endpoint::custom(direction, ty),
    };
    ep.max_packet_size_hs = packet_size;
    ep.max_packet_size_ss = packet_size;
    if matches!(ty, TransferType::Interrupt) {
        ep.interval = 1;
    }
    ep
}

fn open_endpoint_fd(path: PathBuf) -> Result<OwnedFd> {
    let file = File::options()
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    Ok(to_owned_fd(file))
}

fn to_owned_fd(file: File) -> OwnedFd {
    let raw = file.into_raw_fd();
    unsafe { OwnedFd::from_raw_fd(raw) }
}

async fn cleanup_ublk_devices(
    ublk: &mut SmooUblk,
    runtime: &mut RuntimeState,
    forceful: bool,
) -> Result<()> {
    for (_, tasks) in runtime.queue_tasks.drain() {
        if forceful {
            tasks.abort();
        } else {
            tasks.shutdown().await;
        }
    }
    let mut force_remove_ids = Vec::new();
    for controller in runtime.exports.values_mut() {
        if let Some((ctrl, queues)) = controller.take_device_handles() {
            let dev_id = ctrl.dev_id();
            if forceful {
                info!(dev_id, "forceful shutdown: dropping ublk device handles");
                drop(SmooUblkDevice::from_parts(ctrl, queues));
                force_remove_ids.push(dev_id);
            } else {
                info!(dev_id, "stopping ublk device");
                if let Err(err) = ublk
                    .stop_dev(SmooUblkDevice::from_parts(ctrl, queues), true)
                    .await
                {
                    warn!(
                        dev_id,
                        error = ?err,
                        "graceful stop failed; will force-remove"
                    );
                    force_remove_ids.push(dev_id);
                }
            }
        } else if let Some(dev_id) = controller.dev_id() {
            force_remove_ids.push(dev_id);
        }
    }

    for dev_id in force_remove_ids {
        force_remove_with_retry(ublk, dev_id).await?;
    }
    Ok(())
}

async fn force_remove_with_retry(ublk: &mut SmooUblk, dev_id: u32) -> Result<()> {
    let mut attempt: u32 = 0;
    loop {
        attempt = attempt.wrapping_add(1);
        match ublk.force_remove_device(dev_id).await {
            Ok(()) => {
                info!(dev_id, attempt, "force-removed ublk device");
                break;
            }
            Err(err) => {
                if error_is_errno(&err, libc::ENOENT) {
                    info!(dev_id, attempt, "ublk device already absent");
                    break;
                }
                warn!(
                    dev_id,
                    attempt,
                    error = ?err,
                    "force-remove ublk device failed; retrying"
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(())
}

async fn begin_user_recovery(ublk: &mut SmooUblk, runtime: &mut RuntimeState) -> Result<()> {
    ublk.preserve_devices_on_drop();
    for (_, tasks) in runtime.queue_tasks.drain() {
        tasks.shutdown().await;
    }
    let mut dev_ids = Vec::new();
    for ctrl in runtime.exports.values_mut() {
        if let Some((ctrl, queues)) = ctrl.take_device_handles() {
            dev_ids.push(ctrl.dev_id());
            drop(SmooUblkDevice::from_parts(ctrl, queues));
        } else if let Some(dev_id) = ctrl.dev_id() {
            dev_ids.push(dev_id);
        }
    }
    for dev_id in dev_ids {
        if let Err(err) = ublk.start_user_recovery(dev_id).await {
            warn!(dev_id, error = ?err, "start user recovery failed");
        }
    }
    Ok(())
}

async fn park_inflight_requests(
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
) {
    let mut guard = inflight.lock().await;
    let mut drained = Vec::new();
    for (export_id, mut requests) in guard.drain() {
        for (_req_id, req) in requests.drain() {
            drained.push((export_id, req));
        }
    }
    update_request_gauges(&guard);
    drop(guard);

    for (export_id, req) in drained {
        park_request(
            outstanding,
            export_id,
            req.request.dev_id,
            req.queues,
            req.request,
        );
    }
}

async fn process_link_commands(
    runtime: &mut RuntimeState,
    link: &mut LinkController,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    response_task: &mut Option<JoinHandle<()>>,
) -> Result<()> {
    while let Some(cmd) = link.take_command() {
        match cmd {
            LinkCommand::DropLink => {
                if runtime.gadget.is_none() {
                    continue;
                }
                park_inflight_requests(inflight, outstanding).await;
                if let Some(pump) = runtime.io_pump.take() {
                    drop(pump);
                }
                if let Some(task) = runtime.io_pump_task.take() {
                    task.abort();
                    let _ = task.await;
                }
                if let Some(task) = response_task.take() {
                    task.abort();
                    let _ = task.await;
                }
                runtime.gadget = None;
                runtime.data_plane_epoch = runtime.data_plane_epoch.wrapping_add(1);
                warn!("link controller requested drop; data plane closed");
            }
            LinkCommand::Reopen => {
                if runtime.gadget.is_some() {
                    continue;
                }
                match open_data_endpoints(&runtime.ffs_dir) {
                    Ok(endpoints) => match SmooGadget::new(endpoints, runtime.gadget_config) {
                        Ok(gadget) => {
                            let gadget = Arc::new(gadget);
                            let (handle, task) =
                                IoPumpHandle::spawn(gadget.clone(), runtime.io_pump_capacity);
                            runtime.io_pump = Some(handle);
                            runtime.io_pump_task = Some(task);
                            runtime.gadget = Some(gadget);
                            warn!("link controller reopened data plane");
                        }
                        Err(err) => {
                            warn!(error = ?err, "reopen data plane failed");
                        }
                    },
                    Err(err) => {
                        warn!(error = ?err, "open endpoints failed during reopen");
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_data_plane_event(
    runtime: &mut RuntimeState,
    link: &mut LinkController,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    response_task: &mut Option<JoinHandle<()>>,
    event: DataPlaneEvent,
) -> Result<()> {
    match event {
        DataPlaneEvent::IoError { epoch, error } => {
            if epoch != runtime.data_plane_epoch {
                trace!(
                    event_epoch = epoch,
                    current_epoch = runtime.data_plane_epoch,
                    "ignoring stale data plane error"
                );
                return Ok(());
            }
            warn!(error = ?error, "data plane error; dropping link");
            link.on_io_error(&error);
        }
    }
    process_link_commands(runtime, link, inflight, outstanding, response_task).await?;
    Ok(())
}

async fn handle_queue_event(
    runtime: &mut RuntimeState,
    link: &mut LinkController,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    data_plane_tx: &mpsc::UnboundedSender<DataPlaneEvent>,
    event: QueueEvent,
) -> Result<()> {
    match event {
        QueueEvent::Request {
            export_id,
            dev_id,
            request,
            queues,
        } => {
            let Some(ctrl) = runtime.exports.get_mut(&export_id) else {
                return Ok(());
            };
            let Some(handle) = ctrl.device_handle() else {
                park_request(outstanding, export_id, dev_id, queues.clone(), request);
                return Ok(());
            };
            if handle.dev_id() != dev_id {
                trace!(export_id, dev_id, "dropping request for stale device id");
                return Ok(());
            }
            let handle_ready = matches!(
                handle,
                DeviceHandle::Online { .. } | DeviceHandle::Starting { .. }
            );
            if !matches!(link.state(), LinkState::Online)
                || runtime.gadget.is_none()
                || !handle_ready
            {
                trace!(
                    export_id,
                    queue = request.queue_id,
                    tag = request.tag,
                    "link not online; parking IO"
                );
                park_request(outstanding, export_id, dev_id, queues.clone(), request);
                return Ok(());
            }
            let Some(pump) = runtime.io_pump.as_ref() else {
                park_request(outstanding, export_id, dev_id, queues.clone(), request);
                return Ok(());
            };
            trace!(
                export_id,
                dev_id,
                queue = request.queue_id,
                tag = request.tag,
                op = ?request.op,
                sector = request.sector,
                num_sectors = request.num_sectors,
                "dispatch ublk request to host"
            );
            if let Err(err) = handle_request(
                pump.clone(),
                data_plane_tx.clone(),
                runtime.data_plane_epoch,
                inflight,
                export_id,
                queues.clone(),
                request,
            )
            .await
            {
                let io_err = io_error_from_anyhow(&err);
                link.on_io_error(&io_err);
                park_request(outstanding, export_id, dev_id, queues.clone(), request);
                warn!(export_id, queue = request.queue_id, tag = request.tag, error = ?err, "link error handling request; parked for retry");
            }
        }
        QueueEvent::QueueError {
            export_id,
            dev_id,
            error,
        } => {
            if let Some(ctrl) = runtime.exports.get_mut(&export_id) {
                ctrl.fail_device(format!("device {dev_id} queue task error: {error:#}"));
            }
            if let Some(mut pending) = outstanding.remove(&export_id) {
                for ((_queue_id, _tag), req) in pending.drain() {
                    let _ = req.queues.complete_io(req.request, -libc::ENOLINK);
                }
            }
            link.on_io_error(&io::Error::other("queue task error"));
        }
    }
    Ok(())
}

fn park_request(
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    export_id: u32,
    dev_id: u32,
    queues: Arc<UblkQueueRuntime>,
    req: UblkIoRequest,
) {
    let entry = outstanding.entry(export_id).or_default();
    entry.insert(
        (req.queue_id, req.tag),
        OutstandingRequest {
            dev_id,
            request: req,
            queues,
        },
    );
}

fn prune_outstanding_for_missing_exports(
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    exports: &HashMap<u32, ExportController>,
) {
    let mut to_fail = Vec::new();
    for export_id in outstanding.keys() {
        if !exports.contains_key(export_id) {
            to_fail.push(*export_id);
        }
    }
    for export_id in to_fail {
        if let Some(mut pending) = outstanding.remove(&export_id) {
            for ((_queue_id, _tag), req) in pending.drain() {
                let _ = req.queues.complete_io(req.request, -libc::ENODEV);
            }
        }
    }
}

async fn drain_inflight(inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>) {
    let mut guard = inflight.lock().await;
    for (_export, mut requests) in guard.drain() {
        for (_req_id, req) in requests.drain() {
            let _ = req.queues.complete_io(req.request, -libc::ENOLINK);
        }
    }
    update_request_gauges(&guard);
}

fn io_error_from_anyhow(err: &anyhow::Error) -> io::Error {
    if let Some(cause) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>())
    {
        io::Error::new(cause.kind(), cause.to_string())
    } else {
        io::Error::other(err.to_string())
    }
}

fn error_is_errno(err: &anyhow::Error, code: i32) -> bool {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .and_then(|io_err| io_err.raw_os_error())
        == Some(code)
}

fn error_is_missing(err: &anyhow::Error) -> bool {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .and_then(|io_err| io_err.raw_os_error())
        .is_some_and(|code| code == libc::ENOENT || code == libc::EINVAL)
}

fn pid_is_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let res = unsafe { libc::kill(pid, 0) };
    if res == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    !matches!(err.raw_os_error(), Some(libc::ESRCH))
}

fn parse_hex_u16(input: &str) -> Result<u16, String> {
    let trimmed = input.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(trimmed, 16).map_err(|err| err.to_string())
}

fn validate_persisted_record(record: &PersistedExportRecord) -> Result<()> {
    ensure!(
        record.export_id != 0,
        "persisted export_id must be non-zero"
    );
    let block_size = record.spec.block_size;
    ensure!(
        block_size.is_power_of_two(),
        "persisted block size must be power-of-two"
    );
    ensure!(
        (512..=65536).contains(&block_size),
        "persisted block size out of range"
    );
    ensure!(
        record.spec.size_bytes != 0,
        "persisted export size_bytes must be non-zero"
    );
    ensure!(
        record.spec.size_bytes.is_multiple_of(block_size as u64),
        "persisted export size_bytes must be multiple of block_size"
    );
    let blocks = record
        .spec
        .size_bytes
        .checked_div(block_size as u64)
        .context("persisted size_bytes smaller than block_size")?;
    ensure!(blocks > 0, "persisted export size too small");
    usize::try_from(blocks).context("persisted export block count overflows usize")?;
    Ok(())
}

fn config_entries_to_records(entries: &[ConfigExport]) -> Result<Vec<PersistedExportRecord>> {
    let mut seen = HashSet::new();
    let mut records = Vec::with_capacity(entries.len());
    for export in entries {
        ensure!(
            seen.insert(export.export_id),
            "duplicate export_id {} in CONFIG_EXPORTS",
            export.export_id
        );
        let spec = build_spec_from_export(*export)?;
        records.push(PersistedExportRecord {
            export_id: export.export_id,
            spec,
            assigned_dev_id: None,
        });
    }
    Ok(records)
}

fn build_spec_from_export(export: ConfigExport) -> Result<ExportSpec> {
    let block_size = export.block_size as usize;
    ensure!(
        export.size_bytes != 0,
        "CONFIG_EXPORTS size_bytes must be non-zero"
    );
    ensure!(
        export.size_bytes.is_multiple_of(block_size as u64),
        "CONFIG_EXPORTS size_bytes must be multiple of block_size"
    );
    let blocks = export
        .size_bytes
        .checked_div(block_size as u64)
        .context("size bytes smaller than block size")?;
    ensure!(blocks > 0, "export size too small");
    usize::try_from(blocks).context("export block count overflows usize")?;
    Ok(ExportSpec {
        block_size: export.block_size,
        size_bytes: export.size_bytes,
        flags: ExportFlags::empty(),
    })
}
