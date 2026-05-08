use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::mpsc::Sender;
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use async_trait::async_trait;
use gibblox_core::BlockReader;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use smoo_host_blocksource_gibblox::GibbloxBlockSource;
use smoo_host_core::{
    BlockSource, BlockSourceHandle, ControlTransport, CountingTransport, Transport,
    TransportCounterSnapshot, TransportResult, register_export,
};
use smoo_host_session::{
    HostSession, HostSessionConfig, HostSessionDriveConfig, HostSessionDriveEvent,
    HostSessionDriveOutcome, drive_host_session,
};
use smoo_host_transport_rusb::RusbTransport;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::boot_ui::{BootEvent, BootPhase};

const SMOO_INTERFACE_CLASS: u8 = 0xFF;
const SMOO_INTERFACE_SUBCLASS: u8 = 0x53;
const SMOO_INTERFACE_PROTOCOL: u8 = 0x4D;
const FASTBOOT_INTERFACE_SUBCLASS: u8 = 0x42;
const FASTBOOT_INTERFACE_PROTOCOL: u8 = 0x03;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(1);
const DISCOVERY_RETRY: Duration = Duration::from_millis(500);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const STATUS_RETRY_ATTEMPTS: usize = 5;

#[derive(Clone, Copy, Debug)]
pub(crate) struct SmooHostOptions {
    pub impersonate_fastboot: bool,
    pub metrics_port: u16,
}

pub(crate) async fn run_host_daemon(
    reader: Arc<dyn BlockReader>,
    size_bytes: u64,
    identity: String,
    options: SmooHostOptions,
    events: Sender<BootEvent>,
    shutdown: CancellationToken,
) -> Result<()> {
    run_host_daemon_async(reader, size_bytes, identity, options, events, shutdown).await
}

async fn run_host_daemon_async(
    reader: Arc<dyn BlockReader>,
    size_bytes: u64,
    identity: String,
    options: SmooHostOptions,
    events: Sender<BootEvent>,
    shutdown: CancellationToken,
) -> Result<()> {
    let shutdown_watch = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown_watch.cancel();
    });

    let metrics = SmooMetricsRegistry::default();
    let metrics_shutdown = CancellationToken::new();
    let metrics_shutdown_watch = metrics_shutdown.clone();
    let host_shutdown_watch = shutdown.clone();
    tokio::spawn(async move {
        host_shutdown_watch.cancelled().await;
        metrics_shutdown_watch.cancel();
    });
    let metrics_task = spawn_metrics_listener(
        options.metrics_port,
        metrics.clone(),
        metrics_shutdown.clone(),
    )?;
    if options.metrics_port != 0 {
        emit(
            &events,
            BootEvent::Log(format!(
                "smoo host metrics listening on http://0.0.0.0:{}/metrics",
                options.metrics_port
            )),
        );
    }

    emit(
        &events,
        BootEvent::Phase {
            phase: BootPhase::WaitingForSmoo,
            detail: "waiting for smoo gadget".to_string(),
        },
    );
    emit(
        &events,
        BootEvent::Log("Waiting for smoo gadget and starting host daemon...".to_string()),
    );
    let (interface_subclass, interface_protocol) = if options.impersonate_fastboot {
        (FASTBOOT_INTERFACE_SUBCLASS, FASTBOOT_INTERFACE_PROTOCOL)
    } else {
        (SMOO_INTERFACE_SUBCLASS, SMOO_INTERFACE_PROTOCOL)
    };

    while !shutdown.is_cancelled() {
        let (transport, control) = match RusbTransport::open_matching(
            None,
            None,
            SMOO_INTERFACE_CLASS,
            interface_subclass,
            interface_protocol,
            TRANSFER_TIMEOUT,
        )
        .await
        {
            Ok(pair) => pair,
            Err(err) => {
                if shutdown.is_cancelled() {
                    break;
                }
                emit(
                    &events,
                    BootEvent::Log(format!("smoo gadget not ready: {err}")),
                );
                tokio::time::sleep(DISCOVERY_RETRY).await;
                continue;
            }
        };

        let outcome = run_session(
            transport,
            control,
            reader.clone(),
            size_bytes,
            identity.clone(),
            SessionRuntime {
                shutdown: shutdown.clone(),
                events: events.clone(),
                metrics: metrics.clone(),
            },
        )
        .await;
        match outcome {
            Ok(SessionEnd::Shutdown) => break,
            Ok(SessionEnd::TransportLost) => {
                if shutdown.is_cancelled() {
                    break;
                }
                emit(
                    &events,
                    BootEvent::Log("smoo gadget disconnected; waiting to reconnect...".to_string()),
                );
            }
            Err(err) => {
                if shutdown.is_cancelled() {
                    break;
                }
                emit(
                    &events,
                    BootEvent::Log(format!("smoo host session ended with error: {err}")),
                );
                tokio::time::sleep(DISCOVERY_RETRY).await;
            }
        }
    }

    metrics_shutdown.cancel();
    if let Some(task) = metrics_task {
        let _ = task.await;
    }

    Ok(())
}

enum SessionEnd {
    Shutdown,
    TransportLost,
}

#[derive(Clone)]
struct SessionRuntime {
    shutdown: CancellationToken,
    events: Sender<BootEvent>,
    metrics: SmooMetricsRegistry,
}

async fn run_session(
    transport: RusbTransport,
    mut control: smoo_host_transport_rusb::RusbControl,
    reader: Arc<dyn BlockReader>,
    size_bytes: u64,
    identity: String,
    runtime: SessionRuntime,
) -> Result<SessionEnd> {
    let transport = CountingTransport::new(transport);
    let counters = transport.counters();
    let transport = InflightTransport::new(transport, runtime.metrics.clone());

    let source = GibbloxBlockSource::new(reader, identity.clone());
    let block_size = source.block_size();
    ensure!(block_size > 0, "block size must be non-zero");
    ensure!(
        size_bytes.is_multiple_of(block_size as u64),
        "image size must align to export block size"
    );

    let source_handle = BlockSourceHandle::new(source, identity.clone());
    let mut sources = BTreeMap::new();
    let mut entries = Vec::new();
    register_export(
        &mut sources,
        &mut entries,
        source_handle,
        identity,
        block_size,
        size_bytes,
    )
    .map_err(|err| anyhow!(err.to_string()))?;
    let session = HostSession::new(
        sources,
        HostSessionConfig {
            status_retry_attempts: STATUS_RETRY_ATTEMPTS,
        },
    )
    .map_err(|err| anyhow!(err.to_string()))?;
    runtime.metrics.begin_session();
    let task = match session.start(transport, &mut control).await {
        Ok(task) => task,
        Err(err) => {
            runtime.metrics.end_session(counters.snapshot());
            return Err(anyhow!(err.to_string()));
        }
    };
    emit(
        &runtime.events,
        BootEvent::Phase {
            phase: BootPhase::Serving,
            detail: "smoo gadget connected".to_string(),
        },
    );
    emit(
        &runtime.events,
        BootEvent::Log("smoo gadget connected; serving export...".to_string()),
    );

    let events = runtime.events.clone();
    let metrics = runtime.metrics.clone();
    let counters_for_events = counters.clone();
    let outcome = drive_host_session(
        task,
        control,
        runtime.shutdown.cancelled(),
        || tokio::time::sleep(HEARTBEAT_INTERVAL),
        HostSessionDriveConfig::default(),
        move |event| match event {
            HostSessionDriveEvent::HeartbeatStatus { status } => {
                let snapshot = metrics.update_status(
                    status.export_active(),
                    status.export_count,
                    status.session_id,
                    counters_for_events.snapshot(),
                );
                emit(
                    &events,
                    BootEvent::SmooStatus {
                        active: status.export_active(),
                        export_count: status.export_count,
                        session_id: status.session_id,
                        ios_up: snapshot.ios_up,
                        ios_down: snapshot.ios_down,
                        bytes_up: snapshot.bytes_up,
                        bytes_down: snapshot.bytes_down,
                        inflight_requests: snapshot.inflight_requests,
                        max_inflight_requests: snapshot.max_inflight_requests,
                    },
                );
            }
            HostSessionDriveEvent::HeartbeatRecovered { missed_heartbeats } => {
                metrics.update_counters(counters_for_events.snapshot());
                emit(
                    &events,
                    BootEvent::Log(format!(
                        "smoo heartbeat recovered after {missed_heartbeats} misses"
                    )),
                );
            }
            HostSessionDriveEvent::HeartbeatMiss {
                error,
                missed_heartbeats,
                budget,
            } => {
                metrics.update_counters(counters_for_events.snapshot());
                emit(
                    &events,
                    BootEvent::Log(format!(
                        "smoo heartbeat failed: {error} (miss {missed_heartbeats}/{budget})"
                    )),
                );
            }
            HostSessionDriveEvent::HeartbeatMissBudgetExhausted {
                missed_heartbeats,
                budget,
            } => {
                metrics.update_counters(counters_for_events.snapshot());
                emit(
                    &events,
                    BootEvent::Log(format!(
                        "smoo heartbeat miss budget exhausted ({missed_heartbeats}/{budget})"
                    )),
                );
            }
        },
    )
    .await;
    runtime.metrics.end_session(counters.snapshot());

    match outcome {
        HostSessionDriveOutcome::Shutdown => Ok(SessionEnd::Shutdown),
        HostSessionDriveOutcome::TransportLost => Ok(SessionEnd::TransportLost),
        HostSessionDriveOutcome::SessionChanged { previous, current } => {
            emit(
                &runtime.events,
                BootEvent::Log(format!(
                    "smoo session changed (0x{previous:016x} -> 0x{current:016x}); reconnecting"
                )),
            );
            Ok(SessionEnd::TransportLost)
        }
        HostSessionDriveOutcome::Failed(err) => Err(anyhow!(err.to_string())),
    }
}

fn emit(events: &Sender<BootEvent>, event: BootEvent) {
    let _ = events.send(event);
}

#[derive(Clone)]
struct InflightTransport<T> {
    inner: T,
    metrics: SmooMetricsRegistry,
}

impl<T> InflightTransport<T> {
    fn new(inner: T, metrics: SmooMetricsRegistry) -> Self {
        Self { inner, metrics }
    }
}

#[async_trait]
impl<T> ControlTransport for InflightTransport<T>
where
    T: ControlTransport + Send + Sync,
{
    async fn control_in(
        &self,
        request_type: u8,
        request: u8,
        buf: &mut [u8],
    ) -> TransportResult<usize> {
        self.inner.control_in(request_type, request, buf).await
    }

    async fn control_out(
        &self,
        request_type: u8,
        request: u8,
        data: &[u8],
    ) -> TransportResult<usize> {
        self.inner.control_out(request_type, request, data).await
    }
}

#[async_trait]
impl<T> Transport for InflightTransport<T>
where
    T: Transport + Clone + Send + Sync,
{
    async fn read_interrupt(&self, buf: &mut [u8]) -> TransportResult<usize> {
        let result = self.inner.read_interrupt(buf).await;
        if matches!(result, Ok(len) if len == buf.len()) {
            self.metrics.request_started();
        }
        result
    }

    async fn write_interrupt(&self, buf: &[u8]) -> TransportResult<usize> {
        let result = self.inner.write_interrupt(buf).await;
        if matches!(result, Ok(len) if len == buf.len()) {
            self.metrics.request_finished();
        }
        result
    }

    async fn read_bulk(&self, buf: &mut [u8]) -> TransportResult<usize> {
        self.inner.read_bulk(buf).await
    }

    async fn write_bulk(&self, buf: &[u8]) -> TransportResult<usize> {
        self.inner.write_bulk(buf).await
    }
}

#[derive(Clone, Default)]
struct SmooMetricsRegistry {
    inner: Arc<RwLock<SmooMetricsState>>,
}

#[derive(Clone, Copy, Debug, Default)]
struct SmooMetricsSnapshot {
    connected: bool,
    active: bool,
    export_count: u32,
    session_id: u64,
    ios_up: u64,
    ios_down: u64,
    bytes_up: u64,
    bytes_down: u64,
    inflight_requests: u64,
    max_inflight_requests: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct SmooCounterTotals {
    ios_up: u64,
    ios_down: u64,
    bytes_up: u64,
    bytes_down: u64,
}

#[derive(Default)]
struct SmooMetricsState {
    connected: bool,
    active: bool,
    export_count: u32,
    session_id: u64,
    totals: SmooCounterTotals,
    last_transport: Option<SmooCounterTotals>,
    inflight_requests: u64,
    max_inflight_requests: u64,
}

impl SmooMetricsRegistry {
    fn begin_session(&self) -> SmooMetricsSnapshot {
        let mut state = self.inner.write().expect("smoo metrics lock poisoned");
        state.connected = true;
        state.active = false;
        state.inflight_requests = 0;
        state.last_transport = Some(SmooCounterTotals::default());
        state.snapshot()
    }

    fn update_status(
        &self,
        active: bool,
        export_count: u32,
        session_id: u64,
        counters: TransportCounterSnapshot,
    ) -> SmooMetricsSnapshot {
        let mut state = self.inner.write().expect("smoo metrics lock poisoned");
        state.connected = true;
        state.active = active;
        state.export_count = export_count;
        state.session_id = session_id;
        state.accumulate(counters);
        state.snapshot()
    }

    fn update_counters(&self, counters: TransportCounterSnapshot) -> SmooMetricsSnapshot {
        let mut state = self.inner.write().expect("smoo metrics lock poisoned");
        state.accumulate(counters);
        state.snapshot()
    }

    fn request_started(&self) -> SmooMetricsSnapshot {
        let mut state = self.inner.write().expect("smoo metrics lock poisoned");
        state.inflight_requests = state.inflight_requests.saturating_add(1);
        state.max_inflight_requests = state.max_inflight_requests.max(state.inflight_requests);
        state.snapshot()
    }

    fn request_finished(&self) -> SmooMetricsSnapshot {
        let mut state = self.inner.write().expect("smoo metrics lock poisoned");
        state.inflight_requests = state.inflight_requests.saturating_sub(1);
        state.snapshot()
    }

    fn end_session(&self, counters: TransportCounterSnapshot) -> SmooMetricsSnapshot {
        let mut state = self.inner.write().expect("smoo metrics lock poisoned");
        state.accumulate(counters);
        state.connected = false;
        state.active = false;
        state.inflight_requests = 0;
        state.last_transport = None;
        state.snapshot()
    }

    fn snapshot(&self) -> SmooMetricsSnapshot {
        self.inner
            .read()
            .expect("smoo metrics lock poisoned")
            .snapshot()
    }
}

impl SmooMetricsState {
    fn accumulate(&mut self, counters: TransportCounterSnapshot) {
        let current = SmooCounterTotals::from(counters);
        let previous = self.last_transport.unwrap_or_default();
        self.totals.ios_up = self
            .totals
            .ios_up
            .saturating_add(current.ios_up.saturating_sub(previous.ios_up));
        self.totals.ios_down = self
            .totals
            .ios_down
            .saturating_add(current.ios_down.saturating_sub(previous.ios_down));
        self.totals.bytes_up = self
            .totals
            .bytes_up
            .saturating_add(current.bytes_up.saturating_sub(previous.bytes_up));
        self.totals.bytes_down = self
            .totals
            .bytes_down
            .saturating_add(current.bytes_down.saturating_sub(previous.bytes_down));
        self.last_transport = Some(current);
    }

    fn snapshot(&self) -> SmooMetricsSnapshot {
        SmooMetricsSnapshot {
            connected: self.connected,
            active: self.active,
            export_count: self.export_count,
            session_id: self.session_id,
            ios_up: self.totals.ios_up,
            ios_down: self.totals.ios_down,
            bytes_up: self.totals.bytes_up,
            bytes_down: self.totals.bytes_down,
            inflight_requests: self.inflight_requests,
            max_inflight_requests: self.max_inflight_requests,
        }
    }
}

impl From<TransportCounterSnapshot> for SmooCounterTotals {
    fn from(value: TransportCounterSnapshot) -> Self {
        Self {
            ios_up: value.ios_up,
            ios_down: value.ios_down,
            bytes_up: value.bytes_up,
            bytes_down: value.bytes_down,
        }
    }
}

fn spawn_metrics_listener(
    port: u16,
    registry: SmooMetricsRegistry,
    shutdown: CancellationToken,
) -> Result<Option<JoinHandle<()>>> {
    if port == 0 {
        return Ok(None);
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let builder =
        Server::try_bind(&addr).map_err(|err| anyhow!("bind smoo metrics listener: {err}"))?;
    let task = tokio::spawn(async move {
        let make_svc = make_service_fn(move |_conn| {
            let registry = registry.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                    let registry = registry.clone();
                    async move {
                        if req.uri().path() != "/metrics" {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Body::from("not found"))
                                    .unwrap(),
                            );
                        }

                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(hyper::header::CONTENT_TYPE, "text/plain; version=0.0.4")
                                .body(Body::from(render_prometheus(registry.snapshot())))
                                .unwrap(),
                        )
                    }
                }))
            }
        });

        let graceful = builder.serve(make_svc).with_graceful_shutdown(async {
            shutdown.cancelled().await;
        });
        if let Err(err) = graceful.await {
            tracing::warn!(error = %err, %addr, "smoo metrics server error");
        }
    });

    Ok(Some(task))
}

fn render_prometheus(snapshot: SmooMetricsSnapshot) -> String {
    let connected = u8::from(snapshot.connected);
    let active = u8::from(snapshot.active);
    format!(
        "# HELP fastboop_smoo_host_connected Whether fastboop has an active smoo transport session.\n\
         # TYPE fastboop_smoo_host_connected gauge\n\
         fastboop_smoo_host_connected {connected}\n\
         # HELP fastboop_smoo_host_export_active Whether the smoo export is active according to gadget status.\n\
         # TYPE fastboop_smoo_host_export_active gauge\n\
         fastboop_smoo_host_export_active {active}\n\
         # HELP fastboop_smoo_host_export_count Number of exports reported by the smoo gadget.\n\
         # TYPE fastboop_smoo_host_export_count gauge\n\
         fastboop_smoo_host_export_count {export_count}\n\
         # HELP fastboop_smoo_host_session_id Current smoo gadget session id.\n\
         # TYPE fastboop_smoo_host_session_id gauge\n\
         fastboop_smoo_host_session_id {session_id}\n\
         # HELP fastboop_smoo_host_ios_up_total Host-to-gadget smoo transport operations.\n\
         # TYPE fastboop_smoo_host_ios_up_total counter\n\
         fastboop_smoo_host_ios_up_total {ios_up}\n\
         # HELP fastboop_smoo_host_ios_down_total Gadget-to-host smoo transport operations.\n\
         # TYPE fastboop_smoo_host_ios_down_total counter\n\
         fastboop_smoo_host_ios_down_total {ios_down}\n\
         # HELP fastboop_smoo_host_bytes_up_total Host-to-gadget smoo transport bytes.\n\
         # TYPE fastboop_smoo_host_bytes_up_total counter\n\
         fastboop_smoo_host_bytes_up_total {bytes_up}\n\
         # HELP fastboop_smoo_host_bytes_down_total Gadget-to-host smoo transport bytes.\n\
         # TYPE fastboop_smoo_host_bytes_down_total counter\n\
         fastboop_smoo_host_bytes_down_total {bytes_down}\n\
         # HELP fastboop_smoo_host_inflight_requests Requests read from the smoo interrupt endpoint and not yet answered.\n\
         # TYPE fastboop_smoo_host_inflight_requests gauge\n\
         fastboop_smoo_host_inflight_requests {inflight_requests}\n\
         # HELP fastboop_smoo_host_max_inflight_requests Maximum observed host-side in-flight smoo requests.\n\
         # TYPE fastboop_smoo_host_max_inflight_requests gauge\n\
         fastboop_smoo_host_max_inflight_requests {max_inflight_requests}\n",
        export_count = snapshot.export_count,
        session_id = snapshot.session_id,
        ios_up = snapshot.ios_up,
        ios_down = snapshot.ios_down,
        bytes_up = snapshot.bytes_up,
        bytes_down = snapshot.bytes_down,
        inflight_requests = snapshot.inflight_requests,
        max_inflight_requests = snapshot.max_inflight_requests,
    )
}
