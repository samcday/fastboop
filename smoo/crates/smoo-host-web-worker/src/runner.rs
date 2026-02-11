use crate::api::{HostWorkerConfig, HostWorkerEvent};
use futures_channel::oneshot;
use futures_util::{FutureExt, select_biased};
use gibblox_blockreader_messageport::MessagePortBlockReaderClient;
use gibblox_core::BlockReader;
use gloo_timers::future::sleep;
use smoo_host_blocksource_gibblox::GibbloxBlockSource;
use smoo_host_core::{BlockSource, BlockSourceHandle, CountingTransport, register_export};
use smoo_host_session::{HostSession, HostSessionConfig, HostSessionOutcome};
use smoo_host_webusb::WebUsbTransport;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};
use wasm_bindgen_futures::spawn_local;
use web_sys::{MessagePort, UsbDevice};

pub(crate) struct WorkerRuntime {
    cfg: Option<Arc<RuntimeConfig>>,
    busy: bool,
    stop_tx: Option<oneshot::Sender<()>>,
}

impl WorkerRuntime {
    pub(crate) fn new() -> Self {
        Self {
            cfg: None,
            busy: false,
            stop_tx: None,
        }
    }

    pub(crate) fn initialized(&self) -> bool {
        self.cfg.is_some()
    }

    pub(crate) fn running(&self) -> bool {
        self.stop_tx.is_some()
    }
}

pub(crate) struct RuntimeConfig {
    pub(crate) reader: Arc<dyn BlockReader>,
    pub(crate) host_cfg: HostWorkerConfig,
}

const HEARTBEAT_MISS_BUDGET: u32 = 5;

pub(crate) async fn init_runtime(
    runtime: &mut WorkerRuntime,
    cfg: HostWorkerConfig,
    gibblox_port: MessagePort,
) -> Result<(), String> {
    if runtime.initialized() {
        return Err("worker is already initialized".to_string());
    }
    let client = MessagePortBlockReaderClient::connect(gibblox_port)
        .await
        .map_err(|err| err.to_string())?;
    runtime.cfg = Some(Arc::new(RuntimeConfig {
        reader: Arc::new(client),
        host_cfg: cfg,
    }));
    Ok(())
}

pub(crate) async fn start_session(
    runtime: &mut WorkerRuntime,
    device: UsbDevice,
    emit: impl Fn(HostWorkerEvent) + Clone + 'static,
    on_exit: impl Fn() + Clone + 'static,
) -> Result<(), String> {
    if !runtime.initialized() {
        return Err("worker is not initialized".to_string());
    }
    if runtime.busy {
        return Err("worker is busy".to_string());
    }
    if runtime.running() {
        return Err("session already running".to_string());
    }
    let cfg = runtime
        .cfg
        .as_ref()
        .cloned()
        .ok_or_else(|| "worker is not initialized".to_string())?;

    runtime.busy = true;
    info!("host worker session start requested");
    emit(HostWorkerEvent::Starting);

    let transport = match WebUsbTransport::new(device, cfg.host_cfg.transport).await {
        Ok(transport) => transport,
        Err(err) => {
            runtime.busy = false;
            warn!(error = %err, "host worker failed to open transport");
            return Err(err.to_string());
        }
    };
    info!("host worker transport connected");
    emit(HostWorkerEvent::TransportConnected);

    let mut control = transport.control_handle();
    let counting = CountingTransport::new(transport);
    let counters = counting.counters();

    let source = GibbloxBlockSource::new(cfg.reader.clone(), cfg.host_cfg.identity.clone());
    let block_size = source.block_size();
    if block_size == 0 {
        runtime.busy = false;
        return Err("block size must be non-zero".to_string());
    }
    if !cfg.host_cfg.size_bytes.is_multiple_of(block_size as u64) {
        runtime.busy = false;
        return Err("image size must align to export block size".to_string());
    }

    let source_handle = BlockSourceHandle::new(source, cfg.host_cfg.identity.clone());
    let mut sources = BTreeMap::new();
    let mut entries = Vec::new();
    register_export(
        &mut sources,
        &mut entries,
        source_handle,
        cfg.host_cfg.identity.clone(),
        block_size,
        cfg.host_cfg.size_bytes,
    )
    .map_err(|err| {
        runtime.busy = false;
        err.to_string()
    })?;

    let session = HostSession::new(
        sources,
        HostSessionConfig {
            status_retry_attempts: cfg.host_cfg.status_retry_attempts,
        },
    )
    .map_err(|err| {
        runtime.busy = false;
        err.to_string()
    })?;
    let mut task = session.start(counting, &mut control).await.map_err(|err| {
        runtime.busy = false;
        err.to_string()
    })?;
    info!("host worker session configured");
    emit(HostWorkerEvent::Configured);
    emit_counters(&emit, counters.snapshot());

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    runtime.stop_tx = Some(stop_tx);
    runtime.busy = false;

    let emit_for_task = emit.clone();
    spawn_local(async move {
        let mut stop_rx = stop_rx.fuse();
        let interval = Duration::from_millis(cfg.host_cfg.heartbeat_interval_ms as u64);
        let mut counters_tick = sleep(interval).fuse();
        let mut missed_heartbeats: u32 = 0;

        loop {
            select_biased! {
                _ = stop_rx => {
                    task.stop();
                    let finish = task.await;
                    emit_finish(&emit_for_task, finish.outcome);
                    emit_for_task(HostWorkerEvent::Stopped);
                    on_exit();
                    break;
                }
                finish = (&mut task).fuse() => {
                    emit_finish(&emit_for_task, finish.outcome);
                    emit_for_task(HostWorkerEvent::Stopped);
                    on_exit();
                    break;
                }
                _ = counters_tick => {
                    emit_counters(&emit_for_task, counters.snapshot());
                    match task.heartbeat(&mut control).await {
                        Ok(_status) => {
                            if missed_heartbeats > 0 {
                                info!(missed_heartbeats, "host worker heartbeat recovered");
                            }
                            missed_heartbeats = 0;
                        }
                        Err(err) => {
                            missed_heartbeats = missed_heartbeats.saturating_add(1);
                            warn!(
                                error = %err,
                                missed_heartbeats,
                                budget = HEARTBEAT_MISS_BUDGET,
                                "host worker heartbeat failed"
                            );
                            if missed_heartbeats >= HEARTBEAT_MISS_BUDGET {
                                warn!("host worker heartbeat miss budget exhausted");
                                task.stop();
                                let finish = task.await;
                                emit_finish(&emit_for_task, finish.outcome);
                                emit_for_task(HostWorkerEvent::Stopped);
                                on_exit();
                                break;
                            }
                        }
                    }
                    counters_tick = sleep(interval).fuse();
                }
            }
        }
    });

    Ok(())
}

pub(crate) fn stop_session(runtime: &mut WorkerRuntime) -> Result<(), String> {
    if runtime.busy {
        return Err("worker is busy".to_string());
    }
    let Some(stop_tx) = runtime.stop_tx.take() else {
        return Err("session is not running".to_string());
    };
    let _ = stop_tx.send(());
    Ok(())
}

pub(crate) fn mark_session_stopped(runtime: &mut WorkerRuntime) {
    runtime.stop_tx = None;
}

fn emit_finish(
    emit: &impl Fn(HostWorkerEvent),
    outcome: Result<HostSessionOutcome, smoo_host_session::HostSessionError>,
) {
    match outcome {
        Ok(HostSessionOutcome::Stopped) => {
            debug!("host worker session stopped");
        }
        Ok(HostSessionOutcome::TransportLost) => {
            warn!("host worker session transport lost");
            emit(HostWorkerEvent::TransportLost)
        }
        Ok(HostSessionOutcome::SessionChanged { previous, current }) => {
            warn!(previous, current, "host worker session changed");
            emit(HostWorkerEvent::SessionChanged { previous, current });
        }
        Err(err) => {
            warn!(error = %err, "host worker session failed");
            emit(HostWorkerEvent::Error {
                message: err.to_string(),
            })
        }
    }
}

fn emit_counters(
    emit: &impl Fn(HostWorkerEvent),
    snapshot: smoo_host_core::TransportCounterSnapshot,
) {
    emit(HostWorkerEvent::Counters {
        ios_up: snapshot.ios_up,
        ios_down: snapshot.ios_down,
        bytes_up: snapshot.bytes_up,
        bytes_down: snapshot.bytes_down,
    });
}
