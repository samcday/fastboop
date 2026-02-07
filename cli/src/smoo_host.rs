use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use gibblox_core::BlockReader;
use smoo_host_blocksource_gibblox::GibbloxBlockSource;
use smoo_host_core::control::{ConfigExportsV0, read_status};
use smoo_host_core::{
    BlockSource, BlockSourceHandle, HostErrorKind, SmooHost, TransportError, TransportErrorKind,
    heartbeat_once, register_export, start_host_io_pump,
};
use smoo_host_transport_rusb::RusbTransport;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const SMOO_INTERFACE_CLASS: u8 = 0xFF;
const SMOO_INTERFACE_SUBCLASS: u8 = 0x53;
const SMOO_INTERFACE_PROTOCOL: u8 = 0x4D;
const TRANSFER_TIMEOUT: Duration = Duration::from_millis(200);
const DISCOVERY_RETRY: Duration = Duration::from_millis(500);
const IDLE_POLL: Duration = Duration::from_millis(5);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const STATUS_RETRY_INTERVAL: Duration = Duration::from_millis(200);
const STATUS_RETRY_ATTEMPTS: usize = 5;

pub(crate) fn run_host_daemon(
    reader: Arc<dyn BlockReader>,
    size_bytes: u64,
    identity: String,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("create tokio runtime for smoo host")?;
    runtime.block_on(run_host_daemon_async(reader, size_bytes, identity))
}

async fn run_host_daemon_async(
    reader: Arc<dyn BlockReader>,
    size_bytes: u64,
    identity: String,
) -> Result<()> {
    let shutdown = CancellationToken::new();
    let shutdown_watch = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown_watch.cancel();
    });

    eprintln!("Waiting for smoo gadget and starting host daemon...");
    while !shutdown.is_cancelled() {
        let (transport, control) = match RusbTransport::open_matching(
            None,
            None,
            SMOO_INTERFACE_CLASS,
            SMOO_INTERFACE_SUBCLASS,
            SMOO_INTERFACE_PROTOCOL,
            TRANSFER_TIMEOUT,
        )
        .await
        {
            Ok(pair) => pair,
            Err(err) => {
                if shutdown.is_cancelled() {
                    break;
                }
                eprintln!("smoo gadget not ready: {err}");
                tokio::time::sleep(DISCOVERY_RETRY).await;
                continue;
            }
        };

        eprintln!("smoo gadget connected; serving export...");
        let outcome = run_session(
            transport,
            control,
            reader.clone(),
            size_bytes,
            identity.clone(),
            shutdown.clone(),
        )
        .await;
        match outcome {
            Ok(SessionEnd::Shutdown) => break,
            Ok(SessionEnd::TransportLost) => {
                if shutdown.is_cancelled() {
                    break;
                }
                eprintln!("smoo gadget disconnected; waiting to reconnect...");
            }
            Err(err) => {
                if shutdown.is_cancelled() {
                    break;
                }
                eprintln!("smoo host session ended with error: {err}");
                tokio::time::sleep(DISCOVERY_RETRY).await;
            }
        }
    }

    Ok(())
}

enum SessionEnd {
    Shutdown,
    TransportLost,
}

async fn run_session(
    transport: RusbTransport,
    control: smoo_host_transport_rusb::RusbControl,
    reader: Arc<dyn BlockReader>,
    size_bytes: u64,
    identity: String,
    shutdown: CancellationToken,
) -> Result<SessionEnd> {
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
    let payload = ConfigExportsV0::from_slice(&entries)
        .map_err(|err| anyhow!("build CONFIG_EXPORTS payload: {err:?}"))?;

    let (pump_handle, request_rx, pump_task) = start_host_io_pump(transport.clone());
    let pump_task = tokio::spawn(pump_task);

    let mut host = SmooHost::new(pump_handle.clone(), request_rx, sources);
    host.setup(&control).await.context("IDENT handshake")?;
    host.configure_exports_v0(&control, &payload)
        .await
        .context("send CONFIG_EXPORTS")?;

    let initial_session_id =
        match fetch_status_with_retry(&control, STATUS_RETRY_ATTEMPTS, STATUS_RETRY_INTERVAL).await
        {
            Ok(session_id) => session_id,
            Err(err) => {
                eprintln!("SMOO_STATUS failed after CONFIG_EXPORTS: {err}");
                shutdown_pump(pump_handle, pump_task).await;
                return Ok(SessionEnd::TransportLost);
            }
        };

    let (heartbeat_tx, mut heartbeat_rx) = tokio::sync::mpsc::unbounded_channel();
    let heartbeat_client = control.clone();
    let heartbeat_task = tokio::spawn(async move {
        if let Err(err) =
            run_heartbeat(heartbeat_client, initial_session_id, HEARTBEAT_INTERVAL).await
        {
            let _ = heartbeat_tx.send(err);
        }
    });

    let mut pump_task = pump_task;
    let result = loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                break Ok(SessionEnd::Shutdown);
            }
            pump_result = &mut pump_task => {
                match pump_result {
                    Ok(Ok(())) | Ok(Err(_)) | Err(_) => break Ok(SessionEnd::TransportLost),
                }
            }
            event = heartbeat_rx.recv() => {
                if let Some(event) = event {
                    eprintln!("smoo heartbeat ended: {event}");
                }
                break Ok(SessionEnd::TransportLost);
            }
            _ = tokio::time::sleep(IDLE_POLL) => {
                match host.run_once().await {
                    Ok(()) => {}
                    Err(err) if err.kind() == HostErrorKind::Transport => break Ok(SessionEnd::TransportLost),
                    Err(err) => break Err(anyhow!(err.to_string())),
                }
            }
        }
    };

    if !heartbeat_task.is_finished() {
        heartbeat_task.abort();
    }
    let _ = heartbeat_task.await;

    shutdown_pump(pump_handle, pump_task).await;
    result
}

#[derive(Debug, Clone)]
enum HeartbeatEvent {
    SessionChanged { previous: u64, current: u64 },
    TransferFailed(String),
}

impl std::fmt::Display for HeartbeatEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeartbeatEvent::SessionChanged { previous, current } => {
                write!(
                    f,
                    "gadget session changed (0x{previous:016x} -> 0x{current:016x})"
                )
            }
            HeartbeatEvent::TransferFailed(err) => write!(f, "heartbeat transfer failed: {err}"),
        }
    }
}

async fn run_heartbeat(
    client: smoo_host_transport_rusb::RusbControl,
    initial_session_id: u64,
    interval: Duration,
) -> std::result::Result<(), HeartbeatEvent> {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match heartbeat_once(&client).await {
            Ok(status) => {
                if status.session_id != initial_session_id {
                    return Err(HeartbeatEvent::SessionChanged {
                        previous: initial_session_id,
                        current: status.session_id,
                    });
                }
            }
            Err(err) => {
                return Err(HeartbeatEvent::TransferFailed(err.to_string()));
            }
        }
    }
}

async fn fetch_status_with_retry(
    client: &smoo_host_transport_rusb::RusbControl,
    attempts: usize,
    delay: Duration,
) -> std::result::Result<u64, TransportError> {
    let mut attempt = 0;
    loop {
        match read_status(client).await {
            Ok(status) => return Ok(status.session_id),
            Err(err) => {
                attempt += 1;
                if attempt >= attempts {
                    return Err(err);
                }
                if err.kind() != TransportErrorKind::Timeout || attempt > 1 {
                    eprintln!("SMOO_STATUS attempt {attempt}/{attempts} failed: {err}; retrying");
                }
                tokio::time::sleep(delay).await;
            }
        }
    }
}

async fn shutdown_pump(
    pump_handle: smoo_host_core::HostIoPumpHandle,
    pump_task: JoinHandle<smoo_host_core::TransportResult<()>>,
) {
    let _ = pump_handle.shutdown().await;
    if !pump_task.is_finished() {
        pump_task.abort();
    }
    let _ = pump_task.await;
}
