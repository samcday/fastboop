use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use gibblox_core::BlockReader;
use smoo_host_blocksource_gibblox::GibbloxBlockSource;
use smoo_host_core::{BlockSource, BlockSourceHandle, register_export};
use smoo_host_session::{
    HostSession, HostSessionConfig, HostSessionDriveConfig, HostSessionDriveEvent,
    HostSessionDriveOutcome, drive_host_session,
};
use smoo_host_transport_rusb::RusbTransport;
use tokio_util::sync::CancellationToken;

use crate::boot_ui::{BootEvent, BootPhase};

const SMOO_INTERFACE_CLASS: u8 = 0xFF;
const SMOO_INTERFACE_SUBCLASS: u8 = 0x53;
const SMOO_INTERFACE_PROTOCOL: u8 = 0x4D;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(1);
const DISCOVERY_RETRY: Duration = Duration::from_millis(500);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const STATUS_RETRY_ATTEMPTS: usize = 5;

pub(crate) async fn run_host_daemon(
    reader: Arc<dyn BlockReader>,
    size_bytes: u64,
    identity: String,
    events: Sender<BootEvent>,
    shutdown: CancellationToken,
) -> Result<()> {
    run_host_daemon_async(reader, size_bytes, identity, events, shutdown).await
}

async fn run_host_daemon_async(
    reader: Arc<dyn BlockReader>,
    size_bytes: u64,
    identity: String,
    events: Sender<BootEvent>,
    shutdown: CancellationToken,
) -> Result<()> {
    let shutdown_watch = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown_watch.cancel();
    });

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
}

async fn run_session(
    transport: RusbTransport,
    mut control: smoo_host_transport_rusb::RusbControl,
    reader: Arc<dyn BlockReader>,
    size_bytes: u64,
    identity: String,
    runtime: SessionRuntime,
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
    let session = HostSession::new(
        sources,
        HostSessionConfig {
            status_retry_attempts: STATUS_RETRY_ATTEMPTS,
        },
    )
    .map_err(|err| anyhow!(err.to_string()))?;
    let task = session
        .start(transport, &mut control)
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
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
    let outcome = drive_host_session(
        task,
        control,
        runtime.shutdown.cancelled(),
        || tokio::time::sleep(HEARTBEAT_INTERVAL),
        HostSessionDriveConfig::default(),
        move |event| match event {
            HostSessionDriveEvent::HeartbeatStatus { status } => {
                emit(
                    &events,
                    BootEvent::SmooStatus {
                        active: status.export_active(),
                        export_count: status.export_count,
                        session_id: status.session_id,
                    },
                );
            }
            HostSessionDriveEvent::HeartbeatRecovered { missed_heartbeats } => {
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
