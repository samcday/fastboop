use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use gibblox_core::BlockReader;
use smoo_host_blocksource_gibblox::GibbloxBlockSource;
use smoo_host_core::{BlockSource, BlockSourceHandle, register_export};
use smoo_host_session::{HostSession, HostSessionConfig, HostSessionOutcome};
use smoo_host_transport_rusb::RusbTransport;
use tokio_util::sync::CancellationToken;

const SMOO_INTERFACE_CLASS: u8 = 0xFF;
const SMOO_INTERFACE_SUBCLASS: u8 = 0x53;
const SMOO_INTERFACE_PROTOCOL: u8 = 0x4D;
const TRANSFER_TIMEOUT: Duration = Duration::from_millis(200);
const DISCOVERY_RETRY: Duration = Duration::from_millis(500);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
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
    mut control: smoo_host_transport_rusb::RusbControl,
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
    let session = HostSession::new(
        sources,
        HostSessionConfig {
            status_retry_attempts: STATUS_RETRY_ATTEMPTS,
        },
    )
    .map_err(|err| anyhow!(err.to_string()))?;
    let mut task = session
        .start(transport, &mut control)
        .await
        .map_err(|err| anyhow!(err.to_string()))?;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                task.stop();
                let _ = task.await;
                return Ok(SessionEnd::Shutdown);
            }
            finish = &mut task => {
                return map_finish(finish);
            }
            _ = tokio::time::sleep(HEARTBEAT_INTERVAL) => {
                if let Err(err) = task.heartbeat(&mut control).await {
                    eprintln!("smoo heartbeat failed: {err}");
                    return Ok(SessionEnd::TransportLost);
                }
            }
        }
    }
}

fn map_finish(
    finish: smoo_host_session::HostSessionFinish,
) -> std::result::Result<SessionEnd, anyhow::Error> {
    match finish.outcome {
        Ok(HostSessionOutcome::Stopped) => Ok(SessionEnd::Shutdown),
        Ok(HostSessionOutcome::TransportLost) | Ok(HostSessionOutcome::SessionChanged { .. }) => {
            Ok(SessionEnd::TransportLost)
        }
        Err(err) => Err(anyhow!(err.to_string())),
    }
}
