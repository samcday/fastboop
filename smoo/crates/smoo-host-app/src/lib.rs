use anyhow::{anyhow, ensure, Context, Result};
use clap::{ArgGroup, Parser};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use metrics_exporter_prometheus::PrometheusBuilder;
use smoo_host_blocksource_cached::{CachedBlockSource, MemoryCacheStore};
use smoo_host_blocksource_http::HttpBlockSource;
use smoo_host_blocksources::device::DeviceBlockSource;
use smoo_host_blocksources::file::FileBlockSource;
use smoo_host_blocksources::random::RandomBlockSource;
use smoo_host_core::{
    register_export, BlockSource, BlockSourceHandle, BlockSourceResult, ExportIdentity,
};
use smoo_host_session::{HostSession, HostSessionConfig, HostSessionOutcome};
use smoo_host_transport_rusb::RusbTransport;
use std::{
    collections::BTreeMap, convert::Infallible, fs, net::SocketAddr, path::PathBuf, time::Duration,
};
use tokio::task::JoinHandle;
use tokio::{signal, time};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const SMOO_INTERFACE_CLASS: u8 = 0xFF;
const SMOO_INTERFACE_SUBCLASS: u8 = 0x53;
const SMOO_INTERFACE_PROTOCOL: u8 = 0x4D;
const HEARTBEAT_INTERVAL_SECS: u64 = 1;
const DISCOVERY_DELAY_INITIAL: Duration = Duration::from_millis(500);
const DISCOVERY_DELAY_MAX: Duration = Duration::from_secs(5);
const STATUS_RETRY_ATTEMPTS: usize = 5;
const RECONNECT_PAUSE: Duration = Duration::from_secs(1);

#[derive(Debug, Parser)]
#[command(name = "smoo-host-cli", version)]
#[command(
    about = "Host shim for smoo gadgets",
    long_about = "Host shim for smoo gadgets. By default all visible USB devices are scanned and the first interface matching the vendor triple 0xFF/0x53/0x4D is selected."
)]
#[command(
    group = ArgGroup::new("backing")
        .args(["files", "devices", "http", "cached_http", "random"])
        .required(true)
)]
pub struct Args {
    /// Optional USB vendor ID filter (hex). Defaults to all vendors.
    #[arg(long, value_name = "HEX", value_parser = parse_hex_u16)]
    pub vendor_id: Option<u16>,
    /// Optional USB product ID filter (hex). Defaults to all products.
    #[arg(long, value_name = "HEX", value_parser = parse_hex_u16)]
    pub product_id: Option<u16>,
    /// Disk image backing file(s). Repeatable for multiple exports.
    #[arg(long = "file", value_name = "PATH")]
    pub files: Vec<PathBuf>,
    /// Raw block device path(s). Repeatable for multiple exports.
    #[arg(long = "device", value_name = "PATH")]
    pub devices: Vec<PathBuf>,
    /// HTTP backing image(s). Repeatable; must be absolute URLs.
    #[arg(long = "http", value_name = "URL")]
    pub http: Vec<String>,
    /// HTTP backing image(s) cached in memory. Repeatable; must be absolute URLs.
    #[arg(long = "cached-http", value_name = "URL")]
    pub cached_http: Vec<String>,
    /// Synthetic random backing sized in blocks. Repeatable.
    #[arg(long = "random", value_name = "BLOCKS")]
    pub random: Vec<u64>,
    /// Seed for random backing. When multiple --random entries are provided, each uses seed+index.
    #[arg(long, default_value_t = 0)]
    pub random_seed: u64,
    /// Logical block size exposed through the gadget (bytes)
    #[arg(long, default_value_t = 512)]
    pub block_size: u32,
    /// Per-transfer timeout in milliseconds (clamped to 200ms for cancellation)
    #[arg(long, default_value_t = 1000)]
    pub timeout_ms: u64,
    /// Expose Prometheus metrics on this TCP port (0 disables)
    #[arg(long, default_value_t = 0)]
    pub metrics_port: u16,
}

enum HostSource {
    File(FileBlockSource),
    Device(DeviceBlockSource),
    Http(HttpBlockSource),
    CachedHttp(CachedBlockSource<HttpBlockSource, MemoryCacheStore>),
    Random(RandomBlockSource),
}

#[async_trait::async_trait]
impl BlockSource for HostSource {
    fn block_size(&self) -> u32 {
        match self {
            HostSource::File(inner) => inner.block_size(),
            HostSource::Device(inner) => inner.block_size(),
            HostSource::Http(inner) => inner.block_size(),
            HostSource::CachedHttp(inner) => inner.block_size(),
            HostSource::Random(inner) => inner.block_size(),
        }
    }

    async fn total_blocks(&self) -> BlockSourceResult<u64> {
        match self {
            HostSource::File(inner) => inner.total_blocks().await,
            HostSource::Device(inner) => inner.total_blocks().await,
            HostSource::Http(inner) => inner.total_blocks().await,
            HostSource::CachedHttp(inner) => inner.total_blocks().await,
            HostSource::Random(inner) => inner.total_blocks().await,
        }
    }

    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        match self {
            HostSource::File(inner) => inner.read_blocks(lba, buf).await,
            HostSource::Device(inner) => inner.read_blocks(lba, buf).await,
            HostSource::Http(inner) => inner.read_blocks(lba, buf).await,
            HostSource::CachedHttp(inner) => inner.read_blocks(lba, buf).await,
            HostSource::Random(inner) => inner.read_blocks(lba, buf).await,
        }
    }

    async fn write_blocks(&self, lba: u64, buf: &[u8]) -> BlockSourceResult<usize> {
        match self {
            HostSource::File(inner) => inner.write_blocks(lba, buf).await,
            HostSource::Device(inner) => inner.write_blocks(lba, buf).await,
            HostSource::Http(inner) => inner.write_blocks(lba, buf).await,
            HostSource::CachedHttp(inner) => inner.write_blocks(lba, buf).await,
            HostSource::Random(inner) => inner.write_blocks(lba, buf).await,
        }
    }

    async fn flush(&self) -> BlockSourceResult<()> {
        match self {
            HostSource::File(inner) => inner.flush().await,
            HostSource::Device(inner) => inner.flush().await,
            HostSource::Http(inner) => inner.flush().await,
            HostSource::CachedHttp(inner) => inner.flush().await,
            HostSource::Random(inner) => inner.flush().await,
        }
    }

    async fn discard(&self, lba: u64, num_blocks: u32) -> BlockSourceResult<()> {
        match self {
            HostSource::File(inner) => inner.discard(lba, num_blocks).await,
            HostSource::Device(inner) => inner.discard(lba, num_blocks).await,
            HostSource::Http(inner) => inner.discard(lba, num_blocks).await,
            HostSource::CachedHttp(inner) => inner.discard(lba, num_blocks).await,
            HostSource::Random(inner) => inner.discard(lba, num_blocks).await,
        }
    }
}

impl smoo_host_core::ExportIdentity for HostSource {
    fn write_export_id(&self, state: &mut dyn core::hash::Hasher) {
        match self {
            HostSource::File(inner) => ExportIdentity::write_export_id(inner, state),
            HostSource::Device(inner) => ExportIdentity::write_export_id(inner, state),
            HostSource::Http(inner) => ExportIdentity::write_export_id(inner, state),
            HostSource::CachedHttp(inner) => ExportIdentity::write_export_id(inner, state),
            HostSource::Random(inner) => ExportIdentity::write_export_id(inner, state),
        }
    }
}

pub async fn run_from_env() -> Result<()> {
    let args = Args::parse();
    run_with_args(args).await
}

pub async fn run_with_args(args: Args) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let shutdown = CancellationToken::new();
    let shutdown_watch = shutdown.clone();
    tokio::spawn(async move {
        let _ = signal::ctrl_c().await;
        shutdown_watch.cancel();
    });
    let _metrics_task = spawn_metrics_listener(args.metrics_port, shutdown.clone())?;
    let sources = open_sources(&args).await.context("open block sources")?;
    let mut has_connected = false;
    while !shutdown.is_cancelled() {
        match run_session(&args, sources.clone(), has_connected, shutdown.clone()).await? {
            SessionEnd::Shutdown => break,
            SessionEnd::TransportLost => {
                info!("gadget disconnected; waiting for reconnection");
                has_connected = true;
                time::sleep(RECONNECT_PAUSE).await;
            }
            SessionEnd::SessionRestart => {
                info!("gadget session changed; restarting host session");
                has_connected = true;
            }
        }
    }

    Ok(())
}

enum SessionEnd {
    Shutdown,
    TransportLost,
    SessionRestart,
}

async fn run_session(
    args: &Args,
    sources: BTreeMap<u32, BlockSourceHandle>,
    has_connected: bool,
    shutdown: CancellationToken,
) -> Result<SessionEnd> {
    let mut attempts = 0usize;
    let mut delay = DISCOVERY_DELAY_INITIAL;
    let transfer_timeout = Duration::from_millis(args.timeout_ms.min(200));
    let (transport, mut control) = loop {
        match RusbTransport::open_matching(
            args.vendor_id,
            args.product_id,
            SMOO_INTERFACE_CLASS,
            SMOO_INTERFACE_SUBCLASS,
            SMOO_INTERFACE_PROTOCOL,
            transfer_timeout,
        )
        .await
        {
            Ok((transport, control)) => break (transport, control),
            Err(err) => {
                if !has_connected && attempts == 0 {
                    warn!(error = %err, "no smoo gadget found; waiting for connection");
                } else {
                    debug!(error = %err, "gadget not present; retrying discovery");
                }
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        info!("shutdown requested");
                        return Ok(SessionEnd::Shutdown);
                    }
                    _ = time::sleep(delay) => {}
                }
                delay = delay.saturating_mul(2).min(DISCOVERY_DELAY_MAX);
                attempts += 1;
            }
        }
    };
    let session = HostSession::new(
        sources,
        HostSessionConfig {
            status_retry_attempts: STATUS_RETRY_ATTEMPTS,
        },
    )
    .map_err(|err| anyhow!(err.to_string()))?;
    let mut task = match session.start(transport, &mut control).await {
        Ok(task) => task,
        Err(err) => {
            warn!(error = %err, "host session setup failed");
            return Ok(SessionEnd::TransportLost);
        }
    };

    let heartbeat_interval = Duration::from_secs(HEARTBEAT_INTERVAL_SECS);
    info!("connected to smoo gadget");

    let outcome = loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("shutdown requested");
                task.stop();
                let _ = (&mut task).await;
                break SessionEnd::Shutdown;
            }
            finish = &mut task => {
                match finish.outcome {
                    Ok(HostSessionOutcome::Stopped) => break SessionEnd::Shutdown,
                    Ok(HostSessionOutcome::TransportLost) => break SessionEnd::TransportLost,
                    Ok(HostSessionOutcome::SessionChanged { previous, current }) => {
                        info!(
                            previous = format_args!("0x{previous:016x}"),
                            current = format_args!("0x{current:016x}"),
                            "gadget session changed; restarting"
                        );
                        break SessionEnd::SessionRestart;
                    }
                    Err(err) => return Err(anyhow!(err.to_string())),
                }
            }
            _ = time::sleep(heartbeat_interval), if !shutdown.is_cancelled() => {
                if let Err(err) = task.heartbeat(&mut control).await {
                    warn!(error = %err, "heartbeat transfer failed");
                    break SessionEnd::TransportLost;
                }
            }
        }
    };

    Ok(outcome)
}

async fn open_sources(args: &Args) -> Result<BTreeMap<u32, BlockSourceHandle>> {
    let mut sources = BTreeMap::new();
    let mut entries: Vec<smoo_proto::ConfigExport> = Vec::new();
    let block_size = args.block_size;
    ensure!(
        block_size.is_power_of_two(),
        "block size must be a power of two"
    );
    ensure!(block_size > 0, "block size must be non-zero");

    for path in &args.files {
        let canonical = canonicalize_path(path)?;
        let identity = format!("file:{}", canonical.display());
        let file_source = FileBlockSource::open(path, block_size).await?;
        let total_blocks = file_source
            .total_blocks()
            .await
            .map_err(|err| anyhow!(err))?;
        let size_bytes = total_blocks
            .checked_mul(block_size as u64)
            .ok_or_else(|| anyhow!("file backing size overflows u64"))?;
        ensure!(size_bytes > 0, "file backing size must be non-zero");
        let source = BlockSourceHandle::new(HostSource::File(file_source), identity.clone());
        register_export(
            &mut sources,
            &mut entries,
            source,
            identity,
            block_size,
            size_bytes,
        )
        .map_err(|err| anyhow!(err.to_string()))?;
    }

    for path in &args.devices {
        let canonical = canonicalize_path(path)?;
        let identity = format!("device:{}", canonical.display());
        let device_source = DeviceBlockSource::open(path, block_size).await?;
        let total_blocks = device_source
            .total_blocks()
            .await
            .map_err(|err| anyhow!(err))?;
        let size_bytes = total_blocks
            .checked_mul(block_size as u64)
            .ok_or_else(|| anyhow!("device backing size overflows u64"))?;
        ensure!(size_bytes > 0, "device backing size must be non-zero");
        let source = BlockSourceHandle::new(HostSource::Device(device_source), identity.clone());
        register_export(
            &mut sources,
            &mut entries,
            source,
            identity,
            block_size,
            size_bytes,
        )
        .map_err(|err| anyhow!(err.to_string()))?;
    }

    for url_str in &args.http {
        let url = url::Url::parse(url_str)
            .with_context(|| format!("parse http backing URL {url_str}"))?;
        ensure!(
            url.scheme() == "http" || url.scheme() == "https",
            "unsupported URL scheme {}",
            url.scheme()
        );
        let source = HttpBlockSource::new(url.clone(), block_size)
            .await
            .context("init HTTP block source")?;
        let size_bytes = source.size_bytes();
        ensure!(
            size_bytes % block_size as u64 == 0,
            "HTTP backing size must align to block size"
        );
        let source_id = format!("http:{url}");
        let shared = BlockSourceHandle::new(HostSource::Http(source), source_id);
        register_export(
            &mut sources,
            &mut entries,
            shared,
            format!("http:{url}"),
            block_size,
            size_bytes,
        )
        .map_err(|err| anyhow!(err.to_string()))?;
    }

    for url_str in &args.cached_http {
        let url = url::Url::parse(url_str)
            .with_context(|| format!("parse cached-http backing URL {url_str}"))?;
        ensure!(
            url.scheme() == "http" || url.scheme() == "https",
            "unsupported URL scheme {}",
            url.scheme()
        );
        let source = HttpBlockSource::new(url.clone(), block_size)
            .await
            .context("init HTTP block source")?;
        let size_bytes = source.size_bytes();
        ensure!(
            size_bytes % block_size as u64 == 0,
            "HTTP backing size must align to block size"
        );
        let total_blocks = size_bytes / block_size as u64;
        let cache = MemoryCacheStore::new(block_size, total_blocks)
            .context("allocate HTTP cache backing")?;
        let cached = CachedBlockSource::new(source, cache)
            .await
            .context("init cached HTTP block source")?;
        let source_id = format!("cached-http:{url}");
        let shared = BlockSourceHandle::new(HostSource::CachedHttp(cached), source_id);
        register_export(
            &mut sources,
            &mut entries,
            shared,
            format!("cached-http:{url}"),
            block_size,
            size_bytes,
        )
        .map_err(|err| anyhow!(err.to_string()))?;
    }

    for (idx, blocks) in args.random.iter().copied().enumerate() {
        ensure!(blocks > 0, "random backing requires block count > 0");
        let size_bytes = blocks
            .checked_mul(block_size as u64)
            .ok_or_else(|| anyhow!("random backing size overflows u64"))?;
        let seed = args.random_seed.wrapping_add(idx as u64);
        let source = BlockSourceHandle::new(
            HostSource::Random(RandomBlockSource::new(block_size, blocks, seed)?),
            format!("random:{seed}"),
        );
        register_export(
            &mut sources,
            &mut entries,
            source,
            format!("random:{seed}"),
            block_size,
            size_bytes,
        )
        .map_err(|err| anyhow!(err.to_string()))?;
    }

    Ok(sources)
}

fn canonicalize_path(path: &PathBuf) -> Result<PathBuf> {
    fs::canonicalize(path).with_context(|| format!("canonicalize {}", path.display()))
}

fn parse_hex_u16(s: &str) -> Result<u16, std::num::ParseIntError> {
    let trimmed = s.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(trimmed, 16)
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
                Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                    let handle = handle.clone();
                    async move {
                        if req.uri().path() != "/metrics" {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Body::from("not found"))
                                    .unwrap(),
                            );
                        }
                        let body = handle.render();
                        Ok::<_, Infallible>(
                            Response::builder()
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
