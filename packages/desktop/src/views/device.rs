use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use dioxus::prelude::*;
use fastboop_core::bootimg::build_android_bootimg;
use fastboop_core::device::DeviceHandle as _;
use fastboop_core::fastboot::{boot, download};
use fastboop_core::Personalization;
use fastboop_rootfs_erofs::{CacheStatsHandle, CacheStatsSource, ErofsRootfs, RootfsCacheStats};
use fastboop_stage0_generator::{build_stage0, Stage0Options};
use gibblox_cache::CachedBlockReader;
use gibblox_cache_store_std::StdCacheOps;
use gibblox_core::{block_identity_string, BlockReader};
use gibblox_http::HttpBlockReader;
use smoo_host_blocksource_gibblox::GibbloxBlockSource;
use smoo_host_core::{
    register_export, BlockSource, BlockSourceHandle, CountingTransport, TransportCounterSnapshot,
};
use smoo_host_session::{HostSession, HostSessionConfig, HostSessionOutcome};
use smoo_host_transport_rusb::RusbTransport;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info};
use ui::{
    oneplus_fajita_dtbo_overlays, CacheStatsPanel, CacheStatsViewModel, SmooStatsHandle,
    SmooStatsPanel, SmooStatsViewModel,
};
use url::Url;

use super::session::{update_session_phase, BootRuntime, SessionPhase, SessionStore};

const ROOTFS_URL: &str = "https://bleeding.fastboop.win/sdm845-live-fedora/20260208.ero";
const EXTRA_CMDLINE: &str =
    "selinux=0 sysrq_always_enabled=1 panic=5 smoo.max_io_bytes=1048576 init_on_alloc=0 rhgb drm.panic_screen=kmsg smoo.queue_count=1 smoo.queue_depth=1 regulator_ignore_unused";
const SMOO_INTERFACE_CLASS: u8 = 0xFF;
const SMOO_INTERFACE_SUBCLASS: u8 = 0x53;
const SMOO_INTERFACE_PROTOCOL: u8 = 0x4D;
const FASTBOOT_INTERFACE_SUBCLASS: u8 = 0x42;
const FASTBOOT_INTERFACE_PROTOCOL: u8 = 0x03;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(1);
const DISCOVERY_RETRY: Duration = Duration::from_millis(500);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const HEARTBEAT_MISS_BUDGET: u32 = 5;
const STATUS_RETRY_ATTEMPTS: usize = 5;
const CACHE_STATS_POLL_INTERVAL: Duration = Duration::from_millis(500);

struct DesktopCacheStatsSource {
    reader: Arc<CachedBlockReader<HttpBlockReader, StdCacheOps>>,
}

#[async_trait::async_trait]
impl CacheStatsSource for DesktopCacheStatsSource {
    async fn snapshot(&self) -> Result<RootfsCacheStats> {
        let stats = self.reader.get_stats().await;
        Ok(RootfsCacheStats {
            total_hits: stats.total_hits,
            total_misses: stats.total_misses,
            cached_blocks: stats.cached_blocks,
            total_blocks: stats.total_blocks,
        })
    }
}

#[component]
pub fn DevicePage(session_id: String) -> Element {
    let sessions = use_context::<SessionStore>();
    let navigator = use_navigator();

    let Some(session) = sessions.read().iter().find(|s| s.id == session_id).cloned() else {
        return rsx! {
            section { id: "landing",
                div { class: "landing__panel",
                    h1 { "Session not found" }
                    p { "That device session no longer exists." }
                    button { class: "cta__button", onclick: move |_| { navigator.push(crate::Route::Home {}); }, "Back" }
                }
            }
        };
    };

    match session.phase {
        SessionPhase::Booting { step, cache_stats } => {
            rsx! { BootingDevice { session_id, step, cache_stats } }
        }
        SessionPhase::Active { .. } => rsx! { BootedDevice { session_id } },
        SessionPhase::Error { summary } => rsx! { BootError { summary } },
    }
}

#[component]
fn BootingDevice(
    session_id: String,
    step: String,
    cache_stats: Option<CacheStatsViewModel>,
) -> Element {
    let sessions = use_context::<SessionStore>();
    let mut started = use_signal(|| false);

    use_effect(move || {
        if started() {
            return;
        }
        started.set(true);
        let mut sessions = sessions;
        let session_id = session_id.clone();
        spawn(async move {
            match boot_selected_device(&mut sessions, &session_id).await {
                Ok(runtime) => update_session_phase(
                    &mut sessions,
                    &session_id,
                    SessionPhase::Active {
                        runtime,
                        host_started: false,
                    },
                ),
                Err(err) => update_session_phase(
                    &mut sessions,
                    &session_id,
                    SessionPhase::Error {
                        summary: err.to_string(),
                    },
                ),
            }
        });
    });

    rsx! {
        section { id: "landing",
            div { class: "landing__panel",
                p { class: "landing__eyebrow", "Booting" }
                h1 { "Working on it..." }
                p { class: "landing__lede", "{step}" }
                if let Some(cache_stats) = cache_stats {
                    CacheStatsPanel { stats: cache_stats }
                }
            }
        }
    }
}

#[component]
fn BootedDevice(session_id: String) -> Element {
    let mut sessions = use_context::<SessionStore>();
    let state = sessions
        .read()
        .iter()
        .find(|s| s.id == session_id)
        .and_then(|s| match &s.phase {
            SessionPhase::Active {
                runtime,
                host_started,
            } => Some((runtime.clone(), *host_started)),
            _ => None,
        });
    let Some((runtime, host_started)) = state else {
        return rsx! {};
    };
    let mut kickoff = use_signal(|| false);
    let cache_stats = use_signal(|| Option::<CacheStatsViewModel>::None);
    let smoo_stats = use_signal(|| Option::<SmooStatsViewModel>::None);
    let cache_stats_stop = use_signal(|| Option::<Arc<AtomicBool>>::None);
    let smoo_stats_stop = use_signal(|| Option::<Arc<AtomicBool>>::None);
    let runtime_for_kickoff = runtime.clone();
    use_effect(move || {
        if host_started || kickoff() {
            return;
        }
        kickoff.set(true);
        update_session_phase(
            &mut sessions,
            &session_id,
            SessionPhase::Active {
                runtime: runtime_for_kickoff.clone(),
                host_started: true,
            },
        );
        let runtime_for_host = runtime_for_kickoff.clone();
        std::thread::Builder::new()
            .name(format!("fastboop-smoo-{session_id}"))
            .spawn(move || {
                if let Err(err) = run_rusb_host_daemon(
                    runtime_for_host.reader,
                    runtime_for_host.size_bytes,
                    runtime_for_host.identity,
                    runtime_for_host.smoo_stats,
                ) {
                    error!(%err, "desktop smoo host daemon stopped");
                }
            })
            .ok();
    });

    {
        let mut cache_stats = cache_stats;
        let mut cache_stats_stop = cache_stats_stop;
        let cache_stats_handle = runtime.cache_stats.clone();
        use_effect(move || {
            let Some(cache_stats_handle) = cache_stats_handle.clone() else {
                return;
            };
            if cache_stats_stop().is_some() {
                return;
            }

            let stop = Arc::new(AtomicBool::new(false));
            cache_stats_stop.set(Some(stop.clone()));
            spawn(async move {
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    match cache_stats_handle.snapshot().await {
                        Ok(snapshot) => {
                            cache_stats.set(Some(CacheStatsViewModel {
                                total_blocks: snapshot.total_blocks,
                                cached_blocks: snapshot.cached_blocks,
                                total_hits: snapshot.total_hits,
                                total_misses: snapshot.total_misses,
                            }));
                        }
                        Err(err) => {
                            tracing::debug!("cache stats poll failed: {err}");
                        }
                    }
                    tokio::time::sleep(CACHE_STATS_POLL_INTERVAL).await;
                }
            });
        });
    }

    {
        let mut smoo_stats = smoo_stats;
        let mut smoo_stats_stop = smoo_stats_stop;
        let smoo_stats_handle = runtime.smoo_stats.clone();
        use_effect(move || {
            if smoo_stats_stop().is_some() {
                return;
            }
            let smoo_stats_handle = smoo_stats_handle.clone();

            let stop = Arc::new(AtomicBool::new(false));
            smoo_stats_stop.set(Some(stop.clone()));
            spawn(async move {
                let mut previous = smoo_stats_handle.snapshot();
                let mut previous_ts = std::time::Instant::now();
                let mut ewma_iops = 0.0f64;
                let mut ewma_up_bps = 0.0f64;
                let mut ewma_down_bps = 0.0f64;
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    tokio::time::sleep(CACHE_STATS_POLL_INTERVAL).await;
                    let now_ts = std::time::Instant::now();
                    let dt = now_ts.duration_since(previous_ts).as_secs_f64().max(0.001);
                    let snapshot = smoo_stats_handle.snapshot();

                    let io_delta = snapshot.total_ios.saturating_sub(previous.total_ios) as f64;
                    let up_delta = snapshot
                        .total_bytes_up
                        .saturating_sub(previous.total_bytes_up)
                        as f64;
                    let down_delta = snapshot
                        .total_bytes_down
                        .saturating_sub(previous.total_bytes_down)
                        as f64;

                    let inst_iops = io_delta / dt;
                    let inst_up_bps = up_delta / dt;
                    let inst_down_bps = down_delta / dt;
                    let alpha = 1.0 - (-dt / 5.0).exp();

                    ewma_iops += alpha * (inst_iops - ewma_iops);
                    ewma_up_bps += alpha * (inst_up_bps - ewma_up_bps);
                    ewma_down_bps += alpha * (inst_down_bps - ewma_down_bps);

                    smoo_stats.set(Some(SmooStatsViewModel {
                        connected: snapshot.connected,
                        total_ios: snapshot.total_ios,
                        total_bytes_up: snapshot.total_bytes_up,
                        total_bytes_down: snapshot.total_bytes_down,
                        ewma_iops,
                        ewma_up_bps,
                        ewma_down_bps,
                    }));

                    previous = snapshot;
                    previous_ts = now_ts;
                }
            });
        });
    }

    {
        let mut cache_stats_stop = cache_stats_stop;
        use_drop(move || {
            if let Some(stop) = cache_stats_stop.write().take() {
                stop.store(true, Ordering::Relaxed);
            }
        });
    }

    {
        let mut smoo_stats_stop = smoo_stats_stop;
        use_drop(move || {
            if let Some(stop) = smoo_stats_stop.write().take() {
                stop.store(true, Ordering::Relaxed);
            }
        });
    }

    let cache_stats = cache_stats();
    let smoo_stats = smoo_stats();

    rsx! {
        section { id: "landing",
            div { class: "landing__panel",
                p { class: "landing__eyebrow", "Active" }
                h1 { "We're live." }
                p { class: "landing__lede", "Please don't close this window while the session is active." }
                p { class: "landing__note", "Rootfs: {ROOTFS_URL}" }
                if let Some(smoo_stats) = smoo_stats {
                    SmooStatsPanel { stats: smoo_stats }
                }
                if let Some(cache_stats) = cache_stats {
                    CacheStatsPanel { stats: cache_stats }
                }
            }
        }
    }
}

#[component]
fn BootError(summary: String) -> Element {
    rsx! {
        section { id: "landing",
            div { class: "landing__panel",
                p { class: "landing__eyebrow", "onoes" }
                h1 { "Boot failed" }
                p { class: "landing__lede", "{summary}" }
            }
        }
    }
}

async fn boot_selected_device(
    sessions: &mut SessionStore,
    session_id: &str,
) -> Result<BootRuntime> {
    let session = sessions
        .read()
        .iter()
        .find(|s| s.id == session_id)
        .cloned()
        .ok_or_else(|| anyhow!("session not found"))?;

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: format!(
                "Opening rootfs {} for {} ({:04x}:{:04x})",
                ROOTFS_URL, session.device.name, session.device.vid, session.device.pid
            ),
            cache_stats: None,
        },
    );
    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Building stage0".to_string(),
            cache_stats: None,
        },
    );
    let dtbo_overlays = if session.device.profile.id == "oneplus-fajita" {
        oneplus_fajita_dtbo_overlays()
    } else {
        Vec::new()
    };
    let stage0_opts = Stage0Options {
        extra_modules: vec!["erofs".to_string()],
        dtb_override: None,
        dtbo_overlays,
        enable_serial: true,
        mimic_fastboot: true,
        smoo_vendor: Some(session.device.vid),
        smoo_product: Some(session.device.pid),
        smoo_serial: session.device.serial.clone(),
        personalization: Some(personalization_from_host()),
    };
    let (build, runtime) = build_stage0_artifacts(
        session.device.profile.clone(),
        stage0_opts,
        *sessions,
        session_id.to_string(),
    )
    .await
    .context("open rootfs and build stage0")?;

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Assembling android boot image".to_string(),
            cache_stats: None,
        },
    );
    let cmdline = join_cmdline(
        session
            .device
            .profile
            .boot
            .fastboot_boot
            .android_bootimg
            .cmdline_append
            .as_deref(),
        Some(build.kernel_cmdline_append.as_str()),
    );
    let mut kernel_image = build.kernel_image;
    let mut profile = session.device.profile.clone();
    if profile
        .boot
        .fastboot_boot
        .android_bootimg
        .kernel
        .encoding
        .append_dtb()
    {
        kernel_image.extend_from_slice(&build.dtb);
        let header_version = profile.boot.fastboot_boot.android_bootimg.header_version;
        if header_version >= 2 {
            profile.boot.fastboot_boot.android_bootimg.header_version = 0;
        }
    }
    let bootimg = build_android_bootimg(
        &profile,
        &kernel_image,
        &build.initrd,
        Some(&build.dtb),
        &cmdline,
    )
    .map_err(|err| anyhow!("bootimg build failed: {err}"))?;

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Opening fastboot transport".to_string(),
            cache_stats: None,
        },
    );
    let mut fastboot = session
        .device
        .handle
        .open_fastboot()
        .await
        .map_err(|err| anyhow!("open fastboot failed: {err}"))?;

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Downloading boot image".to_string(),
            cache_stats: None,
        },
    );
    download(&mut fastboot, &bootimg)
        .await
        .map_err(|err| anyhow!("fastboot download failed: {err}"))?;

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Issuing fastboot boot".to_string(),
            cache_stats: None,
        },
    );
    boot(&mut fastboot)
        .await
        .map_err(|err| anyhow!("fastboot boot failed: {err}"))?;

    Ok(BootRuntime {
        reader: runtime.reader,
        size_bytes: runtime.size_bytes,
        identity: runtime.identity,
        cache_stats: runtime.cache_stats,
        smoo_stats: runtime.smoo_stats,
    })
}

async fn build_stage0_artifacts(
    profile: fastboop_core::DeviceProfile,
    stage0_opts: Stage0Options,
    mut sessions: SessionStore,
    session_id: String,
) -> Result<(fastboop_stage0_generator::Stage0Build, BootRuntime)> {
    let (tx, rx) = oneshot::channel();
    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<CacheStatsViewModel>();
    std::thread::Builder::new()
        .name("fastboop-stage0-build".to_string())
        .spawn(move || {
            let result: Result<_> = (|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("create tokio runtime for stage0 build")?;
                runtime.block_on(async move {
                    info!(profile = %profile.id, "opening rootfs for desktop boot");
                    let url = Url::parse(ROOTFS_URL)
                        .map_err(|err| anyhow!("parse rootfs URL {ROOTFS_URL}: {err}"))?;
                    let http_reader = HttpBlockReader::new(
                        url.clone(),
                        fastboop_rootfs_erofs::DEFAULT_IMAGE_BLOCK_SIZE,
                    )
                    .await
                    .map_err(|err| anyhow!("open HTTP reader {url}: {err}"))?;
                    let size_bytes = http_reader.size_bytes();
                    let cache = StdCacheOps::open_default_for_reader(&http_reader)
                        .await
                        .map_err(|err| anyhow!("open std cache for HTTP rootfs: {err}"))?;
                    let cached =
                        Arc::new(CachedBlockReader::new(http_reader, cache).await.map_err(
                            |err| anyhow!("initialize std cache for HTTP rootfs: {err}"),
                        )?);
                    let reader: Arc<dyn BlockReader> = cached.clone();
                    let provider = ErofsRootfs::wrap(reader.clone(), size_bytes).await?;
                    let cache_stats: Option<CacheStatsHandle> =
                        Some(Arc::new(DesktopCacheStatsSource { reader: cached })
                            as CacheStatsHandle);
                    let cache_stats_stop = Arc::new(AtomicBool::new(false));
                    if let Some(cache_stats) = cache_stats.clone() {
                        let cache_stats_stop = cache_stats_stop.clone();
                        let progress_tx = progress_tx.clone();
                        tokio::spawn(async move {
                            loop {
                                if cache_stats_stop.load(Ordering::Relaxed) {
                                    break;
                                }
                                match cache_stats.snapshot().await {
                                    Ok(snapshot) => {
                                        let _ = progress_tx.send(CacheStatsViewModel {
                                            total_blocks: snapshot.total_blocks,
                                            cached_blocks: snapshot.cached_blocks,
                                            total_hits: snapshot.total_hits,
                                            total_misses: snapshot.total_misses,
                                        });
                                    }
                                    Err(err) => {
                                        tracing::debug!(
                                            "boot-stage cache stats poll failed: {err}"
                                        );
                                    }
                                }
                                tokio::time::sleep(CACHE_STATS_POLL_INTERVAL).await;
                            }
                        });
                    }
                    info!(profile = %profile.id, "building stage0 payload");
                    let build =
                        build_stage0(&profile, &provider, &stage0_opts, Some(EXTRA_CMDLINE), None)
                            .await
                            .map_err(|err| anyhow!("stage0 build failed: {err:?}"))?;
                    let rootfs_identity = block_identity_string(reader.as_ref());
                    cache_stats_stop.store(true, Ordering::Relaxed);
                    Ok((
                        build,
                        BootRuntime {
                            reader,
                            size_bytes,
                            identity: rootfs_identity,
                            cache_stats,
                            smoo_stats: SmooStatsHandle::new(),
                        },
                    ))
                })
            })();
            let _ = tx.send(result);
        })
        .context("spawn stage0 build worker thread")?;

    let mut rx = rx;
    loop {
        tokio::select! {
            maybe_stats = progress_rx.recv() => {
                if let Some(cache_stats) = maybe_stats {
                    update_session_phase(
                        &mut sessions,
                        &session_id,
                        SessionPhase::Booting {
                            step: "Building stage0".to_string(),
                            cache_stats: Some(cache_stats),
                        },
                    );
                }
            }
            result = &mut rx => {
                return result.map_err(|_| anyhow!("stage0 build worker thread exited unexpectedly"))?;
            }
        }
    }
}

fn run_rusb_host_daemon(
    reader: std::sync::Arc<dyn gibblox_core::BlockReader>,
    size_bytes: u64,
    identity: String,
    smoo_stats: SmooStatsHandle,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("create tokio runtime for smoo host")?;
    runtime.block_on(async move {
        loop {
            let (transport, control) = match open_matching_rusb_transport().await {
                Ok(pair) => pair,
                Err(err) => {
                    info!(%err, "desktop smoo gadget not ready yet");
                    tokio::time::sleep(DISCOVERY_RETRY).await;
                    continue;
                }
            };

            match run_rusb_session(
                transport,
                control,
                reader.clone(),
                size_bytes,
                identity.clone(),
                smoo_stats.clone(),
            )
            .await
            {
                Ok(SessionEnd::TransportLost) => {
                    info!("desktop smoo gadget disconnected; waiting to reconnect");
                }
                Err(err) => {
                    error!(%err, "desktop smoo session failed");
                }
            }
            tokio::time::sleep(DISCOVERY_RETRY).await;
        }
    })
}

async fn open_matching_rusb_transport() -> std::result::Result<
    (RusbTransport, smoo_host_transport_rusb::RusbControl),
    smoo_host_core::TransportError,
> {
    match RusbTransport::open_matching(
        None,
        None,
        SMOO_INTERFACE_CLASS,
        SMOO_INTERFACE_SUBCLASS,
        SMOO_INTERFACE_PROTOCOL,
        TRANSFER_TIMEOUT,
    )
    .await
    {
        Ok(pair) => Ok(pair),
        Err(_) => {
            RusbTransport::open_matching(
                None,
                None,
                SMOO_INTERFACE_CLASS,
                FASTBOOT_INTERFACE_SUBCLASS,
                FASTBOOT_INTERFACE_PROTOCOL,
                TRANSFER_TIMEOUT,
            )
            .await
        }
    }
}

enum SessionEnd {
    TransportLost,
}

async fn run_rusb_session(
    transport: RusbTransport,
    mut control: smoo_host_transport_rusb::RusbControl,
    reader: std::sync::Arc<dyn gibblox_core::BlockReader>,
    size_bytes: u64,
    identity: String,
    smoo_stats: SmooStatsHandle,
) -> Result<SessionEnd> {
    let transport = CountingTransport::new(transport);
    let counters = transport.counters();
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
    smoo_stats.set_connected(true);
    let mut counter_snapshot = counters.snapshot();
    let mut missed_heartbeats: u32 = 0;

    loop {
        tokio::select! {
            finish = &mut task => {
                update_smoo_stats_from_transport(
                    &smoo_stats,
                    &mut counter_snapshot,
                    counters.snapshot(),
                );
                smoo_stats.set_connected(false);
                match finish.outcome {
                    Ok(HostSessionOutcome::Stopped) => return Ok(SessionEnd::TransportLost),
                    Ok(HostSessionOutcome::TransportLost) => return Ok(SessionEnd::TransportLost),
                    Ok(HostSessionOutcome::SessionChanged { previous, current }) => {
                        info!(
                            previous = format_args!("0x{previous:016x}"),
                            current = format_args!("0x{current:016x}"),
                            "desktop smoo session changed; reconnecting"
                        );
                        return Ok(SessionEnd::TransportLost);
                    }
                    Err(err) => return Err(anyhow!(err.to_string())),
                }
            }
            _ = tokio::time::sleep(HEARTBEAT_INTERVAL) => {
                match tokio::time::timeout(HEARTBEAT_INTERVAL, task.heartbeat(&mut control)).await {
                    Ok(Ok(_status)) => {
                        if missed_heartbeats > 0 {
                            info!(missed_heartbeats, "desktop smoo heartbeat recovered");
                        }
                        missed_heartbeats = 0;
                    }
                    Ok(Err(err)) => {
                        missed_heartbeats = missed_heartbeats.saturating_add(1);
                        warn!(
                            %err,
                            missed_heartbeats,
                            budget = HEARTBEAT_MISS_BUDGET,
                            "desktop smoo heartbeat failed"
                        );
                    }
                    Err(_) => {
                        missed_heartbeats = missed_heartbeats.saturating_add(1);
                        warn!(
                            missed_heartbeats,
                            budget = HEARTBEAT_MISS_BUDGET,
                            "desktop smoo heartbeat timed out"
                        );
                    }
                }
                if missed_heartbeats >= HEARTBEAT_MISS_BUDGET {
                    error!("desktop smoo heartbeat budget exhausted");
                    update_smoo_stats_from_transport(
                        &smoo_stats,
                        &mut counter_snapshot,
                        counters.snapshot(),
                    );
                    smoo_stats.set_connected(false);
                    return Ok(SessionEnd::TransportLost);
                }
                update_smoo_stats_from_transport(
                    &smoo_stats,
                    &mut counter_snapshot,
                    counters.snapshot(),
                );
            }
        }
    }
}

fn update_smoo_stats_from_transport(
    smoo_stats: &SmooStatsHandle,
    previous: &mut TransportCounterSnapshot,
    current: TransportCounterSnapshot,
) {
    let bytes_up_delta = current.bytes_up.saturating_sub(previous.bytes_up);
    let bytes_down_delta = current.bytes_down.saturating_sub(previous.bytes_down);
    let ios_up_delta = current.ios_up.saturating_sub(previous.ios_up);
    let ios_down_delta = current.ios_down.saturating_sub(previous.ios_down);
    smoo_stats.add_deltas(
        ios_up_delta.saturating_add(ios_down_delta),
        bytes_up_delta,
        bytes_down_delta,
    );
    *previous = current;
}

fn join_cmdline(left: Option<&str>, right: Option<&str>) -> String {
    let mut out = String::new();
    if let Some(left) = left {
        out.push_str(left.trim());
    }
    if let Some(right) = right {
        let right = right.trim();
        if !right.is_empty() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(right);
        }
    }
    out
}

fn personalization_from_host() -> Personalization {
    let locale = detect_locale().unwrap_or_else(|| "en_US.UTF-8".to_string());
    let locale_messages = detect_locale_messages().unwrap_or_else(|| locale.clone());
    let keymap = detect_keymap().unwrap_or_else(|| "us".to_string());
    let timezone = detect_timezone().unwrap_or_else(|| "UTC".to_string());
    Personalization {
        locale: Some(locale),
        locale_messages: Some(locale_messages),
        keymap: Some(keymap),
        timezone: Some(timezone),
    }
}

fn detect_locale() -> Option<String> {
    locale_from_env_or_file("LC_ALL").or_else(|| locale_from_env_or_file("LANG"))
}

fn detect_locale_messages() -> Option<String> {
    locale_from_env_or_file("LC_MESSAGES")
        .or_else(|| locale_from_env_or_file("LC_ALL"))
        .or_else(|| locale_from_env_or_file("LANG"))
}

fn locale_from_env_or_file(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .and_then(nonempty)
        .or_else(|| read_key_from_file(Path::new("/etc/locale.conf"), key))
}

fn detect_keymap() -> Option<String> {
    read_key_from_file(Path::new("/etc/vconsole.conf"), "KEYMAP")
        .or_else(|| read_key_from_file(Path::new("/etc/default/keyboard"), "XKBLAYOUT"))
        .map(|s| s.split(',').next().unwrap_or(&s).trim().to_string())
        .and_then(nonempty)
}

fn detect_timezone() -> Option<String> {
    if let Some(tz) = read_timezone_from_localtime() {
        return Some(tz);
    }
    if let Ok(tz) = fs::read_to_string("/etc/timezone") {
        if let Some(tz) = nonempty(tz) {
            return Some(tz);
        }
    }
    env::var("TZ").ok().and_then(nonempty)
}

fn read_timezone_from_localtime() -> Option<String> {
    let target = fs::read_link("/etc/localtime").ok()?;
    let target = if target.is_absolute() {
        target
    } else {
        Path::new("/etc").join(target)
    };
    let target = target.to_string_lossy();
    let marker = "zoneinfo/";
    let idx = target.find(marker)? + marker.len();
    let tz = target[idx..].trim();
    if tz.is_empty() {
        None
    } else {
        Some(tz.to_string())
    }
}

fn read_key_from_file(path: &Path, key: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once('=')?;
        if k.trim() != key {
            continue;
        }
        let v = v.trim().trim_matches('"').trim_matches('\'');
        if let Some(v) = nonempty(v.to_string()) {
            return Some(v);
        }
    }
    None
}

fn nonempty(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
