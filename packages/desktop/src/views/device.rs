use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use dioxus::prelude::*;
use fastboop_core::bootimg::build_android_bootimg;
use fastboop_core::device::DeviceHandle as _;
use fastboop_core::fastboot::{boot, download};
use fastboop_core::Personalization;
use fastboop_rootfs_erofs::ErofsRootfs;
use fastboop_serial::{spawn_native_serial_reader, NativeSerialEvent, NativeSerialSelector};
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
use tokio::sync::oneshot;
use tracing::{error, info, warn};
use ui::{
    apply_transport_counters, oneplus_fajita_dtbo_overlays, run_smoo_stats_view_loop,
    SerialLogBuffer, SerialLogOutput, SmooStatsHandle, SmooStatsPanel, SmooStatsViewModel,
    SmooTransportCounters,
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
const SERIAL_UI_POLL_INTERVAL: Duration = Duration::from_millis(60);

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
        SessionPhase::Booting { step } => {
            rsx! { BootingDevice { session_id, step } }
        }
        SessionPhase::Active { .. } => rsx! { BootedDevice { session_id } },
        SessionPhase::Error { summary } => rsx! { BootError { summary } },
    }
}

#[component]
fn BootingDevice(session_id: String, step: String) -> Element {
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
            } => Some((
                runtime.clone(),
                *host_started,
                s.device.vid,
                s.device.pid,
                s.device.serial.clone(),
            )),
            _ => None,
        });
    let Some((runtime, host_started, device_vid, device_pid, device_serial)) = state else {
        return rsx! {};
    };
    let mut kickoff = use_signal(|| false);
    let smoo_stats = use_signal(|| Option::<SmooStatsViewModel>::None);
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
                let started = std::time::Instant::now();
                run_smoo_stats_view_loop(
                    smoo_stats_handle,
                    || tokio::time::sleep(CACHE_STATS_POLL_INTERVAL),
                    move || started.elapsed().as_secs_f64(),
                    move || stop.load(Ordering::Relaxed),
                    move |stats_view| {
                        smoo_stats.set(Some(stats_view));
                    },
                )
                .await;
            });
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
                SerialLogPanel {
                    device_vid,
                    device_pid,
                    device_serial,
                }
            }
        }
    }
}

#[derive(Clone, PartialEq)]
enum NativeSerialState {
    Connecting,
    Connected,
    Disconnected,
    Error(String),
}

#[component]
fn SerialLogPanel(device_vid: u16, device_pid: u16, device_serial: Option<String>) -> Element {
    let state = use_signal(|| NativeSerialState::Connecting);
    let logs = use_signal(SerialLogBuffer::new);
    let stop_flag = use_signal(|| Option::<Arc<AtomicBool>>::None);
    let mut started = use_signal(|| false);

    {
        let device_serial = device_serial.clone();
        use_effect(move || {
            if started() {
                return;
            }
            started.set(true);
            start_desktop_serial_stream(
                device_vid,
                device_pid,
                device_serial.clone(),
                state,
                logs,
                stop_flag,
            );
        });
    }

    {
        let mut stop_flag = stop_flag;
        use_drop(move || {
            if let Some(stop) = stop_flag.write().take() {
                stop.store(true, Ordering::Relaxed);
            }
        });
    }

    let on_connect = {
        let device_serial = device_serial.clone();
        move |_| {
            start_desktop_serial_stream(
                device_vid,
                device_pid,
                device_serial.clone(),
                state,
                logs,
                stop_flag,
            );
        }
    };

    let on_disconnect = {
        let mut state = state;
        let mut logs = logs;
        let mut stop_flag = stop_flag;
        move |_| {
            if let Some(stop) = stop_flag.write().take() {
                stop.store(true, Ordering::Relaxed);
            }
            logs.write().push_status("Disconnect requested.");
            state.set(NativeSerialState::Disconnected);
        }
    };

    let on_clear = {
        let mut logs = logs;
        move |_| {
            logs.write().clear();
        }
    };

    let status_text = match state() {
        NativeSerialState::Connecting => "Connecting",
        NativeSerialState::Connected => "Connected",
        NativeSerialState::Disconnected => "Disconnected",
        NativeSerialState::Error(_) => "Error",
    };
    let status_class = match state() {
        NativeSerialState::Connected => "serial-logs__status serial-logs__status--ok",
        NativeSerialState::Error(_) => "serial-logs__status serial-logs__status--err",
        NativeSerialState::Connecting => "serial-logs__status serial-logs__status--warn",
        _ => "serial-logs__status",
    };
    let error_message = match state() {
        NativeSerialState::Error(message) => Some(message),
        _ => None,
    };
    let rendered_rows = logs.read().render_rows();

    rsx! {
        div { class: "serial-logs",
            div { class: "serial-logs__header",
                p { class: "serial-logs__title", "Device serial output" }
                p { class: status_class, "{status_text}" }
            }
            p { class: "serial-logs__hint", "Streaming stage0 kernel and early userspace logs over CDC-ACM." }

            div { class: "serial-logs__actions",
                if !matches!(state(), NativeSerialState::Connected | NativeSerialState::Connecting) {
                    button { class: "serial-logs__connect", onclick: on_connect, "Connect" }
                }
                if matches!(state(), NativeSerialState::Connected | NativeSerialState::Connecting) {
                    button { class: "serial-logs__disconnect", onclick: on_disconnect, "Disconnect" }
                }
                button { class: "serial-logs__clear", onclick: on_clear, "Clear" }
            }

            if let Some(error_message) = error_message {
                p { class: "serial-logs__error", "{error_message}" }
            }

            SerialLogOutput { rows: rendered_rows }
        }
    }
}

fn start_desktop_serial_stream(
    device_vid: u16,
    device_pid: u16,
    device_serial: Option<String>,
    mut state: Signal<NativeSerialState>,
    mut logs: Signal<SerialLogBuffer>,
    mut stop_flag: Signal<Option<Arc<AtomicBool>>>,
) {
    if let Some(stop) = stop_flag.write().take() {
        stop.store(true, Ordering::Relaxed);
    }

    let (event_tx, event_rx) = mpsc::channel::<NativeSerialEvent>();
    let selector = NativeSerialSelector::new(device_vid, device_pid, device_serial);
    let stop = spawn_native_serial_reader(selector, move |event| {
        let _ = event_tx.send(event);
    });
    stop_flag.set(Some(stop.clone()));

    state.set(NativeSerialState::Connecting);
    logs.write()
        .push_status("Waiting for matching CDC-ACM gadget...");

    spawn(async move {
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }

            loop {
                match event_rx.try_recv() {
                    Ok(event) => apply_native_serial_event(event, &mut state, &mut logs),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return,
                }
            }

            tokio::time::sleep(SERIAL_UI_POLL_INTERVAL).await;
        }
    });
}

fn apply_native_serial_event(
    event: NativeSerialEvent,
    state: &mut Signal<NativeSerialState>,
    logs: &mut Signal<SerialLogBuffer>,
) {
    match event {
        NativeSerialEvent::Status(message) => {
            logs.write().push_status(message);
            state.set(NativeSerialState::Connecting);
        }
        NativeSerialEvent::Connected { port } => {
            logs.write()
                .push_status(format!("Connected on {port}. Streaming device logs."));
            state.set(NativeSerialState::Connected);
        }
        NativeSerialEvent::Disconnected { port } => {
            logs.write()
                .push_status(format!("Disconnected from {port}."));
            state.set(NativeSerialState::Disconnected);
        }
        NativeSerialEvent::Error(message) => {
            logs.write().push_status(format!("Serial error: {message}"));
            state.set(NativeSerialState::Error(message));
        }
        NativeSerialEvent::Bytes(bytes) => {
            logs.write().push_bytes(bytes.as_slice());
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
        },
    );
    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Building stage0".to_string(),
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
    let (build, runtime) = build_stage0_artifacts(session.device.profile.clone(), stage0_opts)
        .await
        .context("open rootfs and build stage0")?;

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Assembling android boot image".to_string(),
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
        },
    );
    boot(&mut fastboot)
        .await
        .map_err(|err| anyhow!("fastboot boot failed: {err}"))?;

    Ok(BootRuntime {
        reader: runtime.reader,
        size_bytes: runtime.size_bytes,
        identity: runtime.identity,
        smoo_stats: runtime.smoo_stats,
    })
}

async fn build_stage0_artifacts(
    profile: fastboop_core::DeviceProfile,
    stage0_opts: Stage0Options,
) -> Result<(fastboop_stage0_generator::Stage0Build, BootRuntime)> {
    let (tx, rx) = oneshot::channel();
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
                    let provider = ErofsRootfs::new(reader.clone(), size_bytes).await?;
                    info!(profile = %profile.id, "building stage0 payload");
                    let build =
                        build_stage0(&profile, &provider, &stage0_opts, Some(EXTRA_CMDLINE), None)
                            .await
                            .map_err(|err| anyhow!("stage0 build failed: {err:?}"))?;
                    let rootfs_identity = block_identity_string(reader.as_ref());
                    Ok((
                        build,
                        BootRuntime {
                            reader,
                            size_bytes,
                            identity: rootfs_identity,
                            smoo_stats: SmooStatsHandle::new(),
                        },
                    ))
                })
            })();
            let _ = tx.send(result);
        })
        .context("spawn stage0 build worker thread")?;

    rx.await
        .map_err(|_| anyhow!("stage0 build worker thread exited unexpectedly"))?
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
    let mut counter_snapshot = transport_counters_from_snapshot(counters.snapshot());
    let mut missed_heartbeats: u32 = 0;

    loop {
        tokio::select! {
            finish = &mut task => {
                update_smoo_stats_from_transport(
                    &smoo_stats,
                    &mut counter_snapshot,
                    transport_counters_from_snapshot(counters.snapshot()),
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
                        transport_counters_from_snapshot(counters.snapshot()),
                    );
                    smoo_stats.set_connected(false);
                    return Ok(SessionEnd::TransportLost);
                }
                update_smoo_stats_from_transport(
                    &smoo_stats,
                    &mut counter_snapshot,
                    transport_counters_from_snapshot(counters.snapshot()),
                );
            }
        }
    }
}

fn update_smoo_stats_from_transport(
    smoo_stats: &SmooStatsHandle,
    previous: &mut SmooTransportCounters,
    current: SmooTransportCounters,
) {
    apply_transport_counters(smoo_stats, previous, current);
}

fn transport_counters_from_snapshot(snapshot: TransportCounterSnapshot) -> SmooTransportCounters {
    SmooTransportCounters {
        ios_up: snapshot.ios_up,
        ios_down: snapshot.ios_down,
        bytes_up: snapshot.bytes_up,
        bytes_down: snapshot.bytes_down,
    }
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
