use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use dioxus::prelude::*;
use fastboop_core::bootimg::build_android_bootimg;
use fastboop_core::device::DeviceHandle as _;
use fastboop_core::fastboot::{boot, download};
use fastboop_core::Personalization;
use fastboop_erofs_rootfs::open_erofs_rootfs;
use fastboop_stage0_generator::{build_stage0, Stage0Options};
use smoo_host_blocksource_gibblox::GibbloxBlockSource;
use smoo_host_core::control::{read_status, ConfigExportsV0};
use smoo_host_core::{
    heartbeat_once, register_export, start_host_io_pump, BlockSource, BlockSourceHandle,
    HostErrorKind, SmooHost, TransportError, TransportErrorKind,
};
use smoo_host_transport_rusb::RusbTransport;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{error, info};
use ui::oneplus_fajita_dtbo_overlays;

use super::session::{update_session_phase, BootRuntime, SessionPhase, SessionStore};

const ROOTFS_URL: &str = "https://bleeding.fastboop.win/sdm845-live-fedora/20260208.ero";
const EXTRA_CMDLINE: &str =
    "selinux=0 sysrq_always_enabled=1 panic=5 smoo.max_io_bytes=1048576 init_on_alloc=0 rhgb drm.panic_screen=kmsg smoo.queue_count=1 smoo.queue_depth=1 regulator_ignore_unused";
const SMOO_INTERFACE_CLASS: u8 = 0xFF;
const SMOO_INTERFACE_SUBCLASS: u8 = 0x53;
const SMOO_INTERFACE_PROTOCOL: u8 = 0x4D;
const TRANSFER_TIMEOUT: Duration = Duration::from_millis(200);
const DISCOVERY_RETRY: Duration = Duration::from_millis(500);
const IDLE_POLL: Duration = Duration::from_millis(5);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const STATUS_RETRY_INTERVAL: Duration = Duration::from_millis(200);
const STATUS_RETRY_ATTEMPTS: usize = 5;

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
        SessionPhase::Booting { step } => rsx! { BootingDevice { session_id, step } },
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
            } => Some((runtime.clone(), *host_started)),
            _ => None,
        });
    let Some((runtime, host_started)) = state else {
        return rsx! {};
    };
    let mut kickoff = use_signal(|| false);
    use_effect(move || {
        if host_started || kickoff() {
            return;
        }
        kickoff.set(true);
        update_session_phase(
            &mut sessions,
            &session_id,
            SessionPhase::Active {
                runtime: runtime.clone(),
                host_started: true,
            },
        );
        let runtime_for_host = runtime.clone();
        std::thread::Builder::new()
            .name(format!("fastboop-smoo-{session_id}"))
            .spawn(move || {
                if let Err(err) = run_rusb_host_daemon(
                    runtime_for_host.reader,
                    runtime_for_host.size_bytes,
                    runtime_for_host.identity,
                ) {
                    error!(%err, "desktop smoo host daemon stopped");
                }
            })
            .ok();
    });

    rsx! {
        section { id: "landing",
            div { class: "landing__panel",
                p { class: "landing__eyebrow", "Active" }
                h1 { "We're live." }
                p { class: "landing__lede", "Please don't close this window while the session is active." }
                p { class: "landing__note", "Rootfs: {ROOTFS_URL}" }
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
        smoo_vendor: Some(session.device.vid),
        smoo_product: Some(session.device.pid),
        smoo_serial: None,
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
                    let opened = open_erofs_rootfs(ROOTFS_URL).await?;
                    info!(profile = %profile.id, "building stage0 payload");
                    let build = build_stage0(
                        &profile,
                        &opened.provider,
                        &stage0_opts,
                        Some(EXTRA_CMDLINE),
                        None,
                    )
                    .await
                    .map_err(|err| anyhow!("stage0 build failed: {err:?}"))?;
                    Ok((
                        build,
                        BootRuntime {
                            reader: opened.reader,
                            size_bytes: opened.size_bytes,
                            identity: opened.identity,
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
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("create tokio runtime for smoo host")?;
    runtime.block_on(async move {
        loop {
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

enum SessionEnd {
    TransportLost,
}

async fn run_rusb_session(
    transport: RusbTransport,
    control: smoo_host_transport_rusb::RusbControl,
    reader: std::sync::Arc<dyn gibblox_core::BlockReader>,
    size_bytes: u64,
    identity: String,
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
    let pump_task: JoinHandle<smoo_host_core::TransportResult<()>> = tokio::spawn(pump_task);

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
                error!(%err, "SMOO_STATUS failed after CONFIG_EXPORTS");
                shutdown_pump(pump_handle, pump_task).await;
                return Ok(SessionEnd::TransportLost);
            }
        };

    let (heartbeat_tx, mut heartbeat_rx) = mpsc::unbounded_channel();
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
            pump_result = &mut pump_task => {
                match pump_result {
                    Ok(Ok(())) | Ok(Err(_)) | Err(_) => break Ok(SessionEnd::TransportLost),
                }
            }
            event = heartbeat_rx.recv() => {
                if let Some(event) = event {
                    error!(%event, "desktop smoo heartbeat ended");
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
                    info!(attempt, attempts, %err, "SMOO_STATUS retry");
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
