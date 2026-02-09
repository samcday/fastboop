use anyhow::{anyhow, ensure, Context, Result};
use dioxus::prelude::*;
use fastboop_core::bootimg::build_android_bootimg;
use fastboop_core::device::DeviceHandle as _;
use fastboop_core::fastboot::{boot, download};
use fastboop_core::Personalization;
use fastboop_erofs_rootfs::open_erofs_rootfs;
use fastboop_stage0_generator::{build_stage0, Stage0Options};
#[cfg(target_arch = "wasm32")]
use gloo_timers::future::sleep;
#[cfg(target_arch = "wasm32")]
use js_sys::{Array, Reflect};
#[cfg(target_arch = "wasm32")]
use smoo_host_blocksource_gibblox::GibbloxBlockSource;
#[cfg(target_arch = "wasm32")]
use smoo_host_core::{
    control::{read_status, ConfigExportsV0},
    heartbeat_once, register_export, start_host_io_pump, BlockSource, BlockSourceHandle,
    HostErrorKind, SmooHost, TransportError, TransportErrorKind,
};
#[cfg(target_arch = "wasm32")]
use smoo_host_webusb::{WebUsbControl, WebUsbTransport, WebUsbTransportConfig};
#[cfg(target_arch = "wasm32")]
use std::collections::BTreeMap;
use std::future::Future;
#[cfg(target_arch = "wasm32")]
use std::time::Duration;
#[cfg(target_arch = "wasm32")]
use std::{cell::Cell, rc::Rc};
use ui::oneplus_fajita_dtbo_overlays;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, JsValue};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;

use super::session::{update_session_phase, BootRuntime, SessionPhase, SessionStore};

const ROOTFS_URL: &str = "https://bleeding.fastboop.win/sdm845-live-fedora/20260208.ero";
const EXTRA_CMDLINE: &str =
    "selinux=0 sysrq_always_enabled=1 panic=5 smoo.max_io_bytes=1048576 init_on_alloc=0 rhgb drm.panic_screen=kmsg smoo.queue_count=1 smoo.queue_depth=1 regulator_ignore_unused";
#[cfg(target_arch = "wasm32")]
const STATUS_RETRY_INTERVAL: Duration = Duration::from_millis(200);
#[cfg(target_arch = "wasm32")]
const STATUS_RETRY_ATTEMPTS: usize = 5;
#[cfg(target_arch = "wasm32")]
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(target_arch = "wasm32")]
const IDLE_POLL: Duration = Duration::from_millis(5);

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
        spawn_detached(async move {
            match boot_selected_device(&mut sessions, &session_id).await {
                Ok(runtime) => update_session_phase(
                    &mut sessions,
                    &session_id,
                    SessionPhase::Active {
                        runtime,
                        host_started: false,
                    },
                ),
                Err(err) => {
                    tracing::error!("boot flow failed for {session_id}: {err:#}");
                    update_session_phase(
                        &mut sessions,
                        &session_id,
                        SessionPhase::Error {
                            summary: format!("{err:#}"),
                        },
                    )
                }
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

    #[cfg(target_arch = "wasm32")]
    {
        use_effect(move || {
            if let Some(window) = web_sys::window() {
                let handler = js_sys::Function::new_no_args(
                    "event.preventDefault(); event.returnValue=''; return '';",
                );
                let _ = Reflect::set(
                    window.as_ref(),
                    &JsValue::from_str("onbeforeunload"),
                    handler.as_ref(),
                );
            }
        });

        use_drop(move || {
            if let Some(window) = web_sys::window() {
                let _ = Reflect::set(
                    window.as_ref(),
                    &JsValue::from_str("onbeforeunload"),
                    &JsValue::NULL,
                );
            }
        });
    }

    use_effect(move || {
        if host_started || kickoff() {
            return;
        }
        kickoff.set(true);
        let session = sessions.read().iter().find(|s| s.id == session_id).cloned();
        if let Some(session) = session {
            update_session_phase(
                &mut sessions,
                &session_id,
                SessionPhase::Active {
                    runtime: runtime.clone(),
                    host_started: true,
                },
            );

            #[cfg(target_arch = "wasm32")]
            {
                let mut sessions = sessions;
                let session_id = session_id.clone();
                let runtime_for_host = runtime.clone();
                spawn_detached(async move {
                    let device = session.device.handle.device();
                    if let Err(err) = run_web_host_daemon(
                        device,
                        runtime_for_host.reader,
                        runtime_for_host.size_bytes,
                        runtime_for_host.identity,
                    )
                    .await
                    {
                        tracing::error!("web host daemon failed for {session_id}: {err:#}");
                        update_session_phase(
                            &mut sessions,
                            &session_id,
                            SessionPhase::Error {
                                summary: format!("{err:#}"),
                            },
                        );
                    }
                });
            }
        }
    });

    rsx! {
        section { id: "landing",
            div { class: "landing__panel",
                p { class: "landing__eyebrow", "Active" }
                h1 { "We're live." }
                p { class: "landing__lede", "Please don't close this page while the session is active." }
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

#[cfg(target_arch = "wasm32")]
fn spawn_detached(fut: impl Future<Output = ()> + 'static) {
    wasm_bindgen_futures::spawn_local(fut);
}

#[cfg(not(target_arch = "wasm32"))]
fn spawn_detached(fut: impl Future<Output = ()> + 'static) {
    spawn(fut);
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
        smoo_serial: webusb_serial_number(&session.device.handle),
        personalization: Some(personalization_from_browser()),
    };
    let profile_id = session.device.profile.id.clone();
    let (build, runtime) = build_stage0_artifacts(session.device.profile.clone(), stage0_opts)
        .await
        .with_context(|| {
            format!("open rootfs and build stage0 (profile={profile_id}, rootfs={ROOTFS_URL})")
        })?;

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
    use futures_channel::oneshot;

    tracing::info!("build_stage0_artifacts: creating channel");
    let (tx, rx) = oneshot::channel();

    // Spawn the stage0 build outside the Dioxus context using raw spawn_local
    tracing::info!("build_stage0_artifacts: spawning task");
    wasm_bindgen_futures::spawn_local(async move {
        tracing::info!("build_stage0_artifacts: task started");
        let result: Result<_> = async {
            tracing::info!(profile = %profile.id, "opening rootfs for web boot");
            let opened = open_erofs_rootfs(ROOTFS_URL).await?;
            tracing::info!(profile = %profile.id, "building stage0 payload");
            // Yield to allow cache workers to make progress
            gloo_timers::future::sleep(std::time::Duration::from_millis(100)).await;
            let build = build_stage0(
                &profile,
                &opened.provider,
                &stage0_opts,
                Some(EXTRA_CMDLINE),
                None,
            )
            .await
            .map_err(|err| anyhow!("stage0 build failed: {err:?}"))?;
            tracing::info!("build_stage0_artifacts: stage0 build completed");
            Ok((
                build,
                BootRuntime {
                    reader: opened.reader,
                    size_bytes: opened.size_bytes,
                    identity: opened.identity,
                },
            ))
        }
        .await;
        tracing::info!("build_stage0_artifacts: sending result");
        let _ = tx.send(result);
    });

    tracing::info!("build_stage0_artifacts: awaiting result");
    let result = rx
        .await
        .map_err(|_| anyhow!("stage0 build task was cancelled"))?;
    tracing::info!("build_stage0_artifacts: got result");
    result
}

#[cfg(target_arch = "wasm32")]
async fn run_web_host_daemon(
    initial_device: web_sys::UsbDevice,
    reader: std::sync::Arc<dyn gibblox_core::BlockReader>,
    size_bytes: u64,
    identity: String,
) -> Result<()> {
    loop {
        let (transport, control) = match open_webusb_transport(&initial_device).await {
            Ok(pair) => pair,
            Err(err) => {
                warn!(%err, "waiting for smoo webusb gadget");
                sleep(STATUS_RETRY_INTERVAL).await;
                continue;
            }
        };

        match run_web_session(
            transport,
            control,
            reader.clone(),
            size_bytes,
            identity.clone(),
        )
        .await
        {
            Ok(SessionEnd::TransportLost) => {
                warn!("smoo web transport lost; waiting to reconnect");
            }
            Err(err) => {
                warn!(%err, "smoo web session ended");
            }
        }
        sleep(STATUS_RETRY_INTERVAL).await;
    }
}

#[cfg(target_arch = "wasm32")]
enum SessionEnd {
    TransportLost,
}

#[cfg(target_arch = "wasm32")]
async fn run_web_session(
    transport: WebUsbTransport,
    control: WebUsbControl,
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
    wasm_bindgen_futures::spawn_local(async move {
        let _ = pump_task.await;
    });

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
                warn!(%err, "SMOO_STATUS failed after CONFIG_EXPORTS");
                let _ = pump_handle.shutdown().await;
                return Ok(SessionEnd::TransportLost);
            }
        };

    let heartbeat_stop = Rc::new(Cell::new(false));
    let heartbeat_client = control.clone();
    let heartbeat_stop_task = heartbeat_stop.clone();
    wasm_bindgen_futures::spawn_local(async move {
        run_web_heartbeat(
            heartbeat_client,
            initial_session_id,
            HEARTBEAT_INTERVAL,
            heartbeat_stop_task,
        )
        .await;
    });

    loop {
        match host.run_once().await {
            Ok(()) => {
                sleep(IDLE_POLL).await;
            }
            Err(err) if err.kind() == HostErrorKind::Transport => break,
            Err(err) => {
                heartbeat_stop.set(true);
                return Err(anyhow!(err.to_string()));
            }
        }
    }

    heartbeat_stop.set(true);
    let _ = pump_handle.shutdown().await;
    Ok(SessionEnd::TransportLost)
}

#[cfg(target_arch = "wasm32")]
async fn run_web_heartbeat(
    client: WebUsbControl,
    initial_session_id: u64,
    interval: Duration,
    stop: Rc<Cell<bool>>,
) {
    while !stop.get() {
        sleep(interval).await;
        if stop.get() {
            break;
        }
        match heartbeat_once(&client).await {
            Ok(status) => {
                if status.session_id != initial_session_id {
                    warn!(
                        previous = format!("0x{initial_session_id:016x}"),
                        current = format!("0x{:016x}", status.session_id),
                        "web smoo heartbeat session changed"
                    );
                    break;
                }
            }
            Err(err) => {
                warn!(%err, "web smoo heartbeat transfer failed");
                break;
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn fetch_status_with_retry(
    client: &WebUsbControl,
    attempts: usize,
    delay: Duration,
) -> std::result::Result<u64, TransportError> {
    let mut attempt = 0;
    loop {
        match read_status(client).await {
            Ok(status) => {
                return Ok(status.session_id);
            }
            Err(err) => {
                attempt += 1;
                if attempt >= attempts {
                    return Err(err);
                }
                if err.kind() != TransportErrorKind::Timeout || attempt > 1 {
                    warn!(attempt, attempts, %err, "SMOO_STATUS retry");
                }
                sleep(delay).await;
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn open_webusb_transport(
    initial_device: &web_sys::UsbDevice,
) -> Result<(WebUsbTransport, WebUsbControl)> {
    if let Ok(pair) = try_open_transport_for_device(initial_device).await {
        return Ok(pair);
    }

    let devices = authorized_usb_devices().await?;
    let mut errors = Vec::new();
    for device in devices {
        match try_open_transport_for_device(&device).await {
            Ok(pair) => return Ok(pair),
            Err(err) => {
                let serial = Reflect::get(device.as_ref(), &JsValue::from_str("serialNumber"))
                    .ok()
                    .and_then(|v| v.as_string())
                    .unwrap_or_else(|| "<none>".to_string());
                errors.push(format!(
                    "{:04x}:{:04x} serial={serial}: {err}",
                    device.vendor_id(),
                    device.product_id()
                ));
            }
        }
    }
    if errors.is_empty() {
        Err(anyhow!("no authorized smoo webusb gadget found"))
    } else {
        Err(anyhow!(
            "no authorized smoo webusb gadget found; candidates: {}",
            errors.join(" | ")
        ))
    }
}

#[cfg(target_arch = "wasm32")]
async fn try_open_transport_for_device(
    device: &web_sys::UsbDevice,
) -> Result<(WebUsbTransport, WebUsbControl)> {
    let mut last_err = None;
    for interface in 0..=7u8 {
        let config = WebUsbTransportConfig {
            interface,
            interrupt_in: None,
            interrupt_out: None,
            bulk_in: None,
            bulk_out: None,
        };
        match WebUsbTransport::new(device.clone(), config).await {
            Ok(transport) => {
                let control = transport.control_handle();
                debug!(interface, "connected to smoo webusb transport");
                return Ok((transport, control));
            }
            Err(err) => {
                last_err = Some(format!("iface {interface}: {err}"));
                continue;
            }
        }
    }
    let detail = last_err.unwrap_or_else(|| "no interface probe attempts".to_string());
    Err(anyhow!("device is not a compatible smoo gadget ({detail})"))
}

#[cfg(target_arch = "wasm32")]
async fn authorized_usb_devices() -> Result<Vec<web_sys::UsbDevice>> {
    let window = web_sys::window().ok_or_else(|| anyhow!("window unavailable"))?;
    let navigator = window.navigator();
    let usb_value = Reflect::get(navigator.as_ref(), &JsValue::from_str("usb"))
        .map_err(|err| anyhow!("navigator.usb unavailable: {err:?}"))?;
    let usb: web_sys::Usb = usb_value
        .dyn_into()
        .map_err(|_| anyhow!("navigator.usb has unexpected type"))?;
    let values = JsFuture::from(usb.get_devices())
        .await
        .map_err(|err| anyhow!("navigator.usb.getDevices failed: {err:?}"))?;
    let array = Array::from(&values);
    let mut out = Vec::new();
    for value in array.iter() {
        if let Ok(device) = value.dyn_into::<web_sys::UsbDevice>() {
            out.push(device);
        }
    }
    debug!(count = out.len(), "authorized webusb devices enumerated");
    Ok(out)
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

fn personalization_from_browser() -> Personalization {
    let locale = browser_locale().unwrap_or_else(|| "en_US.UTF-8".to_string());
    let timezone = browser_timezone().unwrap_or_else(|| "UTC".to_string());
    Personalization {
        locale: Some(locale.clone()),
        locale_messages: Some(locale),
        keymap: None,
        timezone: Some(timezone),
    }
}

#[cfg(target_arch = "wasm32")]
fn webusb_serial_number(handle: &fastboop_fastboot_webusb::WebUsbDeviceHandle) -> Option<String> {
    let device = handle.device();
    let serial = Reflect::get(device.as_ref(), &JsValue::from_str("serialNumber"))
        .ok()?
        .as_string()?;
    let serial = serial.trim();
    if serial.is_empty() {
        None
    } else {
        Some(serial.to_string())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn webusb_serial_number(_handle: &fastboop_fastboot_webusb::WebUsbDeviceHandle) -> Option<String> {
    None
}

#[cfg(target_arch = "wasm32")]
fn browser_locale() -> Option<String> {
    let window = web_sys::window()?;
    let nav = window.navigator();
    let value = nav.language()?;
    if value.trim().is_empty() {
        None
    } else {
        Some(value.replace('-', "_"))
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn browser_locale() -> Option<String> {
    None
}

#[cfg(target_arch = "wasm32")]
fn browser_timezone() -> Option<String> {
    let tz = js_sys::eval("Intl.DateTimeFormat().resolvedOptions().timeZone")
        .ok()?
        .as_string()?;
    if tz.trim().is_empty() {
        None
    } else {
        Some(tz)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn browser_timezone() -> Option<String> {
    None
}
