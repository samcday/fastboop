#[cfg(target_arch = "wasm32")]
use anyhow::Context;
use dioxus::prelude::*;
use fastboop_core::FastbootBoot;
#[cfg(target_arch = "wasm32")]
use fastboop_environment_web::{
    run_web_smoo_host, WebBootRuntime, WebSmooHostEvent, WebSmooHostOptions, WebSmooHostPhase,
};
use fastboop_environment_web::{
    WebBootConfig, WebBootEnvironment, WebBootStage0Config, WebSelectedFastbootDevice,
};
#[cfg(target_arch = "wasm32")]
use futures_util::{pin_mut, FutureExt, StreamExt};
use std::future::Future;
use std::rc::Rc;
#[cfg(target_arch = "wasm32")]
use ui::SmooStatsHandle;
#[cfg(target_arch = "wasm32")]
use ui::{apply_transport_counters, SmooTransportCounters};

use super::session::{
    update_session_phase, BootRuntime, DeviceSession, SessionPhase, SessionStore,
};
#[cfg(target_arch = "wasm32")]
use ui::update_session_active_host_state;

#[cfg(target_arch = "wasm32")]
const STAGE0_BINARY_ASSET: Option<Asset> =
    option_asset!("/assets/stage0/fastboop-stage0-aarch64-unknown-linux-musl");

pub async fn boot_selected_device(
    sessions: &mut SessionStore,
    session_id: &str,
) -> anyhow::Result<Rc<BootRuntime>> {
    let session = sessions
        .read()
        .iter()
        .find(|s| s.id == session_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;
    let config = web_boot_config_for_session(&session)?;
    let selected_device =
        WebSelectedFastbootDevice::new(session.device.handle, session.device.profile.clone());
    let mut env = WebBootEnvironment::new(config).with_selected_device(selected_device);

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Preparing boot payload".to_string(),
        },
    );
    let prepared = env
        .prepare_boot()
        .await
        .context("prepare web boot payload")?;

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Opening fastboot transport".to_string(),
        },
    );
    let mut fastboot = env
        .connect_fastboot()
        .await
        .context("open selected WebUSB fastboot transport")?;

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: format!(
                "Downloading boot image ({} bytes)",
                prepared.boot_image.len()
            ),
        },
    );
    FastbootBoot::new(&prepared.boot_image)
        .run(&mut fastboot)
        .await
        .map_err(|err| anyhow::anyhow!("fastboot handoff failed: {err}"))?;
    let _ = fastboot.shutdown().await;

    let runtime = env.runtime_for_export(&prepared.export)?;
    Ok(Rc::new(BootRuntime {
        size_bytes: runtime.size_bytes,
        identity: runtime.identity,
        channel: runtime.channel,
        channel_offset_bytes: runtime.channel_offset_bytes,
        #[cfg(target_arch = "wasm32")]
        local_reader_bridge: Some(runtime.local_reader_bridge),
        #[cfg(target_arch = "wasm32")]
        smoo_stats: SmooStatsHandle::new(),
    }))
}

#[cfg(target_arch = "wasm32")]
pub async fn run_web_host_daemon(
    initial_device: web_sys::UsbDevice,
    runtime: Rc<BootRuntime>,
    mut sessions: SessionStore,
    session_id: String,
) -> anyhow::Result<()> {
    let local_reader_bridge = runtime
        .local_reader_bridge
        .clone()
        .ok_or_else(|| anyhow::anyhow!("channel reader bridge unavailable for host startup"))?;
    let web_runtime = WebBootRuntime {
        size_bytes: runtime.size_bytes,
        identity: runtime.identity.clone(),
        channel: runtime.channel.clone(),
        channel_offset_bytes: runtime.channel_offset_bytes,
        local_reader_bridge,
    };
    let smoo_stats = runtime.smoo_stats.clone();
    let (tx, mut rx) = futures_channel::mpsc::unbounded();
    let host = run_web_smoo_host(
        initial_device,
        web_runtime,
        WebSmooHostOptions::default(),
        tx,
    )
    .fuse();
    pin_mut!(host);
    let mut previous_counters = SmooTransportCounters::default();

    update_session_active_host_state(&mut sessions, &session_id, Some(true), Some(false));
    loop {
        futures_util::select! {
            result = host => return result,
            event = rx.next() => {
                let Some(event) = event else {
                    return Err(anyhow::anyhow!("web smoo host event stream closed"));
                };
                forward_smoo_event(
                    event,
                    &mut sessions,
                    &session_id,
                    &smoo_stats,
                    &mut previous_counters,
                );
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn forward_smoo_event(
    event: WebSmooHostEvent,
    sessions: &mut SessionStore,
    session_id: &str,
    smoo_stats: &SmooStatsHandle,
    previous_counters: &mut SmooTransportCounters,
) {
    match event {
        WebSmooHostEvent::Phase { phase, detail } => {
            let connected = matches!(phase, WebSmooHostPhase::Serving);
            update_session_active_host_state(sessions, session_id, Some(true), Some(connected));
            smoo_stats.set_connected(connected);
            tracing::info!(phase = ?phase, detail = %detail, "web smoo host phase");
        }
        WebSmooHostEvent::Log(line) => tracing::warn!(message = %line, "web smoo host"),
        WebSmooHostEvent::Status {
            active,
            ios_up,
            ios_down,
            bytes_up,
            bytes_down,
        } => {
            smoo_stats.set_connected(active || smoo_stats.snapshot().connected);
            apply_transport_counters(
                smoo_stats,
                previous_counters,
                SmooTransportCounters {
                    ios_up,
                    ios_down,
                    bytes_up,
                    bytes_down,
                },
            );
        }
    }
}

fn web_boot_config_for_session(session: &DeviceSession) -> anyhow::Result<WebBootConfig> {
    let channel = session.boot_config.channel.trim();
    if channel.is_empty() {
        return Err(anyhow::anyhow!("channel is empty"));
    }

    Ok(WebBootConfig {
        stage0: WebBootStage0Config {
            channel: channel.to_string(),
            boot_profile: session.boot_config.selected_boot_profile_id.clone(),
            cmdline_append: nonempty_string(session.boot_config.extra_kargs.as_str()),
            serial: session.boot_config.enable_serial,
            stage0_asset_url: stage0_asset_url(),
            smoo_max_io: None,
        },
    })
}

#[cfg(target_arch = "wasm32")]
fn stage0_asset_url() -> Option<String> {
    STAGE0_BINARY_ASSET.map(|asset| asset.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn stage0_asset_url() -> Option<String> {
    None
}

#[cfg(target_arch = "wasm32")]
pub fn spawn_detached(fut: impl Future<Output = ()> + 'static) {
    wasm_bindgen_futures::spawn_local(fut);
}

#[cfg(not(target_arch = "wasm32"))]
pub fn spawn_detached(fut: impl Future<Output = ()> + 'static) {
    spawn(fut);
}

fn nonempty_string(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}
