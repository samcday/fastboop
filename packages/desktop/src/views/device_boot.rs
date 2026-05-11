use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use dioxus::prelude::ReadableExt;
use fastboop_core::fastboot::{boot, download};
use fastboop_environment_std::{
    run_native_smoo_host, NativeBootConfig, NativeBootEnvironment, NativeBootStage0Config,
    NativeSelectedFastbootDevice, SmooHostEvent, SmooHostOptions, SmooHostPhase,
};
use fastboop_session::{
    BootSessionEnvironment, FastboopSession as BootSession, SessionEvent, SessionEventPhase,
};
use tokio_util::sync::CancellationToken;
use tracing::info;
use ui::{apply_transport_counters, SmooStatsHandle, SmooTransportCounters};

use super::session::{
    update_session_phase, BootRuntime, DeviceSession, SessionPhase, SessionStore,
};

const DEFAULT_SMOO_METRICS_PORT: u16 = 0;

pub async fn boot_selected_device(
    sessions: &mut SessionStore,
    session_id: &str,
) -> Result<BootRuntime> {
    let session = sessions
        .read()
        .iter()
        .find(|s| s.id == session_id)
        .cloned()
        .ok_or_else(|| anyhow!("session not found"))?;
    let config = native_boot_config_for_session(&session)?;
    let request = config.boot_request()?;
    let selected_device = NativeSelectedFastbootDevice::new(
        session.device.handle.clone(),
        session.device.profile.clone(),
        session.device.serial.clone(),
    );

    let (session_tx, session_rx) = std::sync::mpsc::channel::<SessionEvent>();
    let mut env = NativeBootEnvironment::new(config, session_tx, CancellationToken::new())
        .with_selected_device(selected_device);
    let boot_session = BootSession::new(request);

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Preparing boot payload".to_string(),
        },
    );
    let prepared = boot_session
        .prepare(&mut env)
        .await
        .context("prepare desktop boot payload")?;
    drain_session_events(&session_rx, sessions, session_id);

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Opening fastboot transport".to_string(),
        },
    );
    let mut fastboot = env
        .connect_fastboot(&boot_session, &prepared.info())
        .await
        .context("open selected fastboot transport")?;

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
    download(&mut fastboot, &prepared.boot_image)
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

    let export = prepared.export;
    Ok(BootRuntime {
        reader: export.reader,
        size_bytes: export.size_bytes,
        identity: export.identity,
        smoo_stats: SmooStatsHandle::new(),
    })
}

pub fn run_rusb_host_daemon(
    reader: Arc<dyn gibblox_core::BlockReader>,
    size_bytes: u64,
    identity: String,
    smoo_stats: SmooStatsHandle,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("create tokio runtime for smoo host")?;
    let (tx, rx) = std::sync::mpsc::channel::<SmooHostEvent>();
    let forwarder = std::thread::Builder::new()
        .name("fastboop-desktop-smoo-events".to_string())
        .spawn({
            let smoo_stats = smoo_stats.clone();
            move || forward_smoo_events(rx, smoo_stats)
        })
        .context("spawn smoo event forwarder")?;

    let result = runtime.block_on(run_native_smoo_host(
        reader,
        size_bytes,
        identity,
        SmooHostOptions {
            impersonate_fastboot: true,
            metrics_port: DEFAULT_SMOO_METRICS_PORT,
        },
        tx,
        CancellationToken::new(),
    ));

    let _ = forwarder.join();
    result
}

fn native_boot_config_for_session(session: &DeviceSession) -> Result<NativeBootConfig> {
    let channel = session.boot_config.channel.trim();
    if channel.is_empty() {
        return Err(anyhow!("channel is empty"));
    }

    Ok(NativeBootConfig {
        stage0: NativeBootStage0Config {
            channel: PathBuf::from(channel),
            ostree: fastboop_environment_std::OstreeArg::Disabled,
            device_profile: Some(session.device.profile.id.clone()),
            boot_profile: session.boot_config.selected_boot_profile_id.clone(),
            dtb: None,
            dtbo: Vec::new(),
            augment: None,
            stage0: None,
            require_modules: Vec::new(),
            cmdline_append: nonempty_string(session.boot_config.extra_kargs.as_str()),
            serial: session.boot_config.enable_serial,
            impersonate_fastboot: true,
            smoo_queue_count: None,
            smoo_queue_depth: None,
            smoo_max_io: None,
            abl_exorcist: None,
            local_artifact: Vec::new(),
        },
        boot_device: true,
        system_time: false,
        systemd_firstboot: true,
        wait: std::time::Duration::ZERO,
        smoo_metrics_port: DEFAULT_SMOO_METRICS_PORT,
        session_state: None,
    })
}

fn drain_session_events(
    rx: &Receiver<SessionEvent>,
    sessions: &mut SessionStore,
    session_id: &str,
) {
    while let Ok(event) = rx.try_recv() {
        match event {
            SessionEvent::Phase { phase, detail } => match phase {
                SessionEventPhase::Preparing
                | SessionEventPhase::WaitingForDevice
                | SessionEventPhase::DeviceDetected
                | SessionEventPhase::BuildingStage0
                | SessionEventPhase::BuildingBootImage
                | SessionEventPhase::Downloading
                | SessionEventPhase::Booting
                | SessionEventPhase::WaitingForSmoo => update_session_phase(
                    sessions,
                    session_id,
                    SessionPhase::Booting { step: detail },
                ),
                SessionEventPhase::Serving | SessionEventPhase::Failed => {}
            },
            SessionEvent::Log(line) => info!(message = %line, "desktop boot session event"),
            SessionEvent::SmooStatus { .. } => {}
        }
    }
}

fn forward_smoo_events(rx: Receiver<SmooHostEvent>, smoo_stats: SmooStatsHandle) {
    let mut previous = SmooTransportCounters::default();
    while let Ok(event) = rx.recv() {
        match event {
            SmooHostEvent::Phase { phase, detail } => {
                smoo_stats.set_connected(matches!(phase, SmooHostPhase::Serving));
                info!(phase = ?phase, detail = %detail, "desktop smoo host phase");
            }
            SmooHostEvent::Log(line) => info!(message = %line, "desktop smoo host"),
            SmooHostEvent::Status {
                active,
                ios_up,
                ios_down,
                bytes_up,
                bytes_down,
                ..
            } => {
                smoo_stats.set_connected(active || smoo_stats.snapshot().connected);
                apply_transport_counters(
                    &smoo_stats,
                    &mut previous,
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
}

fn nonempty_string(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}
