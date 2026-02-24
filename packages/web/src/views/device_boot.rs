#[cfg(target_arch = "wasm32")]
use anyhow::Context;
use dioxus::prelude::*;
use fastboop_core::bootimg::build_android_bootimg;
use fastboop_core::device::DeviceHandle as _;
use fastboop_core::fastboot::{boot, download};
use fastboop_core::{
    read_channel_stream_head, ChannelStreamHead, Personalization,
    CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES,
};
use fastboop_stage0_generator::{build_stage0, Stage0Options, Stage0SwitchrootFs};
#[cfg(target_arch = "wasm32")]
use futures_util::StreamExt;
#[cfg(not(target_arch = "wasm32"))]
use gibblox_core::BlockReader;
use gibblox_core::{block_identity_string, ReadContext};
use gibblox_http::HttpBlockReader;
#[cfg(not(target_arch = "wasm32"))]
use gibblox_zip::ZipEntryBlockReader;
#[cfg(target_arch = "wasm32")]
use gloo_timers::future::sleep;
use gobblytes_erofs::ErofsRootfs;
#[cfg(target_arch = "wasm32")]
use js_sys::Reflect;
#[cfg(target_arch = "wasm32")]
use smoo_host_web_worker::{HostWorker, HostWorkerConfig, HostWorkerEvent, HostWorkerState};
use std::future::Future;
use std::rc::Rc;
use std::sync::Arc;
#[cfg(target_arch = "wasm32")]
use std::time::Duration;
#[cfg(target_arch = "wasm32")]
use ui::{apply_transport_counters, SmooTransportCounters};
use ui::{oneplus_fajita_dtbo_overlays, SmooStatsHandle};
use url::Url;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

#[cfg(target_arch = "wasm32")]
use super::session::update_session_active_host_state;
use super::session::{update_session_phase, BootConfig, BootRuntime, SessionPhase, SessionStore};
#[cfg(target_arch = "wasm32")]
use crate::gibblox_worker::spawn_gibblox_worker;

#[cfg(target_arch = "wasm32")]
const STATUS_RETRY_INTERVAL: Duration = Duration::from_millis(200);
#[cfg(target_arch = "wasm32")]
const STATUS_RETRY_ATTEMPTS: usize = 5;
#[cfg(target_arch = "wasm32")]
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

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
    let boot_config = session.boot_config.clone();

    let channel = boot_config.channel.trim();
    if channel.is_empty() {
        return Err(anyhow::anyhow!("channel is empty"));
    }

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: format!(
                "Opening channel {} for {} ({:04x}:{:04x})",
                channel, session.device.name, session.device.vid, session.device.pid
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
        switchroot_fs: Stage0SwitchrootFs::Erofs,
        extra_modules: vec!["erofs".to_string()],
        kernel_override: None,
        dtb_override: None,
        dtbo_overlays,
        enable_serial: boot_config.enable_serial,
        mimic_fastboot: true,
        smoo_vendor: Some(session.device.vid),
        smoo_product: Some(session.device.pid),
        smoo_serial: webusb_serial_number(&session.device.handle),
        personalization: Some(personalization_from_browser()),
    };
    let profile_id = session.device.profile.id.clone();
    let (build, runtime) = build_stage0_artifacts(
        session.device.profile.clone(),
        stage0_opts,
        boot_config.clone(),
    )
    .await
    .with_context(|| {
        format!("open channel and build stage0 (profile={profile_id}, channel={channel})")
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
    .map_err(|err| anyhow::anyhow!("bootimg build failed: {err}"))?;

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
        .map_err(|err| anyhow::anyhow!("open fastboot failed: {err}"))?;

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Downloading boot image".to_string(),
        },
    );
    download(&mut fastboot, &bootimg)
        .await
        .map_err(|err| anyhow::anyhow!("fastboot download failed: {err}"))?;

    update_session_phase(
        sessions,
        session_id,
        SessionPhase::Booting {
            step: "Issuing fastboot boot".to_string(),
        },
    );
    boot(&mut fastboot)
        .await
        .map_err(|err| anyhow::anyhow!("fastboot boot failed: {err}"))?;
    let _ = fastboot.shutdown().await;

    Ok(Rc::new(BootRuntime {
        size_bytes: runtime.size_bytes,
        identity: runtime.identity,
        channel: runtime.channel,
        channel_offset_bytes: runtime.channel_offset_bytes,
        #[cfg(target_arch = "wasm32")]
        gibblox_worker: runtime.gibblox_worker,
        smoo_stats: runtime.smoo_stats,
    }))
}

async fn build_stage0_artifacts(
    profile: fastboop_core::DeviceProfile,
    stage0_opts: Stage0Options,
    boot_config: BootConfig,
) -> anyhow::Result<(fastboop_stage0_generator::Stage0Build, BootRuntime)> {
    use futures_channel::oneshot;

    let channel = boot_config.channel.trim().to_string();
    if channel.is_empty() {
        return Err(anyhow::anyhow!("channel is empty"));
    }
    let extra_kargs = boot_config.extra_kargs.trim().to_string();

    let (tx, rx) = oneshot::channel();
    wasm_bindgen_futures::spawn_local(async move {
        let result: anyhow::Result<_> = async {
            tracing::info!(profile = %profile.id, channel = %channel, "opening channel for web boot");
            #[cfg(target_arch = "wasm32")]
            let (provider, size_bytes, gibblox_worker, channel_identity, channel_offset_bytes) = {
                let (stream_head, total_size_bytes) =
                    read_channel_stream_head_for_url(&channel).await?;

                if stream_head.warning_count > 0 {
                    tracing::info!(
                        warning_count = stream_head.warning_count,
                        consumed_bytes = stream_head.consumed_bytes,
                        channel,
                        "channel stream head stopped early while scanning records"
                    );
                }

                validate_session_dev_profiles(&profile.id, &stream_head.dev_profiles)?;

                if stream_head.consumed_bytes >= total_size_bytes {
                    anyhow::bail!(
                        "channel stream has only profile records and no trailing artifact payload"
                    );
                }

                let channel_offset_bytes = stream_head.consumed_bytes;
                let gibblox_worker = spawn_gibblox_worker(channel.clone(), channel_offset_bytes)
                    .await
                    .map_err(|err| anyhow::anyhow!("spawn gibblox worker failed: {err}"))?;
                let reader_for_erofs = gibblox_worker.create_reader().await.map_err(|err| {
                    anyhow::anyhow!("attach gibblox block reader for stage0: {err}")
                })?;
                let size_bytes = reader_size_bytes(&reader_for_erofs).await?;
                let channel_identity = block_identity_string(&reader_for_erofs);
                let provider = ErofsRootfs::new(Arc::new(reader_for_erofs), size_bytes).await?;
                (
                    provider,
                    size_bytes,
                    Some(gibblox_worker),
                    channel_identity,
                    channel_offset_bytes,
                )
            };
            #[cfg(not(target_arch = "wasm32"))]
            let (provider, size_bytes, channel_identity, channel_offset_bytes) = {
                let url = Url::parse(&channel)
                    .map_err(|err| anyhow::anyhow!("parse channel URL {channel}: {err}"))?;
                let http_reader = HttpBlockReader::new(
                    url.clone(),
                    gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE,
                )
                .await
                .map_err(|err| anyhow::anyhow!("open HTTP reader {url}: {err}"))?;
                let reader: Arc<dyn BlockReader> = Arc::new(http_reader);
                let reader: Arc<dyn BlockReader> = match zip_entry_name_from_url(&url)? {
                    Some(entry_name) => {
                        let zip_reader = ZipEntryBlockReader::new(&entry_name, reader)
                            .await
                            .map_err(|err| anyhow::anyhow!("open ZIP entry {entry_name}: {err}"))?;
                        Arc::new(zip_reader)
                    }
                    None => reader,
                };
                let size_bytes = reader_size_bytes(reader.as_ref()).await?;
                let provider = ErofsRootfs::new(reader.clone(), size_bytes).await?;
                let identity = block_identity_string(reader.as_ref());
                (provider, size_bytes, identity, 0)
            };

            tracing::info!(profile = %profile.id, "building stage0 payload");
            #[cfg(target_arch = "wasm32")]
            gloo_timers::future::sleep(std::time::Duration::from_millis(100)).await;

            let build = build_stage0(
                &profile,
                &provider,
                &stage0_opts,
                nonempty(&extra_kargs),
                None,
            )
            .await
            .map_err(|err| anyhow::anyhow!("stage0 build failed: {err:?}"))?;

            Ok((
                build,
                BootRuntime {
                    size_bytes,
                    identity: channel_identity,
                    channel: channel.clone(),
                    channel_offset_bytes,
                    #[cfg(target_arch = "wasm32")]
                    gibblox_worker,
                    smoo_stats: SmooStatsHandle::new(),
                },
            ))
        }
        .await;
        let _ = tx.send(result);
    });

    rx.await
        .map_err(|_| anyhow::anyhow!("stage0 build task was cancelled"))?
}

#[cfg(target_arch = "wasm32")]
async fn read_channel_stream_head_for_url(
    channel: &str,
) -> anyhow::Result<(ChannelStreamHead, u64)> {
    let url =
        Url::parse(channel).map_err(|err| anyhow::anyhow!("parse channel URL {channel}: {err}"))?;
    let channel_reader =
        HttpBlockReader::new(url.clone(), gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE)
            .await
            .map_err(|err| anyhow::anyhow!("open HTTP channel reader {url}: {err}"))?;

    let total_size_bytes = reader_size_bytes(&channel_reader).await?;
    let scan_cap = core::cmp::min(
        CHANNEL_BOOT_PROFILE_STREAM_SCAN_MAX_BYTES as u64,
        total_size_bytes,
    ) as usize;
    let prefix = read_channel_prefix(&channel_reader, scan_cap).await?;
    let stream_head = read_channel_stream_head(prefix.as_slice(), total_size_bytes)
        .map_err(|err| anyhow::anyhow!("decode channel stream head: {err}"))?;

    Ok((stream_head, total_size_bytes))
}

#[cfg(target_arch = "wasm32")]
async fn read_channel_prefix<R>(reader: &R, scan_cap: usize) -> anyhow::Result<Vec<u8>>
where
    R: gibblox_core::BlockReader + ?Sized,
{
    let block_size = usize::try_from(reader.block_size()).map_err(|_| {
        anyhow::anyhow!(
            "channel block size {} does not fit in usize",
            reader.block_size()
        )
    })?;
    if block_size == 0 {
        anyhow::bail!("channel block size is zero");
    }

    let total_blocks = reader
        .total_blocks()
        .await
        .map_err(|err| anyhow::anyhow!("read channel total blocks: {err}"))?;
    let total_size_bytes = total_blocks
        .checked_mul(reader.block_size() as u64)
        .ok_or_else(|| anyhow::anyhow!("channel total size overflows u64"))?;
    let prefix_len = core::cmp::min(scan_cap as u64, total_size_bytes) as usize;
    if prefix_len == 0 {
        return Ok(Vec::new());
    }

    let blocks_to_read = prefix_len.div_ceil(block_size);
    let mut scratch = vec![0u8; blocks_to_read * block_size];
    let mut read = reader
        .read_blocks(0, &mut scratch, ReadContext::FOREGROUND)
        .await
        .map_err(|err| anyhow::anyhow!("read channel prefix: {err}"))?;
    read = core::cmp::min(read, prefix_len);
    scratch.truncate(read);
    Ok(scratch)
}

#[cfg(target_arch = "wasm32")]
fn validate_session_dev_profiles(
    session_device_profile_id: &str,
    accepted: &[fastboop_core::DeviceProfile],
) -> anyhow::Result<()> {
    if accepted.is_empty() {
        return Ok(());
    }

    if accepted
        .iter()
        .any(|profile| profile.id == session_device_profile_id)
    {
        return Ok(());
    }

    let allowed: Vec<_> = accepted.iter().map(|profile| profile.id.as_str()).collect();
    anyhow::bail!(
        "device '{}' is not accepted by this channel stream; channel-dev-profiles: {}",
        session_device_profile_id,
        allowed.join(", ")
    )
}

#[cfg(target_arch = "wasm32")]
async fn reader_size_bytes(reader: &dyn gibblox_core::BlockReader) -> anyhow::Result<u64> {
    let total_blocks = reader
        .total_blocks()
        .await
        .map_err(|err| anyhow::anyhow!("read channel total blocks: {err}"))?;
    total_blocks
        .checked_mul(reader.block_size() as u64)
        .ok_or_else(|| anyhow::anyhow!("channel size overflow"))
}

#[cfg(not(target_arch = "wasm32"))]
async fn reader_size_bytes(reader: &dyn gibblox_core::BlockReader) -> anyhow::Result<u64> {
    let total_blocks = reader
        .total_blocks()
        .await
        .map_err(|err| anyhow::anyhow!("read channel total blocks: {err}"))?;
    total_blocks
        .checked_mul(reader.block_size() as u64)
        .ok_or_else(|| anyhow::anyhow!("channel size overflow"))
}

#[cfg(not(target_arch = "wasm32"))]
fn zip_entry_name_from_url(url: &Url) -> anyhow::Result<Option<String>> {
    let file_name = url
        .path_segments()
        .and_then(|segments| segments.filter(|segment| !segment.is_empty()).next_back());
    zip_entry_name_from_file_name(file_name)
}

#[cfg(not(target_arch = "wasm32"))]
fn zip_entry_name_from_file_name(file_name: Option<&str>) -> anyhow::Result<Option<String>> {
    let Some(file_name) = file_name else {
        return Ok(None);
    };
    if !file_name.to_ascii_lowercase().ends_with(".zip") {
        return Ok(None);
    }

    let stem = &file_name[..file_name.len() - 4];
    if stem.is_empty() {
        return Err(anyhow::anyhow!(
            "zip artifact name must include a filename stem"
        ));
    }
    Ok(Some(format!("{stem}.ero")))
}

#[cfg(target_arch = "wasm32")]
pub async fn run_web_host_daemon(
    initial_device: web_sys::UsbDevice,
    runtime: Rc<BootRuntime>,
    mut sessions: SessionStore,
    session_id: String,
) -> anyhow::Result<()> {
    let gibblox_worker = runtime
        .gibblox_worker
        .clone()
        .ok_or_else(|| anyhow::anyhow!("gibblox worker unavailable for host startup"))?;
    let reader_client = gibblox_worker.create_reader().await.map_err(|err| {
        anyhow::anyhow!("attach gibblox block reader for smoo host worker: {err}")
    })?;
    let smoo_stats = runtime.smoo_stats.clone();

    let host = HostWorker::spawn(
        reader_client,
        HostWorkerConfig {
            status_retry_attempts: STATUS_RETRY_ATTEMPTS,
            heartbeat_interval_ms: HEARTBEAT_INTERVAL.as_millis() as u32,
            size_bytes: runtime.size_bytes,
            identity: runtime.identity.clone(),
            ..HostWorkerConfig::default()
        },
    )
    .await
    .map_err(|err| anyhow::anyhow!("spawn host worker failed: {err}"))?;
    let mut events = host
        .take_event_receiver()
        .ok_or_else(|| anyhow::anyhow!("host worker events receiver unavailable"))?;
    let mut previous_counters = SmooTransportCounters::default();

    update_session_active_host_state(&mut sessions, &session_id, Some(true), Some(false));
    loop {
        if host.state() == HostWorkerState::Idle {
            if let Err(err) = host.start(initial_device.clone()).await {
                tracing::warn!(%err, "starting host worker session failed");
                sleep(STATUS_RETRY_INTERVAL).await;
                continue;
            }
        }

        let Some(event) = events.next().await else {
            return Err(anyhow::anyhow!("host worker event stream closed"));
        };

        match event {
            HostWorkerEvent::Starting => {
                update_session_active_host_state(
                    &mut sessions,
                    &session_id,
                    Some(true),
                    Some(false),
                );
            }
            HostWorkerEvent::TransportConnected | HostWorkerEvent::Configured => {
                update_session_active_host_state(
                    &mut sessions,
                    &session_id,
                    Some(true),
                    Some(true),
                );
                smoo_stats.set_connected(true);
            }
            HostWorkerEvent::Counters {
                ios_up,
                ios_down,
                bytes_up,
                bytes_down,
            } => {
                apply_transport_counters(
                    &smoo_stats,
                    &mut previous_counters,
                    SmooTransportCounters {
                        ios_up,
                        ios_down,
                        bytes_up,
                        bytes_down,
                    },
                );
            }
            HostWorkerEvent::SessionChanged { previous, current } => {
                tracing::warn!(
                    previous = format!("0x{previous:016x}"),
                    current = format!("0x{current:016x}"),
                    "web smoo session changed; waiting to restart"
                );
                update_session_active_host_state(
                    &mut sessions,
                    &session_id,
                    Some(true),
                    Some(false),
                );
                smoo_stats.set_connected(false);
            }
            HostWorkerEvent::TransportLost => {
                tracing::warn!("smoo web transport lost; waiting to restart");
                update_session_active_host_state(
                    &mut sessions,
                    &session_id,
                    Some(true),
                    Some(false),
                );
                smoo_stats.set_connected(false);
            }
            HostWorkerEvent::Error { message } => {
                tracing::warn!(error = %message, "host worker event");
            }
            HostWorkerEvent::Stopped => {
                update_session_active_host_state(
                    &mut sessions,
                    &session_id,
                    Some(true),
                    Some(false),
                );
                smoo_stats.set_connected(false);
                sleep(STATUS_RETRY_INTERVAL).await;
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub fn spawn_detached(fut: impl Future<Output = ()> + 'static) {
    wasm_bindgen_futures::spawn_local(fut);
}

#[cfg(not(target_arch = "wasm32"))]
pub fn spawn_detached(fut: impl Future<Output = ()> + 'static) {
    spawn(fut);
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

fn nonempty(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
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
