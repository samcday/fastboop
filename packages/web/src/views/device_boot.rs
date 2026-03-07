#[cfg(target_arch = "wasm32")]
use anyhow::Context;
use dioxus::prelude::*;
use fastboop_core::bootimg::build_android_bootimg;
use fastboop_core::device::DeviceHandle as _;
use fastboop_core::fastboot::{boot, download};
#[cfg(target_arch = "wasm32")]
use fastboop_core::BootProfileArtifactSource;
use fastboop_core::Personalization;
use fastboop_core::{resolve_effective_boot_profile_stage0, BootProfile};
use fastboop_stage0_generator::{build_stage0, Stage0Options, Stage0SwitchrootFs};
#[cfg(target_arch = "wasm32")]
use futures_util::StreamExt;
#[cfg(target_arch = "wasm32")]
use gibblox_android_sparse::{
    AndroidSparseBlockReader, AndroidSparseChunkIndex, AndroidSparseImageIndex,
};
#[cfg(target_arch = "wasm32")]
use gibblox_core::AlignedByteReader;
use gibblox_core::{block_identity_string, BlockByteReader, BlockReader};
#[cfg(target_arch = "wasm32")]
use gibblox_core::{GptBlockReader, GptPartitionSelector};
#[cfg(not(target_arch = "wasm32"))]
use gibblox_http::HttpReader;
#[cfg(target_arch = "wasm32")]
use gibblox_mbr::{MbrBlockReader, MbrPartitionSelector};
#[cfg(target_arch = "wasm32")]
use gibblox_pipeline::{
    encode_pipeline, PipelineSource, PipelineSourceCasync, PipelineSourceCasyncSource,
    PipelineSourceHttpSource,
};
#[cfg(target_arch = "wasm32")]
use gibblox_web_file::WebFileReader;
#[cfg(target_arch = "wasm32")]
use gibblox_web_worker::GibbloxWebWorker;
#[cfg(target_arch = "wasm32")]
use gibblox_xz::XzBlockReader;
use gibblox_zip::ZipEntryBlockReader;
#[cfg(target_arch = "wasm32")]
use gloo_timers::future::sleep;
#[cfg(target_arch = "wasm32")]
use gobblytes_core::{Filesystem, FilesystemEntryType, OstreeFs as OstreeRootfs};
use gobblytes_erofs::ErofsRootfs;
#[cfg(target_arch = "wasm32")]
use js_sys::Reflect;
#[cfg(target_arch = "wasm32")]
use smoo_host_web_worker::{HostWorker, HostWorkerConfig, HostWorkerEvent, HostWorkerState};
use std::future::Future;
#[cfg(target_arch = "wasm32")]
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
#[cfg(target_arch = "wasm32")]
use std::time::Duration;
use ui::oneplus_fajita_dtbo_overlays;
#[cfg(target_arch = "wasm32")]
use ui::SmooStatsHandle;
#[cfg(target_arch = "wasm32")]
use ui::{apply_transport_counters, SmooTransportCounters};
use url::Url;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

#[cfg(target_arch = "wasm32")]
use super::session::update_session_active_host_state;
#[cfg(target_arch = "wasm32")]
use super::session::LocalReaderBridge;
use super::session::{
    update_session_phase, BootConfig, BootRuntime, DeviceSession, SessionChannelIntake,
    SessionPhase, SessionStore,
};
#[cfg(target_arch = "wasm32")]
use crate::gibblox_worker::spawn_gibblox_worker;

#[cfg(target_arch = "wasm32")]
const STATUS_RETRY_INTERVAL: Duration = Duration::from_millis(200);
#[cfg(target_arch = "wasm32")]
const STATUS_RETRY_ATTEMPTS: usize = 5;
#[cfg(target_arch = "wasm32")]
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const SMOO_MAX_IO_BYTES_KARG: &str = "smoo.max_io_bytes=1048576";

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
    let mut boot_config = session.boot_config.clone();

    validate_session_dev_profiles(
        &session.device.profile.id,
        &session.channel_intake.accepted_dev_profiles,
    )
    .with_context(|| {
        format!(
            "device '{}' is not accepted by channel stream dev profiles",
            session.device.profile.id
        )
    })?;

    let selected_boot_profile = select_boot_profile_for_session(&session)?;
    let profile_stage0 = selected_boot_profile
        .as_ref()
        .map(|boot_profile| {
            resolve_effective_boot_profile_stage0(boot_profile, session.device.profile.id.as_str())
        })
        .unwrap_or_default();

    let channel = boot_config.channel.trim();
    if channel.is_empty() {
        return Err(anyhow::anyhow!("channel is empty"));
    }

    if session.channel_intake.warning_count > 0 {
        tracing::warn!(
            warning_count = session.channel_intake.warning_count,
            consumed_bytes = session.channel_intake.consumed_bytes,
            channel,
            "channel stream contained trailing bytes that were not valid profile records"
        );
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
    let mut dtbo_overlays = dtbo_overlays;
    dtbo_overlays.extend(profile_stage0.dt_overlays);

    let mut extra_modules = vec!["erofs".to_string()];
    extra_modules.extend(profile_stage0.extra_modules);

    boot_config.extra_kargs = join_cmdline(
        profile_stage0.extra_cmdline.as_deref(),
        nonempty(boot_config.extra_kargs.as_str()),
    );

    let stage0_opts = Stage0Options {
        switchroot_fs: Stage0SwitchrootFs::Erofs,
        extra_modules,
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
        session.channel_intake.clone(),
        selected_boot_profile,
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
        local_reader_bridge: runtime.local_reader_bridge,
        #[cfg(target_arch = "wasm32")]
        smoo_stats: runtime.smoo_stats,
    }))
}

async fn build_stage0_artifacts(
    profile: fastboop_core::DeviceProfile,
    stage0_opts: Stage0Options,
    boot_config: BootConfig,
    channel_intake: SessionChannelIntake,
    selected_boot_profile: Option<BootProfile>,
) -> anyhow::Result<(fastboop_stage0_generator::Stage0Build, BootRuntime)> {
    use futures_channel::oneshot;

    let channel = boot_config.channel.trim().to_string();
    if channel.is_empty() {
        return Err(anyhow::anyhow!("channel is empty"));
    }
    let extra_kargs = join_cmdline(
        nonempty(boot_config.extra_kargs.as_str()),
        Some(SMOO_MAX_IO_BYTES_KARG),
    );

    #[cfg(not(target_arch = "wasm32"))]
    let _ = (&channel_intake, &selected_boot_profile);

    let (tx, rx) = oneshot::channel();
    wasm_bindgen_futures::spawn_local(async move {
        let result: anyhow::Result<_> = async {
            tracing::info!(profile = %profile.id, channel = %channel, "opening channel for web boot");
            #[cfg(target_arch = "wasm32")]
            let (
                provider_reader,
                size_bytes,
                local_reader_bridge,
                channel_identity,
                channel_offset_bytes,
                using_boot_profile_rootfs,
            ) = {
                if channel_intake.has_artifact_payload {
                    if let Some(web_file) = crate::resolve_web_file_channel(&channel) {
                        let channel_offset_bytes = channel_intake.consumed_bytes;
                        let provider_reader =
                            open_web_file_channel_payload_reader(web_file, channel_offset_bytes)
                                .await?;
                        let size_bytes = reader_size_bytes(provider_reader.as_ref()).await?;
                        let channel_identity = block_identity_string(provider_reader.as_ref());
                        let local_reader_bridge = LocalReaderBridge::new(provider_reader.clone());
                        (
                            provider_reader,
                            size_bytes,
                            Some(local_reader_bridge),
                            channel_identity,
                            channel_offset_bytes,
                            false,
                        )
                    } else {
                        let channel_offset_bytes = channel_intake.consumed_bytes;
                        let gibblox_worker = spawn_gibblox_worker(channel.clone(), 0, None)
                            .await
                            .map_err(|err| anyhow::anyhow!("spawn gibblox worker failed: {err}"))?;
                        let provider_reader = open_channel_payload_reader_via_worker(
                            &gibblox_worker,
                            &channel,
                            channel_offset_bytes,
                            None,
                        )
                        .await?;
                        let size_bytes = reader_size_bytes(provider_reader.as_ref()).await?;
                        let channel_identity = block_identity_string(provider_reader.as_ref());
                        let local_reader_bridge = LocalReaderBridge::new(provider_reader.clone());
                        (
                            provider_reader,
                            size_bytes,
                            Some(local_reader_bridge),
                            channel_identity,
                            channel_offset_bytes,
                            false,
                        )
                    }
                } else {
                    let boot_profile = selected_boot_profile.as_ref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "channel has no trailing artifact payload and no compatible boot profile selected"
                        )
                    })?;
                    let provider_reader = open_boot_profile_rootfs_reader(boot_profile).await?;
                    let size_bytes = reader_size_bytes(provider_reader.as_ref()).await?;
                    let channel_identity = block_identity_string(provider_reader.as_ref());
                    let local_reader_bridge = LocalReaderBridge::new(provider_reader.clone());
                    (
                        provider_reader,
                        size_bytes,
                        Some(local_reader_bridge),
                        channel_identity,
                        0,
                        true,
                    )
                }
            };
            #[cfg(not(target_arch = "wasm32"))]
            let (provider, size_bytes, channel_identity, channel_offset_bytes) = {
                let url = Url::parse(&channel)
                    .map_err(|err| anyhow::anyhow!("parse channel URL {channel}: {err}"))?;
                let http_reader = HttpReader::new(
                    url.clone(),
                    gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE,
                )
                .await
                .map_err(|err| anyhow::anyhow!("open HTTP reader {url}: {err}"))?;
                let http_reader = BlockByteReader::new(
                    http_reader,
                    gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE,
                )
                .map_err(|err| anyhow::anyhow!("open HTTP block view {url}: {err}"))?;
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

            #[cfg(target_arch = "wasm32")]
            let build = {
                let provider = ErofsRootfs::new(provider_reader.clone(), size_bytes).await?;
                let selected_ostree = if using_boot_profile_rootfs
                    && selected_boot_profile
                        .as_ref()
                        .is_some_and(|boot_profile| boot_profile.rootfs.is_ostree())
                {
                    let detected = auto_detect_ostree_deployment_path(&provider).await?;
                    tracing::debug!(ostree = %detected, "auto-detected ostree deployment path");
                    Some(detected)
                } else {
                    None
                };
                let extra_cmdline = if let Some(ostree) = selected_ostree.as_deref() {
                    Some(join_cmdline(
                        Some(format!("ostree=/{ostree}").as_str()),
                        nonempty(&extra_kargs),
                    ))
                } else {
                    nonempty(&extra_kargs).map(str::to_string)
                };

                if let Some(ostree) = selected_ostree.as_deref() {
                    let resolved_ostree = OstreeRootfs::resolve_deployment_path(&provider, ostree)
                        .await
                        .map_err(|err| anyhow::anyhow!(
                            "resolve ostree deployment path {ostree}: {err}"
                        ))?;
                    tracing::debug!(
                        ostree = %ostree,
                        resolved_ostree = %resolved_ostree,
                        "resolved ostree deployment path"
                    );
                    let provider = OstreeRootfs::new(provider, &resolved_ostree).map_err(|err| {
                        anyhow::anyhow!("initialize ostree filesystem view: {err}")
                    })?;
                    build_stage0(
                        &profile,
                        &provider,
                        &stage0_opts,
                        extra_cmdline.as_deref(),
                        None,
                    )
                    .await
                } else {
                    build_stage0(
                        &profile,
                        &provider,
                        &stage0_opts,
                        extra_cmdline.as_deref(),
                        None,
                    )
                    .await
                }
            }
            .map_err(|err| anyhow::anyhow!("stage0 build failed: {err:?}"))?;

            #[cfg(not(target_arch = "wasm32"))]
            let build = build_stage0(&profile, &provider, &stage0_opts, nonempty(&extra_kargs), None)
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
                    local_reader_bridge,
                    #[cfg(target_arch = "wasm32")]
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
async fn open_channel_payload_reader_via_worker(
    worker: &GibbloxWebWorker,
    channel: &str,
    channel_offset_bytes: u64,
    channel_chunk_store_url: Option<&str>,
) -> anyhow::Result<Arc<dyn BlockReader>> {
    let channel = channel.trim();
    if channel.is_empty() {
        anyhow::bail!("channel URL is empty");
    }

    let url =
        Url::parse(channel).map_err(|err| anyhow::anyhow!("parse channel URL {channel}: {err}"))?;
    if is_casync_archive_index_url(&url) {
        anyhow::bail!(
            "casync archive indexes (.caidx) are not supported for channel block reads; provide a casync blob index (.caibx)"
        );
    }

    let chunk_store_url = parse_optional_chunk_store_url(channel_chunk_store_url)?;
    if !is_casync_blob_index_url(&url) && chunk_store_url.is_some() {
        anyhow::bail!(
            "channel chunk store override is only supported with casync blob-index channels (.caibx)"
        );
    }

    let pipeline_source = if is_casync_blob_index_url(&url) {
        PipelineSource::Casync(PipelineSourceCasyncSource {
            casync: PipelineSourceCasync {
                index: url.to_string(),
                chunk_store: Some(
                    chunk_store_url
                        .unwrap_or(derive_casync_chunk_store_url(&url)?)
                        .to_string(),
                ),
            },
        })
    } else {
        PipelineSource::Http(PipelineSourceHttpSource {
            http: url.to_string(),
        })
    };

    let pipeline_bytes = encode_pipeline(&pipeline_source)
        .map_err(|err| anyhow::anyhow!("encode channel pipeline source: {err}"))?;
    let opened = worker
        .open_pipeline(&pipeline_bytes)
        .await
        .map_err(|err| anyhow::anyhow!("open gibblox worker pipeline: {err}"))?;

    let reader: Arc<dyn BlockReader> = Arc::new(opened.reader);
    let reader = crate::channel_source::maybe_offset_reader(reader, channel_offset_bytes).await?;
    let reader: Arc<dyn BlockReader> = match zip_entry_name_from_url(&url)? {
        Some(entry_name) => {
            let zip_reader = ZipEntryBlockReader::new(&entry_name, reader)
                .await
                .map_err(|err| anyhow::anyhow!("open ZIP entry {entry_name}: {err}"))?;
            Arc::new(zip_reader)
        }
        None => reader,
    };
    Ok(reader)
}

#[cfg(target_arch = "wasm32")]
fn parse_optional_chunk_store_url(value: Option<&str>) -> anyhow::Result<Option<Url>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let url = Url::parse(value)
        .map_err(|err| anyhow::anyhow!("parse casync chunk_store URL {value}: {err}"))?;
    Ok(Some(url))
}

#[cfg(target_arch = "wasm32")]
fn is_casync_blob_index_url(url: &Url) -> bool {
    url.path().to_ascii_lowercase().ends_with(".caibx")
}

#[cfg(target_arch = "wasm32")]
fn is_casync_archive_index_url(url: &Url) -> bool {
    url.path().to_ascii_lowercase().ends_with(".caidx")
}

#[cfg(target_arch = "wasm32")]
fn derive_casync_chunk_store_url(index_url: &Url) -> anyhow::Result<Url> {
    if let Some(segments) = index_url.path_segments() {
        let segments: Vec<&str> = segments.collect();
        if let Some(index_pos) = segments.iter().rposition(|segment| *segment == "indexes") {
            let mut base_segments = segments[..=index_pos].to_vec();
            base_segments[index_pos] = "chunks";
            let mut url = index_url.clone();
            let mut path = String::from("/");
            path.push_str(&base_segments.join("/"));
            if !path.ends_with('/') {
                path.push('/');
            }
            url.set_path(&path);
            url.set_query(None);
            url.set_fragment(None);
            return Ok(url);
        }
    }

    index_url
        .join("./")
        .map_err(|err| anyhow::anyhow!("derive casync chunk store URL from {index_url}: {err}"))
}

fn select_boot_profile_for_session(session: &DeviceSession) -> anyhow::Result<Option<BootProfile>> {
    let compatible = &session.channel_intake.compatible_boot_profiles;
    if compatible.is_empty() {
        return Ok(None);
    }

    if let Some(selected_id) = session.boot_config.selected_boot_profile_id.as_deref() {
        let selected = compatible
            .iter()
            .find(|profile| profile.id == selected_id)
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "selected boot profile '{}' is not compatible with device profile '{}'",
                    selected_id,
                    session.device.profile.id
                )
            })?;
        return Ok(Some(selected));
    }

    if compatible.len() == 1 {
        return Ok(Some(compatible[0].clone()));
    }

    let available: Vec<_> = compatible
        .iter()
        .map(|profile| profile.id.as_str())
        .collect();
    anyhow::bail!(
        "multiple compatible boot profiles available for '{}'; choose one: {}",
        session.device.profile.id,
        available.join(", ")
    )
}

#[cfg(target_arch = "wasm32")]
async fn open_web_file_channel_payload_reader(
    web_file: web_sys::File,
    channel_offset_bytes: u64,
) -> anyhow::Result<Arc<dyn BlockReader>> {
    let file_name = web_file.name();
    let file_name_lower = file_name.to_ascii_lowercase();

    if file_name_lower.ends_with(".caibx") || file_name_lower.ends_with(".caidx") {
        anyhow::bail!(
            "web-file channel '{}' is a casync index; use an HTTP(S) channel URL so chunk-store URLs can be resolved",
            file_name
        );
    }

    let reader = WebFileReader::new(web_file, gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE)
        .map_err(|err| anyhow::anyhow!("open web file channel reader: {err}"))?;
    let reader: Arc<dyn BlockReader> = Arc::new(reader);
    let reader = crate::channel_source::maybe_offset_reader(reader, channel_offset_bytes).await?;

    match zip_entry_name_from_file_name(Some(file_name.as_str()))? {
        Some(entry_name) => {
            let zip_reader = ZipEntryBlockReader::new(&entry_name, reader)
                .await
                .map_err(|err| anyhow::anyhow!("open ZIP entry {entry_name}: {err}"))?;
            Ok(Arc::new(zip_reader))
        }
        None => Ok(reader),
    }
}

#[cfg(target_arch = "wasm32")]
async fn open_boot_profile_rootfs_reader(
    boot_profile: &BootProfile,
) -> anyhow::Result<Arc<dyn BlockReader>> {
    open_boot_profile_artifact_source(boot_profile.rootfs.source()).await
}

#[cfg(target_arch = "wasm32")]
fn open_boot_profile_artifact_source<'a>(
    source: &'a BootProfileArtifactSource,
) -> Pin<Box<dyn Future<Output = anyhow::Result<Arc<dyn BlockReader>>> + 'a>> {
    Box::pin(async move {
        match source {
            BootProfileArtifactSource::Http(source) => {
                let channel = source.http.trim();
                if channel.is_empty() {
                    anyhow::bail!("boot profile rootfs.http source is empty");
                }
                crate::channel_source::build_channel_reader_pipeline(channel, 0, None)
                    .await
                    .map_err(|err| anyhow::anyhow!("open HTTP artifact source {channel}: {err}"))
            }
            BootProfileArtifactSource::Casync(source) => {
                let index = source.casync.index.trim();
                if index.is_empty() {
                    anyhow::bail!("boot profile rootfs.casync.index source is empty");
                }
                let chunk_store = source
                    .casync
                    .chunk_store
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                crate::channel_source::build_channel_reader_pipeline(index, 0, chunk_store)
                    .await
                    .map_err(|err| anyhow::anyhow!("open casync artifact source {index}: {err}"))
            }
            BootProfileArtifactSource::File(source) => {
                let path = source.file.trim();
                if path.is_empty() {
                    anyhow::bail!("boot profile rootfs.file source is empty");
                }
                let Some(web_file) = crate::resolve_web_file_channel(path) else {
                    anyhow::bail!(
                        "boot profile file source '{}' is not accessible in browser; use HTTP/casync sources or a web-file://<id> source",
                        path
                    );
                };
                let reader =
                    WebFileReader::new(web_file, gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE)
                        .map_err(|err| {
                            anyhow::anyhow!("open web file artifact source {path}: {err}")
                        })?;
                let reader: Arc<dyn BlockReader> = Arc::new(reader);
                Ok(reader)
            }
            BootProfileArtifactSource::Xz(source) => {
                let upstream = open_boot_profile_artifact_source(source.xz.as_ref()).await?;
                let upstream = AlignedByteReader::new(upstream).await.map_err(|err| {
                    anyhow::anyhow!("open aligned byte view for xz source: {err}")
                })?;
                let reader = XzBlockReader::new_from_byte_reader(Arc::new(upstream))
                    .await
                    .map_err(|err| anyhow::anyhow!("open xz block reader: {err}"))?;
                let reader =
                    BlockByteReader::new(reader, gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE)
                        .map_err(|err| anyhow::anyhow!("open xz block view: {err}"))?;
                let reader: Arc<dyn BlockReader> = Arc::new(reader);
                Ok(reader)
            }
            BootProfileArtifactSource::AndroidSparseImg(source) => {
                let upstream =
                    open_boot_profile_artifact_source(source.android_sparseimg.source.as_ref())
                        .await?;
                let reader = if let Some(index) = source.android_sparseimg.index.as_ref() {
                    let sparse_index = AndroidSparseImageIndex {
                        file_hdr_sz: index.file_hdr_sz,
                        chunk_hdr_sz: index.chunk_hdr_sz,
                        blk_sz: index.blk_sz,
                        total_blks: index.total_blks,
                        total_chunks: index.total_chunks,
                        image_checksum: index.image_checksum,
                        chunks: index
                            .chunks
                            .iter()
                            .map(|chunk| AndroidSparseChunkIndex {
                                chunk_index: chunk.chunk_index,
                                chunk_type: chunk.chunk_type,
                                chunk_sz: chunk.chunk_sz,
                                total_sz: chunk.total_sz,
                                chunk_offset: chunk.chunk_offset,
                                payload_offset: chunk.payload_offset,
                                payload_size: chunk.payload_size,
                                output_start: chunk.output_start,
                                output_end: chunk.output_end,
                                fill_pattern: chunk.fill_pattern,
                                crc32: chunk.crc32,
                            })
                            .collect(),
                    };
                    AndroidSparseBlockReader::new_with_index(upstream, sparse_index)
                        .await
                        .map_err(|err| {
                            anyhow::anyhow!("open android sparse reader from index: {err}")
                        })?
                } else {
                    AndroidSparseBlockReader::new(upstream)
                        .await
                        .map_err(|err| anyhow::anyhow!("open android sparse reader: {err}"))?
                };
                let reader: Arc<dyn BlockReader> = Arc::new(reader);
                Ok(reader)
            }
            BootProfileArtifactSource::Mbr(source) => {
                let selector = if let Some(partuuid) = source.mbr.partuuid.as_deref() {
                    MbrPartitionSelector::part_uuid(partuuid)
                } else if let Some(index) = source.mbr.index {
                    MbrPartitionSelector::index(index)
                } else {
                    anyhow::bail!("boot profile MBR source missing selector")
                };

                let upstream =
                    open_boot_profile_artifact_source(source.mbr.source.as_ref()).await?;
                let reader = MbrBlockReader::new(
                    upstream,
                    selector,
                    gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE,
                )
                .await
                .map_err(|err| anyhow::anyhow!("open MBR partition reader: {err}"))?;
                let reader: Arc<dyn BlockReader> = Arc::new(reader);
                Ok(reader)
            }
            BootProfileArtifactSource::Gpt(source) => {
                let selector = if let Some(partlabel) = source.gpt.partlabel.as_deref() {
                    GptPartitionSelector::part_label(partlabel)
                } else if let Some(partuuid) = source.gpt.partuuid.as_deref() {
                    GptPartitionSelector::part_uuid(partuuid)
                } else if let Some(index) = source.gpt.index {
                    GptPartitionSelector::index(index)
                } else {
                    anyhow::bail!("boot profile GPT source missing selector")
                };

                let upstream =
                    open_boot_profile_artifact_source(source.gpt.source.as_ref()).await?;
                let reader = GptBlockReader::new(
                    upstream,
                    selector,
                    gobblytes_erofs::DEFAULT_IMAGE_BLOCK_SIZE,
                )
                .await
                .map_err(|err| anyhow::anyhow!("open GPT partition reader: {err}"))?;
                let reader: Arc<dyn BlockReader> = Arc::new(reader);
                Ok(reader)
            }
        }
    })
}

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

fn zip_entry_name_from_url(url: &Url) -> anyhow::Result<Option<String>> {
    let file_name = url
        .path_segments()
        .and_then(|segments| segments.filter(|segment| !segment.is_empty()).next_back());
    zip_entry_name_from_file_name(file_name)
}

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
    let reader_client = if let Some(local_reader_bridge) = runtime.local_reader_bridge.clone() {
        local_reader_bridge
            .create_reader()
            .await
            .map_err(|err| anyhow::anyhow!("attach local channel reader bridge: {err}"))?
    } else {
        anyhow::bail!("channel reader bridge unavailable for host startup");
    };
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

#[cfg(target_arch = "wasm32")]
async fn auto_detect_ostree_deployment_path<P>(rootfs: &P) -> anyhow::Result<String>
where
    P: Filesystem,
    P::Error: core::fmt::Display,
{
    const OSTREE_ROOT: &str = "/ostree";

    if !is_directory(rootfs, OSTREE_ROOT).await? {
        anyhow::bail!("auto-detect ostree deployment failed: {OSTREE_ROOT} is not a directory");
    }

    for boot_dir in sorted_dir_entries(rootfs, OSTREE_ROOT).await? {
        if !boot_dir.starts_with("boot.") {
            continue;
        }
        let boot_path = format!("{OSTREE_ROOT}/{boot_dir}");
        if !is_directory(rootfs, &boot_path).await? {
            continue;
        }

        for stateroot in sorted_dir_entries(rootfs, &boot_path).await? {
            let stateroot_path = format!("{boot_path}/{stateroot}");
            if !is_directory(rootfs, &stateroot_path).await? {
                continue;
            }

            for checksum in sorted_dir_entries(rootfs, &stateroot_path).await? {
                let checksum_path = format!("{stateroot_path}/{checksum}");
                if !is_directory(rootfs, &checksum_path).await? {
                    continue;
                }

                for deploy_index in sorted_dir_entries(rootfs, &checksum_path).await? {
                    let candidate_path = format!("{checksum_path}/{deploy_index}");
                    if is_symlink(rootfs, &candidate_path).await? {
                        return Ok(candidate_path.trim_start_matches('/').to_string());
                    }
                }
            }
        }
    }

    anyhow::bail!(
        "auto-detect ostree deployment failed: no deployment symlink found under /ostree/boot.*"
    )
}

#[cfg(target_arch = "wasm32")]
async fn sorted_dir_entries<P>(rootfs: &P, path: &str) -> anyhow::Result<Vec<String>>
where
    P: Filesystem,
    P::Error: core::fmt::Display,
{
    let mut entries = rootfs
        .read_dir(path)
        .await
        .map_err(|err| anyhow::anyhow!("read directory {path}: {err}"))?;
    entries.sort();
    Ok(entries)
}

#[cfg(target_arch = "wasm32")]
async fn is_directory<P>(rootfs: &P, path: &str) -> anyhow::Result<bool>
where
    P: Filesystem,
    P::Error: core::fmt::Display,
{
    let ty = rootfs
        .entry_type(path)
        .await
        .map_err(|err| anyhow::anyhow!("read entry type {path}: {err}"))?;
    Ok(matches!(ty, Some(FilesystemEntryType::Directory)))
}

#[cfg(target_arch = "wasm32")]
async fn is_symlink<P>(rootfs: &P, path: &str) -> anyhow::Result<bool>
where
    P: Filesystem,
    P::Error: core::fmt::Display,
{
    let ty = rootfs
        .entry_type(path)
        .await
        .map_err(|err| anyhow::anyhow!("read entry type {path}: {err}"))?;
    Ok(matches!(ty, Some(FilesystemEntryType::Symlink)))
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
