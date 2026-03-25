#[cfg(target_arch = "wasm32")]
use anyhow::Context;
use dioxus::prelude::*;
use fastboop_core::bootimg::build_android_bootimg;
use fastboop_core::device::DeviceHandle as _;
use fastboop_core::fastboot::{boot, download};
#[cfg(target_arch = "wasm32")]
use fastboop_core::BootProfileArtifactSource;
use fastboop_core::Personalization;
#[cfg(target_arch = "wasm32")]
use fastboop_core::{
    boot_profile_pipeline_identities, read_channel_pipeline_hints_for_identities, ChannelStreamHead,
};
use fastboop_core::{resolve_effective_boot_profile_stage0, BootProfile};
#[cfg(target_arch = "wasm32")]
use fastboop_core::{BootProfileRootfs, BootProfileRootfsFilesystemSource};
use fastboop_stage0_generator::{
    build_stage0, Stage0KernelOverride, Stage0Options, Stage0SwitchrootFs,
};
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
#[cfg(target_arch = "wasm32")]
use gibblox_ext4::{Ext4EntryType, Ext4Fs};
#[cfg(not(target_arch = "wasm32"))]
use gibblox_http::HttpReader;
#[cfg(target_arch = "wasm32")]
use gibblox_mbr::{MbrBlockReader, MbrPartitionSelector};
#[cfg(target_arch = "wasm32")]
use gibblox_pipeline::{
    encode_pipeline, pipeline_identity_string, validate_pipeline_hints, PipelineCachePolicy,
    PipelineHint, PipelineHints, PipelineSource,
};
#[cfg(target_arch = "wasm32")]
use gibblox_web_file::WebFileReader;
#[cfg(target_arch = "wasm32")]
use gibblox_web_worker::{GibbloxWebWorker, OpenPipelineRequestOptions};
#[cfg(target_arch = "wasm32")]
use gibblox_xz::XzBlockReader;
use gibblox_zip::ZipEntryBlockReader;
#[cfg(target_arch = "wasm32")]
use gloo_timers::future::sleep;
#[cfg(target_arch = "wasm32")]
use gobblytes_core::{Filesystem, FilesystemEntryType, OstreeFs as OstreeRootfs};
use gobblytes_erofs::ErofsRootfs;
#[cfg(target_arch = "wasm32")]
use gobblytes_fat::FatFs;
#[cfg(target_arch = "wasm32")]
use js_sys::Reflect;
#[cfg(target_arch = "wasm32")]
use serde_json::json;
#[cfg(target_arch = "wasm32")]
use smoo_host_web_worker::{HostWorker, HostWorkerConfig, HostWorkerEvent, HostWorkerState};
#[cfg(target_arch = "wasm32")]
use std::collections::HashMap;
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

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage0RootfsKind {
    Erofs,
    Ext4,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
struct Ext4Rootfs {
    fs: Ext4Fs,
}

#[cfg(target_arch = "wasm32")]
impl Ext4Rootfs {
    async fn open(reader: Arc<dyn BlockReader>) -> anyhow::Result<Self> {
        let fs = Ext4Fs::open(reader)
            .await
            .map_err(|err| anyhow::anyhow!("open ext4 rootfs: {err}"))?;
        Ok(Self { fs })
    }
}

#[cfg(target_arch = "wasm32")]
impl Filesystem for Ext4Rootfs {
    type Error = anyhow::Error;

    async fn read_all(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        self.fs
            .read_all(path)
            .await
            .map_err(|err| anyhow::anyhow!("read ext4 path {path}: {err}"))
    }

    async fn read_range(&self, path: &str, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        self.fs
            .read_range(path, offset, len)
            .await
            .map_err(|err| anyhow::anyhow!("read ext4 path range {path}@{offset}+{len}: {err}"))
    }

    async fn read_dir(&self, path: &str) -> anyhow::Result<Vec<String>> {
        self.fs
            .read_dir(path)
            .await
            .map_err(|err| anyhow::anyhow!("read ext4 directory {path}: {err}"))
    }

    async fn entry_type(&self, path: &str) -> anyhow::Result<Option<FilesystemEntryType>> {
        let ty = self
            .fs
            .entry_type(path)
            .await
            .map_err(|err| anyhow::anyhow!("read ext4 entry type {path}: {err}"))?;
        Ok(ty.map(|entry| match entry {
            Ext4EntryType::File => FilesystemEntryType::File,
            Ext4EntryType::Directory => FilesystemEntryType::Directory,
            Ext4EntryType::Symlink => FilesystemEntryType::Symlink,
            Ext4EntryType::Other => FilesystemEntryType::Other,
        }))
    }

    async fn read_link(&self, path: &str) -> anyhow::Result<String> {
        self.fs
            .read_link(path)
            .await
            .map_err(|err| anyhow::anyhow!("read ext4 symlink target {path}: {err}"))
    }

    async fn exists(&self, path: &str) -> anyhow::Result<bool> {
        self.fs
            .exists(path)
            .await
            .map_err(|err| anyhow::anyhow!("check ext4 path {path}: {err}"))
    }
}

#[cfg(target_arch = "wasm32")]
enum Stage0RootfsProvider {
    Erofs(ErofsRootfs),
    Ext4(Ext4Rootfs),
}

#[cfg(target_arch = "wasm32")]
impl Stage0RootfsProvider {
    async fn open(
        kind: Stage0RootfsKind,
        reader: Arc<dyn BlockReader>,
        size_bytes: u64,
    ) -> anyhow::Result<Self> {
        match kind {
            Stage0RootfsKind::Erofs => {
                let rootfs = ErofsRootfs::new(reader, size_bytes)
                    .await
                    .map_err(|err| anyhow::anyhow!("open erofs image: {err}"))?;
                Ok(Self::Erofs(rootfs))
            }
            Stage0RootfsKind::Ext4 => {
                let rootfs = Ext4Rootfs::open(reader).await?;
                Ok(Self::Ext4(rootfs))
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl Filesystem for Stage0RootfsProvider {
    type Error = anyhow::Error;

    async fn read_all(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_all(path).await,
            Self::Ext4(rootfs) => rootfs.read_all(path).await,
        }
    }

    async fn read_range(&self, path: &str, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_range(path, offset, len).await,
            Self::Ext4(rootfs) => rootfs.read_range(path, offset, len).await,
        }
    }

    async fn read_dir(&self, path: &str) -> anyhow::Result<Vec<String>> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_dir(path).await,
            Self::Ext4(rootfs) => rootfs.read_dir(path).await,
        }
    }

    async fn entry_type(&self, path: &str) -> anyhow::Result<Option<FilesystemEntryType>> {
        match self {
            Self::Erofs(rootfs) => rootfs.entry_type(path).await,
            Self::Ext4(rootfs) => rootfs.entry_type(path).await,
        }
    }

    async fn read_link(&self, path: &str) -> anyhow::Result<String> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_link(path).await,
            Self::Ext4(rootfs) => rootfs.read_link(path).await,
        }
    }

    async fn exists(&self, path: &str) -> anyhow::Result<bool> {
        match self {
            Self::Erofs(rootfs) => rootfs.exists(path).await,
            Self::Ext4(rootfs) => rootfs.exists(path).await,
        }
    }
}

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
            #[cfg(target_arch = "wasm32")]
            let mut stage0_opts = stage0_opts;
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
                    let gibblox_worker = spawn_gibblox_worker(channel.clone(), 0, None)
                        .await
                        .map_err(|err| anyhow::anyhow!("spawn gibblox worker failed: {err}"))?;
                    let sparse_hints = load_android_sparse_hints_for_boot_profile(
                        channel.as_str(),
                        &channel_intake,
                        boot_profile,
                    )
                    .await?;
                    let provider_reader = open_boot_profile_rootfs_reader(
                        boot_profile,
                        &sparse_hints,
                        Some(&gibblox_worker),
                    )
                    .await?;
                    let (kernel_override, dtb_override) = resolve_boot_profile_source_overrides_web(
                        boot_profile,
                        &profile,
                        &sparse_hints,
                        Some(&gibblox_worker),
                    )
                    .await?;
                    stage0_opts.kernel_override = kernel_override;
                    stage0_opts.dtb_override = dtb_override;
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
                let rootfs_kind = if using_boot_profile_rootfs {
                    let boot_profile = selected_boot_profile.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("selected boot profile is missing for web rootfs build")
                    })?;
                    rootfs_kind_for_web_boot(boot_profile)?
                } else {
                    Stage0RootfsKind::Erofs
                };
                let provider =
                    Stage0RootfsProvider::open(rootfs_kind, provider_reader.clone(), size_bytes)
                        .await?;
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

    let pipeline_source: PipelineSource = if is_casync_blob_index_url(&url) {
        serde_json::from_value(json!({
            "casync": {
                "index": url.to_string(),
                "chunk_store": chunk_store_url
                    .unwrap_or(derive_casync_chunk_store_url(&url)?)
                    .to_string(),
            }
        }))
        .map_err(|err| anyhow::anyhow!("build casync pipeline source: {err}"))?
    } else {
        serde_json::from_value(json!({
            "http": url.to_string(),
        }))
        .map_err(|err| anyhow::anyhow!("build HTTP pipeline source: {err}"))?
    };

    let pipeline_bytes = encode_pipeline(&pipeline_source)
        .map_err(|err| anyhow::anyhow!("encode channel pipeline source: {err}"))?;
    let open_options = OpenPipelineRequestOptions {
        image_block_size: None,
        cache_policy: Some(PipelineCachePolicy::None),
    };
    let opened = worker
        .open_pipeline_with_options(&pipeline_bytes, &open_options)
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
async fn open_artifact_source_via_worker(
    worker: &GibbloxWebWorker,
    source: &str,
    chunk_store_url: Option<&str>,
    cors_safelisted_mode: bool,
) -> anyhow::Result<Arc<dyn BlockReader>> {
    let source = source.trim();
    if source.is_empty() {
        anyhow::bail!("artifact source is empty");
    }

    let url = Url::parse(source)
        .map_err(|err| anyhow::anyhow!("parse artifact source URL {source}: {err}"))?;
    if is_casync_archive_index_url(&url) {
        anyhow::bail!(
            "casync archive indexes (.caidx) are not supported for artifact block reads; provide a casync blob index (.caibx)"
        );
    }

    let chunk_store_url = parse_optional_chunk_store_url(chunk_store_url)?;
    if !is_casync_blob_index_url(&url) && chunk_store_url.is_some() {
        anyhow::bail!(
            "artifact chunk store override is only supported with casync blob-index sources (.caibx)"
        );
    }

    let pipeline_source: PipelineSource = if is_casync_blob_index_url(&url) {
        serde_json::from_value(json!({
            "casync": {
                "index": url.to_string(),
                "chunk_store": chunk_store_url
                    .unwrap_or(derive_casync_chunk_store_url(&url)?)
                    .to_string(),
            }
        }))
        .map_err(|err| anyhow::anyhow!("build casync artifact pipeline source: {err}"))?
    } else {
        serde_json::from_value(json!({
            "http": url.to_string(),
            "cors_safelisted_mode": cors_safelisted_mode,
        }))
        .map_err(|err| anyhow::anyhow!("build HTTP artifact pipeline source: {err}"))?
    };

    let pipeline_bytes = encode_pipeline(&pipeline_source)
        .map_err(|err| anyhow::anyhow!("encode artifact pipeline source: {err}"))?;
    let open_options = OpenPipelineRequestOptions {
        image_block_size: None,
        cache_policy: Some(PipelineCachePolicy::Head),
    };
    let opened = worker
        .open_pipeline_with_options(&pipeline_bytes, &open_options)
        .await
        .map_err(|err| anyhow::anyhow!("open gibblox worker artifact pipeline: {err}"))?;
    Ok(Arc::new(opened.reader))
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
async fn load_android_sparse_hints_for_boot_profile(
    channel: &str,
    channel_intake: &SessionChannelIntake,
    boot_profile: &BootProfile,
) -> anyhow::Result<HashMap<String, AndroidSparseImageIndex>> {
    if channel_intake.pipeline_hint_records.is_empty() {
        return Ok(HashMap::new());
    }

    let required_identities = boot_profile_pipeline_identities(boot_profile);
    if required_identities.is_empty() {
        return Ok(HashMap::new());
    }

    let reader: Arc<dyn BlockReader> = if let Some(web_file) =
        crate::resolve_web_file_channel(channel)
    {
        open_web_file_channel_payload_reader(web_file, 0).await?
    } else {
        crate::channel_source::build_channel_reader_pipeline(channel, 0, None, None, false, false)
            .await
            .map_err(|err| anyhow::anyhow!("open channel reader for pipeline hints: {err}"))?
    };

    let stream_head = ChannelStreamHead {
        pipeline_hint_records: channel_intake.pipeline_hint_records.clone(),
        ..ChannelStreamHead::default()
    };
    let pipeline_hints = read_channel_pipeline_hints_for_identities(
        reader.as_ref(),
        &stream_head,
        &required_identities,
    )
    .await
    .map_err(|err| anyhow::anyhow!("read channel pipeline hints: {err}"))?;

    android_sparse_hints_by_identity(&pipeline_hints)
}

#[cfg(target_arch = "wasm32")]
fn android_sparse_hints_by_identity(
    pipeline_hints: &PipelineHints,
) -> anyhow::Result<HashMap<String, AndroidSparseImageIndex>> {
    validate_pipeline_hints(pipeline_hints)
        .map_err(|err| anyhow::anyhow!("validate pipeline hints: {err}"))?;

    let mut out = HashMap::new();
    for entry in &pipeline_hints.entries {
        for hint in &entry.hints {
            match hint {
                PipelineHint::AndroidSparseIndex(index) => {
                    out.insert(
                        entry.pipeline_identity.clone(),
                        AndroidSparseImageIndex {
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
                        },
                    );
                }
                PipelineHint::ContentDigest(_) => {}
            }
        }
    }

    Ok(out)
}

#[cfg(target_arch = "wasm32")]
async fn open_boot_profile_rootfs_reader(
    boot_profile: &BootProfile,
    sparse_hints: &HashMap<String, AndroidSparseImageIndex>,
    gibblox_worker: Option<&GibbloxWebWorker>,
) -> anyhow::Result<Arc<dyn BlockReader>> {
    open_boot_profile_artifact_source(boot_profile.rootfs.source(), sparse_hints, gibblox_worker)
        .await
}

#[cfg(target_arch = "wasm32")]
async fn resolve_boot_profile_source_overrides_web(
    boot_profile: &BootProfile,
    device_profile: &fastboop_core::DeviceProfile,
    sparse_hints: &HashMap<String, AndroidSparseImageIndex>,
    gibblox_worker: Option<&GibbloxWebWorker>,
) -> anyhow::Result<(Option<Stage0KernelOverride>, Option<Vec<u8>>)> {
    let kernel_override = if let Some(kernel_source) = boot_profile.kernel.as_ref() {
        let kernel_path = non_empty_profile_path(kernel_source.path.as_str(), "kernel.path")?;
        let source_reader = open_boot_profile_artifact_source(
            kernel_source.artifact_source(),
            sparse_hints,
            gibblox_worker,
        )
        .await?;
        let source_rootfs = ProfileSourceRootfs::open(&kernel_source.source, source_reader).await?;
        let kernel_image = source_rootfs.read_all(kernel_path).await?;
        Some(Stage0KernelOverride {
            path: kernel_path.to_string(),
            image: kernel_image,
        })
    } else {
        None
    };

    let dtb_override = if let Some(dtbs_source) = boot_profile.dtbs.as_ref() {
        let dtbs_base = non_empty_profile_path(dtbs_source.path.as_str(), "dtbs.path")?;
        let source_reader = open_boot_profile_artifact_source(
            dtbs_source.artifact_source(),
            sparse_hints,
            gibblox_worker,
        )
        .await?;
        let source_rootfs = ProfileSourceRootfs::open(&dtbs_source.source, source_reader).await?;
        let dtb_path = resolve_dtb_path_candidate_web(
            &source_rootfs,
            dtbs_base,
            device_profile.devicetree_name.as_str(),
        )
        .await?;
        Some(source_rootfs.read_all(dtb_path.as_str()).await?)
    } else {
        None
    };

    Ok((kernel_override, dtb_override))
}

#[cfg(target_arch = "wasm32")]
enum ProfileSourceRootfs {
    Erofs(ErofsRootfs),
    Ext4(Ext4Rootfs),
    Fat(FatFs),
}

#[cfg(target_arch = "wasm32")]
impl ProfileSourceRootfs {
    async fn open(
        source: &BootProfileRootfs,
        reader: Arc<dyn BlockReader>,
    ) -> anyhow::Result<Self> {
        match source {
            BootProfileRootfs::Ostree(source) => match &source.ostree {
                BootProfileRootfsFilesystemSource::Erofs(_) => {
                    let total_blocks = reader.total_blocks().await?;
                    let image_size_bytes = total_blocks
                        .checked_mul(reader.block_size() as u64)
                        .ok_or_else(|| {
                            anyhow::anyhow!("boot profile source image size overflow")
                        })?;
                    let rootfs = ErofsRootfs::new(reader, image_size_bytes)
                        .await
                        .map_err(|err| anyhow::anyhow!("open boot profile erofs source: {err}"))?;
                    Ok(Self::Erofs(rootfs))
                }
                BootProfileRootfsFilesystemSource::Ext4(_) => {
                    let rootfs = Ext4Rootfs::open(reader).await?;
                    Ok(Self::Ext4(rootfs))
                }
                BootProfileRootfsFilesystemSource::Fat(_) => {
                    let rootfs = FatFs::open(reader)
                        .await
                        .map_err(|err| anyhow::anyhow!("open boot profile fat source: {err}"))?;
                    Ok(Self::Fat(rootfs))
                }
            },
            BootProfileRootfs::Erofs(_) => {
                let total_blocks = reader.total_blocks().await?;
                let image_size_bytes = total_blocks
                    .checked_mul(reader.block_size() as u64)
                    .ok_or_else(|| anyhow::anyhow!("boot profile source image size overflow"))?;
                let rootfs = ErofsRootfs::new(reader, image_size_bytes)
                    .await
                    .map_err(|err| anyhow::anyhow!("open boot profile erofs source: {err}"))?;
                Ok(Self::Erofs(rootfs))
            }
            BootProfileRootfs::Ext4(_) => {
                let rootfs = Ext4Rootfs::open(reader).await?;
                Ok(Self::Ext4(rootfs))
            }
            BootProfileRootfs::Fat(_) => {
                let rootfs = FatFs::open(reader)
                    .await
                    .map_err(|err| anyhow::anyhow!("open boot profile fat source: {err}"))?;
                Ok(Self::Fat(rootfs))
            }
        }
    }

    async fn read_all(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Erofs(rootfs) => rootfs
                .read_all(path)
                .await
                .map_err(|err| anyhow::anyhow!("read boot profile erofs path {path}: {err}")),
            Self::Ext4(rootfs) => rootfs
                .read_all(path)
                .await
                .map_err(|err| anyhow::anyhow!("read boot profile ext4 path {path}: {err}")),
            Self::Fat(rootfs) => rootfs
                .read_all(path)
                .await
                .map_err(|err| anyhow::anyhow!("read boot profile fat path {path}: {err}")),
        }
    }

    async fn exists(&self, path: &str) -> anyhow::Result<bool> {
        match self {
            Self::Erofs(rootfs) => rootfs
                .exists(path)
                .await
                .map_err(|err| anyhow::anyhow!("check boot profile erofs path {path}: {err}")),
            Self::Ext4(rootfs) => rootfs
                .exists(path)
                .await
                .map_err(|err| anyhow::anyhow!("check boot profile ext4 path {path}: {err}")),
            Self::Fat(rootfs) => rootfs
                .exists(path)
                .await
                .map_err(|err| anyhow::anyhow!("check boot profile fat path {path}: {err}")),
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn non_empty_profile_path<'a>(path: &'a str, field: &str) -> anyhow::Result<&'a str> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        anyhow::bail!("boot profile {field} must not be empty");
    }
    Ok(trimmed)
}

#[cfg(target_arch = "wasm32")]
async fn resolve_dtb_path_candidate_web(
    source_rootfs: &ProfileSourceRootfs,
    dtbs_base: &str,
    devicetree_name: &str,
) -> anyhow::Result<String> {
    let devicetree_name = devicetree_name.trim().trim_start_matches('/');
    if devicetree_name.is_empty() {
        anyhow::bail!("device profile devicetree_name is empty");
    }

    let mut candidates = Vec::new();
    if dtbs_base.ends_with(".dtb") {
        candidates.push(dtbs_base.to_string());
    } else {
        let dtb_file = format!("{devicetree_name}.dtb");
        candidates.push(join_profile_path(dtbs_base, dtb_file.as_str()));
        candidates.push(join_profile_path(dtbs_base, devicetree_name));
        candidates.push(dtbs_base.to_string());
    }

    for candidate in candidates {
        if source_rootfs.exists(candidate.as_str()).await? {
            return Ok(candidate);
        }
    }

    anyhow::bail!("boot profile dtbs path {dtbs_base} does not contain dtb for {devicetree_name}")
}

#[cfg(target_arch = "wasm32")]
fn join_profile_path(base: &str, suffix: &str) -> String {
    let base = base.trim_end_matches('/');
    let suffix = suffix.trim_start_matches('/');
    if base.is_empty() {
        format!("/{suffix}")
    } else {
        format!("{base}/{suffix}")
    }
}

#[cfg(target_arch = "wasm32")]
fn open_boot_profile_artifact_source<'a>(
    source: &'a BootProfileArtifactSource,
    sparse_hints: &'a HashMap<String, AndroidSparseImageIndex>,
    gibblox_worker: Option<&'a GibbloxWebWorker>,
) -> Pin<Box<dyn Future<Output = anyhow::Result<Arc<dyn BlockReader>>> + 'a>> {
    Box::pin(async move {
        match source {
            BootProfileArtifactSource::Http(source) => {
                let channel = source.http.trim();
                if channel.is_empty() {
                    anyhow::bail!("boot profile rootfs.http source is empty");
                }
                if let Some(gibblox_worker) = gibblox_worker {
                    return open_artifact_source_via_worker(
                        gibblox_worker,
                        channel,
                        None,
                        source.cors_safelisted_mode,
                    )
                    .await
                    .map_err(|err| anyhow::anyhow!("open HTTP artifact source {channel}: {err}"));
                }
                crate::channel_source::build_channel_reader_pipeline(
                    channel,
                    0,
                    None,
                    source.content.as_ref().map(|content| content.size_bytes),
                    source.cors_safelisted_mode,
                    true,
                )
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
                if let Some(gibblox_worker) = gibblox_worker {
                    return open_artifact_source_via_worker(
                        gibblox_worker,
                        index,
                        chunk_store,
                        false,
                    )
                    .await
                    .map_err(|err| anyhow::anyhow!("open casync artifact source {index}: {err}"));
                }
                crate::channel_source::build_channel_reader_pipeline(
                    index,
                    0,
                    chunk_store,
                    source
                        .casync
                        .content
                        .as_ref()
                        .map(|content| content.size_bytes),
                    false,
                    true,
                )
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
                let upstream = open_boot_profile_artifact_source(
                    source.xz.as_ref(),
                    sparse_hints,
                    gibblox_worker,
                )
                .await?;
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
                let upstream = open_boot_profile_artifact_source(
                    source.android_sparseimg.source.as_ref(),
                    sparse_hints,
                    gibblox_worker,
                )
                .await?;
                let identity = pipeline_identity_string(
                    &BootProfileArtifactSource::AndroidSparseImg(source.clone()),
                );
                let sidecar_index = sparse_hints.get(&identity);
                let reader = if let Some(index) = sidecar_index {
                    AndroidSparseBlockReader::new_with_index(upstream, index.clone())
                        .await
                        .map_err(|err| {
                            anyhow::anyhow!("open android sparse reader from sidecar index: {err}")
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

                let upstream = open_boot_profile_artifact_source(
                    source.mbr.source.as_ref(),
                    sparse_hints,
                    gibblox_worker,
                )
                .await?;
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

                let upstream = open_boot_profile_artifact_source(
                    source.gpt.source.as_ref(),
                    sparse_hints,
                    gibblox_worker,
                )
                .await?;
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
fn rootfs_kind_for_web_boot(boot_profile: &BootProfile) -> anyhow::Result<Stage0RootfsKind> {
    match &boot_profile.rootfs {
        BootProfileRootfs::Erofs(_) => Ok(Stage0RootfsKind::Erofs),
        BootProfileRootfs::Ext4(_) => Ok(Stage0RootfsKind::Ext4),
        BootProfileRootfs::Fat(_) => {
            anyhow::bail!("web stage0 build does not support FAT rootfs providers")
        }
        BootProfileRootfs::Ostree(source) => match &source.ostree {
            BootProfileRootfsFilesystemSource::Erofs(_) => Ok(Stage0RootfsKind::Erofs),
            BootProfileRootfsFilesystemSource::Ext4(_) => Ok(Stage0RootfsKind::Ext4),
            BootProfileRootfsFilesystemSource::Fat(_) => {
                anyhow::bail!("web stage0 build does not support OSTree on FAT rootfs")
            }
        },
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
