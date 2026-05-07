use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use dioxus::prelude::ReadableExt;
use fastboop_core::device::DeviceHandle as _;
use fastboop_core::fastboot::{boot, download};
use fastboop_core::Personalization;
use fastboop_core::{
    bootimg::build_android_bootimg, read_channel_pipeline_hints_for_boot_profile,
    resolve_effective_boot_profile_stage0, BootProfile, BootProfileArtifactSource,
    BootProfileRootfs, BootProfileRootfsFilesystemSource, ChannelStreamHead,
};
use fastboop_stage0_generator::{
    build_stage0, stage0_binary_ready, Stage0KernelOverride, Stage0Options, Stage0SwitchrootFs,
};
use gibblox_core::{
    block_identity_string, AlignedByteReader, BlockReader, GibbloxError, GibbloxErrorKind,
    GibbloxResult, ReadContext,
};
use gibblox_ext4::{Ext4EntryType, Ext4Fs};
use gibblox_pipeline::{open_pipeline, OpenPipelineOptions, PipelineHints};
use gibblox_zip::ZipEntryBlockReader;
use gobblytes_core::{Filesystem, FilesystemEntryType};
use gobblytes_erofs::{ErofsRootfs, DEFAULT_IMAGE_BLOCK_SIZE};
use gobblytes_fat::FatFs;
use smoo_host_blocksource_gibblox::GibbloxBlockSource;
use smoo_host_core::{
    register_export, BlockSource, BlockSourceHandle, CountingTransport, TransportCounterSnapshot,
};
use smoo_host_session::{
    drive_host_session, HostSession, HostSessionConfig, HostSessionDriveConfig,
    HostSessionDriveEvent, HostSessionDriveOutcome,
};
use smoo_host_transport_rusb::RusbTransport;
use tokio::sync::oneshot;
use tracing::{error, info, warn};
use ui::{
    apply_transport_counters, oneplus_fajita_dtbo_overlays, SmooStatsHandle, SmooTransportCounters,
};

use super::session::{
    update_session_phase, BootConfig, BootRuntime, DeviceSession, SessionChannelIntake,
    SessionPhase, SessionStore,
};

const SMOO_INTERFACE_CLASS: u8 = 0xFF;
const SMOO_INTERFACE_SUBCLASS: u8 = 0x53;
const SMOO_INTERFACE_PROTOCOL: u8 = 0x4D;
const FASTBOOT_INTERFACE_SUBCLASS: u8 = 0x42;
const FASTBOOT_INTERFACE_PROTOCOL: u8 = 0x03;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(1);
const DISCOVERY_RETRY: Duration = Duration::from_millis(500);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const STATUS_RETRY_ATTEMPTS: usize = 5;
const SMOO_MAX_IO_BYTES_KARG: &str = "smoo.max_io_bytes=1048576";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootfsKind {
    Erofs,
    Ext4,
    Fat,
}

#[derive(Clone)]
struct Ext4Rootfs {
    fs: Ext4Fs,
}

impl Ext4Rootfs {
    async fn open(reader: Arc<dyn BlockReader>) -> Result<Self> {
        let fs = Ext4Fs::open(reader)
            .await
            .map_err(|err| anyhow!("open ext4 rootfs: {err}"))?;
        Ok(Self { fs })
    }
}

impl Filesystem for Ext4Rootfs {
    type Error = anyhow::Error;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        self.fs
            .read_all(path)
            .await
            .map_err(|err| anyhow!("read ext4 path {path}: {err}"))
    }

    async fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.fs
            .read_range(path, offset, len)
            .await
            .map_err(|err| anyhow!("read ext4 path range {path}@{offset}+{len}: {err}"))
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>> {
        self.fs
            .read_dir(path)
            .await
            .map_err(|err| anyhow!("read ext4 directory {path}: {err}"))
    }

    async fn entry_type(&self, path: &str) -> Result<Option<FilesystemEntryType>> {
        let ty = self
            .fs
            .entry_type(path)
            .await
            .map_err(|err| anyhow!("read ext4 entry type {path}: {err}"))?;
        Ok(ty.map(|entry| match entry {
            Ext4EntryType::File => FilesystemEntryType::File,
            Ext4EntryType::Directory => FilesystemEntryType::Directory,
            Ext4EntryType::Symlink => FilesystemEntryType::Symlink,
            Ext4EntryType::Other => FilesystemEntryType::Other,
        }))
    }

    async fn read_link(&self, path: &str) -> Result<String> {
        self.fs
            .read_link(path)
            .await
            .map_err(|err| anyhow!("read ext4 symlink target {path}: {err}"))
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        self.fs
            .exists(path)
            .await
            .map_err(|err| anyhow!("check ext4 path {path}: {err}"))
    }
}

enum RootfsProvider {
    Erofs(ErofsRootfs),
    Ext4(Ext4Rootfs),
    Fat(FatFs),
}

impl RootfsProvider {
    async fn open(kind: RootfsKind, reader: Arc<dyn BlockReader>, size_bytes: u64) -> Result<Self> {
        match kind {
            RootfsKind::Erofs => {
                let rootfs = ErofsRootfs::new(reader, size_bytes)
                    .await
                    .map_err(|err| anyhow!("open erofs rootfs: {err}"))?;
                Ok(Self::Erofs(rootfs))
            }
            RootfsKind::Ext4 => {
                let rootfs = Ext4Rootfs::open(reader).await?;
                Ok(Self::Ext4(rootfs))
            }
            RootfsKind::Fat => {
                let rootfs = FatFs::open(reader)
                    .await
                    .map_err(|err| anyhow!("open fat rootfs: {err}"))?;
                Ok(Self::Fat(rootfs))
            }
        }
    }

    fn switchroot_fs(&self) -> Option<Stage0SwitchrootFs> {
        match self {
            Self::Erofs(_) => Some(Stage0SwitchrootFs::Erofs),
            Self::Ext4(_) => Some(Stage0SwitchrootFs::Ext4),
            Self::Fat(_) => None,
        }
    }
}

impl Filesystem for RootfsProvider {
    type Error = anyhow::Error;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_all(path).await,
            Self::Ext4(rootfs) => rootfs.read_all(path).await,
            Self::Fat(rootfs) => rootfs
                .read_all(path)
                .await
                .map_err(|err| anyhow!("read fat path {path}: {err}")),
        }
    }

    async fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_range(path, offset, len).await,
            Self::Ext4(rootfs) => rootfs.read_range(path, offset, len).await,
            Self::Fat(rootfs) => rootfs
                .read_range(path, offset, len)
                .await
                .map_err(|err| anyhow!("read fat path range {path}@{offset}+{len}: {err}")),
        }
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_dir(path).await,
            Self::Ext4(rootfs) => rootfs.read_dir(path).await,
            Self::Fat(rootfs) => rootfs
                .read_dir(path)
                .await
                .map_err(|err| anyhow!("read fat directory {path}: {err}")),
        }
    }

    async fn entry_type(&self, path: &str) -> Result<Option<FilesystemEntryType>> {
        match self {
            Self::Erofs(rootfs) => rootfs.entry_type(path).await,
            Self::Ext4(rootfs) => rootfs.entry_type(path).await,
            Self::Fat(rootfs) => <FatFs as Filesystem>::entry_type(rootfs, path)
                .await
                .map_err(|err| anyhow!("read fat entry type {path}: {err}")),
        }
    }

    async fn read_link(&self, path: &str) -> Result<String> {
        match self {
            Self::Erofs(rootfs) => rootfs.read_link(path).await,
            Self::Ext4(rootfs) => rootfs.read_link(path).await,
            Self::Fat(rootfs) => rootfs
                .read_link(path)
                .await
                .map_err(|err| anyhow!("read fat symlink target {path}: {err}")),
        }
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        match self {
            Self::Erofs(rootfs) => rootfs.exists(path).await,
            Self::Ext4(rootfs) => rootfs.exists(path).await,
            Self::Fat(rootfs) => rootfs
                .exists(path)
                .await
                .map_err(|err| anyhow!("check fat path {path}: {err}")),
        }
    }
}

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
    let mut boot_config = session.boot_config.clone();

    let selected_boot_profile = select_boot_profile_for_session(&session)?;
    let profile_stage0 = selected_boot_profile
        .as_ref()
        .map(|boot_profile| {
            resolve_effective_boot_profile_stage0(boot_profile, session.device.profile.id.as_str())
        })
        .unwrap_or_default();

    let channel = boot_config.channel.trim();
    if channel.is_empty() {
        return Err(anyhow!("channel is empty"));
    }

    if session.channel_intake.warning_count > 0 {
        info!(
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

    let mut kernel_modules = vec!["erofs".to_string()];
    kernel_modules.extend(profile_stage0.kernel_modules);

    boot_config.extra_kargs = join_cmdline(
        profile_stage0.extra_cmdline.as_deref(),
        nonempty(boot_config.extra_kargs.as_str()),
    );

    let stage0_opts = Stage0Options {
        switchroot_fs: Stage0SwitchrootFs::Erofs,
        kernel_modules,
        inject_mac: profile_stage0.inject_mac,
        kernel_override: None,
        dtb_override: None,
        dtbo_overlays,
        enable_serial: boot_config.enable_serial,
        mimic_fastboot: true,
        smoo_vendor: Some(session.device.vid),
        smoo_product: Some(session.device.pid),
        stage0_serial: session.device.serial.clone(),
        personalization: Some(personalization_from_host()),
    };
    let (build, runtime) = build_stage0_artifacts(
        session.device.profile.clone(),
        stage0_opts,
        boot_config,
        session.channel_intake.clone(),
        selected_boot_profile,
    )
    .await
    .context("open channel and build stage0")?;

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
    let profile = session.device.profile.clone();
    if profile
        .boot
        .fastboot_boot
        .android_bootimg
        .kernel
        .encoding
        .append_dtb()
    {
        kernel_image.extend_from_slice(&build.dtb);
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
    boot_config: BootConfig,
    channel_intake: SessionChannelIntake,
    selected_boot_profile: Option<BootProfile>,
) -> Result<(fastboop_stage0_generator::Stage0Build, BootRuntime)> {
    let channel = boot_config.channel.trim().to_string();
    if channel.is_empty() {
        return Err(anyhow!("channel is empty"));
    }
    let extra_kargs = join_cmdline(
        nonempty(boot_config.extra_kargs.as_str()),
        Some(SMOO_MAX_IO_BYTES_KARG),
    );
    let stage0_binary = crate::stage0_binary::load_stage0_binary().context("load stage0 binary")?;

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
                    let mut stage0_opts = stage0_opts;
                    info!(profile = %profile.id, channel = %channel, "opening channel for desktop boot");
                    let pipeline_hints = if let Some(boot_profile) = selected_boot_profile.as_ref() {
                        load_pipeline_hints_for_boot_profile(
                            channel.as_str(),
                            &channel_intake,
                            boot_profile,
                        )
                        .await?
                    } else {
                        PipelineHints::default()
                    };
                    let (provider_reader, provider_size_bytes, rootfs_kind) = if channel_intake
                        .has_artifact_payload
                    {
                        let opened = crate::open_desktop_channel(&channel)
                            .await
                            .map_err(|err| anyhow!("open channel {}: {}", channel, err.details))?;
                        let reader = opened.reader;
                        let exact_size_bytes = opened.exact_total_bytes;

                        if exact_size_bytes != channel_intake.exact_total_bytes {
                            warn!(
                                expected = channel_intake.exact_total_bytes,
                                observed = exact_size_bytes,
                                channel,
                                "channel size changed since startup intake"
                            );
                        }

                        let (provider_reader, provider_size_bytes) = if let Some(entry_name) =
                            zip_entry_name_from_channel_location(&opened.location)?
                        {
                            let source_reader: Arc<dyn BlockReader> =
                                if channel_intake.consumed_bytes == 0 {
                                    reader.clone()
                                } else {
                                    Arc::new(OffsetChannelBlockReader::new(
                                        reader.clone(),
                                        channel_intake.consumed_bytes,
                                        exact_size_bytes,
                                    )?)
                                };
                            let zip_reader = ZipEntryBlockReader::new(&entry_name, source_reader)
                                .await
                                .map_err(|err| anyhow!("open ZIP entry {entry_name}: {err}"))?;
                            let zip_reader = Arc::new(zip_reader);
                            let zip_size_bytes = reader_size_bytes(zip_reader.as_ref()).await?;
                            (zip_reader as Arc<dyn BlockReader>, zip_size_bytes)
                        } else {
                            offset_tail_reader(
                                reader.clone(),
                                channel_intake.consumed_bytes,
                                exact_size_bytes,
                            )
                            .map_err(|err| anyhow!("channel stream requires trailing artifact: {err}"))?
                        };
                        let rootfs_kind = detect_stage0_rootfs_kind(provider_reader.as_ref()).await?;
                        (provider_reader, provider_size_bytes, rootfs_kind)
                    } else {
                        let boot_profile = selected_boot_profile.as_ref().ok_or_else(|| {
                            anyhow!(
                                "channel has no trailing artifact payload and no compatible boot profile selected"
                            )
                        })?;
                        let (reader, size_bytes) =
                            open_boot_profile_rootfs_reader(boot_profile, &pipeline_hints).await?;
                        let rootfs_kind = rootfs_kind_for_boot_profile(boot_profile)?;
                        (reader, size_bytes, rootfs_kind)
                    };

                    if let Some(boot_profile) = selected_boot_profile.as_ref() {
                        let (kernel_override, dtb_override) = resolve_boot_profile_source_overrides(
                            boot_profile,
                            &profile,
                            &pipeline_hints,
                        )
                        .await?;
                        stage0_opts.kernel_override = kernel_override;
                        stage0_opts.dtb_override = dtb_override;
                    }

                    let provider =
                        RootfsProvider::open(rootfs_kind, provider_reader.clone(), provider_size_bytes)
                            .await?;
                    stage0_opts.switchroot_fs = provider.switchroot_fs().ok_or_else(|| {
                        anyhow!("rootfs image is not a bootable stage0 filesystem (erofs/ext4)")
                    })?;
                    info!(profile = %profile.id, "building stage0 payload");
                    let build = build_stage0(
                        &profile,
                        &provider,
                        &stage0_opts,
                        stage0_binary_ready(Some(stage0_binary)),
                        nonempty(&extra_kargs),
                        None,
                    )
                    .await
                    .map_err(|err| anyhow!("stage0 build failed: {err:?}"))?;
                    let provider_identity = block_identity_string(provider_reader.as_ref());
                    Ok((
                        build,
                        BootRuntime {
                            reader: provider_reader,
                            size_bytes: provider_size_bytes,
                            identity: provider_identity,
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

fn select_boot_profile_for_session(session: &DeviceSession) -> Result<Option<BootProfile>> {
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
                anyhow!(
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
    bail!(
        "multiple compatible boot profiles available for '{}'; choose one: {}",
        session.device.profile.id,
        available.join(", ")
    )
}

async fn open_boot_profile_rootfs_reader(
    boot_profile: &BootProfile,
    pipeline_hints: &PipelineHints,
) -> Result<(Arc<dyn BlockReader>, u64)> {
    let source = boot_profile.rootfs.source();
    let reader = open_boot_profile_artifact_source(source, pipeline_hints)
        .await
        .map_err(|err| {
            anyhow!(
                "open boot profile '{}' rootfs source: {err}",
                boot_profile.id
            )
        })?;
    let size_bytes = reader_size_bytes(reader.as_ref()).await?;
    Ok((reader, size_bytes))
}

async fn load_pipeline_hints_for_boot_profile(
    channel: &str,
    channel_intake: &SessionChannelIntake,
    boot_profile: &BootProfile,
) -> Result<PipelineHints> {
    if channel_intake.pipeline_hint_records.is_empty() {
        return Ok(channel_intake.pipeline_hints.clone());
    }

    let opened = crate::open_desktop_channel(channel).await.map_err(|err| {
        anyhow!(
            "open channel for pipeline hints {}: {}",
            channel,
            err.details
        )
    })?;
    let stream_head = ChannelStreamHead {
        pipeline_hints: channel_intake.pipeline_hints.clone(),
        pipeline_hint_records: channel_intake.pipeline_hint_records.clone(),
        ..ChannelStreamHead::default()
    };
    read_channel_pipeline_hints_for_boot_profile(opened.reader.as_ref(), &stream_head, boot_profile)
        .await
        .map_err(|err| anyhow!("read channel pipeline hints: {err}"))
}

async fn resolve_boot_profile_source_overrides(
    boot_profile: &BootProfile,
    device_profile: &fastboop_core::DeviceProfile,
    pipeline_hints: &PipelineHints,
) -> Result<(Option<Stage0KernelOverride>, Option<Vec<u8>>)> {
    let kernel_override = if let Some(kernel_source) = boot_profile.kernel.as_ref() {
        let kernel_path = non_empty_profile_path(kernel_source.path.as_str(), "kernel.path")?;
        let source_reader =
            open_boot_profile_artifact_source(kernel_source.artifact_source(), pipeline_hints)
                .await?;
        let source_rootfs =
            open_profile_source_rootfs(&kernel_source.source, source_reader).await?;
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
        let source_reader =
            open_boot_profile_artifact_source(dtbs_source.artifact_source(), pipeline_hints)
                .await?;
        let source_rootfs = open_profile_source_rootfs(&dtbs_source.source, source_reader).await?;
        let dtb_path = resolve_dtb_path_candidate(
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

async fn open_profile_source_rootfs(
    source: &BootProfileRootfs,
    reader: Arc<dyn BlockReader>,
) -> Result<RootfsProvider> {
    let kind = rootfs_kind_for_profile_source(source);
    let image_size_bytes = reader_size_bytes(reader.as_ref()).await?;
    RootfsProvider::open(kind, reader, image_size_bytes).await
}

fn non_empty_profile_path<'a>(path: &'a str, field: &str) -> Result<&'a str> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        bail!("boot profile {field} must not be empty");
    }
    Ok(trimmed)
}

async fn resolve_dtb_path_candidate(
    source_rootfs: &RootfsProvider,
    dtbs_base: &str,
    devicetree_name: &str,
) -> Result<String> {
    let devicetree_name = devicetree_name.trim().trim_start_matches('/');
    if devicetree_name.is_empty() {
        bail!("device profile devicetree_name is empty");
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

    bail!("boot profile dtbs path {dtbs_base} does not contain dtb for {devicetree_name}")
}

fn join_profile_path(base: &str, suffix: &str) -> String {
    let base = base.trim_end_matches('/');
    let suffix = suffix.trim_start_matches('/');
    if base.is_empty() {
        format!("/{suffix}")
    } else {
        format!("{base}/{suffix}")
    }
}

async fn open_boot_profile_artifact_source(
    source: &BootProfileArtifactSource,
    pipeline_hints: &PipelineHints,
) -> Result<Arc<dyn BlockReader>> {
    let opts = OpenPipelineOptions {
        image_block_size: DEFAULT_IMAGE_BLOCK_SIZE,
        pipeline_hints: Some(pipeline_hints.clone()),
        ..OpenPipelineOptions::default()
    };
    let reader = open_pipeline(source, &opts)
        .await
        .map_err(|err| anyhow!("open boot profile artifact source: {err}"))?;
    maybe_zip_entry_reader(reader, zip_entry_name_from_artifact_source(source)?).await
}

fn rootfs_kind_for_boot_profile(boot_profile: &BootProfile) -> Result<RootfsKind> {
    let kind = rootfs_kind_for_profile_source(&boot_profile.rootfs);
    if kind == RootfsKind::Fat {
        bail!("desktop stage0 build does not support FAT rootfs providers");
    }
    Ok(kind)
}

fn rootfs_kind_for_profile_source(source: &BootProfileRootfs) -> RootfsKind {
    match source {
        BootProfileRootfs::Erofs(_) => RootfsKind::Erofs,
        BootProfileRootfs::Ext4(_) => RootfsKind::Ext4,
        BootProfileRootfs::Fat(_) => RootfsKind::Fat,
        BootProfileRootfs::Ostree(source) => match &source.ostree {
            BootProfileRootfsFilesystemSource::Erofs(_) => RootfsKind::Erofs,
            BootProfileRootfsFilesystemSource::Ext4(_) => RootfsKind::Ext4,
            BootProfileRootfsFilesystemSource::Fat(_) => RootfsKind::Fat,
        },
    }
}

async fn detect_stage0_rootfs_kind<R: BlockReader + ?Sized>(reader: &R) -> Result<RootfsKind> {
    if reader_has_erofs_magic(reader).await? {
        return Ok(RootfsKind::Erofs);
    }
    if reader_has_ext4_magic(reader).await? {
        return Ok(RootfsKind::Ext4);
    }
    bail!("rootfs image is not a supported stage0 switchroot filesystem (erofs/ext4)")
}

async fn reader_has_erofs_magic<R: BlockReader + ?Sized>(reader: &R) -> Result<bool> {
    const EROFS_SUPER_OFFSET: u64 = 1024;
    const EROFS_SUPER_MAGIC: u32 = 0xe0f5_e1e2;

    let Some(bytes) = read_magic_bytes(reader, EROFS_SUPER_OFFSET, 4).await? else {
        return Ok(false);
    };
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    Ok(magic == EROFS_SUPER_MAGIC)
}

async fn reader_has_ext4_magic<R: BlockReader + ?Sized>(reader: &R) -> Result<bool> {
    const EXT4_MAGIC_OFFSET: u64 = 1024 + 0x38;
    const EXT4_MAGIC: u16 = 0xef53;

    let Some(bytes) = read_magic_bytes(reader, EXT4_MAGIC_OFFSET, 2).await? else {
        return Ok(false);
    };
    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    Ok(magic == EXT4_MAGIC)
}

async fn read_magic_bytes<R: BlockReader + ?Sized>(
    reader: &R,
    offset: u64,
    len: usize,
) -> Result<Option<Vec<u8>>> {
    if len == 0 {
        return Ok(Some(Vec::new()));
    }

    let block_size = reader.block_size() as u64;
    if block_size == 0 {
        bail!("channel reader block size is zero");
    }
    let total_blocks = reader.total_blocks().await?;
    let total_bytes = total_blocks
        .checked_mul(block_size)
        .ok_or_else(|| anyhow!("channel blob size overflow"))?;
    let required_end = offset
        .checked_add(len as u64)
        .ok_or_else(|| anyhow!("channel magic offset overflow"))?;
    if total_bytes < required_end {
        return Ok(None);
    }

    let super_lba = offset / block_size;
    let within_block = (offset % block_size) as usize;
    let block_size_usize = block_size as usize;
    let required = within_block + len;
    let blocks_to_read = required.div_ceil(block_size_usize);
    let mut scratch = vec![0u8; blocks_to_read * block_size_usize];
    let read = reader
        .read_blocks(super_lba, &mut scratch, ReadContext::FOREGROUND)
        .await?;
    if read < required {
        return Ok(None);
    }

    Ok(Some(scratch[within_block..within_block + len].to_vec()))
}

async fn maybe_zip_entry_reader(
    reader: Arc<dyn BlockReader>,
    entry_name: Option<String>,
) -> Result<Arc<dyn BlockReader>> {
    let Some(entry_name) = entry_name else {
        return Ok(reader);
    };

    let zip_reader = ZipEntryBlockReader::new(&entry_name, reader.clone())
        .await
        .map_err(|err| anyhow!("open ZIP entry {entry_name}: {err}"))?;
    Ok(Arc::new(zip_reader))
}

fn offset_tail_reader(
    reader: Arc<dyn BlockReader>,
    consumed_bytes: u64,
    total_size_bytes: u64,
) -> Result<(Arc<dyn BlockReader>, u64)> {
    if consumed_bytes == 0 {
        return Ok((reader, total_size_bytes));
    }

    if consumed_bytes >= total_size_bytes {
        bail!(
            "channel stream has only profile records and no trailing artifact payload; desktop boot requires an artifact stream"
        );
    }

    Ok((
        Arc::new(OffsetChannelBlockReader::new(
            reader.clone(),
            consumed_bytes,
            total_size_bytes,
        )?),
        total_size_bytes
            .checked_sub(consumed_bytes)
            .ok_or_else(|| anyhow!("channel consumed byte offset overflow"))?,
    ))
}

struct OffsetChannelBlockReader {
    inner: Arc<dyn BlockReader>,
    offset_bytes: u64,
    size_bytes: u64,
    block_size: u32,
}

impl OffsetChannelBlockReader {
    fn new(inner: Arc<dyn BlockReader>, offset_bytes: u64, inner_size_bytes: u64) -> Result<Self> {
        if offset_bytes > inner_size_bytes {
            bail!(
                "offset {offset_bytes} exceeds source size {inner_size_bytes} while truncating channel stream"
            );
        }

        let block_size = inner.block_size();
        if block_size == 0 {
            bail!("block size must be non-zero");
        }

        Ok(Self {
            inner,
            offset_bytes,
            size_bytes: inner_size_bytes
                .checked_sub(offset_bytes)
                .ok_or_else(|| anyhow!("channel consumed byte offset underflow"))?,
            block_size,
        })
    }
}

#[async_trait::async_trait]
impl gibblox_core::BlockReader for OffsetChannelBlockReader {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> GibbloxResult<u64> {
        let block_size = u64::from(self.block_size);
        if block_size == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "block size must be non-zero",
            ));
        }
        Ok(self.size_bytes.div_ceil(block_size))
    }

    fn write_identity(&self, out: &mut dyn core::fmt::Write) -> std::fmt::Result {
        let mut identity = String::new();
        self.inner.write_identity(&mut identity)?;
        write!(out, "{}|offset:{}", identity, self.offset_bytes)
    }

    async fn read_blocks(
        &self,
        lba: u64,
        buf: &mut [u8],
        ctx: ReadContext,
    ) -> GibbloxResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let local_offset = lba.checked_mul(u64::from(self.block_size)).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "offset overflow")
        })?;
        if local_offset >= self.size_bytes {
            return Ok(0);
        }

        let remaining = self.size_bytes.checked_sub(local_offset).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "read offset underflow")
        })?;
        let max_read = core::cmp::min(buf.len() as u64, remaining) as usize;
        let global_offset = self.offset_bytes.checked_add(local_offset).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "global read offset overflow")
        })?;

        let byte_reader = AlignedByteReader::new(self.inner.clone()).await?;
        byte_reader
            .read_exact_at(global_offset, &mut buf[..max_read], ctx)
            .await?;
        Ok(max_read)
    }
}

fn zip_entry_name_from_channel_location(
    location: &crate::DesktopChannelLocation,
) -> Result<Option<String>> {
    let file_name = location.file_name();
    zip_entry_name_from_file_name(file_name.as_deref())
}

fn zip_entry_name_from_artifact_source(
    source: &BootProfileArtifactSource,
) -> Result<Option<String>> {
    let file_name = match source {
        BootProfileArtifactSource::Http(source) => {
            let url = url::Url::parse(source.http.trim()).map_err(|err| {
                anyhow!(
                    "parse boot profile rootfs HTTP source {}: {err}",
                    source.http
                )
            })?;
            url.path_segments()
                .and_then(|segments| segments.filter(|segment| !segment.is_empty()).next_back())
                .map(str::to_string)
        }
        BootProfileArtifactSource::File(source) => Path::new(source.file.as_str())
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string),
        _ => None,
    };

    zip_entry_name_from_file_name(file_name.as_deref())
}

fn zip_entry_name_from_file_name(file_name: Option<&str>) -> Result<Option<String>> {
    let Some(file_name) = file_name else {
        return Ok(None);
    };
    if !file_name.to_ascii_lowercase().ends_with(".zip") {
        return Ok(None);
    }

    let stem = &file_name[..file_name.len() - 4];
    if stem.is_empty() {
        return Err(anyhow!("zip artifact name must include a filename stem"));
    }
    Ok(Some(format!("{stem}.ero")))
}

async fn reader_size_bytes(reader: &dyn BlockReader) -> Result<u64> {
    let total_blocks = reader
        .total_blocks()
        .await
        .map_err(|err| anyhow!("read total blocks for channel: {err}"))?;
    total_blocks
        .checked_mul(reader.block_size() as u64)
        .ok_or_else(|| anyhow!("channel size overflow"))
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
    reader: Arc<dyn gibblox_core::BlockReader>,
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
    let task = session
        .start(transport, &mut control)
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    smoo_stats.set_connected(true);
    let mut counter_snapshot = transport_counters_from_snapshot(counters.snapshot());

    let outcome = drive_host_session(
        task,
        control,
        std::future::pending::<()>(),
        || tokio::time::sleep(HEARTBEAT_INTERVAL),
        HostSessionDriveConfig::default(),
        |event| {
            update_smoo_stats_from_transport(
                &smoo_stats,
                &mut counter_snapshot,
                transport_counters_from_snapshot(counters.snapshot()),
            );
            match event {
                HostSessionDriveEvent::HeartbeatStatus { .. } => {}
                HostSessionDriveEvent::HeartbeatRecovered { missed_heartbeats } => {
                    info!(missed_heartbeats, "desktop smoo heartbeat recovered");
                }
                HostSessionDriveEvent::HeartbeatMiss {
                    error,
                    missed_heartbeats,
                    budget,
                } => {
                    warn!(
                        %error,
                        missed_heartbeats,
                        budget,
                        "desktop smoo heartbeat failed"
                    );
                }
                HostSessionDriveEvent::HeartbeatMissBudgetExhausted {
                    missed_heartbeats,
                    budget,
                } => {
                    error!(
                        missed_heartbeats,
                        budget, "desktop smoo heartbeat budget exhausted"
                    );
                }
            }
        },
    )
    .await;

    update_smoo_stats_from_transport(
        &smoo_stats,
        &mut counter_snapshot,
        transport_counters_from_snapshot(counters.snapshot()),
    );
    smoo_stats.set_connected(false);

    match outcome {
        HostSessionDriveOutcome::Shutdown | HostSessionDriveOutcome::TransportLost => {
            Ok(SessionEnd::TransportLost)
        }
        HostSessionDriveOutcome::SessionChanged { previous, current } => {
            info!(
                previous = format_args!("0x{previous:016x}"),
                current = format_args!("0x{current:016x}"),
                "desktop smoo session changed; reconnecting"
            );
            Ok(SessionEnd::TransportLost)
        }
        HostSessionDriveOutcome::Failed(err) => Err(anyhow!(err.to_string())),
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

fn nonempty(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
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
        .and_then(nonempty_owned)
        .or_else(|| read_key_from_file(Path::new("/etc/locale.conf"), key))
}

fn detect_keymap() -> Option<String> {
    read_key_from_file(Path::new("/etc/vconsole.conf"), "KEYMAP")
        .or_else(|| read_key_from_file(Path::new("/etc/default/keyboard"), "XKBLAYOUT"))
        .map(|s| s.split(',').next().unwrap_or(&s).trim().to_string())
        .and_then(nonempty_owned)
}

fn detect_timezone() -> Option<String> {
    if let Some(tz) = read_timezone_from_localtime() {
        return Some(tz);
    }
    if let Ok(tz) = fs::read_to_string("/etc/timezone") {
        if let Some(tz) = nonempty_owned(tz) {
            return Some(tz);
        }
    }
    env::var("TZ").ok().and_then(nonempty_owned)
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
        if let Some(v) = nonempty_owned(v.to_string()) {
            return Some(v);
        }
    }
    None
}

fn nonempty_owned(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
