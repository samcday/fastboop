use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use fastboop_core::device::{DeviceEvent, DeviceHandle as _, DeviceWatcher as _, profile_filters};
use fastboop_core::fastboot::{FastbootSession, profile_matches_vid_pid};
use fastboop_core::prober::probe_candidates;
use fastboop_core::{DeviceProfile, Personalization, resolve_effective_boot_profile_stage0};
use fastboop_fastboot_rusb::{DeviceWatcher, FastbootRusb, RusbDeviceHandle};
use fastboop_session::{
    BootRequest, BootSessionEnvironment, FastboopSession, PreparedBoot, PreparedBootInfo,
    RuntimeExport, SessionCodecError, SessionEnvironment, SessionEvent, SessionEventPhase,
    SessionSnapshot, SessionStatus, Stage0Assembly, build_android_boot_payload_with_options,
    join_cmdline,
};
use gibblox_core::{BlockReader, block_identity_string};
use gobblytes_core::OstreeFs as OstreeRootfs;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use crate::channel::{
    ArtifactReaderResolver, OstreeArg, Stage0CoalescingFilesystem,
    auto_detect_ostree_deployment_path, format_probe_error, parse_ostree_arg, read_dtbo_overlays,
    read_existing_initrd, resolve_boot_profile_source_overrides, resolve_effective_ostree_arg,
};
use crate::devpro::{channel_matching_pool, resolve_devpro_dirs, resolve_profile_in_pool};
use crate::native_smoo::{SmooHostEvent, SmooHostOptions, SmooHostPhase, run_native_smoo_host};
use crate::stage0_binary::load_stage0_binary_for_initrd;

const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const DEFAULT_SMOO_MAX_IO_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct NativeBootStage0Config {
    pub channel: PathBuf,
    pub ostree: OstreeArg,
    pub device_profile: Option<String>,
    pub boot_profile: Option<String>,
    pub dtb: Option<PathBuf>,
    pub dtbo: Vec<PathBuf>,
    pub augment: Option<PathBuf>,
    pub stage0: Option<PathBuf>,
    pub require_modules: Vec<String>,
    pub cmdline_append: Option<String>,
    pub serial: bool,
    pub impersonate_fastboot: bool,
    pub smoo_queue_count: Option<u16>,
    pub smoo_queue_depth: Option<u16>,
    pub smoo_max_io: Option<usize>,
    pub abl_exorcist: Option<PathBuf>,
    pub local_artifact: Vec<PathBuf>,
}

impl NativeBootStage0Config {
    pub fn from_raw_ostree(
        channel: PathBuf,
        ostree: Option<&Option<String>>,
    ) -> Result<NativeBootStage0Config> {
        Ok(Self {
            channel,
            ostree: parse_ostree_arg(ostree)?,
            device_profile: None,
            boot_profile: None,
            dtb: None,
            dtbo: Vec::new(),
            augment: None,
            stage0: None,
            require_modules: Vec::new(),
            cmdline_append: None,
            serial: false,
            impersonate_fastboot: true,
            smoo_queue_count: None,
            smoo_queue_depth: None,
            smoo_max_io: None,
            abl_exorcist: None,
            local_artifact: Vec::new(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct NativeBootConfig {
    pub stage0: NativeBootStage0Config,
    pub boot_device: bool,
    pub system_time: bool,
    pub systemd_firstboot: bool,
    pub wait: Duration,
    pub smoo_metrics_port: u16,
    pub session_state: Option<PathBuf>,
}

impl NativeBootConfig {
    pub fn boot_request(&self) -> Result<BootRequest> {
        let mut request = BootRequest::new(session_seed()?);
        request.source = Some(self.stage0.channel.to_string_lossy().to_string());
        request.requested_device_profile = self.stage0.device_profile.clone();
        request.requested_boot_profile = self.stage0.boot_profile.clone();
        Ok(request)
    }
}

pub struct NativeBootEnvironment {
    config: NativeBootConfig,
    events: Sender<SessionEvent>,
    shutdown: CancellationToken,
    selected_device: Option<NativeSelectedFastbootDevice>,
    detected_device: Option<DetectedFastbootDevice>,
}

#[derive(Clone, Debug)]
pub struct NativeSelectedFastbootDevice {
    pub handle: RusbDeviceHandle,
    pub profile: DeviceProfile,
    pub vid: u16,
    pub pid: u16,
    pub serial: Option<String>,
}

impl NativeSelectedFastbootDevice {
    pub fn new(handle: RusbDeviceHandle, profile: DeviceProfile, serial: Option<String>) -> Self {
        let vid = handle.vid();
        let pid = handle.pid();
        Self {
            handle,
            profile,
            vid,
            pid,
            serial,
        }
    }

    fn info(&self) -> DetectedFastbootInfo {
        DetectedFastbootInfo {
            vid: self.vid,
            pid: self.pid,
            serial: self.serial.clone(),
        }
    }
}

impl NativeBootEnvironment {
    pub fn new(
        config: NativeBootConfig,
        events: Sender<SessionEvent>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            config,
            events,
            shutdown,
            selected_device: None,
            detected_device: None,
        }
    }

    pub fn with_selected_device(mut self, device: NativeSelectedFastbootDevice) -> Self {
        self.selected_device = Some(device);
        self
    }
}

impl SessionEnvironment for NativeBootEnvironment {
    type Error = anyhow::Error;

    fn session_codec_error(&mut self, err: SessionCodecError) -> Self::Error {
        anyhow!(err.to_string())
    }

    async fn persist_session(&mut self, snapshot: &SessionSnapshot, encoded: &[u8]) -> Result<()> {
        if let Some(path) = self.config.session_state.as_deref() {
            write_session_snapshot(path, encoded)?;
        }
        emit_session_status(&self.events, &snapshot.status);
        Ok(())
    }

    async fn prepare_boot(&mut self, session: &FastboopSession) -> Result<PreparedBoot> {
        emit(
            &self.events,
            SessionEvent::Phase {
                phase: SessionEventPhase::Preparing,
                detail: "loading profiles".to_string(),
            },
        );

        let devpro_dirs = resolve_devpro_dirs()?;
        let mut artifact_resolver = ArtifactReaderResolver::with_local_artifacts(
            self.config.stage0.local_artifact.as_slice(),
        )?;
        let channel_head = artifact_resolver
            .read_channel_stream_head(&self.config.stage0.channel)
            .await
            .with_context(|| {
                format!(
                    "read channel profile stream head for {}",
                    self.config.stage0.channel.display()
                )
            })?;

        if channel_head.warning_count > 0 {
            emit(
                &self.events,
                SessionEvent::Log(format!(
                    "channel stream has {} warning(s) while reading profile head; using {} bytes of leading records",
                    channel_head.warning_count, channel_head.consumed_bytes
                )),
            );
        }

        let resume_status = session.status().await;
        let post_handoff_resume = resume_status.is_post_handoff();
        let matching_pool = channel_matching_pool(&channel_head.dev_profiles, &devpro_dirs)?;
        let selected_device = if self.config.boot_device && !post_handoff_resume {
            self.selected_device.as_ref()
        } else {
            None
        };
        let mut profile = if let Some(profile_id) = resume_status.profile_id() {
            Some(resolve_profile_in_pool(
                &matching_pool,
                &devpro_dirs,
                profile_id,
            )?)
        } else {
            match self.config.stage0.device_profile.as_deref() {
                Some(requested) => Some(resolve_profile_in_pool(
                    &matching_pool,
                    &devpro_dirs,
                    requested,
                )?),
                None => None,
            }
        };

        if let Some(selected_device) = selected_device {
            if let Some(profile) = profile.as_ref()
                && profile.id != selected_device.profile.id
            {
                bail!(
                    "selected fastboot device profile '{}' does not match requested profile '{}'",
                    selected_device.profile.id,
                    profile.id
                );
            }
            profile = Some(selected_device.profile.clone());
        }

        if !self.config.boot_device && profile.is_none() {
            bail!(
                "--device-profile is required when using --output; profile auto-detection needs a connected device"
            );
        }

        let mut detected_fastboot = None;
        let detected_device = if self.config.boot_device && !post_handoff_resume {
            if let Some(selected_device) = selected_device {
                Some(selected_device.info())
            } else if let Some(selected_profile) = profile.as_ref() {
                emit(
                    &self.events,
                    SessionEvent::Phase {
                        phase: SessionEventPhase::WaitingForDevice,
                        detail: format!("profile={}", selected_profile.id),
                    },
                );
                let detected =
                    wait_for_fastboot_device(selected_profile, self.config.wait, &self.events)
                        .await?;
                let info = detected.info.clone();
                detected_fastboot = Some(detected);
                Some(info)
            } else {
                emit(
                    &self.events,
                    SessionEvent::Phase {
                        phase: SessionEventPhase::WaitingForDevice,
                        detail: "profile=auto".to_string(),
                    },
                );
                let resolved =
                    wait_for_fastboot_device_auto(&matching_pool, self.config.wait, &self.events)
                        .await?;
                profile = Some(resolved.profile);
                let info = resolved.device.info.clone();
                detected_fastboot = Some(resolved.device);
                Some(info)
            }
        } else {
            None
        };

        let profile = profile.expect("profile resolved before build");
        emit_detected_device(&self.events, &profile, detected_device.as_ref());

        emit(
            &self.events,
            SessionEvent::Phase {
                phase: SessionEventPhase::BuildingStage0,
                detail: "building stage0 payload".to_string(),
            },
        );

        let personalization = self
            .config
            .systemd_firstboot
            .then(personalization_from_host);
        let system_time_part = if self.config.system_time {
            Some(system_time_cmdline()?)
        } else {
            None
        };
        let prepared = build_stage0_artifacts(
            &mut artifact_resolver,
            &self.config.stage0,
            &profile,
            detected_device.as_ref(),
            personalization,
            system_time_part.as_deref(),
        )
        .await?;

        let build = prepared
            .build
            .map_err(|e| anyhow::anyhow!("stage0 build failed: {e:?}"))?;
        let bootimg = build_android_boot_payload_with_options(
            &profile,
            build,
            self.config.stage0.abl_exorcist.is_some(),
        )
            .map_err(|e| anyhow::anyhow!("bootimg build failed: {e}"))?;

        self.detected_device = detected_fastboot;
        Ok(PreparedBoot {
            profile_id: profile.id,
            boot_image: bootimg,
            export: RuntimeExport {
                reader: prepared.block_reader,
                size_bytes: prepared.image_size_bytes,
                identity: prepared.image_identity,
            },
        })
    }
}

impl BootSessionEnvironment for NativeBootEnvironment {
    type Fastboot = FastbootRusb;

    async fn connect_fastboot(
        &mut self,
        _session: &FastboopSession,
        _prepared: &PreparedBootInfo,
    ) -> Result<FastbootRusb> {
        if let Some(device) = self.detected_device.take() {
            return Ok(device.fastboot);
        }

        if let Some(device) = self.selected_device.take() {
            return device
                .handle
                .open_fastboot()
                .await
                .map_err(|err| anyhow!("open selected fastboot device failed: {err}"));
        }

        Err(anyhow!("fastboot device was not prepared for boot handoff"))
    }

    async fn serve_runtime(
        &mut self,
        _session: &FastboopSession,
        export: RuntimeExport,
    ) -> Result<()> {
        let (tx, rx) = std::sync::mpsc::channel::<SmooHostEvent>();
        let events = self.events.clone();
        let forwarder = std::thread::spawn(move || {
            while let Ok(event) = rx.recv() {
                emit(&events, smoo_event_to_session_event(event));
            }
        });

        let result = run_native_smoo_host(
            export.reader,
            export.size_bytes,
            export.identity,
            SmooHostOptions {
                impersonate_fastboot: self.config.stage0.impersonate_fastboot,
                metrics_port: self.config.smoo_metrics_port,
            },
            tx,
            self.shutdown.clone(),
        )
        .await
        .context("running smoo host daemon after boot");

        let _ = forwarder.join();
        result
    }
}

pub struct Stage0InitrdOutput {
    pub warnings: Vec<String>,
    pub initrd: Vec<u8>,
    pub kernel_cmdline_append: String,
    pub kernel_path: String,
    pub kernel_image_len: usize,
    pub init_path: String,
}

#[derive(Clone, Debug)]
pub struct NativeDetectConfig {
    pub device_profile: Option<String>,
    pub channel: Option<PathBuf>,
    pub wait: Option<Duration>,
}

#[derive(Clone, Debug)]
pub struct NativeDetectedDevice {
    pub profile: DeviceProfile,
    pub vid: u16,
    pub pid: u16,
}

pub async fn detect_native_fastboot(
    config: NativeDetectConfig,
    events: Sender<SessionEvent>,
) -> Result<Vec<NativeDetectedDevice>> {
    const NO_MATCHING_DEVICE_MSG: &str = "No matching fastboot devices detected.";

    let devpro_dirs = resolve_devpro_dirs()?;
    let channel_dev_profiles = if let Some(channel) = config.channel.as_deref() {
        let resolver = ArtifactReaderResolver::new();
        let head = resolver
            .read_channel_stream_head(channel)
            .await
            .with_context(|| {
                format!("read channel profile stream head for {}", channel.display())
            })?;
        if head.warning_count > 0 {
            emit(
                &events,
                SessionEvent::Log(format!(
                    "channel stream has {} warning(s) while reading profile head; using {} bytes of leading records",
                    head.warning_count, head.consumed_bytes
                )),
            );
        }
        head.dev_profiles
    } else {
        Vec::new()
    };

    let pool = channel_matching_pool(&channel_dev_profiles, &devpro_dirs)?;
    let profiles: Vec<DeviceProfile> = match config.device_profile.as_deref() {
        Some(requested) => vec![resolve_profile_in_pool(&pool, &devpro_dirs, requested)?],
        None => pool,
    };

    let mut profiles_by_id = HashMap::new();
    for profile in &profiles {
        profiles_by_id.insert(profile.id.clone(), profile);
    }

    let filters = profile_filters(&profiles);
    let mut watcher = DeviceWatcher::new(&filters).context("starting USB hotplug watcher")?;
    let deadline = config.wait.and_then(|wait| {
        if wait.is_zero() {
            None
        } else {
            Some(Instant::now() + wait)
        }
    });

    let mut waiting = false;
    loop {
        match watcher.try_next_event() {
            Poll::Ready(Ok(DeviceEvent::Arrived { device })) => {
                let detected =
                    handle_detect_arrived_device(&profiles, &profiles_by_id, device).await;
                if !detected.is_empty() {
                    return Ok(detected);
                }
            }
            Poll::Ready(Ok(DeviceEvent::Left { .. })) => {}
            Poll::Ready(Err(err)) => {
                bail!("USB watcher disconnected: {err}");
            }
            Poll::Pending => {
                let Some(wait) = config.wait else {
                    bail!(NO_MATCHING_DEVICE_MSG);
                };

                if !waiting {
                    waiting = true;
                    if wait.is_zero() {
                        emit(
                            &events,
                            SessionEvent::Log(
                                "No matching fastboot devices detected. Waiting for devices..."
                                    .to_string(),
                            ),
                        );
                    } else {
                        emit(
                            &events,
                            SessionEvent::Log(format!(
                                "No matching fastboot devices detected. Waiting up to {}s...",
                                wait.as_secs()
                            )),
                        );
                    }
                }

                if let Some(deadline) = deadline {
                    let now = Instant::now();
                    if now >= deadline {
                        bail!(NO_MATCHING_DEVICE_MSG);
                    }
                    let remaining = deadline.saturating_duration_since(now);
                    tokio::time::sleep(remaining.min(IDLE_POLL_INTERVAL)).await;
                } else {
                    tokio::time::sleep(IDLE_POLL_INTERVAL).await;
                }
            }
        }
    }
}

async fn handle_detect_arrived_device(
    profiles: &[DeviceProfile],
    profiles_by_id: &HashMap<String, &DeviceProfile>,
    device: RusbDeviceHandle,
) -> Vec<NativeDetectedDevice> {
    trace!(
        vid = %format!("{:04x}", device.vid()),
        pid = %format!("{:04x}", device.pid()),
        "usb device hotplug event"
    );

    let candidates = [device];
    let reports = probe_candidates(profiles, &candidates).await;
    let mut found = Vec::new();
    for report in reports {
        let candidate = &candidates[report.candidate_index];
        let vid = report.vid;
        let pid = report.pid;
        if let Some(err) = report.open_error {
            tracing::info!(%err, vid = %format!("{vid:04x}"), pid = %format!("{pid:04x}"), "skipping fastboot device after open failure");
            continue;
        }
        for attempt in report.attempts {
            let Some(profile) = profiles_by_id.get(&attempt.profile_id) else {
                continue;
            };
            match attempt.result {
                Ok(()) => found.push(NativeDetectedDevice {
                    profile: (*profile).clone(),
                    vid: candidate.vid(),
                    pid: candidate.pid(),
                }),
                Err(err) => {
                    debug!(
                        profile_id = %profile.id,
                        vid = %format!("{:04x}", vid),
                        pid = %format!("{:04x}", pid),
                        error = %format_probe_error(err),
                        "fastboot probe failed"
                    );
                }
            }
        }
    }

    found
}

pub async fn build_stage0_initrd(config: NativeBootStage0Config) -> Result<Stage0InitrdOutput> {
    let devpro_dirs = resolve_devpro_dirs()?;
    let mut artifact_resolver =
        ArtifactReaderResolver::with_local_artifacts(config.local_artifact.as_slice())?;
    let channel_head = artifact_resolver
        .read_channel_stream_head(&config.channel)
        .await
        .with_context(|| {
            format!(
                "read channel profile stream head for {}",
                config.channel.display()
            )
        })?;

    let mut warnings = Vec::new();
    if channel_head.warning_count > 0 {
        warnings.push(format!(
            "channel stream has {} warning(s) while reading profile head; using {} bytes of leading records",
            channel_head.warning_count, channel_head.consumed_bytes
        ));
    }

    let pool = channel_matching_pool(&channel_head.dev_profiles, &devpro_dirs)?;
    let requested = config
        .device_profile
        .as_deref()
        .ok_or_else(|| anyhow!("--device-profile is required"))?;
    let profile = resolve_profile_in_pool(&pool, &devpro_dirs, requested)?;

    let prepared =
        build_stage0_artifacts(&mut artifact_resolver, &config, &profile, None, None, None).await?;
    let build = prepared
        .build
        .map_err(|e| anyhow::anyhow!("stage0 build failed: {e:?}"))?;
    Ok(Stage0InitrdOutput {
        warnings,
        initrd: build.initrd,
        kernel_cmdline_append: build.kernel_cmdline_append,
        kernel_path: build.kernel_path,
        kernel_image_len: build.kernel_image.len(),
        init_path: build.init_path,
    })
}

struct Stage0Artifacts {
    block_reader: std::sync::Arc<dyn BlockReader>,
    image_size_bytes: u64,
    image_identity: String,
    build: std::result::Result<
        fastboop_stage0_generator::Stage0Build,
        fastboop_stage0_generator::Stage0Error,
    >,
}

async fn build_stage0_artifacts(
    artifact_resolver: &mut ArtifactReaderResolver,
    config: &NativeBootStage0Config,
    profile: &DeviceProfile,
    detected_device: Option<&DetectedFastbootInfo>,
    personalization: Option<Personalization>,
    system_time_part: Option<&str>,
) -> Result<Stage0Artifacts> {
    let cli_dtb_override = match &config.dtb {
        Some(path) => {
            Some(std::fs::read(path).with_context(|| format!("reading dtb {}", path.display()))?)
        }
        None => None,
    };
    let cli_dtbo_overlays = read_dtbo_overlays(&config.dtbo)?;
    let abl_exorcist_image = read_abl_exorcist(config.abl_exorcist.as_deref())?;
    let existing = read_existing_initrd(&config.augment)?;
    let stage0_binary =
        load_stage0_binary_for_initrd(config.stage0.as_deref(), existing.as_deref())?;
    let cli_cmdline_append = config
        .cmdline_append
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let input = artifact_resolver
        .open_channel_input(&config.channel, &profile.id, config.boot_profile.as_deref())
        .await?;
    let profile_source_overrides = resolve_boot_profile_source_overrides(
        input.boot_profile.as_ref(),
        profile,
        artifact_resolver,
    )
    .await?;
    let profile_stage0 = input
        .boot_profile
        .as_ref()
        .map(|boot_profile| resolve_effective_boot_profile_stage0(boot_profile, &profile.id))
        .unwrap_or_default();
    let reader = input.reader;
    let stage0_readers = input.stage0_readers;

    let total_blocks = reader.total_blocks().await?;
    let image_size_bytes = total_blocks
        .checked_mul(reader.block_size() as u64)
        .ok_or_else(|| anyhow!("channel image size overflow"))?;
    let image_identity = block_identity_string(reader.as_ref());
    let provider = Stage0CoalescingFilesystem::open(stage0_readers).await?;

    let mut kernel_modules = profile_stage0.kernel_modules;
    kernel_modules.extend(config.require_modules.iter().cloned());

    let mut dtbo_overlays = profile_stage0.dt_overlays;
    dtbo_overlays.extend(cli_dtbo_overlays.iter().cloned());

    let merged_profile_cmdline = join_cmdline(
        profile_stage0.extra_cmdline.as_deref(),
        cli_cmdline_append.as_deref(),
    );

    let opts = fastboop_stage0_generator::Stage0Options {
        switchroot_fs: provider.switchroot_fs(),
        kernel_modules,
        inject_mac: profile_stage0.inject_mac,
        kernel_override: profile_source_overrides.kernel_override,
        abl_exorcist: abl_exorcist_image.map(|image| fastboop_stage0_generator::Stage0AblExorcist {
            image,
        }),
        dtb_override: cli_dtb_override.or(profile_source_overrides.dtb_override),
        dtbo_overlays,
        enable_serial: config.serial,
        mimic_fastboot: config.impersonate_fastboot,
        smoo_vendor: detected_device.map(|device| device.vid),
        smoo_product: detected_device.map(|device| device.pid),
        stage0_serial: detected_device.and_then(|device| device.serial.clone()),
        personalization,
    };

    let effective_ostree_arg =
        resolve_effective_ostree_arg(&config.ostree, input.boot_profile.as_ref());
    let selected_ostree = match &effective_ostree_arg {
        OstreeArg::Disabled => None,
        OstreeArg::AutoDetect => {
            let detected = auto_detect_ostree_deployment_path(&provider).await?;
            debug!(ostree = %detected, "auto-detected ostree deployment path");
            Some(detected)
        }
        OstreeArg::Explicit(path) => Some(path.clone()),
    };

    let mut extra_parts = Vec::new();
    if let Some(ostree) = selected_ostree.as_deref() {
        extra_parts.push(format!("ostree=/{ostree}"));
    }
    if !merged_profile_cmdline.is_empty() {
        extra_parts.push(merged_profile_cmdline);
    }
    if let Some(system_time) = system_time_part {
        extra_parts.push(system_time.to_string());
    }
    if let Some(queue_count) = config.smoo_queue_count {
        extra_parts.push(format!("smoo.queue_count={queue_count}"));
    }
    if let Some(queue_depth) = config.smoo_queue_depth {
        extra_parts.push(format!("smoo.queue_depth={queue_depth}"));
    }
    extra_parts.push(format!(
        "smoo.max_io_bytes={}",
        config.smoo_max_io.unwrap_or(DEFAULT_SMOO_MAX_IO_BYTES)
    ));
    let extra_cmdline = if extra_parts.is_empty() {
        None
    } else {
        Some(extra_parts.join(" "))
    };

    let assembly = Stage0Assembly::new(opts, stage0_binary)
        .with_extra_cmdline(extra_cmdline)
        .with_existing_cpio(existing);

    let build = if let Some(ostree) = selected_ostree.as_deref() {
        let resolved_ostree = OstreeRootfs::resolve_deployment_path(&provider, ostree)
            .await
            .map_err(|err| anyhow!("resolve ostree deployment path {ostree}: {err}"))?;
        debug!(ostree = %ostree, resolved_ostree = %resolved_ostree, "resolved ostree deployment path");
        let provider = OstreeRootfs::new(provider, &resolved_ostree)
            .map_err(|err| anyhow!("initialize ostree filesystem view: {err}"))?;
        assembly.build(profile, &provider).await
    } else {
        assembly.build(profile, &provider).await
    };

    Ok(Stage0Artifacts {
        block_reader: reader,
        image_size_bytes,
        image_identity,
        build,
    })
}

fn read_abl_exorcist(path: Option<&Path>) -> Result<Option<Vec<u8>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let data = std::fs::read(path)
        .with_context(|| format!("reading abl-exorcist shim {}", path.display()))?;
    if data.is_empty() {
        bail!("abl-exorcist shim is empty: {}", path.display());
    }
    Ok(Some(data))
}

struct DetectedFastbootDevice {
    fastboot: FastbootRusb,
    info: DetectedFastbootInfo,
}

#[derive(Clone, Debug)]
struct DetectedFastbootInfo {
    vid: u16,
    pid: u16,
    serial: Option<String>,
}

struct ResolvedDetectedFastbootDevice {
    profile: DeviceProfile,
    device: DetectedFastbootDevice,
}

async fn wait_for_fastboot_device(
    profile: &DeviceProfile,
    wait: Duration,
    events: &Sender<SessionEvent>,
) -> Result<DetectedFastbootDevice> {
    let filters = profile_filters(std::slice::from_ref(profile));
    let mut watcher = DeviceWatcher::new(&filters).context("starting USB hotplug watcher")?;
    let deadline = if wait.is_zero() {
        None
    } else {
        Some(Instant::now() + wait)
    };
    let mut waiting = false;

    loop {
        match watcher.try_next_event() {
            Poll::Ready(Ok(DeviceEvent::Arrived { device })) => {
                if let Some(fastboot) = probe_arrived_device(profile, device, events).await? {
                    return Ok(fastboot);
                }
            }
            Poll::Ready(Ok(DeviceEvent::Left { .. })) => {}
            Poll::Ready(Err(err)) => {
                bail!("USB watcher disconnected: {err}");
            }
            Poll::Pending => {
                if !waiting {
                    waiting = true;
                    if wait.is_zero() {
                        emit(
                            events,
                            SessionEvent::Log(format!(
                                "Waiting for fastboot device matching profile {}...",
                                profile.id
                            )),
                        );
                    } else {
                        emit(
                            events,
                            SessionEvent::Log(format!(
                                "Waiting up to {}s for fastboot device matching profile {}...",
                                wait.as_secs(),
                                profile.id
                            )),
                        );
                    }
                }

                if let Some(deadline) = deadline {
                    let now = Instant::now();
                    if now >= deadline {
                        bail!(
                            "timed out waiting for fastboot device matching profile {}",
                            profile.id
                        );
                    }
                    let remaining = deadline.saturating_duration_since(now);
                    tokio::time::sleep(remaining.min(IDLE_POLL_INTERVAL)).await;
                } else {
                    tokio::time::sleep(IDLE_POLL_INTERVAL).await;
                }
            }
        }
    }
}

async fn wait_for_fastboot_device_auto(
    profiles: &[DeviceProfile],
    wait: Duration,
    events: &Sender<SessionEvent>,
) -> Result<ResolvedDetectedFastbootDevice> {
    if profiles.is_empty() {
        bail!("no device profiles available for auto-detection");
    }

    let filters = profile_filters(profiles);
    let mut watcher = DeviceWatcher::new(&filters).context("starting USB hotplug watcher")?;
    let deadline = if wait.is_zero() {
        None
    } else {
        Some(Instant::now() + wait)
    };
    let mut waiting = false;

    loop {
        match watcher.try_next_event() {
            Poll::Ready(Ok(DeviceEvent::Arrived { device })) => {
                if let Some(resolved) = probe_arrived_device_auto(profiles, device, events).await? {
                    return Ok(resolved);
                }
            }
            Poll::Ready(Ok(DeviceEvent::Left { .. })) => {}
            Poll::Ready(Err(err)) => {
                bail!("USB watcher disconnected: {err}");
            }
            Poll::Pending => {
                if !waiting {
                    waiting = true;
                    if wait.is_zero() {
                        emit(
                            events,
                            SessionEvent::Log(
                                "Waiting for fastboot device matching any profile...".to_string(),
                            ),
                        );
                    } else {
                        emit(
                            events,
                            SessionEvent::Log(format!(
                                "Waiting up to {}s for fastboot device matching any profile...",
                                wait.as_secs()
                            )),
                        );
                    }
                }

                if let Some(deadline) = deadline {
                    let now = Instant::now();
                    if now >= deadline {
                        bail!("timed out waiting for fastboot device matching any profile");
                    }
                    let remaining = deadline.saturating_duration_since(now);
                    tokio::time::sleep(remaining.min(IDLE_POLL_INTERVAL)).await;
                } else {
                    tokio::time::sleep(IDLE_POLL_INTERVAL).await;
                }
            }
        }
    }
}

async fn probe_arrived_device(
    profile: &DeviceProfile,
    device: RusbDeviceHandle,
    events: &Sender<SessionEvent>,
) -> Result<Option<DetectedFastbootDevice>> {
    let vid = device.vid();
    let pid = device.pid();
    if !profile_matches_vid_pid(profile, vid, pid) {
        return Ok(None);
    }
    let serial = device.usb_serial_number();

    let mut fastboot = match device.open_fastboot().await {
        Ok(fastboot) => fastboot,
        Err(err) => {
            emit(
                events,
                SessionEvent::Log(format!("Skipping {vid:04x}:{pid:04x}: open failed: {err}")),
            );
            return Ok(None);
        }
    };

    let mut session = FastbootSession::new(&mut fastboot);
    match session.probe_profile(profile).await {
        Ok(()) => {
            return Ok(Some(DetectedFastbootDevice {
                fastboot,
                info: DetectedFastbootInfo { vid, pid, serial },
            }));
        }
        Err(err) => {
            debug!(
                profile_id = %profile.id,
                vid = %format!("{:04x}", vid),
                pid = %format!("{:04x}", pid),
                error = %format_probe_error(err),
                "fastboot probe failed"
            );
        }
    }

    Ok(None)
}

async fn probe_arrived_device_auto(
    profiles: &[DeviceProfile],
    device: RusbDeviceHandle,
    events: &Sender<SessionEvent>,
) -> Result<Option<ResolvedDetectedFastbootDevice>> {
    let vid = device.vid();
    let pid = device.pid();
    let matching_profiles: Vec<&DeviceProfile> = profiles
        .iter()
        .filter(|profile| profile_matches_vid_pid(profile, vid, pid))
        .collect();
    if matching_profiles.is_empty() {
        return Ok(None);
    }

    let serial = device.usb_serial_number();
    let mut fastboot = match device.open_fastboot().await {
        Ok(fastboot) => fastboot,
        Err(err) => {
            emit(
                events,
                SessionEvent::Log(format!("Skipping {vid:04x}:{pid:04x}: open failed: {err}")),
            );
            return Ok(None);
        }
    };

    let mut session = FastbootSession::new(&mut fastboot);
    let mut matched_profiles = Vec::new();
    for profile in matching_profiles {
        match session.probe_profile(profile).await {
            Ok(()) => matched_profiles.push(profile),
            Err(err) => {
                debug!(
                    profile_id = %profile.id,
                    vid = %format!("{:04x}", vid),
                    pid = %format!("{:04x}", pid),
                    error = %format_probe_error(err),
                    "fastboot probe failed"
                );
            }
        }
    }

    match matched_profiles.as_slice() {
        [] => Ok(None),
        [profile] => Ok(Some(ResolvedDetectedFastbootDevice {
            profile: (*profile).clone(),
            device: DetectedFastbootDevice {
                fastboot,
                info: DetectedFastbootInfo { vid, pid, serial },
            },
        })),
        _ => {
            let mut profile_choices: Vec<String> = matched_profiles
                .iter()
                .map(|profile| profile_choice_label(profile))
                .collect();
            profile_choices.sort();
            let serial_suffix = serial
                .as_deref()
                .map(|serial| format!(" serial={serial}"))
                .unwrap_or_default();
            bail!(
                "multiple device profiles matched {vid:04x}:{pid:04x}{serial_suffix}: {}. --device-profile which-one, guv?",
                profile_choices.join(", "),
            );
        }
    }
}

fn emit_detected_device(
    events: &Sender<SessionEvent>,
    profile: &DeviceProfile,
    device: Option<&DetectedFastbootInfo>,
) {
    let Some(device) = device else {
        return;
    };
    emit(
        events,
        SessionEvent::Phase {
            phase: SessionEventPhase::DeviceDetected,
            detail: format!(
                "{:04x}:{:04x} {} profile={}",
                device.vid,
                device.pid,
                device
                    .serial
                    .as_deref()
                    .map(|s| format!("serial={s}"))
                    .unwrap_or_else(|| "serial=unknown".to_string()),
                profile.id,
            ),
        },
    );
}

fn emit_session_status(events: &Sender<SessionEvent>, status: &SessionStatus) {
    match status {
        SessionStatus::BootImageReady {
            boot_image_size, ..
        } => emit(
            events,
            SessionEvent::Phase {
                phase: SessionEventPhase::BuildingBootImage,
                detail: format!("boot image built ({boot_image_size} bytes)"),
            },
        ),
        SessionStatus::Downloading {
            boot_image_size, ..
        } => emit(
            events,
            SessionEvent::Phase {
                phase: SessionEventPhase::Downloading,
                detail: format!("sending {boot_image_size} bytes"),
            },
        ),
        SessionStatus::BootHandoffStarted { .. } => emit(
            events,
            SessionEvent::Phase {
                phase: SessionEventPhase::Booting,
                detail: "issuing fastboot boot".to_string(),
            },
        ),
        SessionStatus::BootIssued { .. } => {
            emit(
                events,
                SessionEvent::Log("fastboot boot command accepted".to_string()),
            );
        }
        _ => {}
    }
}

fn smoo_event_to_session_event(event: SmooHostEvent) -> SessionEvent {
    match event {
        SmooHostEvent::Phase { phase, detail } => SessionEvent::Phase {
            phase: match phase {
                SmooHostPhase::WaitingForSmoo => SessionEventPhase::WaitingForSmoo,
                SmooHostPhase::Serving => SessionEventPhase::Serving,
            },
            detail,
        },
        SmooHostEvent::Log(line) => SessionEvent::Log(line),
        SmooHostEvent::Status {
            active,
            export_count,
            session_id,
            ios_up,
            ios_down,
            bytes_up,
            bytes_down,
            inflight_requests,
            max_inflight_requests,
        } => SessionEvent::SmooStatus {
            active,
            export_count,
            session_id,
            ios_up,
            ios_down,
            bytes_up,
            bytes_down,
            inflight_requests,
            max_inflight_requests,
        },
    }
}

fn emit(events: &Sender<SessionEvent>, event: SessionEvent) {
    let _ = events.send(event);
}

pub fn session_seed() -> Result<u64> {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX_EPOCH")?;
    let nanos = since_epoch.as_nanos();
    Ok((nanos as u64) ^ ((nanos >> 64) as u64))
}

fn write_session_snapshot(path: &Path, encoded: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating session state directory {}", parent.display()))?;
    }
    let mut tmp_name = path
        .file_name()
        .ok_or_else(|| anyhow!("session state path {} has no file name", path.display()))?
        .to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = path.with_file_name(tmp_name);

    std::fs::write(&tmp_path, encoded)
        .with_context(|| format!("writing session state {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "replacing session state {} with {}",
            path.display(),
            tmp_path.display()
        )
    })?;
    Ok(())
}

fn profile_choice_label(profile: &DeviceProfile) -> String {
    match profile.display_name.as_deref() {
        Some(display_name) => format!("{} ({display_name})", profile.id),
        None => profile.id.clone(),
    }
}

fn system_time_cmdline() -> Result<String> {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX_EPOCH")?;
    let usec: u64 = since_epoch
        .as_micros()
        .try_into()
        .context("system time exceeds u64 microseconds")?;
    Ok(format!("systemd.clock_usec={usec}"))
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
    std::env::var(key)
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
    if let Ok(tz) = std::fs::read_to_string("/etc/timezone")
        && let Some(tz) = nonempty(tz)
    {
        return Some(tz);
    }
    std::env::var("TZ").ok().and_then(nonempty)
}

fn read_timezone_from_localtime() -> Option<String> {
    let target = std::fs::read_link("/etc/localtime").ok()?;
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
    let text = std::fs::read_to_string(path).ok()?;
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
