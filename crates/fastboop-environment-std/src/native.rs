use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use fastboop_core::device::{DeviceEvent, DeviceHandle as _, DeviceWatcher as _, profile_filters};
use fastboop_core::fastboot::{FastbootSession, profile_matches_vid_pid};
use fastboop_core::prober::probe_candidates;
use fastboop_core::{
    BootImageComponents, BootProfileSourceOverrides, BootStrategy, DeviceProfile, Personalization,
    PreparedBoot, RuntimeExport, Stage0ExtraCmdline, build_android_boot_payload_with_options,
    build_stage0_extra_cmdline,
};
use fastboop_fastboot_rusb::{DeviceWatcher, FastbootRusb, RusbDeviceHandle};
use fastboop_stage0_generator::{build_stage0, stage0_binary_ready};
use gibblox_core::{BlockReader, block_identity_string};
use gobblytes_core::OstreeFs as OstreeRootfs;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use crate::channel::{
    ArtifactReaderResolver, ChannelInput, OstreeArg, Stage0CoalescingFilesystem,
    auto_detect_ostree_deployment_path, format_probe_error, parse_ostree_arg, read_dtbo_overlays,
    read_existing_initrd, resolve_boot_profile_source_overrides, resolve_effective_ostree_arg,
};
use crate::devpro::{channel_matching_pool, resolve_devpro_dirs, resolve_profile_in_pool};
use crate::native_smoo::{SmooHostEvent, SmooHostOptions, run_native_smoo_host};
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
}

pub struct NativeBootEnvironment {
    config: NativeBootConfig,
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
    pub fn new(config: NativeBootConfig, shutdown: CancellationToken) -> Self {
        Self {
            config,
            shutdown,
            selected_device: None,
            detected_device: None,
        }
    }

    pub fn with_selected_device(mut self, device: NativeSelectedFastbootDevice) -> Self {
        self.selected_device = Some(device);
        self
    }
    pub async fn prepare_boot(&mut self) -> Result<PreparedBoot> {
        tracing::info!("loading profiles");

        let devpro_dirs = resolve_devpro_dirs()?;
        let artifact_resolver = ArtifactReaderResolver::new();
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
            tracing::warn!(
                warning_count = channel_head.warning_count,
                consumed_bytes = channel_head.consumed_bytes,
                "channel stream warnings while reading profile head"
            );
        }

        let matching_pool = channel_matching_pool(&channel_head.dev_profiles, &devpro_dirs)?;
        let selected_device = if self.config.boot_device {
            self.selected_device.as_ref()
        } else {
            None
        };
        let mut profile = match self.config.stage0.device_profile.as_deref() {
            Some(requested) => Some(resolve_profile_in_pool(
                &matching_pool,
                &devpro_dirs,
                requested,
            )?),
            None => None,
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

        let channel = fastboop_core::Channel::new(None, channel_head);
        let candidates = profile
            .as_ref()
            .map(std::slice::from_ref)
            .unwrap_or(&matching_pool);
        validate_native_boot_candidates(&self.config.stage0, &channel, candidates)?;

        let mut detected_fastboot = None;
        let detected_device = if self.config.boot_device {
            if let Some(selected_device) = selected_device {
                Some(selected_device.info())
            } else if let Some(selected_profile) = profile.as_ref() {
                tracing::info!(profile = %selected_profile.id, "waiting for fastboot device");
                let detected = wait_for_fastboot_device(selected_profile, self.config.wait).await?;
                let info = detected.info.clone();
                detected_fastboot = Some(detected);
                Some(info)
            } else {
                tracing::info!("waiting for fastboot device matching any profile");
                let resolved =
                    wait_for_fastboot_device_auto(&matching_pool, self.config.wait).await?;
                profile = Some(resolved.profile);
                let info = resolved.device.info.clone();
                detected_fastboot = Some(resolved.device);
                Some(info)
            }
        } else {
            None
        };

        let profile = profile.expect("profile resolved before build");
        validate_native_boot_candidates(
            &self.config.stage0,
            &channel,
            std::slice::from_ref(&profile),
        )?;
        log_detected_device(&profile, detected_device.as_ref());
        tracing::info!(profile = %profile.id, "building boot payload");

        let mut artifact_resolver = ArtifactReaderResolver::with_local_artifacts(
            self.config.stage0.local_artifact.as_slice(),
        )?;
        let resolved =
            resolve_boot_input(&mut artifact_resolver, &self.config.stage0, &profile).await?;
        if resolved
            .input
            .boot_spec
            .boot_profile()
            .is_some_and(|p| p.boot == BootStrategy::Initrd)
        {
            let prepared = build_native_initrd_boot(
                &self.config.stage0,
                &profile,
                resolved,
                detected_device.as_ref(),
                self.config
                    .system_time
                    .then(system_time_cmdline)
                    .transpose()?
                    .as_deref(),
            )
            .await?;
            self.detected_device = detected_fastboot;
            return Ok(prepared);
        }

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
            resolved,
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
            BootImageComponents {
                kernel_image: build.kernel_image,
                initrd: build.initrd,
                dtb: build.dtb,
                kernel_cmdline_append: build.kernel_cmdline_append,
            },
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

    pub async fn connect_fastboot(&mut self) -> Result<FastbootRusb> {
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

    pub async fn serve_runtime(&mut self, export: RuntimeExport) -> Result<()> {
        let (tx, rx) = std::sync::mpsc::channel::<SmooHostEvent>();
        let forwarder = std::thread::spawn(move || {
            while let Ok(event) = rx.recv() {
                log_smoo_event(event);
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
            tracing::warn!(
                warning_count = head.warning_count,
                consumed_bytes = head.consumed_bytes,
                "channel stream warnings while reading profile head"
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
                        tracing::info!(
                            "no matching fastboot devices detected; waiting for devices"
                        );
                    } else {
                        tracing::info!(
                            wait_seconds = wait.as_secs(),
                            "no matching fastboot devices detected; waiting for devices"
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

    let selected = fastboop_core::Channel::new(None, channel_head)
        .resolve_boot_profile(&profile.id, config.boot_profile.as_deref())
        .map_err(|err| anyhow!(err.to_string()))?;
    if selected
        .as_ref()
        .is_some_and(|p| p.boot == BootStrategy::Initrd)
    {
        bail!("fastboop stage0 cannot build a boot: initrd profile; use fastboop boot");
    }
    let resolved = resolve_boot_input(&mut artifact_resolver, &config, &profile).await?;
    let prepared = build_stage0_artifacts(resolved, &config, &profile, None, None, None).await?;
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

struct ResolvedBootInput {
    input: ChannelInput,
    sources: BootProfileSourceOverrides,
    export: RuntimeExport,
}

async fn resolve_boot_input(
    resolver: &mut ArtifactReaderResolver,
    config: &NativeBootStage0Config,
    profile: &DeviceProfile,
) -> Result<ResolvedBootInput> {
    let input = resolver
        .open_channel_input(&config.channel, profile, config.boot_profile.as_deref())
        .await?;
    let sources =
        resolve_boot_profile_source_overrides(input.boot_spec.boot_profile(), profile, resolver)
            .await?;
    let size_bytes = input
        .reader
        .total_blocks()
        .await?
        .checked_mul(u64::from(input.reader.block_size()))
        .ok_or_else(|| anyhow!("channel image size overflow"))?;
    let export = RuntimeExport {
        identity: block_identity_string(input.reader.as_ref()),
        reader: input.reader.clone(),
        size_bytes,
    };
    Ok(ResolvedBootInput {
        input,
        sources,
        export,
    })
}

fn validate_native_boot_candidates(
    config: &NativeBootStage0Config,
    channel: &fastboop_core::Channel,
    candidates: &[DeviceProfile],
) -> Result<()> {
    let mut first_error = None;
    let mut selection_error = None;
    for device in candidates {
        let selected =
            match channel.resolve_boot_profile(&device.id, config.boot_profile.as_deref()) {
                Ok(selected) => selected,
                Err(err) => {
                    selection_error.get_or_insert_with(|| anyhow!(err.to_string()));
                    continue;
                }
            };
        let result = if let Some(selected) = selected
            && selected.boot == BootStrategy::Initrd
        {
            validate_initrd_boot_options(
                config,
                &fastboop_core::resolve_effective_boot_profile_stage0(&selected, &device.id),
            )
        } else {
            Ok(())
        };
        match result {
            // Before detection, do not reject an invocation that is valid for
            // another candidate. Recheck the actual device before opening inputs.
            Ok(()) => return Ok(()),
            Err(err) if first_error.is_none() => first_error = Some(err),
            Err(_) => {}
        }
    }
    match first_error.or(selection_error) {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

fn validate_initrd_boot_options(
    config: &NativeBootStage0Config,
    settings: &fastboop_core::EffectiveBootProfileStage0,
) -> Result<()> {
    if config.abl_exorcist.is_some() {
        bail!("--abl-exorcist is not supported with boot: initrd");
    }
    if config.stage0.is_some()
        || config.augment.is_some()
        || !config.require_modules.is_empty()
        || config.serial
    {
        bail!(
            "boot: initrd uses a prepared initramfs; --stage0, --augment, --require-module and --serial apply only to stage0 generation"
        );
    }
    if config.ostree != OstreeArg::Disabled {
        bail!("boot: initrd takes its OSTree arguments from the boot profile command line");
    }
    if !settings.kernel_modules.is_empty() {
        bail!(
            "boot: initrd requires modules to be included in the supplied initramfs, not stage0.kernel_modules"
        );
    }
    Ok(())
}

async fn build_native_initrd_boot(
    config: &NativeBootStage0Config,
    profile: &DeviceProfile,
    resolved: ResolvedBootInput,
    detected_device: Option<&DetectedFastbootInfo>,
    system_time: Option<&str>,
) -> Result<PreparedBoot> {
    let ResolvedBootInput {
        input,
        sources,
        export,
    } = resolved;
    let settings = input.boot_spec.stage0();
    validate_initrd_boot_options(config, &settings)?;
    let kernel = sources
        .kernel_override
        .ok_or_else(|| anyhow!("boot: initrd requires a kernel artifact"))?;
    let initrd = sources
        .initrd_override
        .ok_or_else(|| anyhow!("boot: initrd requires an initrd artifact"))?;
    let dtb = match &config.dtb {
        Some(path) => tokio::fs::read(path)
            .await
            .with_context(|| format!("reading dtb {}", path.display()))?,
        None => sources.dtb_override.unwrap_or_default(),
    };
    let mut overlays = settings.dt_overlays.clone();
    overlays.extend(read_dtbo_overlays(&config.dtbo)?);
    let export_id = crate::native_smoo::runtime_export_id(&export)?;
    let mut requested = fastboop_core::join_cmdline(config.cmdline_append.as_deref(), system_time);
    for (key, value) in [
        (
            "rd.smoo.queue_count",
            config.smoo_queue_count.map(u64::from),
        ),
        (
            "rd.smoo.queue_depth",
            config.smoo_queue_depth.map(u64::from),
        ),
        ("rd.smoo.max_io_bytes", config.smoo_max_io.map(|v| v as u64)),
    ] {
        if let Some(value) = value {
            requested =
                fastboop_core::join_cmdline(Some(&requested), Some(&format!("{key}={value}")));
        }
    }
    let cmdline = fastboop_core::build_initrd_extra_cmdline(fastboop_core::InitrdCmdline {
        device: profile
            .boot
            .fastboot_boot
            .android_bootimg
            .cmdline_append
            .as_deref(),
        profile: settings.extra_cmdline.as_deref(),
        requested: Some(&requested),
        export_id,
        mimic_fastboot: config.impersonate_fastboot,
    })
    .map_err(|err| anyhow!(err))?;
    tracing::info!(profile = %profile.id, export_id, kernel_bytes = kernel.image.len(),
        initrd_bytes = initrd.len(), "preparing supplied initrd boot");
    let components = fastboop_stage0_generator::prepare_supplied_initrd(
        profile,
        fastboop_stage0_generator::SuppliedInitrdOptions {
            kernel: &kernel.image,
            initrd,
            dtb: &dtb,
            overlays: &overlays,
            inject_mac: &settings.inject_mac,
            mac_seed: detected_device
                .and_then(|d| d.serial.as_deref())
                .unwrap_or("0"),
            cmdline,
        },
    )
    .map_err(|err| anyhow!("prepare supplied initrd: {err:?}"))?;
    let boot_image = fastboop_core::build_android_boot_payload(profile, components)
        .map_err(|err| anyhow!("bootimg build failed: {err}"))?;
    Ok(PreparedBoot {
        profile_id: profile.id.clone(),
        boot_image,
        export,
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
    resolved: ResolvedBootInput,
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

    let ResolvedBootInput {
        input,
        sources: profile_source_overrides,
        export,
    } = resolved;
    let boot_spec = input.boot_spec;
    let selected_boot_profile = boot_spec.boot_profile();
    let profile_stage0 = boot_spec.stage0();
    let stage0_readers = input.stage0_readers;
    let provider = Stage0CoalescingFilesystem::open(stage0_readers)
        .await
        .map_err(|err| anyhow!(err.to_string()))?;

    let mut kernel_modules = profile_stage0.kernel_modules.clone();
    kernel_modules.extend(config.require_modules.iter().cloned());

    let mut dtbo_overlays = profile_stage0.dt_overlays.clone();
    dtbo_overlays.extend(cli_dtbo_overlays.iter().cloned());

    let opts = fastboop_stage0_generator::Stage0Options {
        switchroot_fs: provider.switchroot_fs(),
        kernel_modules,
        inject_mac: profile_stage0.inject_mac.clone(),
        kernel_override: profile_source_overrides.kernel_override,
        abl_exorcist: abl_exorcist_image
            .map(|image| fastboop_stage0_generator::Stage0AblExorcist { image }),
        dtb_override: cli_dtb_override.or(profile_source_overrides.dtb_override),
        dtbo_overlays,
        enable_serial: config.serial,
        mimic_fastboot: config.impersonate_fastboot,
        smoo_vendor: detected_device.map(|device| device.vid),
        smoo_product: detected_device.map(|device| device.pid),
        stage0_serial: detected_device.and_then(|device| device.serial.clone()),
        personalization,
    };

    let effective_ostree_arg = resolve_effective_ostree_arg(&config.ostree, selected_boot_profile);
    let selected_ostree = match &effective_ostree_arg {
        OstreeArg::Disabled => None,
        OstreeArg::AutoDetect => {
            let detected = auto_detect_ostree_deployment_path(&provider).await?;
            debug!(ostree = %detected, "auto-detected ostree deployment path");
            Some(detected)
        }
        OstreeArg::Explicit(path) => Some(path.clone()),
    };

    let extra_cmdline = build_stage0_extra_cmdline(Stage0ExtraCmdline {
        selected_ostree: selected_ostree.as_deref(),
        profile_cmdline: profile_stage0.extra_cmdline.as_deref(),
        requested_cmdline: cli_cmdline_append.as_deref(),
        system_time: system_time_part,
        smoo_queue_count: config.smoo_queue_count,
        smoo_queue_depth: config.smoo_queue_depth,
        smoo_max_io: config.smoo_max_io,
        default_smoo_max_io: DEFAULT_SMOO_MAX_IO_BYTES,
    });

    let build = if let Some(ostree) = selected_ostree.as_deref() {
        let resolved_ostree = OstreeRootfs::resolve_deployment_path(&provider, ostree)
            .await
            .map_err(|err| anyhow!("resolve ostree deployment path {ostree}: {err}"))?;
        debug!(ostree = %ostree, resolved_ostree = %resolved_ostree, "resolved ostree deployment path");
        let provider = OstreeRootfs::new(provider, &resolved_ostree)
            .map_err(|err| anyhow!("initialize ostree filesystem view: {err}"))?;
        build_stage0(
            profile,
            &provider,
            &opts,
            stage0_binary_ready(stage0_binary.clone()),
            extra_cmdline.as_deref(),
            existing.as_deref(),
        )
        .await
    } else {
        build_stage0(
            profile,
            &provider,
            &opts,
            stage0_binary_ready(stage0_binary.clone()),
            extra_cmdline.as_deref(),
            existing.as_deref(),
        )
        .await
    };

    Ok(Stage0Artifacts {
        block_reader: export.reader,
        image_size_bytes: export.size_bytes,
        image_identity: export.identity,
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
                if let Some(fastboot) = probe_arrived_device(profile, device).await? {
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
                        tracing::info!(
                            profile = %profile.id,
                            "waiting for fastboot device matching profile"
                        );
                    } else {
                        tracing::info!(
                            profile = %profile.id,
                            wait_seconds = wait.as_secs(),
                            "waiting for fastboot device matching profile"
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
                if let Some(resolved) = probe_arrived_device_auto(profiles, device).await? {
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
                        tracing::info!("waiting for fastboot device matching any profile");
                    } else {
                        tracing::info!(
                            wait_seconds = wait.as_secs(),
                            "waiting for fastboot device matching any profile"
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
            tracing::info!(
                %err,
                vid = %format!("{vid:04x}"),
                pid = %format!("{pid:04x}"),
                "skipping fastboot device after open failure"
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
            tracing::info!(
                %err,
                vid = %format!("{vid:04x}"),
                pid = %format!("{pid:04x}"),
                "skipping fastboot device after open failure"
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

fn log_detected_device(profile: &DeviceProfile, device: Option<&DetectedFastbootInfo>) {
    let Some(device) = device else {
        return;
    };
    tracing::info!(
        vid = %format!("{:04x}", device.vid),
        pid = %format!("{:04x}", device.pid),
        serial = device.serial.as_deref().unwrap_or("unknown"),
        profile = %profile.id,
        "detected fastboot device"
    );
}

fn log_smoo_event(event: SmooHostEvent) {
    match event {
        SmooHostEvent::Phase { phase, detail } => {
            tracing::info!(phase = ?phase, detail = %detail, "smoo host phase");
        }
        SmooHostEvent::Log(line) => tracing::info!(message = %line, "smoo host"),
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
        } => tracing::debug!(
            active,
            export_count,
            session_id,
            ios_up,
            ios_down,
            bytes_up,
            bytes_down,
            inflight_requests,
            max_inflight_requests,
            "smoo host status"
        ),
    }
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

#[cfg(test)]
mod initrd_tests {
    use super::*;
    use async_trait::async_trait;
    use fastboop_core::{BootProfileManifest, BootSpec, KernelEncoding, Stage0KernelOverride};
    use gibblox_core::{GibbloxResult, ReadContext};
    use std::sync::Arc;

    struct UnreadRoot;

    #[async_trait]
    impl BlockReader for UnreadRoot {
        fn block_size(&self) -> u32 {
            512
        }
        async fn total_blocks(&self) -> GibbloxResult<u64> {
            Ok(8)
        }
        async fn read_blocks(&self, _: u64, _: &mut [u8], _: ReadContext) -> GibbloxResult<usize> {
            panic!("supplied artifacts must not trigger stage0 rootfs/module discovery");
        }
        fn write_identity(&self, out: &mut dyn std::fmt::Write) -> std::fmt::Result {
            out.write_str("test:root")
        }
    }

    fn fixture() -> (DeviceProfile, ResolvedBootInput) {
        let mut device = fastboop_core::builtin::builtin_profiles()
            .unwrap()
            .remove(0);
        device.boot.fastboot_boot.android_bootimg.kernel.encoding = KernelEncoding::Image;
        device.boot.fastboot_boot.android_bootimg.header_version = 2;
        device.boot.fastboot_boot.android_bootimg.base = None;
        device.boot.fastboot_boot.android_bootimg.ramdisk_offset = Some(0x04000000);
        device.boot.fastboot_boot.android_bootimg.cmdline_append = Some("console=tty0".into());
        let manifest: BootProfileManifest = serde_yaml::from_str(
            r#"
id: supplied
boot: initrd
rootfs:
  ext4:
    file: root.ext4
extra_cmdline: "rd.smoo.cow.size=2G ostree=true"
"#,
        )
        .unwrap();
        let profile = manifest
            .compile_dt_overlays(|_| Ok::<_, anyhow::Error>(Vec::new()))
            .unwrap();
        let reader: Arc<dyn BlockReader> = Arc::new(UnreadRoot);
        let input = ChannelInput {
            boot_spec: BootSpec::new(device.clone(), Some(profile)),
            reader: reader.clone(),
            stage0_readers: Vec::new(),
        };
        let resolved = ResolvedBootInput {
            input,
            sources: BootProfileSourceOverrides {
                kernel_override: Some(Stage0KernelOverride {
                    path: "/kernel".into(),
                    image: vec![0x5a; 128],
                }),
                initrd_override: Some(b"opaque supplied initrd".to_vec()),
                dtb_override: None,
            },
            export: RuntimeExport {
                reader,
                size_bytes: 4096,
                identity: "test:root".into(),
            },
        };
        (device, resolved)
    }

    #[tokio::test]
    async fn supplied_initrd_build_matches_registered_export_without_stage0() {
        let (device, resolved) = fixture();
        let mut sources = std::collections::BTreeMap::new();
        let mut entries = Vec::new();
        let source = fastboop_smoo_gibblox::GibbloxBlockSource::new(
            resolved.export.reader.clone(),
            resolved.export.identity.clone(),
        );
        smoo_host_core::register_export(
            &mut sources,
            &mut entries,
            smoo_host_core::BlockSourceHandle::new(source, resolved.export.identity.clone()),
            resolved.export.identity.clone(),
            512,
            4096,
        )
        .unwrap();
        let mut config = NativeBootStage0Config::from_raw_ostree("unused".into(), None).unwrap();
        config.impersonate_fastboot = false;
        let prepared = build_native_initrd_boot(&config, &device, resolved, None, None)
            .await
            .unwrap();
        let bytes = &prepared.boot_image;
        let u32_at =
            |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        assert_eq!(&bytes[..8], b"ANDROID!");
        assert_eq!(u32_at(20), 0x04000000);
        let page = u32_at(36);
        assert_eq!(&bytes[page..page + 128], &[0x5a; 128]);
        let initrd_offset = page + u32_at(8).div_ceil(page) * page;
        assert_eq!(
            &bytes[initrd_offset..initrd_offset + u32_at(16)],
            b"opaque supplied initrd"
        );
        let cmdline = std::str::from_utf8(&bytes[64..576])
            .unwrap()
            .trim_end_matches('\0');
        assert!(
            cmdline.contains(&format!("rd.smoo.root={}", entries[0].export_id)),
            "{cmdline}"
        );
        assert!(cmdline.contains("rd.smoo.mimic_fastboot=0"));
        assert!(cmdline.contains("rd.smoo.cow=1"));
        assert!(cmdline.contains("rd.smoo.cow.size=2G ostree=true"));
        assert_eq!(prepared.export.identity, "test:root");
        assert_eq!(prepared.export.size_bytes, 4096);
    }

    #[tokio::test]
    async fn initrd_rejects_invalid_invocations_before_device_wait_or_artifact_io() {
        let (device, resolved) = fixture();
        let mut profile = resolved.input.boot_spec.boot_profile().unwrap().clone();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("fastboop-stage0-reject-{nonce}"));
        std::fs::create_dir(&dir).unwrap();
        profile.rootfs =
            fastboop_core::BootProfileRootfs::Ext4(fastboop_core::BootProfileRootfsExt4Source {
                ext4: fastboop_core::BootProfileArtifactSource::File(
                    fastboop_core::BootProfileArtifactSourceFileSource {
                        file: dir.join("missing.ext4").to_string_lossy().into_owned(),
                        content: Some(gibblox_pipeline::PipelineSourceContent {
                            digest: format!("sha512:{}", "1".repeat(128)),
                            size_bytes: 4096,
                        }),
                    },
                ),
            });
        let artifact = fastboop_core::BootProfileArtifactPathSource {
            path: "/artifact".into(),
            source: profile.rootfs.clone(),
        };
        profile.kernel = Some(artifact.clone());
        profile.initrd = Some(artifact);
        let channel = dir.join("profile.fbp");
        std::fs::write(
            &channel,
            fastboop_core::encode_boot_profile(&profile).unwrap(),
        )
        .unwrap();
        let mut config = NativeBootStage0Config::from_raw_ostree(channel, None).unwrap();
        config.device_profile = Some(device.id);
        let result = build_stage0_initrd(config.clone()).await;
        assert_eq!(
            result.err().unwrap().to_string(),
            "fastboop stage0 cannot build a boot: initrd profile; use fastboop boot"
        );
        for option in [
            "--augment",
            "--stage0",
            "--require-module",
            "--serial",
            "OSTree",
            "--abl-exorcist",
        ] {
            for (boot_device, auto_detect) in [(false, false), (true, false), (true, true)] {
                let mut stage0 = config.clone();
                if auto_detect {
                    stage0.device_profile = None;
                }
                match option {
                    "--augment" => stage0.augment = Some("missing.cpio".into()),
                    "--stage0" => stage0.stage0 = Some("missing-stage0".into()),
                    "--require-module" => stage0.require_modules.push("dummy".into()),
                    "--serial" => stage0.serial = true,
                    "OSTree" => stage0.ostree = OstreeArg::AutoDetect,
                    "--abl-exorcist" => stage0.abl_exorcist = Some("missing-shim".into()),
                    _ => unreachable!(),
                }
                let mut environment = NativeBootEnvironment::new(
                    NativeBootConfig {
                        stage0,
                        boot_device,
                        system_time: false,
                        systemd_firstboot: false,
                        wait: Duration::ZERO,
                        smoo_metrics_port: 0,
                    },
                    CancellationToken::new(),
                );
                let error =
                    tokio::time::timeout(Duration::from_secs(1), environment.prepare_boot())
                        .await
                        .expect("invalid invocation must not wait for a device")
                        .err()
                        .expect("unsupported option should fail")
                        .to_string();
                assert!(error.contains(option), "{option}: {error}");
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn early_validation_respects_mixed_strategies_and_device_specific_settings() {
        let (initrd_device, resolved) = fixture();
        let mut stage0_device = initrd_device.clone();
        stage0_device.id = "stage0-device".into();
        let mut initrd = resolved.input.boot_spec.boot_profile().unwrap().clone();
        initrd
            .stage0
            .devices
            .insert(initrd_device.id.clone(), Default::default());
        let mut stage0 = initrd.clone();
        stage0.id = "generated".into();
        stage0.boot = BootStrategy::Stage0;
        stage0.stage0.devices.clear();
        stage0
            .stage0
            .devices
            .insert(stage0_device.id.clone(), Default::default());
        let channel = fastboop_core::Channel::new(
            None,
            fastboop_core::ChannelStreamHead {
                boot_profiles: vec![initrd.clone(), stage0],
                ..Default::default()
            },
        );
        let mut config = NativeBootStage0Config::from_raw_ostree("unused".into(), None).unwrap();
        config.augment = Some("stage0-extra.cpio".into());
        let candidates = [initrd_device.clone(), stage0_device.clone()];
        validate_native_boot_candidates(&config, &channel, &candidates).unwrap();
        validate_native_boot_candidates(&config, &channel, &[stage0_device]).unwrap();
        assert!(
            validate_native_boot_candidates(
                &config,
                &channel,
                std::slice::from_ref(&initrd_device)
            )
            .is_err()
        );
        config.boot_profile = Some(initrd.id.clone());
        assert!(validate_native_boot_candidates(&config, &channel, &candidates).is_err());
        let reversed = [candidates[1].clone(), candidates[0].clone()];
        assert!(
            validate_native_boot_candidates(&config, &channel, &reversed)
                .unwrap_err()
                .to_string()
                .contains("--augment")
        );

        config.augment = None;
        initrd
            .stage0
            .devices
            .get_mut(&initrd_device.id)
            .unwrap()
            .stage0
            .kernel_modules
            .push("dummy".into());
        let channel = fastboop_core::Channel::new(
            None,
            fastboop_core::ChannelStreamHead {
                boot_profiles: vec![initrd],
                ..Default::default()
            },
        );
        let err = validate_native_boot_candidates(&config, &channel, &[initrd_device]).unwrap_err();
        assert!(err.to_string().contains("stage0.kernel_modules"));
    }

    #[tokio::test]
    async fn supplied_initrd_rejects_stage0_only_options() {
        let (device, resolved) = fixture();
        let mut config = NativeBootStage0Config::from_raw_ostree("unused".into(), None).unwrap();
        config.augment = Some("must-not-open.cpio".into());
        let result = build_native_initrd_boot(&config, &device, resolved, None, None).await;
        assert!(result.err().unwrap().to_string().contains("--augment"));
    }
}
