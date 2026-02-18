use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{io::IsTerminal, thread};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use fastboop_core::DeviceProfile;
use fastboop_core::bootimg::build_android_bootimg;
use fastboop_core::device::{DeviceEvent, DeviceHandle as _, DeviceWatcher as _, profile_filters};
use fastboop_core::fastboot::{FastbootSession, profile_matches_vid_pid};
use fastboop_core::fastboot::{boot, download};
use fastboop_fastboot_rusb::{DeviceWatcher, FastbootRusb, RusbDeviceHandle};
use fastboop_rootfs_erofs::{ErofsRootfs, OstreeRootfs, normalize_ostree_deployment_path};
use fastboop_stage0_generator::{Stage0Options, build_stage0};
use gibblox_cache::CachedBlockReader;
use gibblox_cache_store_std::StdCacheOps;
use gibblox_core::{BlockReader, block_identity_string};
use gibblox_file::StdFileBlockReader;
use gibblox_http::HttpBlockReader;
use gibblox_zip::ZipEntryBlockReader;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use url::Url;

use crate::boot_ui::{BootEvent, BootPhase, timestamp_hms};
use crate::devpros::{dedup_profiles, load_device_profiles, resolve_devpro_dirs};
use crate::personalization::personalization_from_host;
use crate::smoo_host::run_host_daemon;
use crate::tui::{TuiOutcome, run_boot_tui};

use super::{format_probe_error, read_dtbo_overlays, read_existing_initrd};

const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(100);

struct DetectedFastbootDevice {
    fastboot: FastbootRusb,
    vid: u16,
    pid: u16,
    serial: Option<String>,
}

struct ResolvedDetectedFastbootDevice {
    profile: DeviceProfile,
    device: DetectedFastbootDevice,
}

#[derive(Args)]
pub struct BootStage0Args {
    /// Path or HTTP(S) URL to EROFS image containing kernel/modules.
    #[arg(value_name = "ROOTFS")]
    pub rootfs: PathBuf,
    /// Resolve kernel/modules inside this OSTree deployment path.
    #[arg(long, value_name = "PATH")]
    pub ostree: Option<String>,
    /// Device profile id to use. If omitted, fastboop auto-probes matching profiles.
    #[arg(long)]
    pub device_profile: Option<String>,
    /// Override DTB path (host path).
    #[arg(long)]
    pub dtb: Option<PathBuf>,
    /// DTBO overlay to apply (repeatable).
    #[arg(long)]
    pub dtbo: Vec<PathBuf>,
    /// Existing initrd (cpio newc) to augment.
    #[arg(long)]
    pub augment: Option<PathBuf>,
    /// Extra required modules (repeatable).
    #[arg(long = "require-module")]
    pub require_modules: Vec<String>,
    /// Extra kernel cmdline to append after generated stage0 arguments.
    #[arg(long, alias = "cmdline")]
    pub cmdline_append: Option<String>,
    /// Enable CDC-ACM gadget (smoo.acm=1) and include usb_f_acm.
    #[arg(long)]
    pub serial: bool,
}

#[derive(Args)]
pub struct BootArgs {
    #[command(flatten)]
    pub stage0: BootStage0Args,
    /// Write boot image to a file and skip device detection/boot.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Append host time to cmdline as systemd.clock_usec=... (use --system-time=false to disable).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub system_time: bool,
    /// Append systemd-firstboot credentials (use --systemd-firstboot=false to disable).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub systemd_firstboot: bool,
    /// Wait up to N seconds for a matching device (0 = infinite).
    #[arg(long, default_value_t = 0)]
    pub wait: u64,
    /// Use plain line-oriented logs (disable TUI view).
    #[arg(long, default_value_t = false)]
    pub plain: bool,
}

pub async fn run_boot(args: BootArgs) -> Result<()> {
    let use_tui = !args.plain && std::io::stdout().is_terminal() && std::io::stderr().is_terminal();
    let (tx, rx) = std::sync::mpsc::channel::<BootEvent>();
    let shutdown = CancellationToken::new();
    let runtime = tokio::runtime::Handle::current();

    if use_tui {
        crate::setup_tui_tracing(tx.clone());
    } else {
        crate::setup_default_tracing();
    }

    let worker_shutdown = shutdown.clone();
    let worker = thread::spawn(move || run_boot_worker(args, tx, worker_shutdown, runtime));

    if use_tui {
        match run_boot_tui(&rx)? {
            TuiOutcome::Completed => {}
            TuiOutcome::Quit => {
                shutdown.cancel();
                eprintln!("Shutting down...");
            }
        }
    } else {
        run_plain_event_loop(&rx);
    }

    worker
        .join()
        .map_err(|_| anyhow::anyhow!("boot worker thread panicked"))?
}

fn run_boot_worker(
    args: BootArgs,
    events: Sender<BootEvent>,
    shutdown: CancellationToken,
    runtime: tokio::runtime::Handle,
) -> Result<()> {
    emit(
        &events,
        BootEvent::Phase {
            phase: BootPhase::Preparing,
            detail: "loading profiles".to_string(),
        },
    );
    let result = runtime.block_on(run_boot_inner(args, events.clone(), shutdown));
    match &result {
        Ok(()) => emit(&events, BootEvent::Finished),
        Err(err) => {
            emit(
                &events,
                BootEvent::Phase {
                    phase: BootPhase::Failed,
                    detail: err.to_string(),
                },
            );
            emit(&events, BootEvent::Failed(err.to_string()));
        }
    }
    result
}

async fn run_boot_inner(
    args: BootArgs,
    events: Sender<BootEvent>,
    shutdown: CancellationToken,
) -> Result<()> {
    let devpro_dirs = resolve_devpro_dirs()?;
    let profiles = load_device_profiles(&devpro_dirs)?;
    let mut profile = match args.stage0.device_profile.as_deref() {
        Some(requested) => Some(resolve_profile_by_id(&profiles, &devpro_dirs, requested)?),
        None => None,
    };

    if args.output.is_some() && profile.is_none() {
        bail!(
            "--device-profile is required when using --output; profile auto-detection needs a connected device"
        );
    }

    let mut detected_device = if args.output.is_none() {
        let wait = Duration::from_secs(args.wait);
        if let Some(selected_profile) = profile.as_ref() {
            emit(
                &events,
                BootEvent::Phase {
                    phase: BootPhase::WaitingForDevice,
                    detail: format!("profile={}", selected_profile.id),
                },
            );
            Some(wait_for_fastboot_device(selected_profile, wait, &events).await?)
        } else {
            let unique_profiles: Vec<DeviceProfile> =
                dedup_profiles(&profiles).into_iter().cloned().collect();
            emit(
                &events,
                BootEvent::Phase {
                    phase: BootPhase::WaitingForDevice,
                    detail: "profile=auto".to_string(),
                },
            );
            let resolved = wait_for_fastboot_device_auto(&unique_profiles, wait, &events).await?;
            profile = Some(resolved.profile);
            Some(resolved.device)
        }
    } else {
        None
    };

    let profile = profile.expect("profile resolved before build");

    if let Some(device) = &detected_device {
        let profile_detail = format!("profile={}", profile.id);
        emit(
            &events,
            BootEvent::Phase {
                phase: BootPhase::DeviceDetected,
                detail: format!(
                    "{:04x}:{:04x} {} {}",
                    device.vid,
                    device.pid,
                    device
                        .serial
                        .as_deref()
                        .map(|s| format!("serial={s}"))
                        .unwrap_or_else(|| "serial=unknown".to_string()),
                    profile_detail,
                ),
            },
        );
    }

    let dtb_override = match &args.stage0.dtb {
        Some(path) => {
            Some(std::fs::read(path).with_context(|| format!("reading dtb {}", path.display()))?)
        }
        None => None,
    };

    let dtbo_overlays = read_dtbo_overlays(&args.stage0.dtbo)?;
    let normalized_ostree = args
        .stage0
        .ostree
        .as_deref()
        .map(normalize_ostree_deployment_path)
        .transpose()?;
    let opts = Stage0Options {
        extra_modules: args.stage0.require_modules,
        dtb_override,
        dtbo_overlays,

        enable_serial: args.stage0.serial,
        mimic_fastboot: false,
        smoo_vendor: detected_device.as_ref().map(|device| device.vid),
        smoo_product: detected_device.as_ref().map(|device| device.pid),
        smoo_serial: detected_device
            .as_ref()
            .and_then(|device| device.serial.clone()),
        personalization: args.systemd_firstboot.then(personalization_from_host),
    };

    let existing = read_existing_initrd(&args.stage0.augment)?;

    let mut extra_parts = Vec::new();
    if let Some(ostree) = normalized_ostree.as_deref() {
        extra_parts.push(format!("ostree=/{ostree}"));
    }
    if let Some(cmdline) = args
        .stage0
        .cmdline_append
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        extra_parts.push(cmdline.to_string());
    }
    if args.system_time {
        extra_parts.push(system_time_cmdline()?);
    }
    let extra_cmdline = if extra_parts.is_empty() {
        None
    } else {
        Some(extra_parts.join(" "))
    };

    emit(
        &events,
        BootEvent::Phase {
            phase: BootPhase::BuildingStage0,
            detail: "building stage0 payload".to_string(),
        },
    );

    const DEFAULT_IMAGE_BLOCK_SIZE: u32 = 512;

    let (block_reader, image_size_bytes, image_identity, build) = {
        let rootfs_str = args.stage0.rootfs.to_string_lossy();

        // Build gibblox pipeline explicitly
        let reader: Arc<dyn BlockReader> =
            if rootfs_str.starts_with("http://") || rootfs_str.starts_with("https://") {
                // HTTP pipeline: HTTP → Cache
                let url = Url::parse(&rootfs_str)
                    .with_context(|| format!("parse rootfs URL {rootfs_str}"))?;
                let http_reader = HttpBlockReader::new(url.clone(), DEFAULT_IMAGE_BLOCK_SIZE)
                    .await
                    .map_err(|err| anyhow!("open HTTP reader {url}: {err}"))?;

                let cache = StdCacheOps::open_default_for_reader(&http_reader)
                    .await
                    .map_err(|err| anyhow!("open std cache: {err}"))?;
                let cached = CachedBlockReader::new(http_reader, cache)
                    .await
                    .map_err(|err| anyhow!("initialize std cache: {err}"))?;
                Arc::new(cached)
            } else {
                // File pipeline: File only
                let canonical = std::fs::canonicalize(&args.stage0.rootfs)
                    .with_context(|| format!("canonicalize {}", args.stage0.rootfs.display()))?;
                let file_reader = StdFileBlockReader::open(&canonical, DEFAULT_IMAGE_BLOCK_SIZE)
                    .map_err(|err| anyhow!("open file {}: {err}", canonical.display()))?;
                Arc::new(file_reader)
            };

        let reader: Arc<dyn BlockReader> = match zip_entry_name_from_rootfs(&rootfs_str)? {
            Some(entry_name) => {
                let zip_reader = ZipEntryBlockReader::new(&entry_name, reader)
                    .await
                    .map_err(|err| anyhow!("open ZIP entry {entry_name}: {err}"))?;
                Arc::new(zip_reader)
            }
            None => reader,
        };

        let total_blocks = reader.total_blocks().await?;
        let image_size_bytes = total_blocks * reader.block_size() as u64;
        let image_identity = block_identity_string(reader.as_ref());

        // Wrap in EROFS
        let provider = ErofsRootfs::new(reader.clone(), image_size_bytes).await?;

        let build = if let Some(ostree) = normalized_ostree.as_deref() {
            let resolved_ostree = OstreeRootfs::resolve_deployment_path(&provider, ostree).await?;
            debug!(ostree = %ostree, resolved_ostree = %resolved_ostree, "resolved ostree deployment path");
            let provider = OstreeRootfs::new(provider, &resolved_ostree)?;
            build_stage0(
                &profile,
                &provider,
                &opts,
                extra_cmdline.as_deref(),
                existing.as_deref(),
            )
            .await
        } else {
            build_stage0(
                &profile,
                &provider,
                &opts,
                extra_cmdline.as_deref(),
                existing.as_deref(),
            )
            .await
        };
        anyhow::Ok((reader, image_size_bytes, image_identity, build))
    }?;

    let build = build.map_err(|e| anyhow::anyhow!("stage0 build failed: {e:?}"))?;

    let cmdline = join_cmdline(
        profile
            .boot
            .fastboot_boot
            .android_bootimg
            .cmdline_append
            .as_deref(),
        Some(build.kernel_cmdline_append.as_str()),
    );

    let mut kernel_image = build.kernel_image;
    let mut profile = profile;
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
            debug!(
                from = header_version,
                to = 0,
                "downgrading android boot header for appended dtb"
            );
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
    .map_err(|e| anyhow::anyhow!("bootimg build failed: {e}"))?;

    emit(
        &events,
        BootEvent::Phase {
            phase: BootPhase::BuildingBootImage,
            detail: format!("boot image built ({} bytes)", bootimg.len()),
        },
    );

    if let Some(path) = args.output {
        std::fs::write(&path, &bootimg)
            .with_context(|| format!("writing bootimg to {}", path.display()))?;
        emit(
            &events,
            BootEvent::Log(format!("Wrote boot image to {}", path.display())),
        );
        return Ok(());
    }

    let mut fastboot = detected_device
        .take()
        .expect("fastboot device probed when no --output");

    emit(
        &events,
        BootEvent::Phase {
            phase: BootPhase::Downloading,
            detail: format!("sending {} bytes", bootimg.len()),
        },
    );

    download(&mut fastboot.fastboot, &bootimg)
        .await
        .map_err(|e| anyhow::anyhow!("fastboot download failed: {e}"))?;

    emit(
        &events,
        BootEvent::Phase {
            phase: BootPhase::Booting,
            detail: "issuing fastboot boot".to_string(),
        },
    );

    boot(&mut fastboot.fastboot)
        .await
        .map_err(|e| anyhow::anyhow!("fastboot boot failed: {e}"))?;

    run_host_daemon(
        block_reader,
        image_size_bytes,
        image_identity,
        events,
        shutdown,
    )
    .await
    .context("running smoo host daemon after boot")?;
    Ok(())
}

fn zip_entry_name_from_rootfs(rootfs: &str) -> Result<Option<String>> {
    let trimmed = rootfs.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let url = Url::parse(trimmed).with_context(|| format!("parse rootfs URL {trimmed}"))?;
        let file_name = url
            .path_segments()
            .and_then(|segments| segments.filter(|segment| !segment.is_empty()).next_back());
        return zip_entry_name_from_file_name(file_name);
    }

    let file_name = std::path::Path::new(trimmed)
        .file_name()
        .and_then(|name| name.to_str());
    zip_entry_name_from_file_name(file_name)
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

async fn wait_for_fastboot_device(
    profile: &DeviceProfile,
    wait: Duration,
    events: &Sender<BootEvent>,
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
                            BootEvent::Log(format!(
                                "Waiting for fastboot device matching profile {}...",
                                profile.id
                            )),
                        );
                    } else {
                        emit(
                            events,
                            BootEvent::Log(format!(
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
    events: &Sender<BootEvent>,
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
                            BootEvent::Log(
                                "Waiting for fastboot device matching any profile...".to_string(),
                            ),
                        );
                    } else {
                        emit(
                            events,
                            BootEvent::Log(format!(
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
    events: &Sender<BootEvent>,
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
                BootEvent::Log(format!("Skipping {vid:04x}:{pid:04x}: open failed: {err}")),
            );
            return Ok(None);
        }
    };

    let mut session = FastbootSession::new(&mut fastboot);
    match session.probe_profile(profile).await {
        Ok(()) => {
            return Ok(Some(DetectedFastbootDevice {
                fastboot,
                vid,
                pid,
                serial,
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
    events: &Sender<BootEvent>,
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
                BootEvent::Log(format!("Skipping {vid:04x}:{pid:04x}: open failed: {err}")),
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
                vid,
                pid,
                serial,
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

fn run_plain_event_loop(rx: &Receiver<BootEvent>) {
    while let Ok(event) = rx.recv() {
        print_plain_event(event);
    }
}

fn print_plain_event(event: BootEvent) {
    match event {
        BootEvent::Phase { phase, detail } => {
            eprintln!("[{}] phase={} {}", timestamp_hms(), phase.label(), detail);
        }
        BootEvent::Log(line) => {
            eprintln!("[{}] {line}", timestamp_hms());
        }
        BootEvent::SmooStatus {
            active,
            export_count,
            session_id,
        } => {
            let status = if active { "up" } else { "down" };
            eprintln!(
                "[{}] smoo status={} exports={} sid={}",
                timestamp_hms(),
                status,
                export_count,
                session_id
            );
        }
        BootEvent::GibbloxStats {
            hit_rate_pct,
            fill_rate_pct,
            cached_blocks,
            total_blocks,
        } => {
            eprintln!(
                "[{}] gibblox hit={}%% fill={}%% cache={}/{}",
                timestamp_hms(),
                hit_rate_pct,
                fill_rate_pct,
                cached_blocks,
                total_blocks
            );
        }
        BootEvent::Finished => {
            eprintln!("[{}] boot flow finished", timestamp_hms());
        }
        BootEvent::Failed(message) => {
            eprintln!("[{}] boot flow failed: {message}", timestamp_hms());
        }
    }
}

fn emit(events: &Sender<BootEvent>, event: BootEvent) {
    let _ = events.send(event);
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

fn resolve_profile_by_id(
    profiles: &HashMap<String, DeviceProfile>,
    devpro_dirs: &[PathBuf],
    requested: &str,
) -> Result<DeviceProfile> {
    profiles.get(requested).cloned().with_context(|| {
        let mut ids: Vec<_> = profiles.keys().cloned().collect();
        ids.sort();
        format!(
            "device profile '{}' not found in {:?}; available ids: {:?}",
            requested, devpro_dirs, ids
        )
    })
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
