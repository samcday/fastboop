use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::Args;
use fastboop_core::bootimg::build_android_bootimg;
use fastboop_core::fastboot::{boot, download};
use fastboop_core::prober::probe_candidates;
use fastboop_stage0::{Stage0Options, build_stage0};
use fastboop_transport_fastboot_rusb::FastbootRusb;
use rusb::{Context as UsbContext, UsbContext as _};
use tracing::debug;

use crate::devpros::{load_device_profiles, resolve_devpro_dirs};
use crate::personalization::personalization_from_host;

use super::{
    DirectoryRootfs, RusbCandidate, Stage0Args, ensure_smoo_source, format_probe_error,
    read_dtbo_overlays, read_existing_initrd,
};

#[derive(Args)]
pub struct BootArgs {
    #[command(flatten)]
    pub stage0: Stage0Args,
    /// Write boot image to a file and skip device detection/boot.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Append host time to cmdline as systemd.clock_usec=... (use --system-time=false to disable).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub system_time: bool,
    /// Append systemd-firstboot credentials (use --systemd-firstboot=false to disable).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub systemd_firstboot: bool,
}

pub fn run_boot(args: BootArgs) -> Result<()> {
    let devpro_dirs = resolve_devpro_dirs()?;
    let profiles = load_device_profiles(&devpro_dirs)?;
    let profile = profiles
        .get(&args.stage0.device_profile)
        .or_else(|| profiles.get(&format!("file:{}", args.stage0.device_profile)));
    let profile = profile.with_context(|| {
        let mut ids: Vec<_> = profiles
            .keys()
            .filter(|k| !k.starts_with("file:"))
            .cloned()
            .collect();
        ids.sort();
        format!(
            "device profile '{}' not found in {:?}; available ids: {:?}",
            args.stage0.device_profile, devpro_dirs, ids
        )
    })?;

    let mut fastboot = if args.output.is_none() {
        let context = UsbContext::new().context("creating USB context")?;
        let devices = context.devices().context("enumerating USB devices")?;
        let mut candidates = Vec::new();
        for device in devices.iter() {
            let desc = match device.device_descriptor() {
                Ok(desc) => desc,
                Err(err) => {
                    eprintln!("Skipping USB device: unable to read descriptor: {err}");
                    continue;
                }
            };
            candidates.push(RusbCandidate::new(
                device,
                desc.vendor_id(),
                desc.product_id(),
            ));
        }

        let profiles = vec![profile.clone()];
        let reports = pollster::block_on(probe_candidates(&profiles, &candidates));
        let mut matched_indices = Vec::new();
        for report in reports {
            let candidate = &candidates[report.candidate_index];
            let device = candidate.device();
            let vid = report.vid;
            let pid = report.pid;
            if let Some(err) = report.open_error {
                eprintln!(
                    "Skipping {:04x}:{:04x} bus={} addr={}: open failed: {err}",
                    vid,
                    pid,
                    device.bus_number(),
                    device.address()
                );
                continue;
            }
            for attempt in report.attempts {
                match attempt.result {
                    Ok(()) => matched_indices.push(report.candidate_index),
                    Err(err) => {
                        debug!(
                            profile_id = %profile.id,
                            vid = %format!("{:04x}", vid),
                            pid = %format!("{:04x}", pid),
                            bus = device.bus_number(),
                            addr = device.address(),
                            error = %format_probe_error(err),
                            "fastboot probe failed"
                        );
                    }
                }
            }
        }

        let idx = match matched_indices.len() {
            0 => bail!(
                "no matching fastboot device found for profile {}",
                profile.id
            ),
            1 => matched_indices[0],
            _ => bail!(
                "multiple fastboot devices matched profile {}; please connect only one",
                profile.id
            ),
        };

        let candidate = &candidates[idx];
        let fastboot = FastbootRusb::open(candidate.device()).map_err(|err| {
            anyhow::anyhow!(
                "open failed for {:04x}:{:04x} bus={} addr={}: {err}",
                candidate.vid,
                candidate.pid,
                candidate.device().bus_number(),
                candidate.device().address()
            )
        })?;

        Some(fastboot)
    } else {
        None
    };

    let dtb_override = match &args.stage0.dtb {
        Some(path) => {
            Some(std::fs::read(path).with_context(|| format!("reading dtb {}", path.display()))?)
        }
        None => None,
    };

    let dtbo_overlays = read_dtbo_overlays(&args.stage0.dtbo)?;
    let opts = Stage0Options {
        extra_modules: args.stage0.require_modules,
        dtb_override,
        dtbo_overlays,

        enable_serial: args.stage0.serial,
        personalization: args.systemd_firstboot.then(personalization_from_host),
    };

    let existing = read_existing_initrd(&args.stage0.augment)?;
    ensure_smoo_source(&args.stage0.smoo, &existing)?;

    let provider = DirectoryRootfs {
        root: args.stage0.rootfs,
        smoo: args.stage0.smoo,
    };

    let mut extra_parts = Vec::new();
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

    let build = build_stage0(
        profile,
        &provider,
        &opts,
        extra_cmdline.as_deref(),
        existing.as_deref(),
    )
    .map_err(|e| anyhow::anyhow!("stage0 build failed: {:?}", e))?;

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
    let mut profile = profile.clone();
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

    if let Some(path) = args.output {
        std::fs::write(&path, &bootimg)
            .with_context(|| format!("writing bootimg to {}", path.display()))?;
        eprintln!("Wrote boot image to {}", path.display());
        return Ok(());
    }

    let mut fastboot = fastboot
        .take()
        .expect("fastboot device probed when no --output");

    pollster::block_on(download(&mut fastboot, &bootimg))
        .map_err(|e| anyhow::anyhow!("fastboot download failed: {e}"))?;
    pollster::block_on(boot(&mut fastboot))
        .map_err(|e| anyhow::anyhow!("fastboot boot failed: {e}"))?;
    Ok(())
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
