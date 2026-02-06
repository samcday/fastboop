use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Args;
use fastboop_core::DeviceProfile;
use fastboop_core::device::DeviceEvent;
use fastboop_core::prober::probe_candidates;
use fastboop_fastboot_rusb::DeviceWatcher;
use rusb::{Context as UsbContext, UsbContext as _};
use tracing::{debug, info};

use crate::devpros::{dedup_profiles, load_device_profiles, resolve_devpro_dirs};

use super::{RusbCandidate, format_probe_error};

#[derive(Args)]
pub struct DetectArgs {
    /// Wait up to N seconds for a matching device (0 = infinite).
    #[arg(long, default_value_t = 0)]
    pub wait: u64,
}

pub fn run_detect(args: DetectArgs) -> Result<()> {
    let devpro_dirs = resolve_devpro_dirs()?;
    let profiles = load_device_profiles(&devpro_dirs)?;
    let profiles = dedup_profiles(&profiles);
    let profiles: Vec<DeviceProfile> = profiles.into_iter().cloned().collect();
    let mut profiles_by_id = HashMap::new();
    for profile in &profiles {
        profiles_by_id.insert(profile.id.clone(), profile);
    }

    let context = UsbContext::new().context("creating USB context")?;

    let wait = Duration::from_secs(args.wait);
    let deadline = if wait.is_zero() {
        None
    } else {
        Some(Instant::now() + wait)
    };
    let (tx, rx) = std::sync::mpsc::channel::<DeviceEvent>();
    let _watcher = DeviceWatcher::new(Box::new(move |event| {
        let _ = tx.send(event);
    }))
    .context("starting USB hotplug watcher")?;

    let mut waiting = false;
    loop {
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

        let reports = pollster::block_on(probe_candidates(&profiles, &candidates));
        let mut found = false;
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
                let Some(profile) = profiles_by_id.get(&attempt.profile_id) else {
                    continue;
                };
                match attempt.result {
                    Ok(()) => {
                        found = true;
                        print_detected(device, profile, vid, pid);
                    }
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

        if found {
            return Ok(());
        }

        if !waiting {
            waiting = true;
            if wait.is_zero() {
                eprintln!("No matching fastboot devices detected. Waiting for devices...");
            } else {
                eprintln!(
                    "No matching fastboot devices detected. Waiting up to {}s...",
                    wait.as_secs()
                );
            }
        }

        if let Some(deadline) = deadline {
            let now = Instant::now();
            if now >= deadline {
                eprintln!("No matching fastboot devices detected.");
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(now);
            let timeout = remaining.min(Duration::from_secs(1));
            match rx.recv_timeout(timeout) {
                Ok(event) => info!(?event, "usb device hotplug event"),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    eprintln!("USB watcher disconnected.");
                    return Ok(());
                }
            }
        } else {
            match rx.recv() {
                Ok(event) => info!(?event, "usb device hotplug event"),
                Err(_) => {
                    eprintln!("USB watcher disconnected.");
                    return Ok(());
                }
            }
        }
    }
}

fn print_detected(device: &rusb::Device<UsbContext>, profile: &DeviceProfile, vid: u16, pid: u16) {
    let name = profile.display_name.as_deref().unwrap_or("unknown");
    println!(
        "{:04x}:{:04x} bus={} addr={} profile={} name=\"{}\"",
        vid,
        pid,
        device.bus_number(),
        device.address(),
        profile.id,
        name
    );
}
