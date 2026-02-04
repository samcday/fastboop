use std::collections::HashMap;

use anyhow::{Context, Result};
use fastboop_core::DeviceProfile;
use fastboop_core::prober::probe_candidates;
use rusb::{Context as UsbContext, UsbContext as _};
use tracing::debug;

use crate::devpros::{dedup_profiles, load_device_profiles, resolve_devpro_dirs};

use super::{RusbCandidate, format_probe_error};

pub fn run_detect() -> Result<()> {
    let devpro_dirs = resolve_devpro_dirs()?;
    let profiles = load_device_profiles(&devpro_dirs)?;
    let profiles = dedup_profiles(&profiles);
    let profiles: Vec<DeviceProfile> = profiles.into_iter().cloned().collect();
    let mut profiles_by_id = HashMap::new();
    for profile in &profiles {
        profiles_by_id.insert(profile.id.clone(), profile);
    }
    let context = UsbContext::new().context("creating USB context")?;
    let devices = context.devices().context("enumerating USB devices")?;
    let mut candidates = Vec::new();
    let mut found = false;
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

    if !found {
        eprintln!("No matching fastboot devices detected.");
    }
    Ok(())
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
