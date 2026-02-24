use std::collections::HashMap;
use std::task::Poll;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Args;
use fastboop_core::DeviceProfile;
use fastboop_core::device::{DeviceEvent, DeviceHandle as _, DeviceWatcher as _, profile_filters};
use fastboop_core::prober::probe_candidates;
use fastboop_fastboot_rusb::{DeviceWatcher, RusbDeviceHandle};
use tracing::{debug, trace};

use crate::devpros::{dedup_profiles, load_device_profiles, resolve_devpro_dirs};

use super::format_probe_error;

const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Args)]
pub struct DetectArgs {
    /// Restrict probing to this device profile id.
    #[arg(long)]
    pub device_profile: Option<String>,

    /// Wait up to N seconds for a matching device (0 = infinite).
    #[arg(long, default_value_t = 0)]
    pub wait: u64,
}

pub async fn run_detect(args: DetectArgs) -> Result<()> {
    let devpro_dirs = resolve_devpro_dirs()?;
    let profiles = load_device_profiles(&devpro_dirs)?;
    let profiles = match args.device_profile.as_deref() {
        Some(requested) => {
            let mut ids: Vec<_> = profiles.keys().cloned().collect();
            ids.sort();
            let Some(profile) = profiles.get(requested) else {
                bail!(
                    "device profile '{}' not found in {:?}; available ids: {:?}",
                    requested,
                    devpro_dirs,
                    ids
                )
            };
            vec![profile]
        }
        None => dedup_profiles(&profiles),
    };
    let profiles: Vec<DeviceProfile> = profiles.into_iter().cloned().collect();
    let mut profiles_by_id = HashMap::new();
    for profile in &profiles {
        profiles_by_id.insert(profile.id.clone(), profile);
    }

    let filters = profile_filters(&profiles);
    let mut watcher = DeviceWatcher::new(&filters).context("starting USB hotplug watcher")?;

    let wait = Duration::from_secs(args.wait);
    let deadline = if wait.is_zero() {
        None
    } else {
        Some(Instant::now() + wait)
    };

    let mut waiting = false;
    loop {
        match watcher.try_next_event() {
            Poll::Ready(Ok(DeviceEvent::Arrived { device })) => {
                if handle_arrived_device(&profiles, &profiles_by_id, device).await {
                    return Ok(());
                }
            }
            Poll::Ready(Ok(DeviceEvent::Left { .. })) => {}
            Poll::Ready(Err(err)) => {
                eprintln!("USB watcher disconnected: {err}");
                return Ok(());
            }
            Poll::Pending => {
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
                    tokio::time::sleep(remaining.min(IDLE_POLL_INTERVAL)).await;
                } else {
                    tokio::time::sleep(IDLE_POLL_INTERVAL).await;
                }
            }
        }
    }
}

async fn handle_arrived_device(
    profiles: &[DeviceProfile],
    profiles_by_id: &HashMap<String, &DeviceProfile>,
    device: RusbDeviceHandle,
) -> bool {
    trace!(
        vid = %format!("{:04x}", device.vid()),
        pid = %format!("{:04x}", device.pid()),
        "usb device hotplug event"
    );

    let candidates = [device];
    let reports = probe_candidates(profiles, &candidates).await;
    let mut found = false;
    for report in reports {
        let candidate = &candidates[report.candidate_index];
        let vid = report.vid;
        let pid = report.pid;
        if let Some(err) = report.open_error {
            eprintln!("Skipping {vid:04x}:{pid:04x}: open failed: {err}");
            continue;
        }
        for attempt in report.attempts {
            let Some(profile) = profiles_by_id.get(&attempt.profile_id) else {
                continue;
            };
            match attempt.result {
                Ok(()) => {
                    found = true;
                    print_detected(profile, candidate.vid(), candidate.pid());
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
        }
    }

    found
}

fn print_detected(profile: &DeviceProfile, vid: u16, pid: u16) {
    let name = profile.display_name.as_deref().unwrap_or("unknown");
    println!(
        "{:04x}:{:04x} profile={} name=\"{}\"",
        vid, pid, profile.id, name
    );
}
