use std::collections::{HashMap, HashSet};

use dioxus::prelude::*;
use fastboop_core::builtin::builtin_profiles;
use fastboop_core::device::{profile_filters, DeviceEvent, DeviceHandle as _, DeviceWatcher as _};
use fastboop_core::prober::probe_candidates;
use fastboop_fastboot_rusb::{DeviceWatcher, RusbDeviceHandle};
use tracing::{debug, info};
use ui::{DetectedDevice, Hero, ProbeState, TransportKind};

#[component]
pub fn Home() -> Element {
    let mut watcher_started = use_signal(|| false);
    let candidates = use_signal(Vec::<RusbDeviceHandle>::new);

    use_effect(move || {
        if watcher_started() {
            return;
        }
        watcher_started.set(true);

        let filters = builtin_profiles()
            .map(|profiles| profile_filters(&profiles))
            .unwrap_or_default();
        let mut candidates = candidates;

        spawn(async move {
            let mut watcher = match DeviceWatcher::new(&filters) {
                Ok(watcher) => watcher,
                Err(err) => {
                    info!(%err, "desktop usb watcher unavailable");
                    return;
                }
            };

            loop {
                match watcher.next_event().await {
                    Ok(DeviceEvent::Arrived { device }) => {
                        let already_present = {
                            let current = candidates.read();
                            current.iter().any(|existing| {
                                existing.vid() == device.vid() && existing.pid() == device.pid()
                            })
                        };
                        if !already_present {
                            candidates.write().push(device);
                        }
                    }
                    Err(err) => {
                        info!(%err, "desktop usb watcher stopped");
                        break;
                    }
                }
            }
        });
    });

    let probe = use_resource(move || {
        let candidates = candidates();
        async move { probe_fastboot_devices(candidates).await }
    });

    let state = match probe() {
        Some(state) => state,
        None => ProbeState::Loading,
    };

    rsx! {
        Hero { state, on_connect: None }
    }
}

async fn probe_fastboot_devices(candidates: Vec<RusbDeviceHandle>) -> ProbeState {
    let profiles = match builtin_profiles() {
        Ok(profiles) => profiles,
        Err(_) => {
            return ProbeState::Ready {
                transport: TransportKind::NativeUsb,
                devices: Vec::new(),
            };
        }
    };
    let profiles_by_id: HashMap<_, _> = profiles
        .iter()
        .map(|profile| (profile.id.clone(), profile))
        .collect();

    debug!(
        candidates = candidates.len(),
        "desktop probe candidates queued"
    );
    let reports = probe_candidates(&profiles, &candidates).await;
    let mut seen = HashSet::new();
    let mut detected = Vec::new();
    for report in reports {
        let matched = report
            .attempts
            .iter()
            .find(|attempt| attempt.result.is_ok());
        let Some(matched) = matched else {
            continue;
        };
        let key = (report.vid, report.pid);
        if !seen.insert(key) {
            continue;
        }
        let name = profiles_by_id
            .get(&matched.profile_id)
            .and_then(|profile| profile.display_name.clone())
            .unwrap_or(matched.profile_id.clone());
        detected.push(DetectedDevice {
            vid: report.vid,
            pid: report.pid,
            name,
        });
    }

    ProbeState::Ready {
        transport: TransportKind::NativeUsb,
        devices: detected,
    }
}
