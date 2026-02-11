use std::collections::{HashMap, HashSet};

use dioxus::prelude::*;
use fastboop_core::builtin::builtin_profiles;
use fastboop_core::device::{profile_filters, DeviceEvent, DeviceHandle as _, DeviceWatcher as _};
use fastboop_core::prober::probe_candidates;
use fastboop_fastboot_rusb::{DeviceWatcher, RusbDeviceHandle};
use tracing::{debug, info};
use ui::{DetectedDevice, Hero, ProbeState, TransportKind};

use crate::Route;

use super::session::{next_session_id, DeviceSession, ProbedDevice, SessionPhase, SessionStore};

#[derive(Clone)]
struct ProbeSnapshot {
    state: ProbeState,
    devices: Vec<ProbedDevice>,
}

#[component]
pub fn Home() -> Element {
    let sessions = use_context::<SessionStore>();
    let navigator = use_navigator();

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
                    Ok(DeviceEvent::Left { device }) => {
                        candidates.write().retain(|candidate| {
                            candidate.vid() != device.vid() || candidate.pid() != device.pid()
                        });
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

    let snapshot = probe
        .read()
        .as_ref()
        .cloned()
        .unwrap_or_else(|| ProbeSnapshot {
            state: ProbeState::Loading,
            devices: Vec::new(),
        });

    let on_boot = {
        let mut sessions = sessions;
        let devices = snapshot.devices.clone();
        Some(EventHandler::new(move |index: usize| {
            let Some(device) = devices.get(index).cloned() else {
                return;
            };
            let session_id = next_session_id();
            sessions.write().push(DeviceSession {
                id: session_id.clone(),
                device,
                phase: SessionPhase::Booting {
                    step: "Queued".to_string(),
                    cache_stats: None,
                },
            });
            navigator.push(Route::DevicePage { session_id });
        }))
    };

    rsx! {
        Hero { state: snapshot.state, on_connect: None, on_boot }
    }
}

async fn probe_fastboot_devices(candidates: Vec<RusbDeviceHandle>) -> ProbeSnapshot {
    let profiles = match builtin_profiles() {
        Ok(profiles) => profiles,
        Err(_) => {
            return ProbeSnapshot {
                state: ProbeState::Ready {
                    transport: TransportKind::NativeUsb,
                    devices: Vec::new(),
                },
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
    let mut probed = Vec::new();
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
        let Some(profile) = profiles_by_id.get(&matched.profile_id) else {
            continue;
        };
        let Some(handle) = candidates.get(report.candidate_index).cloned() else {
            continue;
        };
        let name = profile
            .display_name
            .clone()
            .unwrap_or(matched.profile_id.clone());
        detected.push(DetectedDevice {
            vid: report.vid,
            pid: report.pid,
            name: name.clone(),
        });
        probed.push(ProbedDevice {
            handle,
            profile: (*profile).clone(),
            name,
            vid: report.vid,
            pid: report.pid,
            serial: candidates
                .get(report.candidate_index)
                .and_then(RusbDeviceHandle::usb_serial_number),
        });
    }

    ProbeSnapshot {
        state: ProbeState::Ready {
            transport: TransportKind::NativeUsb,
            devices: detected,
        },
        devices: probed,
    }
}
