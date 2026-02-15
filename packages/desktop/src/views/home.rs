use std::collections::{HashMap, HashSet};

use dioxus::prelude::*;
use fastboop_core::builtin::builtin_profiles;
use fastboop_core::device::{profile_filters, DeviceEvent, DeviceHandle as _, DeviceWatcher as _};
use fastboop_core::prober::probe_candidates;
use fastboop_core::DeviceProfile;
use fastboop_fastboot_rusb::{DeviceWatcher, RusbDeviceHandle};
use tracing::{debug, info};
use ui::{DetectedDevice, DetectedProfileOption, Hero, ProbeState, TransportKind};

use crate::Route;

use super::session::{next_session_id, DeviceSession, ProbedDevice, SessionPhase, SessionStore};

#[derive(Clone)]
struct ProbedProfileOption {
    profile: DeviceProfile,
    name: String,
}

#[derive(Clone)]
struct ProbedCandidateDevice {
    handle: RusbDeviceHandle,
    profile_options: Vec<ProbedProfileOption>,
    vid: u16,
    pid: u16,
    serial: Option<String>,
}

#[derive(Clone)]
struct ProbeSnapshot {
    state: ProbeState,
    devices: Vec<ProbedCandidateDevice>,
}

#[component]
pub fn Home() -> Element {
    let sessions = use_context::<SessionStore>();
    let navigator = use_navigator();

    let mut watcher_started = use_signal(|| false);
    let candidates = use_signal(Vec::<RusbDeviceHandle>::new);
    let selected_profiles = use_signal(HashMap::<(u16, u16), usize>::new);

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

    let state = {
        let mut state = snapshot.state.clone();
        if let ProbeState::Ready { devices, .. } = &mut state {
            let selections = selected_profiles.read();
            for device in devices.iter_mut() {
                device.selected_profile = selected_profile_index(
                    device.vid,
                    device.pid,
                    device.profile_options.len(),
                    &selections,
                );
            }
        }
        state
    };

    let on_select_profile = {
        let mut selected_profiles = selected_profiles;
        let devices = snapshot.devices.clone();
        Some(EventHandler::new(
            move |(device_index, profile_index): (usize, usize)| {
                let Some(device) = devices.get(device_index) else {
                    return;
                };
                if profile_index >= device.profile_options.len() {
                    return;
                }
                selected_profiles
                    .write()
                    .insert((device.vid, device.pid), profile_index);
            },
        ))
    };

    let on_boot = {
        let mut sessions = sessions;
        let devices = snapshot.devices.clone();
        let selected_profiles = selected_profiles;
        Some(EventHandler::new(move |index: usize| {
            let Some(device) = devices.get(index).cloned() else {
                return;
            };

            let profile_index = {
                let selections = selected_profiles.read();
                selected_profile_index(
                    device.vid,
                    device.pid,
                    device.profile_options.len(),
                    &selections,
                )
            };
            let Some(profile_index) = profile_index else {
                return;
            };
            let Some(profile) = device.profile_options.get(profile_index).cloned() else {
                return;
            };

            let session_id = next_session_id();
            sessions.write().push(DeviceSession {
                id: session_id.clone(),
                device: ProbedDevice {
                    handle: device.handle,
                    profile: profile.profile,
                    name: profile.name,
                    vid: device.vid,
                    pid: device.pid,
                    serial: device.serial,
                },
                phase: SessionPhase::Booting {
                    step: "Queued".to_string(),
                },
            });
            navigator.push(Route::DevicePage { session_id });
        }))
    };

    rsx! {
        Hero {
            state,
            on_connect: None,
            on_boot,
            on_select_profile,
        }
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
        let matched: Vec<_> = report
            .attempts
            .iter()
            .filter(|attempt| attempt.result.is_ok())
            .filter_map(|attempt| profiles_by_id.get(&attempt.profile_id).copied())
            .collect();
        if matched.is_empty() {
            continue;
        }
        let key = (report.vid, report.pid);
        if !seen.insert(key) {
            continue;
        }
        let Some(handle) = candidates.get(report.candidate_index).cloned() else {
            continue;
        };

        let mut profile_options = Vec::new();
        for profile in matched {
            let name = profile
                .display_name
                .clone()
                .unwrap_or_else(|| profile.id.clone());
            profile_options.push(ProbedProfileOption {
                profile: profile.clone(),
                name,
            });
        }
        profile_options.sort_by(|left, right| left.profile.id.cmp(&right.profile.id));
        let selected_profile = (profile_options.len() == 1).then_some(0);
        let name = if let Some(profile) = profile_options.first() {
            if profile_options.len() == 1 {
                profile.name.clone()
            } else {
                format!("{} profile matches", profile_options.len())
            }
        } else {
            continue;
        };

        let ui_profile_options = profile_options
            .iter()
            .map(|profile| DetectedProfileOption {
                profile_id: profile.profile.id.clone(),
                name: profile.name.clone(),
            })
            .collect();
        detected.push(DetectedDevice {
            vid: report.vid,
            pid: report.pid,
            name: name.clone(),
            profile_options: ui_profile_options,
            selected_profile,
        });
        probed.push(ProbedCandidateDevice {
            handle,
            profile_options,
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

fn selected_profile_index(
    vid: u16,
    pid: u16,
    option_count: usize,
    selections: &HashMap<(u16, u16), usize>,
) -> Option<usize> {
    if option_count == 1 {
        return Some(0);
    }
    selections
        .get(&(vid, pid))
        .copied()
        .filter(|index| *index < option_count)
}
