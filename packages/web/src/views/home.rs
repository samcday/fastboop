use std::collections::{HashMap, HashSet};

use dioxus::prelude::*;
use fastboop_core::DeviceProfile;
use fastboop_fastboot_webusb::WebUsbDeviceHandle;
#[cfg(target_arch = "wasm32")]
use js_sys::Reflect;
use ui::{DetectedDevice, DetectedProfileOption, Hero, ProbeState, TransportKind};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

use crate::Route;

use super::session::{next_session_id, DeviceSession, ProbedDevice, SessionPhase, SessionStore};

#[cfg(target_arch = "wasm32")]
use fastboop_core::builtin::builtin_profiles;
#[cfg(target_arch = "wasm32")]
use fastboop_core::device::{profile_filters, DeviceEvent, DeviceHandle as _, DeviceWatcher as _};
#[cfg(target_arch = "wasm32")]
use fastboop_core::prober::probe_candidates;
#[cfg(target_arch = "wasm32")]
use fastboop_fastboot_webusb::{request_device, DeviceWatcher};
#[cfg(target_arch = "wasm32")]
use tracing::{debug, info, warn};

#[derive(Clone)]
struct ProbedProfileOption {
    profile: DeviceProfile,
    name: String,
}

#[derive(Clone)]
struct ProbedCandidateDevice {
    handle: WebUsbDeviceHandle,
    profile_options: Vec<ProbedProfileOption>,
    vid: u16,
    pid: u16,
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
    let refresh = use_signal(|| 0u32);
    let selected_profiles = use_signal(HashMap::<(u16, u16), usize>::new);

    #[cfg(target_arch = "wasm32")]
    let candidates = use_signal(Vec::<WebUsbDeviceHandle>::new);

    #[cfg(target_arch = "wasm32")]
    let webusb_supported = webusb_supported();

    #[cfg(target_arch = "wasm32")]
    {
        let mut watcher_started = use_signal(|| false);
        let mut refresh = refresh;
        let mut candidates = candidates;

        use_effect(move || {
            if !webusb_supported {
                return;
            }
            if watcher_started() {
                return;
            }
            watcher_started.set(true);

            let profiles = load_profiles();
            let filters = profile_filters(&profiles);

            spawn(async move {
                let mut watcher = match DeviceWatcher::new(&filters) {
                    Ok(watcher) => watcher,
                    Err(err) => {
                        warn!(target: "fastboop::web::watcher", %err, "webusb watcher unavailable");
                        return;
                    }
                };
                info!(target: "fastboop::web::watcher", "webusb watcher started");

                loop {
                    match watcher.next_event().await {
                        Ok(DeviceEvent::Arrived { device }) => {
                            let exists = {
                                let current = candidates.read();
                                current.iter().any(|candidate| {
                                    candidate.vid() == device.vid()
                                        && candidate.pid() == device.pid()
                                })
                            };
                            if !exists {
                                candidates.write().push(device);
                                refresh.set(refresh().saturating_add(1));
                            }
                        }
                        Ok(DeviceEvent::Left { device }) => {
                            let mut removed = false;
                            candidates.write().retain(|candidate| {
                                let keep = candidate.vid() != device.vid()
                                    || candidate.pid() != device.pid();
                                removed |= !keep;
                                keep
                            });
                            if removed {
                                refresh.set(refresh().saturating_add(1));
                            }
                        }
                        Err(err) => {
                            warn!(target: "fastboop::web::watcher", %err, "webusb watcher stopped");
                            break;
                        }
                    }
                }
            });
        });
    }

    let probe = use_resource(move || {
        let refresh = refresh();
        #[cfg(target_arch = "wasm32")]
        {
            let webusb_supported = webusb_supported;
            let candidates = candidates();
            async move {
                let _ = refresh;
                if !webusb_supported {
                    return ProbeSnapshot {
                        state: ProbeState::Unsupported,
                        devices: Vec::new(),
                    };
                }
                probe_fastboot_devices(candidates).await
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            async move {
                let _ = refresh;
                ProbeSnapshot {
                    state: ProbeState::Unsupported,
                    devices: Vec::new(),
                }
            }
        }
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

    #[cfg(target_arch = "wasm32")]
    let on_connect: Option<EventHandler<MouseEvent>> = {
        if !webusb_supported {
            None
        } else {
            let refresh = refresh;
            let candidates = candidates;
            Some(EventHandler::new(move |_| {
                let profiles = load_profiles();
                let filters = profile_filters(&profiles);
                let mut refresh = refresh;
                let mut candidates = candidates;
                spawn(async move {
                    match request_device(&filters).await {
                        Ok(device) => {
                            let exists = {
                                let current = candidates.read();
                                current.iter().any(|candidate| {
                                    candidate.vid() == device.vid()
                                        && candidate.pid() == device.pid()
                                })
                            };
                            if !exists {
                                candidates.write().push(device);
                                refresh.set(refresh().saturating_add(1));
                            }
                        }
                        Err(err) => {
                            debug!(target: "fastboop::web::probe", %err, "webusb request device failed");
                        }
                    }
                });
            }))
        }
    };

    #[cfg(not(target_arch = "wasm32"))]
    let on_connect: Option<EventHandler<MouseEvent>> = None;

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
            on_connect,
            on_boot,
            on_select_profile,
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn load_profiles() -> Vec<fastboop_core::DeviceProfile> {
    builtin_profiles().unwrap_or_default()
}

#[cfg(target_arch = "wasm32")]
async fn probe_fastboot_devices(candidates: Vec<WebUsbDeviceHandle>) -> ProbeSnapshot {
    let profiles = load_profiles();
    let profiles_by_id: HashMap<_, _> = profiles
        .iter()
        .map(|profile| (profile.id.clone(), profile))
        .collect();

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
        });
    }

    ProbeSnapshot {
        state: ProbeState::Ready {
            transport: TransportKind::WebUsb,
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

#[cfg(target_arch = "wasm32")]
fn webusb_supported() -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    Reflect::has(window.navigator().as_ref(), &JsValue::from_str("usb")).unwrap_or(false)
}
