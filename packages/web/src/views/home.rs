#[cfg(target_arch = "wasm32")]
use std::collections::{HashMap, HashSet};

use dioxus::prelude::*;
#[cfg(target_arch = "wasm32")]
use ui::{DetectedDevice, TransportKind};
use ui::{Hero, ProbeState};

use crate::Route;

use super::session::{next_session_id, DeviceSession, ProbedDevice, SessionPhase, SessionStore};

#[cfg(target_arch = "wasm32")]
use fastboop_core::builtin::builtin_profiles;
#[cfg(target_arch = "wasm32")]
use fastboop_core::device::{profile_filters, DeviceEvent, DeviceHandle as _, DeviceWatcher as _};
#[cfg(target_arch = "wasm32")]
use fastboop_core::prober::probe_candidates;
#[cfg(target_arch = "wasm32")]
use fastboop_fastboot_webusb::{request_device, DeviceWatcher, WebUsbDeviceHandle};
#[cfg(target_arch = "wasm32")]
use tracing::{debug, info, warn};

#[derive(Clone)]
struct ProbeSnapshot {
    state: ProbeState,
    devices: Vec<ProbedDevice>,
}

#[component]
pub fn Home() -> Element {
    let sessions = use_context::<SessionStore>();
    let navigator = use_navigator();
    let refresh = use_signal(|| 0u32);

    #[cfg(target_arch = "wasm32")]
    let candidates = use_signal(Vec::<WebUsbDeviceHandle>::new);

    #[cfg(target_arch = "wasm32")]
    {
        let mut watcher_started = use_signal(|| false);
        let mut refresh = refresh;
        let mut candidates = candidates;

        use_effect(move || {
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
            let candidates = candidates();
            async move {
                let _ = refresh;
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

    #[cfg(target_arch = "wasm32")]
    let on_connect: Option<EventHandler<MouseEvent>> = {
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
                                candidate.vid() == device.vid() && candidate.pid() == device.pid()
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
    };

    #[cfg(not(target_arch = "wasm32"))]
    let on_connect: Option<EventHandler<MouseEvent>> = None;

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
                },
            });
            navigator.push(Route::DevicePage { session_id });
        }))
    };

    rsx! {
        Hero { state: snapshot.state, on_connect, on_boot }
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
