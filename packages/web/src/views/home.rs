use dioxus::prelude::*;
use ui::{Hero, ProbeState};

#[cfg(target_arch = "wasm32")]
use ui::{DetectedDevice, TransportKind};

#[cfg(target_arch = "wasm32")]
use std::collections::{HashMap, HashSet};

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

#[component]
pub fn Home() -> Element {
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
                probe_fastboot_devices().await
            }
        }
    });

    let state = match probe() {
        Some(state) => state,
        None => ProbeState::Loading,
    };

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

    rsx! {
        Hero { state, on_connect }
    }
}

#[cfg(target_arch = "wasm32")]
fn load_profiles() -> Vec<fastboop_core::DeviceProfile> {
    builtin_profiles().unwrap_or_default()
}

#[cfg(target_arch = "wasm32")]
async fn probe_fastboot_devices(candidates: Vec<WebUsbDeviceHandle>) -> ProbeState {
    let profiles = load_profiles();
    let profiles_by_id: HashMap<_, _> = profiles
        .iter()
        .map(|profile| (profile.id.clone(), profile))
        .collect();

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
        transport: TransportKind::WebUsb,
        devices: detected,
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn probe_fastboot_devices() -> ProbeState {
    ProbeState::Unsupported
}
