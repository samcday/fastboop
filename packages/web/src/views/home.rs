use dioxus::prelude::*;
#[cfg(target_arch = "wasm32")]
use fastboop_fastboot_webusb::WebUsbDeviceHandle;
#[cfg(target_arch = "wasm32")]
use js_sys::{decode_uri_component, Reflect};
use ui::{
    apply_selected_profiles, selected_profile_option, update_profile_selection, Hero,
    ProbeSnapshot, ProbeState, ProfileSelectionMap, DEFAULT_ENABLE_SERIAL, DEFAULT_EXTRA_KARGS,
};
#[cfg(target_arch = "wasm32")]
use ui::{build_probe_snapshot, TransportKind};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

use crate::Route;

use super::session::{
    next_session_id, BootConfig, DeviceSession, ProbedDevice, SessionPhase, SessionStore,
};
use super::unsupported::WebUnsupported;

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

#[component]
pub fn Home() -> Element {
    let sessions = use_context::<SessionStore>();
    let navigator = use_navigator();
    let refresh = use_signal(|| 0u32);
    let selected_profiles = use_signal(ProfileSelectionMap::new);

    #[cfg(target_arch = "wasm32")]
    let candidates = use_signal(Vec::<WebUsbDeviceHandle>::new);

    #[cfg(target_arch = "wasm32")]
    let webusb_supported = webusb_supported();

    let channel_hint = cli_boot_channel_hint();

    #[cfg(target_arch = "wasm32")]
    let show_unsupported = !webusb_supported;
    #[cfg(not(target_arch = "wasm32"))]
    let show_unsupported = true;

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
        let selections = selected_profiles.read();
        apply_selected_profiles(&mut state, &selections);
        state
    };

    let on_select_profile = {
        let mut selected_profiles = selected_profiles;
        let devices = snapshot.devices.clone();
        Some(EventHandler::new(
            move |(device_index, profile_index): (usize, usize)| {
                let mut selections = selected_profiles.write();
                update_profile_selection(&mut selections, &devices, device_index, profile_index);
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
        let channel = crate::startup_channel();
        Some(EventHandler::new(move |index: usize| {
            let Some(device) = devices.get(index).cloned() else {
                return;
            };

            let profile = {
                let selections = selected_profiles.read();
                selected_profile_option(&device, &selections).cloned()
            };
            let Some(profile) = profile else {
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
                boot_config: BootConfig::new(
                    channel.clone(),
                    DEFAULT_EXTRA_KARGS,
                    DEFAULT_ENABLE_SERIAL,
                ),
                phase: SessionPhase::Configuring,
            });
            navigator.push(Route::DevicePage { session_id });
        }))
    };

    rsx! {
        if show_unsupported {
            WebUnsupported { channel: channel_hint }
        } else {
            Hero {
                state,
                on_connect,
                on_boot,
                on_select_profile,
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn load_profiles() -> Vec<fastboop_core::DeviceProfile> {
    builtin_profiles().unwrap_or_default()
}

#[cfg(target_arch = "wasm32")]
async fn probe_fastboot_devices(
    candidates: Vec<WebUsbDeviceHandle>,
) -> ProbeSnapshot<WebUsbDeviceHandle> {
    let profiles = load_profiles();

    let reports = probe_candidates(&profiles, &candidates).await;
    build_probe_snapshot(
        TransportKind::WebUsb,
        &profiles,
        reports,
        &candidates,
        |_| None,
    )
}

#[cfg(target_arch = "wasm32")]
fn cli_boot_channel_hint() -> String {
    let search = web_sys::window()
        .and_then(|window| window.location().search().ok())
        .unwrap_or_default();
    parse_query_param(&search, "channel")
        .filter(|channel| !channel.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_CHANNEL.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn cli_boot_channel_hint() -> String {
    DEFAULT_CHANNEL.to_string()
}

#[cfg(target_arch = "wasm32")]
fn parse_query_param(search: &str, key: &str) -> Option<String> {
    let query = search.strip_prefix('?').unwrap_or(search);
    for pair in query.split('&') {
        let Some((k, value)) = pair.split_once('=') else {
            continue;
        };
        if k != key {
            continue;
        }
        return decode_uri_component(value)
            .ok()
            .and_then(|decoded| decoded.as_string())
            .or_else(|| Some(value.to_string()));
    }
    None
}

#[cfg(target_arch = "wasm32")]
fn webusb_supported() -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    Reflect::has(window.navigator().as_ref(), &JsValue::from_str("usb")).unwrap_or(false)
}
