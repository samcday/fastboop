use std::collections::HashMap;

use dioxus::prelude::*;
use fastboop_core::builtin::builtin_profiles;
use fastboop_core::device::{profile_filters, DeviceEvent, DeviceHandle as _, DeviceWatcher as _};
use fastboop_core::prober::probe_candidates;
use fastboop_fastboot_rusb::{DeviceWatcher, RusbDeviceHandle};
use tracing::{debug, info};
use ui::{
    apply_selected_profiles, build_probe_snapshot, selected_profile_option,
    update_profile_selection, Hero, ProbeSnapshot, ProbeState, TransportKind,
};

use crate::Route;

use super::session::{next_session_id, DeviceSession, ProbedDevice, SessionPhase, SessionStore};

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

    let on_boot = {
        let mut sessions = sessions;
        let devices = snapshot.devices.clone();
        let selected_profiles = selected_profiles;
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

async fn probe_fastboot_devices(
    candidates: Vec<RusbDeviceHandle>,
) -> ProbeSnapshot<RusbDeviceHandle> {
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

    debug!(
        candidates = candidates.len(),
        "desktop probe candidates queued"
    );
    let reports = probe_candidates(&profiles, &candidates).await;
    build_probe_snapshot(
        TransportKind::NativeUsb,
        &profiles,
        reports,
        &candidates,
        RusbDeviceHandle::usb_serial_number,
    )
}
