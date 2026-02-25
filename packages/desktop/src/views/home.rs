use std::collections::BTreeSet;

use dioxus::prelude::*;
use fastboop_core::builtin::builtin_profiles;
use fastboop_core::device::{profile_filters, DeviceEvent, DeviceHandle as _, DeviceWatcher as _};
use fastboop_core::prober::probe_candidates;
use fastboop_core::BootProfile;
use fastboop_fastboot_rusb::{DeviceWatcher, RusbDeviceHandle};
use tracing::{debug, info};
use ui::{
    apply_selected_profiles, build_probe_snapshot, selected_profile_option,
    update_profile_selection, Hero, ProbeSnapshot, ProbeState, ProfileSelectionMap, StartupError,
    TransportKind, DEFAULT_ENABLE_SERIAL,
};

use crate::Route;

use super::session::{
    next_session_id, BootConfig, DeviceSession, ProbedDevice, SessionChannelIntake, SessionPhase,
    SessionStore,
};

#[component]
pub fn Home() -> Element {
    let sessions = use_context::<SessionStore>();
    let navigator = use_navigator();

    let startup_channel = match crate::startup_channel() {
        Ok(channel) => channel,
        Err(err) => {
            return rsx! {
                StartupError {
                    title: err.title.to_string(),
                    details: err.details,
                    launch_hint: err.launch_hint,
                    on_drop_channel: None,
                    on_pick_channel: None,
                    drop_hint: None,
                }
            };
        }
    };

    let startup_channel_intake = {
        let startup_channel = startup_channel.clone();
        use_resource(move || {
            let startup_channel = startup_channel.clone();
            async move { crate::load_startup_channel_intake(&startup_channel).await }
        })
    };
    let startup_channel_ready = matches!(startup_channel_intake.read().as_ref(), Some(Ok(_)));

    let mut watcher_started = use_signal(|| false);
    let candidates = use_signal(Vec::<RusbDeviceHandle>::new);
    let selected_profiles = use_signal(ProfileSelectionMap::new);
    let startup_channel_intake_for_watcher = startup_channel_intake;

    use_effect(move || {
        let intake = match startup_channel_intake_for_watcher.read().as_ref() {
            Some(Ok(intake)) => intake.clone(),
            _ => return,
        };

        if !startup_channel_ready {
            return;
        }
        if watcher_started() {
            return;
        }
        watcher_started.set(true);

        let profiles = load_profiles_for_channel(&intake);
        let filters = profile_filters(&profiles);
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
        let startup_channel_intake = startup_channel_intake.read().as_ref().cloned();
        async move {
            let Some(Ok(intake)) = startup_channel_intake else {
                return ProbeSnapshot {
                    state: ProbeState::Loading,
                    devices: Vec::new(),
                };
            };

            let profiles = load_profiles_for_channel(&intake);
            probe_fastboot_devices(candidates, profiles).await
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

    let startup_channel_for_boot = startup_channel.clone();
    let on_boot = {
        let mut sessions = sessions;
        let devices = snapshot.devices.clone();
        let startup_channel_intake = startup_channel_intake;
        Some(EventHandler::new(move |index: usize| {
            let Some(device) = devices.get(index).cloned() else {
                return;
            };

            let intake = match startup_channel_intake.read().as_ref() {
                Some(Ok(intake)) => intake.clone(),
                _ => return,
            };

            let profile = {
                let selections = selected_profiles.read();
                selected_profile_option(&device, &selections).cloned()
            };
            let Some(profile) = profile else {
                return;
            };

            let compatible_boot_profiles =
                compatible_boot_profiles_for_device(&intake, profile.profile.id.as_str());
            let selected_boot_profile_id = if compatible_boot_profiles.len() == 1 {
                Some(compatible_boot_profiles[0].id.clone())
            } else {
                None
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
                channel_intake: SessionChannelIntake {
                    exact_total_bytes: intake.exact_total_bytes,
                    consumed_bytes: intake.stream_head.consumed_bytes,
                    warning_count: intake.stream_head.warning_count,
                    has_artifact_payload: intake.has_artifact_payload(),
                    accepted_dev_profiles: intake.stream_head.dev_profiles.clone(),
                    compatible_boot_profiles,
                },
                boot_config: BootConfig::new(
                    startup_channel_for_boot.clone(),
                    selected_boot_profile_id,
                    "",
                    DEFAULT_ENABLE_SERIAL,
                ),
                phase: SessionPhase::Configuring,
            });
            navigator.push(Route::DevicePage { session_id });
        }))
    };

    if !startup_channel_ready {
        let (title, details, launch_hint) = match startup_channel_intake.read().as_ref() {
            Some(Err(err)) => (
                err.title.to_string(),
                err.details.clone(),
                err.launch_hint.clone(),
            ),
            _ => (
                "Validating launch channel".to_string(),
                "Checking channel reachability and stream shape before enabling device boot."
                    .to_string(),
                format!("Validating channel: {startup_channel}"),
            ),
        };

        return rsx! {
            StartupError {
                title,
                details,
                launch_hint,
                on_drop_channel: None,
                on_pick_channel: None,
                drop_hint: None,
            }
        };
    }

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
    profiles: Vec<fastboop_core::DeviceProfile>,
) -> ProbeSnapshot<RusbDeviceHandle> {
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

fn load_profiles_for_channel(
    intake: &crate::StartupChannelIntake,
) -> Vec<fastboop_core::DeviceProfile> {
    let profiles = builtin_profiles().unwrap_or_default();

    let allowed_by_boot_profiles =
        allowed_boot_profile_device_ids(&intake.stream_head.boot_profiles);

    profiles
        .into_iter()
        .filter(|profile| match allowed_by_boot_profiles.as_ref() {
            Some(allowed) => allowed.contains(profile.id.as_str()),
            None => true,
        })
        .collect()
}

fn allowed_boot_profile_device_ids(boot_profiles: &[BootProfile]) -> Option<BTreeSet<String>> {
    if boot_profiles.is_empty()
        || boot_profiles
            .iter()
            .any(|profile| profile.stage0.devices.is_empty())
    {
        return None;
    }

    let mut out = BTreeSet::new();
    for profile in boot_profiles {
        out.extend(profile.stage0.devices.keys().cloned());
    }
    Some(out)
}

fn compatible_boot_profiles_for_device(
    intake: &crate::StartupChannelIntake,
    device_profile_id: &str,
) -> Vec<BootProfile> {
    intake
        .stream_head
        .boot_profiles
        .iter()
        .filter(|boot_profile| {
            fastboop_core::boot_profile_matches_device(boot_profile, device_profile_id)
        })
        .cloned()
        .collect()
}
