use dioxus::prelude::*;
use fastboop_core::device::{profile_filters, DeviceEvent, DeviceHandle as _, DeviceWatcher as _};
use fastboop_core::prober::probe_candidates;
use fastboop_fastboot_rusb::{DeviceWatcher, RusbDeviceHandle};
use tracing::{debug, info};
use ui::{
    apply_selected_profiles, build_probe_snapshot, compatible_boot_profiles_for_device,
    initial_boot_profile_id, load_profiles_for_channel_head, selected_profile_option,
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

    let initial_startup_options = crate::startup_options();
    let initial_startup_channel = initial_startup_options
        .clone()
        .map(|options| options.channel);
    let startup_boot_profile_id = initial_startup_options
        .clone()
        .ok()
        .and_then(|options| options.boot_profile);
    let startup_extra_kargs = initial_startup_options
        .clone()
        .ok()
        .and_then(|options| options.extra_kargs)
        .unwrap_or_default();
    let startup_channel = use_signal({
        let initial_startup_channel = initial_startup_channel.clone();
        move || initial_startup_channel.clone().ok().flatten()
    });
    let startup_channel_prompt_error = use_signal({
        let initial_startup_channel = initial_startup_channel.clone();
        move || initial_startup_channel.clone().err()
    });
    let startup_channel_url_value = use_signal({
        let initial_startup_channel = initial_startup_channel.clone();
        move || {
            initial_startup_channel
                .clone()
                .ok()
                .flatten()
                .unwrap_or_default()
        }
    });
    let startup_channel_url_submit_pending = use_signal(|| false);

    let channel_url_input_handler: Option<EventHandler<FormEvent>> = {
        let mut startup_channel_url_value = startup_channel_url_value;
        Some(EventHandler::new(move |evt: FormEvent| {
            startup_channel_url_value.set(evt.value());
        }))
    };

    let submit_channel_url_handler: Option<EventHandler<MouseEvent>> = {
        Some(EventHandler::new(move |_evt: MouseEvent| {
            if startup_channel_url_submit_pending() {
                return;
            }

            let channel = startup_channel_url_value().trim().to_string();
            start_desktop_channel_preflight(
                channel,
                startup_channel,
                startup_channel_prompt_error,
                startup_channel_url_value,
                startup_channel_url_submit_pending,
            );
        }))
    };

    let pick_channel_file_handler: EventHandler<MouseEvent> = {
        EventHandler::new(move |_evt: MouseEvent| {
            if startup_channel_url_submit_pending() {
                return;
            }

            let mut startup_channel_prompt_error = startup_channel_prompt_error;
            let mut startup_channel_url_submit_pending = startup_channel_url_submit_pending;
            startup_channel_url_submit_pending.set(true);
            startup_channel_prompt_error.set(Some(crate::StartupChannelError {
                title: "Choose launch channel",
                details: "Waiting for a file from the desktop file picker.".to_string(),
                launch_hint: "Select a local channel file; fastboop will validate it immediately."
                    .to_string(),
            }));

            spawn(async move {
                let Some(file) = rfd::AsyncFileDialog::new()
                    .set_title("Choose fastboop channel")
                    .pick_file()
                    .await
                else {
                    startup_channel_prompt_error.set(None);
                    startup_channel_url_submit_pending.set(false);
                    return;
                };

                start_desktop_channel_preflight(
                    file.path().to_string_lossy().into_owned(),
                    startup_channel,
                    startup_channel_prompt_error,
                    startup_channel_url_value,
                    startup_channel_url_submit_pending,
                );
            });
        })
    };

    let startup_channel_intake = use_resource(move || {
        let startup_channel = startup_channel();
        async move {
            let Some(startup_channel) = startup_channel else {
                return Err(missing_desktop_channel_prompt());
            };

            crate::load_startup_channel_intake(&startup_channel).await
        }
    });
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

        let profiles = load_profiles_for_channel_head(&intake.stream_head);
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

            let profiles = load_profiles_for_channel_head(&intake.stream_head);
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

    let startup_channel_for_boot = startup_channel;
    let startup_boot_profile_id_for_boot = startup_boot_profile_id.clone();
    let startup_extra_kargs_for_boot = startup_extra_kargs.clone();
    let on_boot = {
        let mut sessions = sessions;
        let devices = snapshot.devices.clone();
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

            let Some(startup_channel_for_boot) = startup_channel_for_boot() else {
                return;
            };

            let compatible_boot_profiles = compatible_boot_profiles_for_device(
                &intake.stream_head,
                profile.profile.id.as_str(),
            );
            let selected_boot_profile_id = initial_boot_profile_id(
                &compatible_boot_profiles,
                startup_boot_profile_id_for_boot.as_deref(),
            );

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
                    compatible_boot_profiles,
                },
                boot_config: BootConfig::new(
                    startup_channel_for_boot,
                    selected_boot_profile_id,
                    startup_extra_kargs_for_boot.clone(),
                    DEFAULT_ENABLE_SERIAL,
                ),
                phase: SessionPhase::Configuring,
            });
            navigator.push(Route::DevicePage { session_id });
        }))
    };

    if !startup_channel_ready {
        let active_channel = startup_channel();
        let prompt_error = startup_channel_prompt_error().or_else(|| {
            startup_channel_intake
                .read()
                .as_ref()
                .and_then(|result| result.as_ref().err().cloned())
        });
        let (title, details, launch_hint) = match (prompt_error, active_channel) {
            (Some(err), _) => (err.title.to_string(), err.details, err.launch_hint),
            (None, Some(channel)) => (
                "Validating launch channel".to_string(),
                "Checking channel reachability and stream shape before enabling device boot."
                    .to_string(),
                format!("Validating channel: {channel}"),
            ),
            (None, None) => {
                let err = missing_desktop_channel_prompt();
                (err.title.to_string(), err.details, err.launch_hint)
            }
        };

        return rsx! {
            StartupError {
                title,
                details,
                launch_hint,
                eyebrow: Some("Startup channel".to_string()),
                channel_url_value: Some(startup_channel_url_value()),
                on_channel_url_input: channel_url_input_handler,
                on_submit_channel_url: submit_channel_url_handler,
                submit_channel_url_pending: Some(startup_channel_url_submit_pending()),
                channel_input_label: Some("or enter a channel URL or local path".to_string()),
                channel_input_placeholder: Some("https://example.invalid/channel.ero or /path/to/channel.ero".to_string()),
                channel_input_hint: Some("HTTP(S), file://, and local filesystem paths are supported on desktop.".to_string()),
                channel_picker: rsx! {
                    div { class: "startup-channel-picker",
                        p { class: "startup-channel-picker__label", "or choose a local channel file" }
                        button {
                            class: "cta__button startup-channel-picker__button",
                            disabled: startup_channel_url_submit_pending(),
                            onclick: move |evt| {
                                evt.prevent_default();
                                pick_channel_file_handler.call(evt);
                            },
                            if startup_channel_url_submit_pending() {
                                span {
                                    class: "startup-channel-url__spinner",
                                    aria_hidden: "true",
                                }
                                span { "Checking..." }
                            } else {
                                "Choose file"
                            }
                        }
                        p { class: "startup-channel-picker__hint",
                            "Uses the desktop file picker portal and validates the selected file immediately."
                        }
                    }
                },
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

fn missing_desktop_channel_prompt() -> crate::StartupChannelError {
    crate::StartupChannelError {
        title: "Choose launch channel",
        details: "No launch channel is configured yet.".to_string(),
        launch_hint: "Choose a local channel file, enter a channel URL/path, or launch with --channel=<url-or-path>."
            .to_string(),
    }
}

fn start_desktop_channel_preflight(
    channel: String,
    mut startup_channel: Signal<Option<String>>,
    mut startup_channel_prompt_error: Signal<Option<crate::StartupChannelError>>,
    mut startup_channel_url_value: Signal<String>,
    mut startup_channel_url_submit_pending: Signal<bool>,
) {
    let channel = channel.trim().to_string();
    startup_channel_url_value.set(channel.clone());
    if channel.is_empty() {
        startup_channel.set(None);
        startup_channel_prompt_error.set(Some(crate::StartupChannelError {
            title: "Invalid launch channel",
            details: "channel URL/path is empty".to_string(),
            launch_hint: "Enter an HTTP(S) URL, file:// URL, or local channel path.".to_string(),
        }));
        startup_channel_url_submit_pending.set(false);
        return;
    }

    startup_channel_url_submit_pending.set(true);
    startup_channel_prompt_error.set(Some(crate::StartupChannelError {
        title: "Validating launch channel",
        details: format!("Checking channel: {channel}"),
        launch_hint: "Waiting for channel validation to complete.".to_string(),
    }));

    spawn(async move {
        match crate::preflight_startup_channel(&channel).await {
            Ok(()) => {
                startup_channel_prompt_error.set(None);
                startup_channel.set(Some(channel));
                startup_channel_url_submit_pending.set(false);
            }
            Err(err) => {
                startup_channel.set(None);
                startup_channel_prompt_error.set(Some(err));
                startup_channel_url_submit_pending.set(false);
            }
        }
    });
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
