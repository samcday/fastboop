use dioxus::prelude::*;
#[cfg(target_arch = "wasm32")]
use dioxus::web::WebFileExt;
#[cfg(target_arch = "wasm32")]
use fastboop_fastboot_webusb::WebUsbDeviceHandle;
#[cfg(target_arch = "wasm32")]
use js_sys::{decode_uri_component, Reflect};
#[cfg(target_arch = "wasm32")]
use std::collections::BTreeSet;
use ui::{
    apply_selected_profiles, selected_profile_option, update_profile_selection, Hero,
    ProbeSnapshot, ProbeState, ProfileSelectionMap, StartupError, DEFAULT_ENABLE_SERIAL,
};
#[cfg(target_arch = "wasm32")]
use ui::{build_probe_snapshot, TransportKind};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, JsValue};
#[cfg(target_arch = "wasm32")]
use web_sys::HtmlInputElement;

use crate::Route;

use super::session::{
    next_session_id, BootConfig, DeviceSession, ProbedDevice, SessionChannelIntake, SessionPhase,
    SessionStore,
};
use super::unsupported::WebUnsupported;

#[cfg(target_arch = "wasm32")]
use fastboop_core::builtin::builtin_profiles;
#[cfg(target_arch = "wasm32")]
use fastboop_core::device::{profile_filters, DeviceEvent, DeviceHandle as _, DeviceWatcher as _};
#[cfg(target_arch = "wasm32")]
use fastboop_core::prober::probe_candidates;
use fastboop_core::BootProfile;
#[cfg(target_arch = "wasm32")]
use fastboop_fastboot_webusb::{request_device, DeviceWatcher};
#[cfg(target_arch = "wasm32")]
use tracing::{debug, info, warn};

#[cfg(target_arch = "wasm32")]
const STARTUP_CHANNEL_FILE_PICKER_ID: &str = "startup-channel-file-picker";
const CLI_BOOT_CHANNEL_HINT_FALLBACK: &str = "<channel-url>";

#[component]
pub fn Home() -> Element {
    let sessions = use_context::<SessionStore>();
    let navigator = use_navigator();

    let startup_channel_override = use_signal(|| None::<String>);
    let startup_channel_drop_error = use_signal(|| None::<crate::StartupChannelError>);

    #[cfg(target_arch = "wasm32")]
    let drop_channel_handler: Option<EventHandler<DragEvent>> = {
        let startup_channel_override = startup_channel_override;
        let mut startup_channel_drop_error = startup_channel_drop_error;
        Some(EventHandler::new(move |evt: DragEvent| {
            evt.prevent_default();
            let files = evt.data_transfer().files();
            let Some(file_data) = files.into_iter().next() else {
                startup_channel_drop_error.set(Some(crate::StartupChannelError {
                    title: "Invalid launch channel",
                    details: "drop payload did not include a file".to_string(),
                    launch_hint:
                        "Drop a local channel artifact file (for example .ero, .zip, or .caibx)."
                            .to_string(),
                }));
                return;
            };
            let file_name = file_data.name();
            let Some(web_file) = file_data.get_web_file() else {
                startup_channel_drop_error.set(Some(crate::StartupChannelError {
                    title: "Invalid launch channel",
                    details: format!(
                        "dropped file '{file_name}' is not available as a Web File source"
                    ),
                    launch_hint:
                        "Use drag-and-drop from your local filesystem in this browser tab."
                            .to_string(),
                }));
                return;
            };

            handle_selected_channel_file(
                file_name,
                web_file,
                startup_channel_override,
                startup_channel_drop_error,
            );
        }))
    };

    #[cfg(not(target_arch = "wasm32"))]
    let drop_channel_handler: Option<EventHandler<DragEvent>> = None;

    #[cfg(target_arch = "wasm32")]
    let pick_channel_handler: Option<EventHandler<MouseEvent>> = {
        let startup_channel_drop_error = startup_channel_drop_error;
        Some(EventHandler::new(move |_evt: MouseEvent| {
            open_startup_channel_picker(startup_channel_drop_error);
        }))
    };

    #[cfg(not(target_arch = "wasm32"))]
    let pick_channel_handler: Option<EventHandler<MouseEvent>> = None;

    let startup_channel = if let Some(channel) = startup_channel_override() {
        channel
    } else {
        match crate::startup_channel() {
            Ok(channel) => channel,
            Err(err) => {
                let display_error = startup_channel_drop_error().unwrap_or(err);
                return rsx! {
                    {startup_channel_picker_input(startup_channel_override, startup_channel_drop_error)}
                    StartupError {
                        title: display_error.title.to_string(),
                        details: display_error.details,
                        launch_hint: display_error.launch_hint,
                        on_drop_channel: drop_channel_handler.clone(),
                        on_pick_channel: pick_channel_handler.clone(),
                        drop_hint: Some("Drop a local channel artifact, or click here to choose one from disk.".to_string()),
                    }
                };
            }
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
        let startup_channel_intake = startup_channel_intake;

        use_effect(move || {
            let intake = match startup_channel_intake.read().as_ref() {
                Some(Ok(intake)) => intake.clone(),
                _ => return,
            };

            if !startup_channel_ready {
                return;
            }
            if !webusb_supported {
                return;
            }
            if watcher_started() {
                return;
            }
            watcher_started.set(true);

            let profiles = load_profiles_for_channel(&intake);
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
            let startup_channel_intake = startup_channel_intake.read().as_ref().cloned();
            let webusb_supported = webusb_supported;
            let candidates = candidates();
            async move {
                let _ = refresh;
                let Some(Ok(intake)) = startup_channel_intake else {
                    return ProbeSnapshot {
                        state: ProbeState::Loading,
                        devices: Vec::new(),
                    };
                };
                if !webusb_supported {
                    return ProbeSnapshot {
                        state: ProbeState::Unsupported,
                        devices: Vec::new(),
                    };
                }
                let profiles = load_profiles_for_channel(&intake);
                probe_fastboot_devices(candidates, profiles).await
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
            let startup_channel_intake = startup_channel_intake;
            Some(EventHandler::new(move |_| {
                let intake = match startup_channel_intake.read().as_ref() {
                    Some(Ok(intake)) => intake.clone(),
                    _ => return,
                };
                let profiles = load_profiles_for_channel(&intake);
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
        let (title, details, launch_hint) = if let Some(drop_error) = startup_channel_drop_error() {
            (
                drop_error.title.to_string(),
                drop_error.details,
                drop_error.launch_hint,
            )
        } else {
            match startup_channel_intake.read().as_ref() {
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
            }
        };

        return rsx! {
            {startup_channel_picker_input(startup_channel_override, startup_channel_drop_error)}
            StartupError {
                title,
                details,
                launch_hint,
                on_drop_channel: drop_channel_handler.clone(),
                on_pick_channel: pick_channel_handler.clone(),
                drop_hint: Some("Drop a local channel artifact, or click here to choose one from disk.".to_string()),
            }
        };
    }

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
fn startup_channel_picker_input(
    startup_channel_override: Signal<Option<String>>,
    startup_channel_drop_error: Signal<Option<crate::StartupChannelError>>,
) -> Element {
    rsx! {
        input {
            id: STARTUP_CHANNEL_FILE_PICKER_ID,
            r#type: "file",
            style: "display: none;",
            onchange: move |_| {
                let Some(window) = web_sys::window() else {
                    set_startup_channel_drop_error(
                        startup_channel_drop_error,
                        "file picker window is unavailable in this context",
                        "Drag and drop a local channel artifact file instead.",
                    );
                    return;
                };
                let Some(document) = window.document() else {
                    set_startup_channel_drop_error(
                        startup_channel_drop_error,
                        "file picker document is unavailable in this context",
                        "Drag and drop a local channel artifact file instead.",
                    );
                    return;
                };
                let Some(element) = document.get_element_by_id(STARTUP_CHANNEL_FILE_PICKER_ID)
                else {
                    set_startup_channel_drop_error(
                        startup_channel_drop_error,
                        "startup file picker is not available on this page",
                        "Reload and try again, or drag and drop a local channel artifact file.",
                    );
                    return;
                };
                let Ok(input) = element.dyn_into::<HtmlInputElement>() else {
                    set_startup_channel_drop_error(
                        startup_channel_drop_error,
                        "startup file picker is not an HTML file input",
                        "Reload and try again, or drag and drop a local channel artifact file.",
                    );
                    return;
                };
                let Some(files) = input.files() else {
                    return;
                };
                let Some(web_file) = files.item(0) else {
                    return;
                };
                let file_name = web_file.name();
                input.set_value("");
                handle_selected_channel_file(
                    file_name,
                    web_file,
                    startup_channel_override,
                    startup_channel_drop_error,
                );
            },
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn startup_channel_picker_input(
    _startup_channel_override: Signal<Option<String>>,
    _startup_channel_drop_error: Signal<Option<crate::StartupChannelError>>,
) -> Element {
    rsx! {}
}

#[cfg(target_arch = "wasm32")]
fn open_startup_channel_picker(
    startup_channel_drop_error: Signal<Option<crate::StartupChannelError>>,
) {
    let Some(window) = web_sys::window() else {
        set_startup_channel_drop_error(
            startup_channel_drop_error,
            "file picker window is unavailable in this context",
            "Drag and drop a local channel artifact file instead.",
        );
        return;
    };
    let Some(document) = window.document() else {
        set_startup_channel_drop_error(
            startup_channel_drop_error,
            "file picker document is unavailable in this context",
            "Drag and drop a local channel artifact file instead.",
        );
        return;
    };
    let Some(element) = document.get_element_by_id(STARTUP_CHANNEL_FILE_PICKER_ID) else {
        set_startup_channel_drop_error(
            startup_channel_drop_error,
            "startup file picker is not available on this page",
            "Reload and try again, or drag and drop a local channel artifact file.",
        );
        return;
    };
    let Ok(input) = element.dyn_into::<HtmlInputElement>() else {
        set_startup_channel_drop_error(
            startup_channel_drop_error,
            "startup file picker is not an HTML file input",
            "Reload and try again, or drag and drop a local channel artifact file.",
        );
        return;
    };

    input.set_value("");
    input.click();
}

#[cfg(target_arch = "wasm32")]
fn handle_selected_channel_file(
    file_name: String,
    web_file: web_sys::File,
    mut startup_channel_override: Signal<Option<String>>,
    mut startup_channel_drop_error: Signal<Option<crate::StartupChannelError>>,
) {
    if web_file.size() <= 0.0 {
        set_startup_channel_drop_error(
            startup_channel_drop_error,
            format!("selected file '{file_name}' reports zero bytes from this browser path"),
            "Try clicking to choose the file from disk instead of drag and drop.",
        );
        return;
    }

    let previous_channel = startup_channel_override();
    let dropped_channel = crate::register_web_file_channel(web_file);
    startup_channel_drop_error.set(Some(crate::StartupChannelError {
        title: "Validating dropped channel",
        details: format!("Checking file '{file_name}' for a valid channel stream."),
        launch_hint: "This may take a moment for large files.".to_string(),
    }));

    spawn(async move {
        match crate::preflight_startup_channel(&dropped_channel).await {
            Ok(()) => {
                if let Some(previous_channel) = previous_channel.as_ref() {
                    if previous_channel != &dropped_channel {
                        crate::unregister_web_file_channel(previous_channel);
                    }
                }
                startup_channel_override.set(Some(dropped_channel));
                startup_channel_drop_error.set(None);
            }
            Err(err) => {
                crate::unregister_web_file_channel(&dropped_channel);
                startup_channel_drop_error.set(Some(err));
            }
        }
    });
}

#[cfg(target_arch = "wasm32")]
fn set_startup_channel_drop_error(
    mut startup_channel_drop_error: Signal<Option<crate::StartupChannelError>>,
    details: impl Into<String>,
    launch_hint: impl Into<String>,
) {
    startup_channel_drop_error.set(Some(crate::StartupChannelError {
        title: "Invalid launch channel",
        details: details.into(),
        launch_hint: launch_hint.into(),
    }));
}

#[cfg(target_arch = "wasm32")]
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

#[cfg(target_arch = "wasm32")]
async fn probe_fastboot_devices(
    candidates: Vec<WebUsbDeviceHandle>,
    profiles: Vec<fastboop_core::DeviceProfile>,
) -> ProbeSnapshot<WebUsbDeviceHandle> {
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
        .unwrap_or_else(|| CLI_BOOT_CHANNEL_HINT_FALLBACK.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn cli_boot_channel_hint() -> String {
    CLI_BOOT_CHANNEL_HINT_FALLBACK.to_string()
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

#[cfg(target_arch = "wasm32")]
fn webusb_supported() -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    Reflect::has(window.navigator().as_ref(), &JsValue::from_str("usb")).unwrap_or(false)
}
