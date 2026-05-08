use dioxus::prelude::*;
#[cfg(target_arch = "wasm32")]
use gloo_timers::future::sleep;
#[cfg(target_arch = "wasm32")]
use js_sys::{Date, Reflect};
#[cfg(target_arch = "wasm32")]
use std::cell::Cell;
use std::rc::Rc;
#[cfg(target_arch = "wasm32")]
use std::time::Duration;
#[cfg(target_arch = "wasm32")]
use ui::run_smoo_stats_view_loop;
use ui::{BootConfigCard, BootProfileOptionView, SmooStatsPanel, SmooStatsViewModel};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::closure::Closure;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, JsValue};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use web_sys::{WakeLockSentinel, WakeLockType};

#[cfg(target_arch = "wasm32")]
use super::device_boot::run_web_host_daemon;
use super::device_boot::{boot_selected_device, spawn_detached};
use super::serial_logs::SerialLogPanel;
use super::session::{
    update_session_boot_config, update_session_phase, SessionPhase, SessionStore,
};

#[cfg(target_arch = "wasm32")]
const CACHE_STATS_POLL_INTERVAL: Duration = Duration::from_millis(500);

#[component]
pub fn DevicePage(session_id: String, channel: Option<String>) -> Element {
    let sessions = use_context::<SessionStore>();
    let navigator = use_navigator();

    let Some(session) = sessions.read().iter().find(|s| s.id == session_id).cloned() else {
        return rsx! {
            section { id: "landing",
                div { class: "landing__panel",
                    h1 { "Session not found" }
                    p { "That device session no longer exists." }
                    button {
                        class: "cta__button",
                        onclick: move |_| {
                            navigator.push(crate::Route::Home {
                                channel: channel.clone(),
                            });
                        },
                        "Back"
                    }
                }
            }
        };
    };

    match session.phase {
        SessionPhase::Configuring => rsx! { BootConfigDevice { session_id } },
        SessionPhase::Booting { step } => rsx! { BootingDevice { session_id, step } },
        SessionPhase::Active { .. } => rsx! { BootedDevice { session_id } },
        SessionPhase::Error { summary } => rsx! { BootError { summary } },
    }
}

#[component]
fn BootConfigDevice(session_id: String) -> Element {
    let sessions = use_context::<SessionStore>();

    let session = sessions.read().iter().find(|s| s.id == session_id).cloned();
    let Some(session) = session else {
        return rsx! {};
    };

    let mut sessions_for_channel = sessions;
    let session_id_for_channel = session_id.clone();
    let on_channel_change = move |value: String| {
        update_session_boot_config(
            &mut sessions_for_channel,
            &session_id_for_channel,
            |config| {
                config.channel = value;
            },
        );
    };

    let mut sessions_for_kargs = sessions;
    let session_id_for_kargs = session_id.clone();
    let on_extra_kargs_change = move |value: String| {
        update_session_boot_config(&mut sessions_for_kargs, &session_id_for_kargs, |config| {
            config.extra_kargs = value;
        });
    };

    let mut sessions_for_boot_profile = sessions;
    let session_id_for_boot_profile = session_id.clone();
    let on_boot_profile_change = move |value: String| {
        update_session_boot_config(
            &mut sessions_for_boot_profile,
            &session_id_for_boot_profile,
            |config| {
                config.selected_boot_profile_id = Some(value);
            },
        );
    };

    let mut sessions_for_serial = sessions;
    let session_id_for_serial = session_id.clone();
    let on_enable_serial_change = move |value: bool| {
        update_session_boot_config(&mut sessions_for_serial, &session_id_for_serial, |config| {
            config.enable_serial = value;
        });
    };

    let mut sessions_for_start = sessions;
    let session_id_for_start = session_id.clone();
    let compatible_boot_profile_ids: Vec<String> = session
        .channel_intake
        .compatible_boot_profiles
        .iter()
        .map(|profile| profile.id.clone())
        .collect();
    let selected_boot_profile_id = session.boot_config.selected_boot_profile_id.clone();
    let on_start_boot = move |_| {
        let selected_boot_profile_id = selected_boot_profile_id.clone();
        if compatible_boot_profile_ids.len() > 1 && selected_boot_profile_id.is_none() {
            return;
        }
        if let Some(selected_boot_profile_id) = selected_boot_profile_id.as_ref() {
            if !compatible_boot_profile_ids
                .iter()
                .any(|id| id == selected_boot_profile_id)
            {
                return;
            }
        }

        update_session_phase(
            &mut sessions_for_start,
            &session_id_for_start,
            SessionPhase::Booting {
                step: "Queued".to_string(),
            },
        );
    };

    let boot_profile_options: Vec<BootProfileOptionView> = session
        .channel_intake
        .compatible_boot_profiles
        .iter()
        .map(|profile| BootProfileOptionView {
            id: profile.id.clone(),
            label: profile
                .display_name
                .clone()
                .unwrap_or_else(|| profile.id.clone()),
        })
        .collect();

    rsx! {
        BootConfigCard {
            device_name: session.device.name,
            device_id: format!("{:04x}:{:04x}", session.device.vid, session.device.pid),
            profile_id: session.device.profile.id,
            boot_profile_options,
            selected_boot_profile_id: session.boot_config.selected_boot_profile_id,
            channel: session.boot_config.channel,
            extra_kargs: session.boot_config.extra_kargs,
            enable_serial: session.boot_config.enable_serial,
            on_channel_change,
            on_boot_profile_change,
            on_extra_kargs_change,
            on_enable_serial_change,
            on_start_boot,
            show_channel_input: false,
        }
    }
}

#[component]
fn BootingDevice(session_id: String, step: String) -> Element {
    #[cfg(target_arch = "wasm32")]
    use_screen_wake_lock();

    let sessions = use_context::<SessionStore>();
    let mut started = use_signal(|| false);

    use_effect(move || {
        if started() {
            return;
        }
        started.set(true);
        let mut sessions = sessions;
        let session_id = session_id.clone();
        spawn_detached(async move {
            match boot_selected_device(&mut sessions, &session_id).await {
                Ok(runtime) => update_session_phase(
                    &mut sessions,
                    &session_id,
                    SessionPhase::Active {
                        runtime,
                        host_started: false,
                        host_connected: false,
                    },
                ),
                Err(err) => {
                    tracing::error!("boot flow failed for {session_id}: {err:#}");
                    update_session_phase(
                        &mut sessions,
                        &session_id,
                        SessionPhase::Error {
                            summary: format!("{err:#}"),
                        },
                    )
                }
            }
        });
    });

    rsx! {
        section { id: "landing",
            div { class: "landing__panel",
                p { class: "landing__eyebrow", "Booting" }
                h1 { "Working on it..." }
                p { class: "landing__lede", "{step}" }
            }
        }
    }
}

#[component]
fn BootedDevice(session_id: String) -> Element {
    let mut sessions = use_context::<SessionStore>();
    let state = sessions
        .read()
        .iter()
        .find(|s| s.id == session_id)
        .map(|s| {
            (
                s.device.vid,
                s.device.pid,
                s.boot_config.channel.clone(),
                s.boot_config.selected_boot_profile_id.clone(),
                s.phase.clone(),
            )
        });
    let Some((device_vid, device_pid, channel, selected_boot_profile_id, phase)) = state else {
        return rsx! {};
    };

    let SessionPhase::Active {
        runtime,
        host_started,
        host_connected,
    } = phase
    else {
        return rsx! {};
    };

    #[cfg(target_arch = "wasm32")]
    use_screen_wake_lock();

    let mut kickoff = use_signal(|| false);
    let smoo_stats = use_signal(|| Option::<SmooStatsViewModel>::None);
    #[cfg(target_arch = "wasm32")]
    let smoo_stats_stop = use_signal(|| Option::<Rc<Cell<bool>>>::None);
    let runtime_for_kickoff = Rc::clone(&runtime);

    #[cfg(target_arch = "wasm32")]
    {
        use_effect(move || {
            if let Some(window) = web_sys::window() {
                let handler = js_sys::Function::new_no_args(
                    "event.preventDefault(); event.returnValue=''; return '';",
                );
                let _ = Reflect::set(
                    window.as_ref(),
                    &JsValue::from_str("onbeforeunload"),
                    handler.as_ref(),
                );
            }
        });

        use_drop(move || {
            if let Some(window) = web_sys::window() {
                let _ = Reflect::set(
                    window.as_ref(),
                    &JsValue::from_str("onbeforeunload"),
                    &JsValue::NULL,
                );
            }
        });
    }

    use_effect(move || {
        if host_started || kickoff() {
            return;
        }
        kickoff.set(true);
        let session = sessions.read().iter().find(|s| s.id == session_id).cloned();
        if let Some(_session) = session {
            update_session_phase(
                &mut sessions,
                &session_id,
                SessionPhase::Active {
                    runtime: Rc::clone(&runtime_for_kickoff),
                    host_started: true,
                    host_connected: false,
                },
            );

            #[cfg(target_arch = "wasm32")]
            {
                let mut sessions = sessions;
                let session_id = session_id.clone();
                let runtime_for_host = Rc::clone(&runtime_for_kickoff);
                spawn_detached(async move {
                    let device = _session.device.handle.device();
                    if let Err(err) =
                        run_web_host_daemon(device, runtime_for_host, sessions, session_id.clone())
                            .await
                    {
                        tracing::error!("web host daemon failed for {session_id}: {err:#}");
                        update_session_phase(
                            &mut sessions,
                            &session_id,
                            SessionPhase::Error {
                                summary: format!("{err:#}"),
                            },
                        );
                    }
                });
            }
        }
    });

    #[cfg(target_arch = "wasm32")]
    {
        let mut smoo_stats = smoo_stats;
        let mut smoo_stats_stop = smoo_stats_stop;
        let smoo_stats_handle = runtime.smoo_stats.clone();
        use_effect(move || {
            if smoo_stats_stop().is_some() {
                return;
            }
            let smoo_stats_handle = smoo_stats_handle.clone();

            let stop = Rc::new(Cell::new(false));
            smoo_stats_stop.set(Some(stop.clone()));
            spawn_detached(async move {
                run_smoo_stats_view_loop(
                    smoo_stats_handle,
                    || sleep(CACHE_STATS_POLL_INTERVAL),
                    || Date::now() / 1000.0,
                    move || stop.get(),
                    move |stats_view| {
                        smoo_stats.set(Some(stats_view));
                    },
                )
                .await;
            });
        });
    }

    #[cfg(target_arch = "wasm32")]
    {
        let mut smoo_stats_stop = smoo_stats_stop;
        use_drop(move || {
            if let Some(stop) = smoo_stats_stop.write().take() {
                stop.set(true);
            }
        });
    }

    let smoo_stats = smoo_stats();

    rsx! {
        section { id: "landing",
            div { class: "landing__panel",
                p { class: "landing__eyebrow", "Active" }
                h1 { "We're live." }
                p { class: "landing__lede", "Please don't close this page while the session is active." }
                p { class: "landing__note", "Channel: {channel}" }
                if let Some(selected_boot_profile_id) = selected_boot_profile_id {
                    p { class: "landing__note", "Boot profile: {selected_boot_profile_id}" }
                }
                if let Some(smoo_stats) = smoo_stats {
                    SmooStatsPanel { stats: smoo_stats }
                }
                if host_connected {
                    SerialLogPanel { device_vid, device_pid }
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn use_screen_wake_lock() {
    let mut sentinel = use_signal(|| Option::<WakeLockSentinel>::None);
    let cancelled = use_signal(|| Rc::new(Cell::new(false)));
    let request_pending = use_signal(|| Rc::new(Cell::new(false)));
    let mut visibility_listener = use_signal(|| Option::<Closure<dyn FnMut(JsValue)>>::None);

    use_effect(move || {
        acquire_screen_wake_lock(sentinel, cancelled(), request_pending());
    });

    use_effect(move || {
        if visibility_listener.read().is_some() {
            return;
        }

        let Some(document) = web_sys::window().and_then(|window| window.document()) else {
            return;
        };

        let listener = Closure::<dyn FnMut(JsValue)>::new(move |_| {
            acquire_screen_wake_lock(sentinel, cancelled(), request_pending());
        });
        if let Err(err) = document
            .add_event_listener_with_callback("visibilitychange", listener.as_ref().unchecked_ref())
        {
            tracing::warn!(
                error = %js_value_to_string(&err),
                "screen wake lock visibility listener registration failed"
            );
            return;
        }
        visibility_listener.set(Some(listener));
    });

    use_drop(move || {
        cancelled().set(true);
        if let Some(listener) = visibility_listener.write().take() {
            if let Some(document) = web_sys::window().and_then(|window| window.document()) {
                let _ = document.remove_event_listener_with_callback(
                    "visibilitychange",
                    listener.as_ref().unchecked_ref(),
                );
            }
        }
        if let Some(lock) = sentinel.write().take() {
            spawn_detached(async move {
                release_screen_wake_lock(lock).await;
            });
        }
    });
}

#[cfg(target_arch = "wasm32")]
fn acquire_screen_wake_lock(
    mut sentinel: Signal<Option<WakeLockSentinel>>,
    cancelled: Rc<Cell<bool>>,
    request_pending: Rc<Cell<bool>>,
) {
    if cancelled.get() || request_pending.get() || document_hidden() {
        return;
    }

    if let Some(lock) = sentinel() {
        if !lock.released() {
            return;
        }
        sentinel.write().take();
    }

    request_pending.set(true);
    spawn_detached(async move {
        match request_screen_wake_lock().await {
            Ok(lock) if cancelled.get() => {
                request_pending.set(false);
                release_screen_wake_lock(lock).await;
            }
            Ok(lock) => {
                request_pending.set(false);
                tracing::info!("screen wake lock acquired");
                sentinel.set(Some(lock));
            }
            Err(err) => {
                request_pending.set(false);
                tracing::warn!(
                    error = %js_value_to_string(&err),
                    "screen wake lock request failed"
                );
            }
        }
    });
}

#[cfg(target_arch = "wasm32")]
async fn request_screen_wake_lock() -> Result<WakeLockSentinel, JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("window unavailable"))?;
    let navigator = window.navigator();
    let wake_lock = Reflect::get(navigator.as_ref(), &JsValue::from_str("wakeLock"))?;
    if wake_lock.is_null() || wake_lock.is_undefined() {
        return Err(JsValue::from_str("Screen Wake Lock API unavailable"));
    }

    let wake_lock = navigator.wake_lock();
    let sentinel = JsFuture::from(wake_lock.request(WakeLockType::Screen)).await?;
    Ok(sentinel.unchecked_into::<WakeLockSentinel>())
}

#[cfg(target_arch = "wasm32")]
async fn release_screen_wake_lock(sentinel: WakeLockSentinel) {
    if sentinel.released() {
        return;
    }

    if let Err(err) = JsFuture::from(sentinel.release()).await {
        tracing::debug!(
            error = %js_value_to_string(&err),
            "screen wake lock release failed"
        );
    }
}

#[cfg(target_arch = "wasm32")]
fn document_hidden() -> bool {
    web_sys::window()
        .and_then(|window| window.document())
        .map(|document| document.hidden())
        .unwrap_or(false)
}

#[cfg(target_arch = "wasm32")]
fn js_value_to_string(value: &JsValue) -> String {
    js_sys::JSON::stringify(value)
        .ok()
        .and_then(|s| s.as_string())
        .unwrap_or_else(|| format!("{value:?}"))
}

#[component]
fn BootError(summary: String) -> Element {
    rsx! {
        section { id: "landing",
            div { class: "landing__panel",
                p { class: "landing__eyebrow", "onoes" }
                h1 { "Boot failed" }
                p { class: "landing__lede", "{summary}" }
            }
        }
    }
}
