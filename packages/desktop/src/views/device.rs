use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dioxus::prelude::*;
use tracing::error;
use ui::{run_smoo_stats_view_loop, BootConfigCard, SmooStatsPanel, SmooStatsViewModel};

use super::device_boot::{boot_selected_device, run_rusb_host_daemon};
use super::session::{
    update_session_boot_config, update_session_phase, SessionPhase, SessionStore,
};

const CACHE_STATS_POLL_INTERVAL: Duration = Duration::from_millis(500);

#[component]
pub fn DevicePage(session_id: String) -> Element {
    let sessions = use_context::<SessionStore>();
    let navigator = use_navigator();

    let Some(session) = sessions.read().iter().find(|s| s.id == session_id).cloned() else {
        return rsx! {
            section { id: "landing",
                div { class: "landing__panel",
                    h1 { "Session not found" }
                    p { "That device session no longer exists." }
                    button { class: "cta__button", onclick: move |_| { navigator.push(crate::Route::Home {}); }, "Back" }
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

    let mut sessions_for_serial = sessions;
    let session_id_for_serial = session_id.clone();
    let on_enable_serial_change = move |value: bool| {
        update_session_boot_config(&mut sessions_for_serial, &session_id_for_serial, |config| {
            config.enable_serial = value;
        });
    };

    let mut sessions_for_start = sessions;
    let session_id_for_start = session_id.clone();
    let on_start_boot = move |_| {
        update_session_phase(
            &mut sessions_for_start,
            &session_id_for_start,
            SessionPhase::Booting {
                step: "Queued".to_string(),
            },
        );
    };

    rsx! {
        BootConfigCard {
            device_name: session.device.name,
            device_id: format!("{:04x}:{:04x}", session.device.vid, session.device.pid),
            profile_id: session.device.profile.id,
            channel: session.boot_config.channel,
            extra_kargs: session.boot_config.extra_kargs,
            enable_serial: session.boot_config.enable_serial,
            on_channel_change,
            on_extra_kargs_change,
            on_enable_serial_change,
            on_start_boot,
        }
    }
}

#[component]
fn BootingDevice(session_id: String, step: String) -> Element {
    let sessions = use_context::<SessionStore>();
    let mut started = use_signal(|| false);

    use_effect(move || {
        if started() {
            return;
        }
        started.set(true);
        let mut sessions = sessions;
        let session_id = session_id.clone();
        spawn(async move {
            match boot_selected_device(&mut sessions, &session_id).await {
                Ok(runtime) => update_session_phase(
                    &mut sessions,
                    &session_id,
                    SessionPhase::Active {
                        runtime,
                        host_started: false,
                    },
                ),
                Err(err) => update_session_phase(
                    &mut sessions,
                    &session_id,
                    SessionPhase::Error {
                        summary: err.to_string(),
                    },
                ),
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
        .and_then(|s| match &s.phase {
            SessionPhase::Active {
                runtime,
                host_started,
            } => Some((
                runtime.clone(),
                *host_started,
                s.boot_config.channel.clone(),
            )),
            _ => None,
        });
    let Some((runtime, host_started, channel)) = state else {
        return rsx! {};
    };

    let mut kickoff = use_signal(|| false);
    let smoo_stats = use_signal(|| Option::<SmooStatsViewModel>::None);
    let smoo_stats_stop = use_signal(|| Option::<Arc<AtomicBool>>::None);
    let runtime_for_kickoff = runtime.clone();
    use_effect(move || {
        if host_started || kickoff() {
            return;
        }
        kickoff.set(true);
        update_session_phase(
            &mut sessions,
            &session_id,
            SessionPhase::Active {
                runtime: runtime_for_kickoff.clone(),
                host_started: true,
            },
        );
        let runtime_for_host = runtime_for_kickoff.clone();
        std::thread::Builder::new()
            .name(format!("fastboop-smoo-{session_id}"))
            .spawn(move || {
                if let Err(err) = run_rusb_host_daemon(
                    runtime_for_host.reader,
                    runtime_for_host.size_bytes,
                    runtime_for_host.identity,
                    runtime_for_host.smoo_stats,
                ) {
                    error!(%err, "desktop smoo host daemon stopped");
                }
            })
            .ok();
    });

    {
        let mut smoo_stats = smoo_stats;
        let mut smoo_stats_stop = smoo_stats_stop;
        let smoo_stats_handle = runtime.smoo_stats.clone();
        use_effect(move || {
            if smoo_stats_stop().is_some() {
                return;
            }
            let smoo_stats_handle = smoo_stats_handle.clone();

            let stop = Arc::new(AtomicBool::new(false));
            smoo_stats_stop.set(Some(stop.clone()));
            spawn(async move {
                let started = std::time::Instant::now();
                run_smoo_stats_view_loop(
                    smoo_stats_handle,
                    || tokio::time::sleep(CACHE_STATS_POLL_INTERVAL),
                    move || started.elapsed().as_secs_f64(),
                    move || stop.load(Ordering::Relaxed),
                    move |stats_view| {
                        smoo_stats.set(Some(stats_view));
                    },
                )
                .await;
            });
        });
    }

    {
        let mut smoo_stats_stop = smoo_stats_stop;
        use_drop(move || {
            if let Some(stop) = smoo_stats_stop.write().take() {
                stop.store(true, Ordering::Relaxed);
            }
        });
    }

    let smoo_stats = smoo_stats();

    rsx! {
        section { id: "landing",
            div { class: "landing__panel",
                p { class: "landing__eyebrow", "Active" }
                h1 { "We're live." }
                p { class: "landing__lede", "Please don't close this window while the session is active." }
                p { class: "landing__note", "Channel: {channel}" }
                if let Some(smoo_stats) = smoo_stats {
                    SmooStatsPanel { stats: smoo_stats }
                }
            }
        }
    }
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
