use dioxus::prelude::*;

use crate::{DetectedDevice, ProbeState, TransportKind};

const HERO_CSS: Asset = asset!("/assets/styling/hero.css");

fn stylesheet_href(asset: &Asset, flatpak_path: &str) -> String {
    if std::env::var_os("FLATPAK_ID").is_some() {
        flatpak_path.to_string()
    } else {
        asset.to_string()
    }
}

#[component]
pub fn Hero(
    state: ProbeState,
    on_connect: Option<EventHandler<MouseEvent>>,
    on_boot: Option<EventHandler<usize>>,
    on_select_profile: Option<EventHandler<(usize, usize)>>,
) -> Element {
    let hero_css = stylesheet_href(&HERO_CSS, "/assets/styling/hero.css");

    let (cta, status_class) = match &state {
        ProbeState::Loading => (
            rsx! {
                p { class: "cta__hint", "Checking for devices..." }
            },
            "cta cta--checking",
        ),
        ProbeState::Unsupported => (
            rsx! {
                p { class: "cta__error", "Unsupported browser" }
                p { class: "cta__hint", "Yes, I know it's 2026. But WebUSB is missing in this browser, sorry :( fastboop requires a Chromium-based browser. Otherwise, use the CLI or the desktop app." }
            },
            "cta cta--blocked",
        ),
        ProbeState::Ready {
            transport: TransportKind::WebUsb,
            ..
        } => {
            let cta = match on_connect {
                Some(handler) => rsx! {
                    button { class: "cta__button", onclick: move |evt| handler.call(evt), "Connect a device" }
                    p { class: "cta__hint", "WebUSB only shows previously authorized devices." }
                },
                None => rsx! {
                    p { class: "cta__hint", "WebUSB only shows previously authorized devices." }
                },
            };
            (cta, "cta cta--ready")
        }
        ProbeState::Ready {
            transport: TransportKind::NativeUsb,
            ..
        } => (
            rsx! {
                p { class: "cta__hint", "Native USB will scan for fastboot devices." }
            },
            "cta cta--ready",
        ),
    };

    let devices = match &state {
        ProbeState::Ready { devices, .. } => devices.as_slice(),
        _ => &[],
    };

    let device_list = if devices.is_empty() {
        rsx! {}
    } else {
        rsx! {
            div { class: "device-list",
                h2 { "Detected devices" }
                ul {
                    for (index, device) in devices.iter().enumerate() {
                        DeviceRow {
                            index,
                            device: device.clone(),
                            on_boot: on_boot,
                            on_select_profile: on_select_profile,
                        }
                    }
                }
            }
        }
    };

    rsx! {
        document::Link { rel: "stylesheet", href: hero_css }

        section {
            id: "landing",
            div { class: "landing__glow" }
            div { class: "landing__panel",
                p { class: "landing__eyebrow", "Zero-flash Linux boot" }
                h1 { "Boot real Linux on pocket hardware without flashing." }
                p { class: "landing__lede",
                    "fastboop talks to a vendor bootloader over USB (WebUSB in the browser), builds a tiny stage0 initrd, "
                    "and boots straight into smoo. Nothing is written to storage."
                }

                ol { class: "landing__steps",
                    li { "Plug a device in fastboot mode" }
                    li { "Verify the DevPro match" }
                    li { "Stage0 is built from your rootfs" }
                    li { "Ephemeral RAM boot into smoo" }
                }

                {device_list}

                if devices.is_empty() {
                    div { class: status_class, {cta} }
                }

                p { class: "landing__note",
                    "Desktop app coming soon on Flathub for folks who can't use WebUSB."
                }
            }
        }
    }
}

#[component]
fn DeviceRow(
    index: usize,
    device: DetectedDevice,
    on_boot: Option<EventHandler<usize>>,
    on_select_profile: Option<EventHandler<(usize, usize)>>,
) -> Element {
    let id = format!("{:04x}:{:04x}", device.vid, device.pid);
    let selected_profile = if device.profile_options.len() == 1 {
        Some(0)
    } else {
        device.selected_profile
    };
    let boot_enabled = selected_profile.is_some();
    let boot_button = match on_boot {
        Some(handler) => rsx! {
            button {
                class: "device-boot",
                disabled: !boot_enabled,
                onclick: move |_| handler.call(index),
                "Boot"
            }
        },
        None => rsx! {},
    };
    let profile_badge = if device.profile_options.len() == 1 {
        let profile = &device.profile_options[0];
        rsx! {
            span { class: "device-profile", "{profile.name} ({profile.profile_id})" }
        }
    } else {
        rsx! {}
    };
    let profile_picker = if device.profile_options.len() > 1 {
        let selected = selected_profile
            .map(|choice| choice.to_string())
            .unwrap_or_default();
        match on_select_profile {
            Some(handler) => rsx! {
                label { class: "device-profile-picker",
                    span { class: "device-profile-picker__label", "Device profile" }
                    select {
                        class: "device-profile-picker__select",
                        value: selected,
                        onchange: move |evt| {
                            let value = evt.value();
                            if let Ok(choice) = value.parse::<usize>() {
                                handler.call((index, choice));
                            }
                        },
                        option { value: "", disabled: true, "-- choose a profile --" }
                        for (choice_index, profile) in device.profile_options.iter().enumerate() {
                            option {
                                value: "{choice_index}",
                                "{profile.name} ({profile.profile_id})"
                            }
                        }
                    }
                }
            },
            None => rsx! {},
        }
    } else {
        rsx! {}
    };
    let profile_hint = if device.profile_options.len() > 1 && selected_profile.is_none() {
        rsx! {
            p { class: "device-hint", "Choose a device profile before booting." }
        }
    } else {
        rsx! {}
    };
    rsx! {
        li {
            span { class: "device-id", "{id}" }
            div { class: "device-details",
                span { class: "device-name", "{device.name}" }
                {profile_badge}
                {profile_picker}
                {profile_hint}
            }
            span { class: "device-mode", "fastboot" }
            {boot_button}
        }
    }
}
