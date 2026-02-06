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
pub fn Hero(state: ProbeState, on_connect: Option<EventHandler<MouseEvent>>) -> Element {
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
                    for device in devices {
                        DeviceRow { device: device.clone() }
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
fn DeviceRow(device: DetectedDevice) -> Element {
    let id = format!("{:04x}:{:04x}", device.vid, device.pid);
    rsx! {
        li {
            span { class: "device-id", "{id}" }
            span { class: "device-name", "{device.name}" }
            span { class: "device-mode", "fastboot" }
        }
    }
}
