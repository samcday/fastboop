use dioxus::prelude::*;

use crate::{DetectedDevice, ProbeState, TransportKind};

const HERO_CSS: Asset = asset!("/assets/styling/hero.css");

#[component]
pub fn Hero(state: ProbeState) -> Element {
    let (cta, status_class) = match &state {
        ProbeState::Loading => (
            rsx! {
                p { class: "cta__hint", "Checking for devices..." }
            },
            "cta cta--checking",
        ),
        ProbeState::Unsupported => (
            rsx! {
                p { class: "cta__error", "sorry ur browser sux lol" }
                p { class: "cta__hint", "WebUSB is missing here. Chromium-based browsers are required." }
            },
            "cta cta--blocked",
        ),
        ProbeState::Ready {
            transport: TransportKind::WebUsb,
            ..
        } => (
            rsx! {
                button { class: "cta__button", "Connect a device" }
                p { class: "cta__hint", "WebUSB only shows previously authorized devices." }
            },
            "cta cta--ready",
        ),
        ProbeState::Ready {
            transport: TransportKind::NativeUsb,
            ..
        } => (
            rsx! {
                button { class: "cta__button", "Connect a device" }
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
        document::Link { rel: "stylesheet", href: HERO_CSS }

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
            span { class: "device-mode", "fastboot" }
        }
    }
}
