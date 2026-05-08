use dioxus::prelude::*;
use ui::{Hero, ProbeState, TransportKind};

use crate::android_usb::{self, UsbSnapshot};

#[component]
pub fn Home() -> Element {
    rsx! {
        div { class: "mobile-home",
            Hero {
                state: ProbeState::Ready {
                    transport: TransportKind::NativeUsb,
                    devices: Vec::new(),
                },
                on_connect: None,
                on_boot: None,
                on_select_profile: None,
            }

            AndroidUsbPanel {}
        }
    }
}

#[component]
fn AndroidUsbPanel() -> Element {
    let mut snapshot = use_signal(UsbSnapshot::default);
    let mut status = use_signal(|| "Press refresh to read Android UsbManager state.".to_string());

    let refresh = move |_| match android_usb::snapshot() {
        Ok(next) => {
            let count = next.devices.len();
            status.set(format!("UsbManager returned {count} device(s)."));
            snapshot.set(next);
        }
        Err(err) => status.set(err.to_string()),
    };

    let current = snapshot();
    let status_text = status();
    let last_permission = current
        .last_permission_result
        .clone()
        .unwrap_or_else(|| "none yet".to_string());

    rsx! {
        section { class: "android-usb",
            div { class: "android-usb__header",
                div {
                    p { class: "android-usb__eyebrow", "Android USB host spike" }
                    h2 { "Permission and fd plumbing" }
                }
                button { class: "android-usb__button", onclick: refresh, "Refresh" }
            }

            p { class: "android-usb__copy",
                "This panel calls Android UsbManager through MainActivity JNI helpers. It only proves device enumeration, permission prompts, and raw fd handoff; fastboot and smoo transport binding come next."
            }

            p { class: "android-usb__status", "{status_text}" }

            if !current.supported {
                p { class: "android-usb__empty", "USB host probing is available only in Android builds." }
            } else if current.devices.is_empty() {
                p { class: "android-usb__empty", "No Android USB devices are currently visible." }
            } else {
                ul { class: "android-usb__devices",
                    for device in current.devices.iter() {
                        AndroidUsbDeviceRow { device: device.clone(), status }
                    }
                }
            }

            p { class: "android-usb__permission", "Last permission result: {last_permission}" }
        }
    }
}

#[component]
fn AndroidUsbDeviceRow(device: android_usb::UsbDevice, mut status: Signal<String>) -> Element {
    let id = format!("{:04x}:{:04x}", device.vendor_id, device.product_id);
    let class = format!(
        "class {:02x}/{:02x}/{:02x}, {} interface(s)",
        device.device_class, device.device_subclass, device.device_protocol, device.interface_count
    );
    let permission = if device.has_permission {
        "permission granted"
    } else {
        "permission needed"
    };
    let request_name = device.name.clone();
    let open_name = device.name.clone();

    rsx! {
        li { class: "android-usb-device",
            div { class: "android-usb-device__main",
                span { class: "android-usb-device__id", "{id}" }
                span { class: "android-usb-device__name", "{device.name}" }
                span { class: "android-usb-device__meta", "{class}" }
            }

            span { class: "android-usb-device__permission", "{permission}" }

            button {
                class: "android-usb__button android-usb__button--secondary",
                disabled: device.has_permission,
                onclick: move |_| match android_usb::request_permission(&request_name) {
                    Ok(true) => status.set(format!("Requested Android USB permission for {request_name}.")),
                    Ok(false) => status.set(format!("Android could not find {request_name}.")),
                    Err(err) => status.set(err.to_string()),
                },
                "Request"
            }

            button {
                class: "android-usb__button android-usb__button--secondary",
                disabled: !device.has_permission,
                onclick: move |_| match android_usb::open_device_fd(&open_name) {
                    Ok(fd) if fd >= 0 => status.set(format!("Opened {open_name}; Android returned fd {fd}.")),
                    Ok(-1) => status.set(format!("Android could not find {open_name}.")),
                    Ok(-2) => status.set(format!("Android permission is missing for {open_name}.")),
                    Ok(-3) => status.set(format!("Android failed to open {open_name}.")),
                    Ok(code) => status.set(format!("Android returned unexpected fd status {code} for {open_name}.")),
                    Err(err) => status.set(err.to_string()),
                },
                "Open fd"
            }
        }
    }
}
