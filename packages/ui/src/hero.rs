use dioxus::prelude::*;

const HERO_CSS: Asset = asset!("/assets/styling/hero.css");

#[component]
pub fn Hero(webusb_supported: Option<bool>) -> Element {
    let status_class = match webusb_supported {
        Some(true) => "cta cta--ready",
        Some(false) => "cta cta--blocked",
        None => "cta cta--ready",
    };

    let cta = match webusb_supported {
        Some(true) | None => rsx! {
            button { class: "cta__button", "Connect a device" }
            p { class: "cta__hint", "Put your device into fastboot mode and click the big button already!" }
        },
        Some(false) => rsx! {
            p { class: "cta__error", "WebUSB unsupported" }
            p { class: "cta__hint", "fastboop requires WebUSB, which is only available in Chromium-based browsers. Desktop app coming soon on Flathub for Firefox users." }
        },
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
                    "fastboop talks to a vendor bootloader over WebUSB, builds a tiny stage0 initrd, "
                    "and boots straight into smoo. Nothing is written to storage."
                }

                ol { class: "landing__steps",
                    li { "Plug a device in fastboot mode" }
                    li { "Verify the DevPro match" }
                    li { "Stage0 is built from your rootfs" }
                    li { "Ephemeral RAM boot into smoo" }
                }

                div { class: status_class, {cta} }
            }
        }
    }
}
