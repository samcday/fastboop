use dioxus::prelude::*;

#[component]
pub fn WebUnsupported(channel: String) -> Element {
    let command = cli_boot_command(&channel);

    rsx! {
        section { class: "unsupported",
            div { class: "unsupported__panel",
                p { class: "unsupported__eyebrow", "WebUSB unavailable" }
                h1 { "fastboop does not support this browser" }
                p {
                    class: "unsupported__copy",
                    "Sorry! fastboop needs WebUSB, which is typically only available on Chromium browsers."
                }
                p {
                    class: "unsupported__copy",
                    a {
                        href: "http://docs.fastboop.win/user/quick-start/",
                        target: "_blank",
                        rel: "noopener noreferrer",
                        "Use the CLI"
                    }
                    " on this machine to continue booting."
                }
                pre { class: "unsupported__command",
                    code { "{command}" }
                }
                p {
                    class: "unsupported__copy unsupported__copy--muted",
                    a {
                        href: "https://github.com/samcday/fastboop/issues/41",
                        target: "_blank",
                        rel: "noopener noreferrer",
                        "A desktop app will be available soon."
                    }
                }
            }
        }
    }
}

fn cli_boot_command(channel: &str) -> String {
    format!("fastboop boot \"{}\"", channel)
}
