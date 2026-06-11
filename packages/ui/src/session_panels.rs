use dioxus::prelude::*;

use crate::{SmooStatsPanel, SmooStatsViewModel};

#[component]
pub fn BootingPanel(step: String) -> Element {
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
pub fn ActiveSessionPanel(
    channel: String,
    selected_boot_profile_id: Option<String>,
    close_target: String,
    stats: Option<SmooStatsViewModel>,
    extra: Element,
) -> Element {
    rsx! {
        section { id: "landing",
            div { class: "landing__panel",
                p { class: "landing__eyebrow", "Active" }
                h1 { "We're live." }
                p { class: "landing__lede", "Please don't close this {close_target} while the session is active." }
                p { class: "landing__note", "Channel: {channel}" }
                if let Some(selected_boot_profile_id) = selected_boot_profile_id {
                    p { class: "landing__note", "Boot profile: {selected_boot_profile_id}" }
                }
                if let Some(stats) = stats {
                    SmooStatsPanel { stats }
                }
                {extra}
            }
        }
    }
}

#[component]
pub fn BootErrorPanel(summary: String) -> Element {
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
