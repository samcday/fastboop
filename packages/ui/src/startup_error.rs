use dioxus::prelude::*;

const HERO_CSS: Asset = asset!("/assets/styling/hero.css");

fn stylesheet_href(asset: &Asset, flatpak_path: &str) -> String {
    if cfg!(flatpak_runtime_paths) {
        flatpak_path.to_string()
    } else {
        asset.to_string()
    }
}

#[component]
pub fn StartupError(title: String, details: String, launch_hint: String) -> Element {
    let hero_css = stylesheet_href(&HERO_CSS, "/assets/styling/hero.css");

    rsx! {
        document::Link { rel: "stylesheet", href: hero_css }

        section { id: "landing",
            div { class: "landing__glow" }
            div { class: "landing__panel",
                p { class: "landing__eyebrow", "Startup error" }
                h1 { "{title}" }
                p { class: "landing__lede",
                    "fastboop is intended to be launched by a distro integration that provides a boot channel automatically."
                }

                div { class: "cta cta--blocked",
                    p { class: "cta__error", "{details}" }
                    p { class: "cta__hint", "{launch_hint}" }
                }

                p { class: "landing__note",
                    "Looking for a way to try this today? "
                    a {
                        href: "https://github.com/samcday/live-pocket-fedora",
                        target: "_blank",
                        rel: "noopener noreferrer",
                        "live-pocket-fedora"
                    }
                    " is one option."
                }
            }
        }
    }
}
