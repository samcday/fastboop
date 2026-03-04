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
pub fn StartupError(
    title: String,
    details: String,
    launch_hint: String,
    on_drop_channel: Option<EventHandler<DragEvent>>,
    on_pick_channel: Option<EventHandler<MouseEvent>>,
    drop_hint: Option<String>,
    channel_url_value: Option<String>,
    on_channel_url_input: Option<EventHandler<FormEvent>>,
    on_submit_channel_url: Option<EventHandler<MouseEvent>>,
    submit_channel_url_pending: Option<bool>,
) -> Element {
    let hero_css = stylesheet_href(&HERO_CSS, "/assets/styling/hero.css");
    let drop_hint = drop_hint.unwrap_or_else(|| {
        "Drop a local artifact and fastboop will attempt channel detection.".to_string()
    });
    let dropzone_clickable = on_pick_channel.is_some();
    let on_pick_channel_for_dropzone = on_pick_channel.clone();
    let channel_url_value = channel_url_value.unwrap_or_default();
    let submit_channel_url_pending = submit_channel_url_pending.unwrap_or(false);
    let submit_channel_url_disabled =
        submit_channel_url_pending || channel_url_value.trim().is_empty();

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

                if let Some(on_drop_channel) = on_drop_channel {
                    div {
                        class: if dropzone_clickable {
                            "startup-dropzone startup-dropzone--clickable"
                        } else {
                            "startup-dropzone"
                        },
                        ondragenter: move |evt| evt.prevent_default(),
                        ondragover: move |evt| evt.prevent_default(),
                        onclick: move |evt| {
                            if let Some(on_pick_channel) = &on_pick_channel_for_dropzone {
                                evt.prevent_default();
                                on_pick_channel.call(evt);
                            }
                        },
                        ondrop: move |evt| {
                            evt.prevent_default();
                            on_drop_channel.call(evt);
                        },
                        p { class: "startup-dropzone__title", "Drop a channel file to continue" }
                        p { class: "startup-dropzone__hint", "{drop_hint}" }
                    }
                }

                if let (Some(on_channel_url_input), Some(on_submit_channel_url)) =
                    (on_channel_url_input, on_submit_channel_url)
                {
                    div { class: "startup-channel-url",
                        p { class: "startup-channel-url__label", "or enter a channel URL" }
                        div { class: "startup-channel-url__row",
                            input {
                                class: "startup-channel-url__input",
                                r#type: "url",
                                placeholder: "https://example.invalid/channel.ero",
                                value: channel_url_value,
                                disabled: submit_channel_url_pending,
                                oninput: move |evt| on_channel_url_input.call(evt),
                            }
                            button {
                                class: "cta__button startup-channel-url__button",
                                disabled: submit_channel_url_disabled,
                                onclick: move |evt| {
                                    evt.prevent_default();
                                    if !submit_channel_url_disabled {
                                        on_submit_channel_url.call(evt);
                                    }
                                },
                                if submit_channel_url_pending {
                                    span {
                                        class: "startup-channel-url__spinner",
                                        aria_hidden: "true",
                                    }
                                    span { "Checking..." }
                                } else {
                                    "Go"
                                }
                            }
                        }
                        p {
                            class: "startup-channel-url__hint",
                            "HTTP(S) URLs are supported. The channel remains in your address bar."
                        }
                    }
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
