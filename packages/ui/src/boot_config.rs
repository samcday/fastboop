use dioxus::prelude::*;

pub const DEFAULT_EXTRA_KARGS: &str =
    "selinux=0 sysrq_always_enabled=1 panic=5 smoo.max_io_bytes=1048576 init_on_alloc=0 rhgb drm.panic_screen=kmsg smoo.queue_count=1 smoo.queue_depth=1 regulator_ignore_unused";
pub const DEFAULT_ENABLE_SERIAL: bool = true;

#[component]
pub fn BootConfigCard(
    device_name: String,
    device_id: String,
    profile_id: String,
    channel: String,
    extra_kargs: String,
    enable_serial: bool,
    on_channel_change: EventHandler<String>,
    on_extra_kargs_change: EventHandler<String>,
    on_enable_serial_change: EventHandler<bool>,
    on_start_boot: EventHandler<MouseEvent>,
    show_channel_input: bool,
) -> Element {
    rsx! {
        section { id: "landing",
            div { class: "landing__glow" }
            div { class: "landing__panel",
                p { class: "landing__eyebrow", "Boot config" }
                h1 { "{device_name}" }
                p { class: "landing__lede", "Configure extra kernel args and serial options before booting." }
                p { class: "landing__note", "Device: {device_id} | Profile: {profile_id}" }

                div { class: "boot-config",
                    if show_channel_input {
                        label { class: "boot-config__field",
                            span { class: "boot-config__label", "Channel" }
                            input {
                                class: "boot-config__input",
                                r#type: "text",
                                value: channel,
                                oninput: move |evt| on_channel_change.call(evt.value()),
                            }
                        }
                    }

                    label { class: "boot-config__field",
                        span { class: "boot-config__label", "Extra kernel args" }
                        input {
                            class: "boot-config__input",
                            r#type: "text",
                            value: extra_kargs,
                            oninput: move |evt| on_extra_kargs_change.call(evt.value()),
                        }
                    }

                    label { class: "boot-config__toggle",
                        input {
                            r#type: "checkbox",
                            checked: enable_serial,
                            onchange: move |_| on_enable_serial_change.call(!enable_serial),
                        }
                        span { "Enable serial" }
                    }

                    button {
                        class: "cta__button boot-config__submit",
                        onclick: move |evt| on_start_boot.call(evt),
                        "Start boot"
                    }
                }
            }
        }
    }
}
