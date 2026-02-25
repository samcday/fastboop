use dioxus::prelude::*;

pub const DEFAULT_ENABLE_SERIAL: bool = true;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootProfileOptionView {
    pub id: String,
    pub label: String,
}

#[component]
pub fn BootConfigCard(
    device_name: String,
    device_id: String,
    profile_id: String,
    boot_profile_options: Vec<BootProfileOptionView>,
    selected_boot_profile_id: Option<String>,
    channel: String,
    extra_kargs: String,
    enable_serial: bool,
    on_channel_change: EventHandler<String>,
    on_boot_profile_change: EventHandler<String>,
    on_extra_kargs_change: EventHandler<String>,
    on_enable_serial_change: EventHandler<bool>,
    on_start_boot: EventHandler<MouseEvent>,
    show_channel_input: bool,
) -> Element {
    let boot_profile_required = boot_profile_options.len() > 1;
    let can_start_boot = !boot_profile_required || selected_boot_profile_id.is_some();
    let single_boot_profile_label = if boot_profile_options.len() == 1 {
        Some(boot_profile_options[0].label.clone())
    } else {
        None
    };

    rsx! {
        section { id: "landing",
            div { class: "landing__glow" }
            div { class: "landing__panel",
                p { class: "landing__eyebrow", "Boot config" }
                h1 { "{device_name}" }
                p { class: "landing__lede", "Configure extra kernel args and serial options before booting." }
                p { class: "landing__note", "Device: {device_id} | Profile: {profile_id}" }

                div { class: "boot-config",
                    if boot_profile_options.is_empty() {
                        label { class: "boot-config__field",
                            span { class: "boot-config__label", "Boot profile" }
                            input {
                                class: "boot-config__input",
                                r#type: "text",
                                value: "<none: direct channel artifact>",
                                disabled: true,
                            }
                        }
                    } else if boot_profile_options.len() == 1 {
                        label { class: "boot-config__field",
                            span { class: "boot-config__label", "Boot profile" }
                            input {
                                class: "boot-config__input",
                                r#type: "text",
                                value: single_boot_profile_label.clone().unwrap_or_default(),
                                disabled: true,
                            }
                        }
                    } else {
                        label { class: "boot-config__field",
                            span { class: "boot-config__label", "Boot profile" }
                            select {
                                class: "boot-config__input",
                                value: selected_boot_profile_id.clone().unwrap_or_default(),
                                onchange: move |evt| {
                                    let value = evt.value();
                                    if !value.trim().is_empty() {
                                        on_boot_profile_change.call(value);
                                    }
                                },
                                option { value: "", disabled: true, "-- choose boot profile --" }
                                for boot_option in boot_profile_options.iter() {
                                    option {
                                        value: "{boot_option.id}",
                                        "{boot_option.label}"
                                    }
                                }
                            }
                        }
                        if selected_boot_profile_id.is_none() {
                            p { class: "boot-config__hint", "Choose a boot profile before starting boot." }
                        }
                    }

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
                        disabled: !can_start_boot,
                        onclick: move |evt| on_start_boot.call(evt),
                        "Start boot"
                    }
                }
            }
        }
    }
}
