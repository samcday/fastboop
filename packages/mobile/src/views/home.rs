use dioxus::prelude::*;
use ui::{Hero, ProbeState, TransportKind};

#[component]
pub fn Home() -> Element {
    rsx! {
        Hero {
            state: ProbeState::Ready {
                transport: TransportKind::NativeUsb,
                devices: Vec::new(),
            },
            on_connect: None,
        }
    }
}
