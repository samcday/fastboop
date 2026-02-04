use dioxus::prelude::*;
use ui::Hero;

#[component]
pub fn Home() -> Element {
    let webusb_supported = use_resource(|| async move {
        document::eval("return !!(navigator && navigator.usb);")
            .join::<bool>()
            .await
            .unwrap_or(false)
    });

    rsx! {
        Hero { webusb_supported: webusb_supported() }
    }
}
