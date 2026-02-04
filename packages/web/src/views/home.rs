use dioxus::prelude::*;
use ui::{DetectedDevice, Hero, ProbeState, TransportKind};

const WEBUSB_PROBE: &str = r#"
const supported = !!(navigator && navigator.usb);
if (!supported) {
  return "unsupported";
}
try {
  const devices = await navigator.usb.getDevices();
  return devices.map((device) => {
    const vid = device.vendorId.toString(16).padStart(4, "0");
    const pid = device.productId.toString(16).padStart(4, "0");
    return `${vid}:${pid}`;
  }).join(",");
} catch (_) {
  return "error";
}
"#;

fn parse_devices(raw: &str) -> Vec<DetectedDevice> {
    if raw.trim().is_empty() {
        return Vec::new();
    }
    raw.split(',')
        .filter_map(|pair| {
            let (vid, pid) = pair.split_once(':')?;
            let vid = u16::from_str_radix(vid, 16).ok()?;
            let pid = u16::from_str_radix(pid, 16).ok()?;
            Some(DetectedDevice { vid, pid })
        })
        .collect()
}

#[component]
pub fn Home() -> Element {
    let probe = use_resource(|| async move {
        let raw = document::eval(WEBUSB_PROBE)
            .join::<String>()
            .await
            .unwrap_or_else(|_| "error".to_string());

        if raw == "unsupported" {
            return ProbeState::Unsupported;
        }

        let devices = parse_devices(&raw);
        ProbeState::Ready {
            transport: TransportKind::WebUsb,
            devices,
        }
    });

    let state = match probe() {
        Some(state) => state,
        None => ProbeState::Loading,
    };

    rsx! {
        Hero { state }
    }
}
