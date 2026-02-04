use dioxus::prelude::*;
use ui::{Hero, ProbeState};

#[cfg(target_arch = "wasm32")]
use ui::{DetectedDevice, TransportKind};

#[cfg(target_arch = "wasm32")]
use std::collections::{HashMap, HashSet};

#[cfg(target_arch = "wasm32")]
use fastboop_core::builtin::builtin_profiles;
#[cfg(target_arch = "wasm32")]
use fastboop_core::prober::probe_candidates;
#[cfg(target_arch = "wasm32")]
use fastboop_fastboot_webusb::fastboot_candidates_from_devices;
#[cfg(target_arch = "wasm32")]
use js_sys::{Array, Reflect};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, JsValue};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use web_sys::{Usb, UsbDevice, UsbDeviceFilter, UsbDeviceRequestOptions};

#[component]
pub fn Home() -> Element {
    let refresh = use_signal(|| 0u32);
    let probe = use_resource(move || {
        let refresh = refresh();
        async move { probe_fastboot_devices(refresh).await }
    });

    let state = match probe() {
        Some(state) => state,
        None => ProbeState::Loading,
    };

    #[cfg(target_arch = "wasm32")]
    let on_connect: Option<EventHandler<MouseEvent>> = {
        let mut refresh = refresh;
        Some(EventHandler::new(move |_| {
            let mut refresh = refresh;
            spawn(async move {
                if let Some(usb) = webusb_handle() {
                    let profiles = load_profiles();
                    if request_device(&usb, &profiles).await.is_ok() {
                        refresh.set(refresh() + 1);
                    }
                }
            });
        }))
    };

    #[cfg(not(target_arch = "wasm32"))]
    let on_connect: Option<EventHandler<MouseEvent>> = None;

    rsx! {
        Hero { state, on_connect }
    }
}

#[cfg(target_arch = "wasm32")]
fn load_profiles() -> Vec<fastboop_core::DeviceProfile> {
    builtin_profiles().unwrap_or_default()
}

#[cfg(target_arch = "wasm32")]
fn webusb_handle() -> Option<Usb> {
    let window = web_sys::window()?;
    let navigator = window.navigator();
    let has_usb = Reflect::has(&navigator, &JsValue::from_str("usb")).ok()?;
    if !has_usb {
        return None;
    }
    let usb = Reflect::get(&navigator, &JsValue::from_str("usb")).ok()?;
    usb.dyn_into::<Usb>().ok()
}

#[cfg(target_arch = "wasm32")]
async fn probe_fastboot_devices(_refresh: u32) -> ProbeState {
    let Some(usb) = webusb_handle() else {
        return ProbeState::Unsupported;
    };

    let profiles = load_profiles();
    let profiles_by_id: HashMap<_, _> = profiles
        .iter()
        .map(|profile| (profile.id.clone(), profile))
        .collect();
    let devices = match get_authorized_devices(&usb).await {
        Ok(devices) => devices,
        Err(_) => Vec::new(),
    };
    let candidates = fastboot_candidates_from_devices(&devices).await;
    let reports = probe_candidates(&profiles, &candidates).await;
    let mut seen = HashSet::new();
    let mut detected = Vec::new();
    for report in reports {
        let matched = report
            .attempts
            .iter()
            .find(|attempt| attempt.result.is_ok());
        let Some(matched) = matched else {
            continue;
        };
        let key = (report.vid, report.pid);
        if !seen.insert(key) {
            continue;
        }
        let name = profiles_by_id
            .get(&matched.profile_id)
            .and_then(|profile| profile.display_name.clone())
            .unwrap_or(matched.profile_id.clone());
        detected.push(DetectedDevice {
            vid: report.vid,
            pid: report.pid,
            name,
        });
    }

    ProbeState::Ready {
        transport: TransportKind::WebUsb,
        devices: detected,
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn probe_fastboot_devices(_refresh: u32) -> ProbeState {
    ProbeState::Unsupported
}

#[cfg(target_arch = "wasm32")]
async fn get_authorized_devices(usb: &Usb) -> Result<Vec<UsbDevice>, JsValue> {
    let devices = JsFuture::from(usb.get_devices()).await?;
    let devices: Array = devices.dyn_into()?;
    Ok(devices
        .iter()
        .filter_map(|value| value.dyn_into::<UsbDevice>().ok())
        .collect())
}

#[cfg(target_arch = "wasm32")]
fn build_filters(profiles: &[fastboop_core::DeviceProfile]) -> Array {
    let mut seen = HashSet::new();
    let filters = Array::new();
    for profile in profiles {
        for rule in &profile.r#match {
            let key = (rule.fastboot.vid, rule.fastboot.pid);
            if !seen.insert(key) {
                continue;
            }
            let filter = UsbDeviceFilter::new();
            filter.set_vendor_id(rule.fastboot.vid);
            filter.set_product_id(rule.fastboot.pid);
            filters.push(&filter);
        }
    }
    filters
}

#[cfg(target_arch = "wasm32")]
async fn request_device(
    usb: &Usb,
    profiles: &[fastboop_core::DeviceProfile],
) -> Result<UsbDevice, JsValue> {
    let filters = build_filters(profiles);
    let filters_value = JsValue::from(filters);
    let options = UsbDeviceRequestOptions::new(&filters_value);
    let device = JsFuture::from(usb.request_device(&options)).await?;
    device.dyn_into::<UsbDevice>()
}
