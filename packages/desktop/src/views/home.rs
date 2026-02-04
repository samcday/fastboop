use std::collections::{HashMap, HashSet};

use dioxus::prelude::*;
use fastboop_core::builtin::builtin_profiles;
use fastboop_core::prober::probe_candidates;
use fastboop_fastboot_rusb::FastbootRusbCandidate;
use rusb::{Context as UsbContext, UsbContext as _};
use ui::{DetectedDevice, Hero, ProbeState, TransportKind};

#[component]
pub fn Home() -> Element {
    let probe = use_resource(|| async move { probe_fastboot_devices().await });
    let state = match probe() {
        Some(state) => state,
        None => ProbeState::Loading,
    };

    rsx! {
        Hero { state, on_connect: None }
    }
}

async fn probe_fastboot_devices() -> ProbeState {
    let profiles = match builtin_profiles() {
        Ok(profiles) => profiles,
        Err(_) => {
            return ProbeState::Ready {
                transport: TransportKind::NativeUsb,
                devices: Vec::new(),
            }
        }
    };
    let profiles_by_id: HashMap<_, _> = profiles
        .iter()
        .map(|profile| (profile.id.clone(), profile))
        .collect();

    let context = match UsbContext::new() {
        Ok(context) => context,
        Err(_) => {
            return ProbeState::Ready {
                transport: TransportKind::NativeUsb,
                devices: Vec::new(),
            }
        }
    };

    let devices = match context.devices() {
        Ok(devices) => devices,
        Err(_) => {
            return ProbeState::Ready {
                transport: TransportKind::NativeUsb,
                devices: Vec::new(),
            }
        }
    };

    let mut candidates = Vec::new();
    for device in devices.iter() {
        let desc = match device.device_descriptor() {
            Ok(desc) => desc,
            Err(_) => continue,
        };
        candidates.push(FastbootRusbCandidate::new(
            device,
            desc.vendor_id(),
            desc.product_id(),
        ));
    }

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
        transport: TransportKind::NativeUsb,
        devices: detected,
    }
}
