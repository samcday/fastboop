use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use dioxus::core::schedule_update;
use dioxus::prelude::*;
use fastboop_core::builtin::builtin_profiles;
use fastboop_core::prober::probe_candidates;
use fastboop_fastboot_rusb::{DeviceWatcher, FastbootRusbCandidate};
use rusb::{Context as UsbContext, UsbContext as _};
use tracing::{debug, info};
use ui::{DetectedDevice, Hero, ProbeState, TransportKind};

#[component]
pub fn Home() -> Element {
    let refresh = use_signal(|| 0u32);
    let mut watcher = use_signal(|| None::<DeviceWatcher>);
    let pending_events = use_hook(|| Arc::new(AtomicU32::new(0)));
    let schedule_ui_update = schedule_update();
    let pending_events_for_watch = Arc::clone(&pending_events);
    let pending_events_for_drain = Arc::clone(&pending_events);

    use_effect(move || {
        if watcher.read().is_some() {
            return;
        }

        let pending_events = Arc::clone(&pending_events_for_watch);
        let schedule_ui_update = schedule_ui_update.clone();
        let created = DeviceWatcher::new(Box::new(move |event| {
            pending_events.fetch_add(1, Ordering::Relaxed);
            debug!(?event, "desktop usb hotplug event");
            (schedule_ui_update)();
        }));
        if let Ok(created) = created {
            watcher.set(Some(created));
            info!("desktop usb watcher started");
        } else if let Err(err) = created {
            info!(%err, "desktop usb watcher unavailable");
        }
    });

    use_effect(move || {
        let drained = pending_events_for_drain.swap(0, Ordering::Relaxed);
        if drained > 0 {
            let mut refresh = refresh;
            refresh.set(refresh() + drained);
            debug!(drained, "desktop queued usb events");
        }
    });

    let probe = use_resource(move || {
        let refresh = refresh();
        async move { probe_fastboot_devices(refresh).await }
    });
    let state = match probe() {
        Some(state) => state,
        None => ProbeState::Loading,
    };

    rsx! {
        Hero { state, on_connect: None }
    }
}

async fn probe_fastboot_devices(_refresh: u32) -> ProbeState {
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
