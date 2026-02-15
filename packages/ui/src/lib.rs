//! This crate contains all shared UI for the workspace.

use std::collections::{HashMap, HashSet};

use fastboop_core::prober::ProbeCandidateReport;
use fastboop_core::DeviceProfile;

mod hero;
pub use hero::Hero;
mod dtbo;
pub use dtbo::oneplus_fajita_dtbo_overlays;
mod cache_stats;
pub use cache_stats::{CacheStatsPanel, CacheStatsViewModel};
mod smoo_stats;
pub use smoo_stats::{
    apply_transport_counters, run_smoo_stats_view_loop, SmooStatsAccumulator, SmooStatsHandle,
    SmooStatsPanel, SmooStatsSnapshot, SmooStatsViewModel, SmooTransportCounters,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    WebUsb,
    NativeUsb,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectedProfileOption {
    pub profile_id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectedDevice {
    pub vid: u16,
    pub pid: u16,
    pub name: String,
    pub profile_options: Vec<DetectedProfileOption>,
    pub selected_profile: Option<usize>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProbeState {
    Loading,
    Unsupported,
    Ready {
        transport: TransportKind,
        devices: Vec<DetectedDevice>,
    },
}

#[derive(Clone, Debug)]
pub struct ProbedProfileOption {
    pub profile: DeviceProfile,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct ProbedCandidateDevice<Handle> {
    pub handle: Handle,
    pub profile_options: Vec<ProbedProfileOption>,
    pub vid: u16,
    pub pid: u16,
    pub serial: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ProbeSnapshot<Handle> {
    pub state: ProbeState,
    pub devices: Vec<ProbedCandidateDevice<Handle>>,
}

pub fn selected_profile_index(
    vid: u16,
    pid: u16,
    option_count: usize,
    selections: &HashMap<(u16, u16), usize>,
) -> Option<usize> {
    if option_count == 1 {
        return Some(0);
    }
    selections
        .get(&(vid, pid))
        .copied()
        .filter(|index| *index < option_count)
}

pub fn selected_profile_option<'a, Handle>(
    device: &'a ProbedCandidateDevice<Handle>,
    selections: &HashMap<(u16, u16), usize>,
) -> Option<&'a ProbedProfileOption> {
    let index = selected_profile_index(
        device.vid,
        device.pid,
        device.profile_options.len(),
        selections,
    )?;
    device.profile_options.get(index)
}

pub fn update_profile_selection<Handle>(
    selections: &mut HashMap<(u16, u16), usize>,
    devices: &[ProbedCandidateDevice<Handle>],
    device_index: usize,
    profile_index: usize,
) {
    let Some(device) = devices.get(device_index) else {
        return;
    };
    if profile_index >= device.profile_options.len() {
        return;
    }
    selections.insert((device.vid, device.pid), profile_index);
}

pub fn apply_selected_profiles(state: &mut ProbeState, selections: &HashMap<(u16, u16), usize>) {
    if let ProbeState::Ready { devices, .. } = state {
        for device in devices.iter_mut() {
            device.selected_profile = selected_profile_index(
                device.vid,
                device.pid,
                device.profile_options.len(),
                selections,
            );
        }
    }
}

pub fn build_probe_snapshot<Handle, OErr, WErr>(
    transport: TransportKind,
    profiles: &[DeviceProfile],
    reports: Vec<ProbeCandidateReport<OErr, WErr>>,
    candidates: &[Handle],
    serial_for: impl Fn(&Handle) -> Option<String>,
) -> ProbeSnapshot<Handle>
where
    Handle: Clone,
{
    let profiles_by_id: HashMap<_, _> = profiles
        .iter()
        .map(|profile| (profile.id.clone(), profile))
        .collect();

    let mut seen = HashSet::new();
    let mut detected = Vec::new();
    let mut probed = Vec::new();
    for report in reports {
        let matched: Vec<_> = report
            .attempts
            .iter()
            .filter(|attempt| attempt.result.is_ok())
            .filter_map(|attempt| profiles_by_id.get(&attempt.profile_id).copied())
            .collect();
        if matched.is_empty() {
            continue;
        }

        let key = (report.vid, report.pid);
        if !seen.insert(key) {
            continue;
        }

        let Some(candidate) = candidates.get(report.candidate_index) else {
            continue;
        };

        let mut profile_options = Vec::new();
        for profile in matched {
            let name = profile
                .display_name
                .clone()
                .unwrap_or_else(|| profile.id.clone());
            profile_options.push(ProbedProfileOption {
                profile: profile.clone(),
                name,
            });
        }
        profile_options.sort_by(|left, right| left.profile.id.cmp(&right.profile.id));

        let selected_profile = (profile_options.len() == 1).then_some(0);
        let name = if let Some(profile) = profile_options.first() {
            if profile_options.len() == 1 {
                profile.name.clone()
            } else {
                format!("{} profile matches", profile_options.len())
            }
        } else {
            continue;
        };

        let ui_profile_options = profile_options
            .iter()
            .map(|profile| DetectedProfileOption {
                profile_id: profile.profile.id.clone(),
                name: profile.name.clone(),
            })
            .collect();

        detected.push(DetectedDevice {
            vid: report.vid,
            pid: report.pid,
            name,
            profile_options: ui_profile_options,
            selected_profile,
        });

        probed.push(ProbedCandidateDevice {
            handle: candidate.clone(),
            profile_options,
            vid: report.vid,
            pid: report.pid,
            serial: serial_for(candidate),
        });
    }

    ProbeSnapshot {
        state: ProbeState::Ready {
            transport,
            devices: detected,
        },
        devices: probed,
    }
}
