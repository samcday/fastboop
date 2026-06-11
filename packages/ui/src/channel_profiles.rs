use alloc::collections::{BTreeMap, BTreeSet};

use fastboop_core::builtin::builtin_profiles;
use fastboop_core::{boot_profile_matches_device, BootProfile, ChannelStreamHead, DeviceProfile};

use crate::BootProfileOptionView;

pub fn load_profiles_for_channel_head(stream_head: &ChannelStreamHead) -> Vec<DeviceProfile> {
    let mut profiles: BTreeMap<String, DeviceProfile> = BTreeMap::new();
    for profile in builtin_profiles().unwrap_or_default() {
        profiles.insert(profile.id.clone(), profile);
    }
    for profile in &stream_head.dev_profiles {
        profiles.insert(profile.id.clone(), profile.clone());
    }

    let allowed_by_boot_profiles = allowed_boot_profile_device_ids(&stream_head.boot_profiles);

    profiles
        .into_values()
        .filter(|profile| match allowed_by_boot_profiles.as_ref() {
            Some(allowed) => allowed.contains(profile.id.as_str()),
            None => true,
        })
        .collect()
}

pub fn compatible_boot_profiles_for_device(
    stream_head: &ChannelStreamHead,
    device_profile_id: &str,
) -> Vec<BootProfile> {
    stream_head
        .boot_profiles
        .iter()
        .filter(|boot_profile| boot_profile_matches_device(boot_profile, device_profile_id))
        .cloned()
        .collect()
}

pub fn initial_boot_profile_id(
    compatible_boot_profiles: &[BootProfile],
    requested_boot_profile_id: Option<&str>,
) -> Option<String> {
    if let Some(requested_boot_profile_id) = requested_boot_profile_id {
        return compatible_boot_profiles
            .iter()
            .any(|profile| profile.id == requested_boot_profile_id)
            .then(|| requested_boot_profile_id.to_string());
    }

    if compatible_boot_profiles.len() == 1 {
        Some(compatible_boot_profiles[0].id.clone())
    } else {
        None
    }
}

pub fn boot_profile_options(boot_profiles: &[BootProfile]) -> Vec<BootProfileOptionView> {
    boot_profiles
        .iter()
        .map(|profile| BootProfileOptionView {
            id: profile.id.clone(),
            label: profile
                .display_name
                .clone()
                .unwrap_or_else(|| profile.id.clone()),
        })
        .collect()
}

fn allowed_boot_profile_device_ids(boot_profiles: &[BootProfile]) -> Option<BTreeSet<String>> {
    if boot_profiles.is_empty()
        || boot_profiles
            .iter()
            .any(|profile| profile.stage0.devices.is_empty())
    {
        return None;
    }

    let mut out = BTreeSet::new();
    for profile in boot_profiles {
        out.extend(profile.stage0.devices.keys().cloned());
    }
    Some(out)
}
