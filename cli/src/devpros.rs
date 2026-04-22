use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use fastboop_core::DeviceProfile;
use fastboop_core::builtin::builtin_profiles;
use tracing::warn;

pub fn resolve_devpro_dirs() -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    if let Ok(env_paths) = env::var("FASTBOOP_SCHEMA_PATH") {
        for part in env_paths.split(':') {
            if part.is_empty() {
                continue;
            }
            dirs.push(PathBuf::from(part));
        }
    }
    if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
        dirs.push(PathBuf::from(xdg).join("fastboop/devpro"));
    } else if let Ok(home) = env::var("HOME") {
        dirs.push(PathBuf::from(home).join(".config/fastboop/devpro"));
    }
    dirs.push(PathBuf::from("/usr/share/fastboop/devpro"));
    let mut seen = HashMap::new();
    dirs.retain(|p| seen.insert(p.clone(), ()).is_none());
    Ok(dirs)
}

pub fn load_device_profiles(dirs: &[PathBuf]) -> Result<HashMap<String, DeviceProfile>> {
    let mut profiles = HashMap::new();
    let builtin = builtin_profiles().context("loading builtin device profiles")?;
    for profile in builtin {
        profiles.insert(profile.id.clone(), profile);
    }
    for (id, profile) in load_local_device_profiles(dirs)? {
        profiles.insert(id, profile);
    }
    Ok(profiles)
}

pub fn load_local_device_profiles(dirs: &[PathBuf]) -> Result<HashMap<String, DeviceProfile>> {
    let mut profiles = HashMap::new();
    let mut file_ids = HashSet::new();
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(dir)
            .with_context(|| format!("reading device profile dir {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or_default();
            if !matches!(ext, "yml" | "yaml" | "json") {
                continue;
            }
            let text = fs::read_to_string(&path)
                .with_context(|| format!("reading device profile {}", path.display()))?;
            let profile: DeviceProfile = match serde_yaml::from_str(&text) {
                Ok(profile) => profile,
                Err(err) => {
                    warn!(
                        path = %path.display(),
                        error = %err,
                        "Skipping invalid device profile"
                    );
                    continue;
                }
            };
            if !file_ids.insert(profile.id.clone()) {
                bail!(
                    "duplicate device profile id '{}' found in {}",
                    profile.id,
                    path.display()
                );
            }
            profiles.insert(profile.id.clone(), profile);
        }
    }
    Ok(profiles)
}

pub fn dedup_profiles(profiles: &HashMap<String, DeviceProfile>) -> Vec<&DeviceProfile> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for profile in profiles.values() {
        if seen.insert(profile.id.clone()) {
            unique.push(profile);
        }
    }
    unique
}

/// Returns the device profile matching pool. When the channel carries DevPros,
/// those become the pool (replace, not union); otherwise fall back to local +
/// builtin profiles loaded from the configured devpro dirs.
pub fn channel_matching_pool(
    channel_dev_profiles: &[DeviceProfile],
    devpro_dirs: &[PathBuf],
) -> Result<Vec<DeviceProfile>> {
    if !channel_dev_profiles.is_empty() {
        return Ok(channel_dev_profiles.to_vec());
    }
    let local = load_device_profiles(devpro_dirs)?;
    Ok(dedup_profiles(&local).into_iter().cloned().collect())
}

/// Picks a device profile from a matching pool by id. The channel slice is
/// only consulted to shape the error message — when it is non-empty we report
/// the channel-specific failure; otherwise we name the local devpro dirs.
pub fn resolve_profile_in_pool(
    pool: &[DeviceProfile],
    channel_dev_profiles: &[DeviceProfile],
    devpro_dirs: &[PathBuf],
    requested: &str,
) -> Result<DeviceProfile> {
    if let Some(profile) = pool.iter().find(|profile| profile.id == requested) {
        return Ok(profile.clone());
    }

    let mut ids: Vec<_> = pool.iter().map(|profile| profile.id.clone()).collect();
    ids.sort();
    if !channel_dev_profiles.is_empty() {
        bail!(
            "device profile '{}' is not in channel DevPros [{}]",
            requested,
            ids.join(", ")
        );
    }
    bail!(
        "device profile '{}' not found in {:?}; available ids: {:?}",
        requested,
        devpro_dirs,
        ids
    );
}
