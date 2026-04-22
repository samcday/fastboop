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

/// Returns the device profile matching pool: the union of built-in,
/// channel-carried, and locally-loaded DevPros. Precedence on id collision
/// is `local > channel > built-in`.
pub fn channel_matching_pool(
    channel_dev_profiles: &[DeviceProfile],
    devpro_dirs: &[PathBuf],
) -> Result<Vec<DeviceProfile>> {
    let mut profiles: HashMap<String, DeviceProfile> = HashMap::new();
    for profile in builtin_profiles().context("loading builtin device profiles")? {
        profiles.insert(profile.id.clone(), profile);
    }
    for profile in channel_dev_profiles {
        profiles.insert(profile.id.clone(), profile.clone());
    }
    for (id, profile) in load_local_device_profiles(devpro_dirs)? {
        profiles.insert(id, profile);
    }
    Ok(profiles.into_values().collect())
}

pub fn resolve_profile_in_pool(
    pool: &[DeviceProfile],
    devpro_dirs: &[PathBuf],
    requested: &str,
) -> Result<DeviceProfile> {
    if let Some(profile) = pool.iter().find(|profile| profile.id == requested) {
        return Ok(profile.clone());
    }

    let mut ids: Vec<_> = pool.iter().map(|profile| profile.id.clone()).collect();
    ids.sort();
    bail!(
        "device profile '{}' not found; available ids: [{}]; checked dirs: {:?}",
        requested,
        ids.join(", "),
        devpro_dirs
    );
}
