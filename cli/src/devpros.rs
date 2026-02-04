use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use fastboop_core::DeviceProfile;
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
    if let Some(devprofiles) = devprofiles_dir_for_cargo_run() {
        dirs.push(devprofiles);
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
            if profiles.contains_key(&profile.id) {
                bail!(
                    "duplicate device profile id '{}' found in {}",
                    profile.id,
                    path.display()
                );
            }
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                let key = format!("file:{}", stem);
                profiles.entry(key).or_insert_with(|| profile.clone());
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

fn devprofiles_dir_for_cargo_run() -> Option<PathBuf> {
    if !cfg!(debug_assertions) {
        return None;
    }
    let running_under_cargo = env::var_os("CARGO").is_some()
        || env::var_os("CARGO_MANIFEST_DIR").is_some()
        || env::var_os("CARGO_PKG_NAME").is_some();
    if !running_under_cargo {
        return None;
    }
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    let workspace_root = manifest_dir.parent().and_then(|p| p.parent())?;
    Some(workspace_root.join("devprofiles.d"))
}
