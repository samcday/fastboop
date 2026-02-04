use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use fastboop_schema::DeviceProfile;
use fastboop_schema::bin::DeviceProfileBin;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let devpro_dir = workspace_root.join("devprofiles.d");

    println!("cargo:rerun-if-changed={}", devpro_dir.display());

    let mut profiles = Vec::new();
    let mut seen = HashSet::new();

    if devpro_dir.is_dir() {
        let mut paths: Vec<PathBuf> = fs::read_dir(&devpro_dir)
            .unwrap()
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.is_file())
            .collect();
        paths.sort();

        for path in paths {
            if !is_devpro_path(&path) {
                continue;
            }
            println!("cargo:rerun-if-changed={}", path.display());
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
            let profile: DeviceProfile = serde_yaml::from_str(&text)
                .unwrap_or_else(|err| panic!("parsing {}: {err}", path.display()));
            if !seen.insert(profile.id.clone()) {
                panic!(
                    "duplicate device profile id '{}' in {}",
                    profile.id,
                    path.display()
                );
            }
            profiles.push(profile);
        }
    }

    let bin_profiles: Vec<DeviceProfileBin> =
        profiles.into_iter().map(DeviceProfileBin::from).collect();
    let bytes = postcard::to_allocvec(&bin_profiles).expect("serialize builtin devpros");
    let _: Vec<DeviceProfileBin> = postcard::from_bytes(&bytes).expect("roundtrip builtin devpros");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_path = out_dir.join("builtin_devpros.bin");
    fs::write(&out_path, bytes).expect("write builtin devpros");
}

fn is_devpro_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("yml") | Some("yaml") | Some("json")
    )
}
