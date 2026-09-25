use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use fastboop_schema::DeviceProfile;
use fastboop_schema::bin::DeviceProfileBin;

/// Built-in DevPros live inside this crate so they ship in the published
/// `.crate`. Never search outside the manifest directory: an ancestor lookup
/// would let packaged verification builds pick up the repository copy.
const DEVPRO_DIR: &str = "devprofiles.d";

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let devpro_dir = manifest_dir.join(DEVPRO_DIR);

    println!("cargo:rerun-if-changed={}", devpro_dir.display());

    if !devpro_dir.is_dir() {
        panic!(
            "built-in device profile directory {} is missing; fastboop-core must be built \
             from a source tree or package that contains {DEVPRO_DIR}/",
            devpro_dir.display()
        );
    }

    let mut paths: Vec<PathBuf> = fs::read_dir(&devpro_dir)
        .unwrap_or_else(|err| panic!("reading {}: {err}", devpro_dir.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|err| panic!("reading {}: {err}", devpro_dir.display()))
                .path()
        })
        .filter(|path| path.is_file() && is_devpro_path(path))
        .collect();
    paths.sort();

    let mut profiles = Vec::new();
    let mut seen = HashSet::new();
    for path in paths {
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

    if profiles.is_empty() {
        panic!(
            "no built-in device profiles (*.yaml, *.yml, *.json) found in {}",
            devpro_dir.display()
        );
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
