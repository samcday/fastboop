use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(flatpak_runtime_paths)");
    if env::var_os("FLATPAK_ID").is_some() {
        println!("cargo:rustc-cfg=flatpak_runtime_paths");
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let assets_dir = manifest_dir.join("assets/dtbo");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    compile_dtso(
        &assets_dir,
        &out_dir,
        "sdm845-oneplus-fajita-simplefb.dtso",
        "sdm845-oneplus-fajita-simplefb.dtbo",
    );
    compile_dtso(
        &assets_dir,
        &out_dir,
        "sdm845-oneplus-fajita-pmi8998-haptics.dtso",
        "sdm845-oneplus-fajita-pmi8998-haptics.dtbo",
    );
}

fn compile_dtso(assets_dir: &Path, out_dir: &Path, source_name: &str, out_name: &str) {
    let source = assets_dir.join(source_name);
    let output = out_dir.join(out_name);

    println!("cargo:rerun-if-changed={}", source.display());

    let status = Command::new("dtc")
        .arg("-@")
        .arg("-I")
        .arg("dts")
        .arg("-O")
        .arg("dtb")
        .arg("-o")
        .arg(&output)
        .arg(&source)
        .status()
        .unwrap_or_else(|err| panic!("failed to spawn dtc for {}: {err}", source.display()));

    if !status.success() {
        panic!(
            "dtc failed for {} -> {} (status: {status})",
            source.display(),
            output.display()
        );
    }
}
