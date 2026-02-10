use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf();

    let stage0_manifest = workspace_root.join("stage0/Cargo.toml");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let target_dir = out_dir.join("stage0-target");
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    println!("cargo:rerun-if-env-changed=PROFILE");
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("stage0").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("smoo/crates/smoo-gadget-app").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("Cargo.lock").display()
    );

    let mut cmd = Command::new(cargo);
    cmd.arg("build")
        .arg("--manifest-path")
        .arg(&stage0_manifest)
        .arg("--package")
        .arg("fastboop-stage0")
        .arg("--target")
        .arg("aarch64-unknown-linux-musl")
        .arg("--target-dir")
        .arg(&target_dir)
        .arg("--locked");

    // Always force rust-lld for the embedded cross-build so CI/user shell
    // linker environment does not silently break the stage0 sub-build.
    cmd.env("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER", "rust-lld");
    if env::var_os("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS").is_none() {
        cmd.env(
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS",
            "-C target-feature=+crt-static",
        );
    }

    let profile_dir = match profile.as_str() {
        "release" => {
            cmd.arg("--release");
            "release".to_string()
        }
        "debug" => "debug".to_string(),
        other => {
            cmd.arg("--profile").arg(other);
            other.to_string()
        }
    };

    let output = cmd.output().expect("spawn cargo sub-build");
    if !output.status.success() {
        panic!(
            "failed building embedded stage0 binary\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status.code().map_or_else(
                || "terminated by signal".to_string(),
                |code| code.to_string()
            ),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let artifact = target_dir
        .join("aarch64-unknown-linux-musl")
        .join(profile_dir)
        .join("fastboop-stage0");
    let embedded = out_dir.join("fastboop-stage0-embedded");
    fs::copy(&artifact, &embedded).unwrap_or_else(|err| {
        panic!(
            "copy embedded stage0 {} -> {} failed: {err}",
            artifact.display(),
            embedded.display()
        )
    });

    println!(
        "cargo:rustc-env=FASTBOOP_STAGE0_EMBED_PATH={}",
        embedded.display()
    );
}
