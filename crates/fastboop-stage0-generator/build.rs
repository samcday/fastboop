use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-env-changed=FASTBOOP_STAGE0_EMBED_PATH");
    println!("cargo:rerun-if-env-changed=FASTBOOP_STAGE0_CARGO");
    println!("cargo:rerun-if-env-changed=FASTBOOP_STAGE0_TARGET");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    if let Some(prebuilt_embed_path) = resolve_prebuilt_embed_path(&manifest_dir) {
        let embedded = copy_embedded_stage0(&prebuilt_embed_path, &out_dir);
        println!(
            "cargo:warning=fastboop-stage0 embed source: {}",
            prebuilt_embed_path.display()
        );
        println!(
            "cargo:rustc-env=FASTBOOP_STAGE0_EMBED_PATH={}",
            embedded.display()
        );
        return;
    }

    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf();

    let stage0_manifest = workspace_root.join("stage0/Cargo.toml");
    let target_dir = out_dir.join("stage0-target");
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let stage0_cargo = env::var("FASTBOOP_STAGE0_CARGO").unwrap_or_else(|_| cargo.clone());
    let stage0_target = env::var("FASTBOOP_STAGE0_TARGET")
        .unwrap_or_else(|_| "aarch64-unknown-linux-musl".to_string());
    let stage0_target_env = stage0_target.replace('-', "_").to_ascii_uppercase();
    let stage0_linker_env = format!("CARGO_TARGET_{stage0_target_env}_LINKER");
    let stage0_rustflags_env = format!("CARGO_TARGET_{stage0_target_env}_RUSTFLAGS");

    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("stage0").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("Cargo.lock").display()
    );

    let mut cmd = Command::new(stage0_cargo);
    cmd.arg("build")
        .arg("--manifest-path")
        .arg(&stage0_manifest)
        .arg("--package")
        .arg("fastboop-stage0")
        .arg("--target")
        .arg(&stage0_target)
        .arg("--target-dir")
        .arg(&target_dir)
        .arg("--locked");

    if stage0_target == "aarch64-unknown-linux-musl" {
        cmd.env(&stage0_linker_env, "rust-lld");
    }
    if env::var_os(&stage0_rustflags_env).is_none() {
        cmd.env(&stage0_rustflags_env, "-C target-feature=+crt-static");
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
    let stage0_log = workspace_root.join("target/stage0-subbuild.log");
    if let Some(parent) = stage0_log.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut f) = fs::File::create(&stage0_log) {
        let _ = writeln!(f, "status: {:?}", output.status);
        let _ = writeln!(f, "stdout:\n{}", String::from_utf8_lossy(&output.stdout));
        let _ = writeln!(f, "stderr:\n{}", String::from_utf8_lossy(&output.stderr));
    }
    println!(
        "cargo:warning=fastboop-stage0 nested build log: {}",
        stage0_log.display()
    );
    if !output.status.success() {
        panic!(
            "failed building embedded stage0 binary (see {})\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            stage0_log.display(),
            output.status.code().map_or_else(
                || "terminated by signal".to_string(),
                |code| code.to_string()
            ),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let artifact = target_dir
        .join(&stage0_target)
        .join(profile_dir)
        .join("fastboop-stage0");
    let embedded = copy_embedded_stage0(&artifact, &out_dir);

    println!(
        "cargo:rustc-env=FASTBOOP_STAGE0_EMBED_PATH={}",
        embedded.display()
    );
}

fn resolve_prebuilt_embed_path(manifest_dir: &Path) -> Option<PathBuf> {
    let Some(value) = env::var_os("FASTBOOP_STAGE0_EMBED_PATH") else {
        return None;
    };

    let configured = PathBuf::from(value);
    let resolved = if configured.is_absolute() {
        configured
    } else {
        manifest_dir.join(configured)
    };

    if !resolved.is_file() {
        panic!(
            "FASTBOOP_STAGE0_EMBED_PATH points to missing file: {}",
            resolved.display()
        );
    }

    Some(resolved)
}

fn copy_embedded_stage0(source: &Path, out_dir: &Path) -> PathBuf {
    let embedded = out_dir.join("fastboop-stage0-embedded");
    fs::copy(source, &embedded).unwrap_or_else(|err| {
        panic!(
            "copy embedded stage0 {} -> {} failed: {err}",
            source.display(),
            embedded.display()
        )
    });
    embedded
}
