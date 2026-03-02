use std::env;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use sha2::Digest;
use sha2::Sha256;

const DEFAULT_STAGE0_TARGET: &str = "aarch64-unknown-linux-musl";
const RELEASE_STAGE0_AARCH64_TARGET: &str = "aarch64-unknown-linux-musl";
const RELEASE_STAGE0_AARCH64_ASSET: &str = "fastboop-stage0-aarch64-unknown-linux-musl";
const RELEASE_STAGE0_AARCH64_SHA256SUM: &str = "stage0-aarch64.sha256sum";

fn main() {
    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-env-changed=FASTBOOP_STAGE0_EMBED_PATH");
    println!("cargo:rerun-if-env-changed=FASTBOOP_STAGE0_CARGO");
    println!("cargo:rerun-if-env-changed=FASTBOOP_STAGE0_TARGET");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let stage0_target =
        env::var("FASTBOOP_STAGE0_TARGET").unwrap_or_else(|_| DEFAULT_STAGE0_TARGET.to_string());

    if let Some(prebuilt_embed_path) = resolve_prebuilt_embed_path(&manifest_dir) {
        println!("cargo:rerun-if-changed={}", prebuilt_embed_path.display());
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

    if let Some((workspace_root, stage0_manifest)) = resolve_nested_stage0_manifest(&manifest_dir) {
        let embedded = build_stage0_nested(
            &workspace_root,
            &stage0_manifest,
            &out_dir,
            stage0_target.as_str(),
        );
        println!(
            "cargo:rustc-env=FASTBOOP_STAGE0_EMBED_PATH={}",
            embedded.display()
        );
        return;
    }

    if let Some(embedded) = embed_stage0_from_release_asset(&manifest_dir, &out_dir, &stage0_target)
    {
        println!(
            "cargo:rustc-env=FASTBOOP_STAGE0_EMBED_PATH={}",
            embedded.display()
        );
        return;
    }

    let expected_manifest = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("stage0/Cargo.toml"))
        .unwrap_or_else(|| manifest_dir.join("../../stage0/Cargo.toml"));
    panic!(
        "FASTBOOP_STAGE0_EMBED_PATH is required when source-repo nested stage0 build is unavailable (expected local manifest at {}). release-asset fallback is only configured for target {} using {}",
        expected_manifest.display(),
        RELEASE_STAGE0_AARCH64_TARGET,
        RELEASE_STAGE0_AARCH64_SHA256SUM,
    );
}

fn build_stage0_nested(
    workspace_root: &Path,
    stage0_manifest: &Path,
    out_dir: &Path,
    stage0_target: &str,
) -> PathBuf {
    println!(
        "cargo:warning=fastboop-stage0 embed source: local nested build ({})",
        stage0_manifest.display()
    );

    let target_dir = out_dir.join("stage0-target");
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let stage0_cargo = env::var("FASTBOOP_STAGE0_CARGO").unwrap_or_else(|_| cargo.clone());
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
        .arg(stage0_manifest)
        .arg("--package")
        .arg("fastboop-stage0")
        .arg("--target")
        .arg(stage0_target)
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
        .join(stage0_target)
        .join(profile_dir)
        .join("fastboop-stage0");
    copy_embedded_stage0(&artifact, out_dir)
}

fn embed_stage0_from_release_asset(
    manifest_dir: &Path,
    out_dir: &Path,
    stage0_target: &str,
) -> Option<PathBuf> {
    let release_asset = resolve_release_asset(stage0_target)?;
    let checksum_path = manifest_dir.join(release_asset.sha256sum_file);
    println!("cargo:rerun-if-changed={}", checksum_path.display());

    let expected_sha256 = read_sha256sum_sidecar(&checksum_path).unwrap_or_else(|err| {
        panic!(
            "failed loading stage0 checksum sidecar {}: {err}",
            checksum_path.display()
        )
    });

    let package_version = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION");
    let repository = env::var("CARGO_PKG_REPOSITORY")
        .unwrap_or_else(|_| "https://github.com/samcday/fastboop".to_string());
    let (downloaded, download_url) = download_release_stage0(
        out_dir,
        repository.as_str(),
        package_version.as_str(),
        release_asset.asset_name,
        expected_sha256.as_str(),
    );
    println!("cargo:warning=fastboop-stage0 embed source: release asset ({download_url})");

    Some(copy_embedded_stage0(&downloaded, out_dir))
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

fn resolve_nested_stage0_manifest(manifest_dir: &Path) -> Option<(PathBuf, PathBuf)> {
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())?
        .to_path_buf();
    let stage0_manifest = workspace_root.join("stage0/Cargo.toml");
    stage0_manifest
        .is_file()
        .then_some((workspace_root, stage0_manifest))
}

struct ReleaseStage0Asset {
    asset_name: &'static str,
    sha256sum_file: &'static str,
}

fn resolve_release_asset(stage0_target: &str) -> Option<ReleaseStage0Asset> {
    match stage0_target {
        RELEASE_STAGE0_AARCH64_TARGET => Some(ReleaseStage0Asset {
            asset_name: RELEASE_STAGE0_AARCH64_ASSET,
            sha256sum_file: RELEASE_STAGE0_AARCH64_SHA256SUM,
        }),
        _ => None,
    }
}

fn read_sha256sum_sidecar(path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let Some(token) = text.split_whitespace().next() else {
        return Err("expected hex digest, found empty file".to_string());
    };

    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("expected 64-char hex digest, found '{token}'"));
    }

    Ok(token.to_ascii_lowercase())
}

fn download_release_stage0(
    out_dir: &Path,
    repository: &str,
    version: &str,
    asset_name: &str,
    expected_sha256: &str,
) -> (PathBuf, String) {
    let repository = repository.trim_end_matches('/').trim_end_matches(".git");
    let download_url = format!("{repository}/releases/download/v{version}/{asset_name}");
    let response = ureq::get(download_url.as_str())
        .set("User-Agent", "fastboop-stage0-generator/build.rs")
        .call()
        .unwrap_or_else(|err| panic!("failed downloading {download_url}: {err}"));

    let mut bytes = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut bytes)
        .unwrap_or_else(|err| panic!("failed reading {download_url}: {err}"));

    let actual_sha256 = sha256_hex(bytes.as_slice());
    if actual_sha256 != expected_sha256 {
        panic!(
            "sha256 mismatch for {download_url}: expected {expected_sha256}, got {actual_sha256}"
        );
    }

    let downloaded = out_dir.join(asset_name);
    fs::write(&downloaded, bytes)
        .unwrap_or_else(|err| panic!("write {} failed: {err}", downloaded.display()));

    (downloaded, download_url)
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    hex
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
