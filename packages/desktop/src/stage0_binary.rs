use std::env;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

const STAGE0_PATH_ENV: &str = "FASTBOOP_STAGE0_PATH";
const STAGE0_FILE_NAME: &str = "stage0-aarch64";
const SIBLING_STAGE0_FILE_NAMES: &[&str] = &[
    STAGE0_FILE_NAME,
    "fastboop-stage0-aarch64-unknown-linux-musl",
    "fastboop-stage0-aarch64-unknown-linux-gnu",
    "fastboop-stage0",
];

pub(crate) fn load_stage0_binary() -> Result<Vec<u8>> {
    if let Some(path) = env_stage0_path() {
        return read_stage0_binary(&path, STAGE0_PATH_ENV);
    }

    let candidates = default_stage0_candidates();
    for path in &candidates {
        if path.is_file() {
            return read_stage0_binary(path, "auto-detected stage0");
        }
    }

    bail!(missing_stage0_message(&candidates))
}

fn env_stage0_path() -> Option<PathBuf> {
    let value = env::var_os(STAGE0_PATH_ENV)?;
    if value.as_os_str().is_empty() {
        return None;
    }
    Some(PathBuf::from(value))
}

fn read_stage0_binary(path: &Path, source: &str) -> Result<Vec<u8>> {
    let data = std::fs::read(path)
        .with_context(|| format!("read stage0 binary from {source}: {}", path.display()))?;
    if data.is_empty() {
        bail!("stage0 binary from {source} is empty: {}", path.display());
    }
    Ok(data)
}

fn default_stage0_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();

    if let Ok(cwd) = env::current_dir() {
        push_workspace_candidates_from(&mut out, &cwd);
    }

    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            push_sibling_candidates(&mut out, exe_dir);
            push_workspace_candidates_from(&mut out, exe_dir);
        }
    }

    push_package_candidates(&mut out);
    out
}

fn push_workspace_candidates_from(out: &mut Vec<PathBuf>, start: &Path) {
    for ancestor in start.ancestors() {
        if !ancestor.join("stage0/Cargo.toml").is_file() {
            continue;
        }

        push_unique(
            out,
            ancestor.join("target/aarch64-unknown-linux-musl/release/fastboop-stage0"),
        );
        push_unique(
            out,
            ancestor.join("target/aarch64-unknown-linux-gnu/release/fastboop-stage0"),
        );
        push_unique(out, ancestor.join("target/release/fastboop-stage0"));
        push_unique(out, ancestor.join("target/debug/fastboop-stage0"));
    }
}

fn push_sibling_candidates(out: &mut Vec<PathBuf>, dir: &Path) {
    for name in SIBLING_STAGE0_FILE_NAMES {
        push_unique(out, dir.join(name));
        push_unique(out, dir.join("stage0").join(name));
    }
}

fn push_package_candidates(out: &mut Vec<PathBuf>) {
    for prefix in ["/app", "/usr", "/usr/local"] {
        push_unique(
            out,
            Path::new(prefix)
                .join("lib/fastboop/stage0")
                .join(STAGE0_FILE_NAME),
        );
    }
}

fn push_unique(out: &mut Vec<PathBuf>, path: PathBuf) {
    if !out.iter().any(|candidate| candidate == &path) {
        out.push(path);
    }
}

fn missing_stage0_message(candidates: &[PathBuf]) -> String {
    let mut message = format!(
        "stage0 binary not found; build it first with `cargo build --release --target aarch64-unknown-linux-musl -p fastboop-stage0`, install it to `/app/lib/fastboop/stage0/{STAGE0_FILE_NAME}`, or set `{STAGE0_PATH_ENV}`"
    );
    if !candidates.is_empty() {
        message.push_str("; searched: ");
        for (idx, candidate) in candidates.iter().enumerate() {
            if idx > 0 {
                message.push_str(", ");
            }
            message.push_str(candidate.to_string_lossy().as_ref());
        }
    }
    message
}
