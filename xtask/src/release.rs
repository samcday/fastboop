use std::fs;
use std::path::Path;
use std::process::{Command, ExitStatus};

pub fn bump(version: Option<&str>) {
    let version = version.unwrap_or_else(|| die("usage: cargo xtask bump <version>"));
    if !valid_version(version) {
        die("version must match X.Y.Z or X.Y.Z-rc.N");
    }

    let old_cargo_version = workspace_version();
    let cargo_version = version;
    let mut rpm_apk_version = version.to_string();
    let mut debian_version = version.to_string();

    if let Some((base, rc)) = version.split_once("-rc.") {
        rpm_apk_version = format!("{base}_rc{rc}");
        debian_version = format!("{base}~rc{rc}");
    }

    eprintln!("Bumping fastboop to {cargo_version}");
    eprintln!("  - RPM/APK version: {rpm_apk_version}");
    eprintln!("  - Debian version:  {debian_version}");

    replace_line(
        "Cargo.toml",
        "version = ",
        &format!("version = \"{cargo_version}\""),
    );
    replace_line(
        "fastboop.spec",
        "Version:        ",
        &format!("Version:        {rpm_apk_version}"),
    );
    replace_line(
        "APKBUILD",
        "pkgver=",
        &format!("pkgver={rpm_apk_version}_git"),
    );
    replace_first_line(
        "debian/changelog",
        &format!("fastboop ({debian_version}) UNRELEASED; urgency=medium"),
    );

    sync_path_dependency_versions(Path::new("."), &old_cargo_version, cargo_version);
    run(
        "cargo",
        &["update", "-p", "fastboop-cli", "--precise", cargo_version],
    );

    eprintln!("Done. Files updated:");
    eprintln!("  Cargo.toml");
    eprintln!("  fastboop.spec");
    eprintln!("  APKBUILD");
    eprintln!("  debian/changelog");
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  1. Review changes: git diff");
    eprintln!("  2. Commit: git commit -am 'v{cargo_version}'");
    eprintln!("  3. Tag: git tag v{cargo_version}");
    eprintln!("  4. Push: git push && git push --tags");
}

pub fn publish(live: bool) {
    if live {
        run("tools/publish-crates.sh", &["--publish"]);
    } else {
        run("tools/publish-crates.sh", &["--dry-run"]);
    }
}

pub fn www_live(version: Option<&str>) {
    let version = version.unwrap_or_else(|| die("usage: cargo xtask www-live <version>"));
    let Some(raw_version) = version.strip_prefix('v') else {
        die("version must match vX.Y.Z or vX.Y.Z-rc.N");
    };
    if !valid_version(raw_version) {
        die("version must match vX.Y.Z or vX.Y.Z-rc.N");
    }

    let path = "infra/k8s/fastboop-web/live-version.txt";
    fs::write(path, format!("{version}\n"))
        .unwrap_or_else(|err| panic!("failed to write {path}: {err}"));
    eprintln!("Updated {path} -> {version}");
}

fn valid_version(version: &str) -> bool {
    let (core, rc) = if let Some((core, rc)) = version.split_once("-rc.") {
        (core, Some(rc))
    } else {
        (version, None)
    };

    if matches!(rc, Some("")) {
        return false;
    };

    let parts = core.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
        && rc.is_none_or(|rc| rc.chars().all(|c| c.is_ascii_digit()))
}

fn workspace_version() -> String {
    let text = fs::read_to_string("Cargo.toml").expect("failed to read Cargo.toml");
    text.lines()
        .find_map(|line| {
            line.strip_prefix("version = \"")
                .and_then(|rest| rest.strip_suffix('"'))
        })
        .unwrap_or_else(|| die("unable to parse workspace version from Cargo.toml"))
        .to_string()
}

fn replace_line(path: &str, prefix: &str, replacement: &str) {
    let text =
        fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"));
    let updated = text
        .lines()
        .map(|line| {
            if line.starts_with(prefix) {
                replacement
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, format!("{updated}\n"))
        .unwrap_or_else(|err| panic!("failed to write {path}: {err}"));
}

fn replace_first_line(path: &str, replacement: &str) {
    let text =
        fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"));
    let mut lines = text.lines();
    let _ = lines.next();
    let rest = lines.collect::<Vec<_>>().join("\n");
    fs::write(path, format!("{replacement}\n{rest}\n"))
        .unwrap_or_else(|err| panic!("failed to write {path}: {err}"));
}

fn sync_path_dependency_versions(dir: &Path, old_version: &str, new_version: &str) {
    for entry in fs::read_dir(dir).unwrap_or_else(|err| panic!("failed to read {dir:?}: {err}")) {
        let entry = entry.expect("failed to read directory entry");
        let path = entry.path();
        let file_name = entry.file_name();

        if file_name == "target" || file_name == ".git" {
            continue;
        }

        if path.is_dir() {
            sync_path_dependency_versions(&path, old_version, new_version);
        } else if file_name == "Cargo.toml" {
            sync_manifest(&path, old_version, new_version);
        }
    }
}

fn sync_manifest(path: &Path, old_version: &str, new_version: &str) {
    let text =
        fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path:?}: {err}"));
    let needle = format!("version = \"={old_version}\"");
    if !text.contains("path =") || !text.contains(&needle) {
        return;
    }

    let replacement = format!("version = \"={new_version}\"");
    let updated = text
        .lines()
        .map(|line| {
            if line.contains("path =") {
                line.replace(&needle, &replacement)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, format!("{updated}\n"))
        .unwrap_or_else(|err| panic!("failed to write {path:?}: {err}"));
}

fn run(program: &str, args: &[&str]) {
    let status = Command::new(program)
        .args(args)
        .status()
        .unwrap_or_else(|err| panic!("failed to run {program}: {err}"));
    exit_on_failure(status);
}

fn exit_on_failure(status: ExitStatus) {
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn die(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}
