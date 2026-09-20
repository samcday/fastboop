use crate::util;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use toml_edit::{value, DocumentMut, Item, TableLike};

pub fn bump(version: Option<&str>) {
    let version = version.unwrap_or_else(|| die("usage: cargo xtask bump <version>"));
    if !valid_version(version) {
        die("version must match X.Y.Z or X.Y.Z-rc.N (without leading zeroes)");
    }

    // Metadata handles workspace membership (including globs and exclusions) without
    // walking submodules, vendored sources, or unrelated nested workspaces.
    let metadata = command_output("cargo", &["metadata", "--no-deps", "--format-version", "1"]);
    let metadata: serde_json::Value =
        serde_json::from_str(&metadata).expect("parse cargo metadata");
    let root = Path::new(metadata["workspace_root"].as_str().expect("workspace root"));
    let members = metadata["workspace_members"]
        .as_array()
        .expect("workspace members");
    let manifests: Vec<PathBuf> = metadata["packages"]
        .as_array()
        .expect("workspace packages")
        .iter()
        .filter(|package| members.contains(&package["id"]))
        .map(|package| PathBuf::from(package["manifest_path"].as_str().expect("manifest path")))
        .collect();
    let date = command_output("date", &["-R"]);
    bump_files(root, &manifests, version, date.trim());

    // Keep external dependencies locked while updating all workspace package versions.
    util::run(
        "cargo",
        &[
            "update",
            "--workspace",
            "--manifest-path",
            root.join("Cargo.toml")
                .to_str()
                .expect("workspace manifest path"),
        ],
    );
    eprintln!("Prepared {version}; review the diff and commit the release PR.");
}

fn command_output(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to run {program}: {err}"));
    if !output.status.success() {
        die(&format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).expect("command output is UTF-8")
}

fn bump_files(root: &Path, manifests: &[PathBuf], version: &str, date: &str) {
    let root_manifest = root.join("Cargo.toml");
    let mut documents: Vec<_> = manifests
        .iter()
        .chain(std::iter::once(&root_manifest))
        .map(|path| (path.clone(), read_manifest(path)))
        .collect();
    documents.sort_by(|a, b| a.0.cmp(&b.0));
    documents.dedup_by(|a, b| a.0 == b.0);
    let release_paths: BTreeSet<_> = documents
        .iter()
        .filter(|(_, doc)| {
            doc.get("package")
                .and_then(|package| package.get("version"))
                .and_then(Item::as_table_like)
                .and_then(|version| version.get("workspace"))
                .and_then(Item::as_bool)
                == Some(true)
        })
        .map(|(path, _)| {
            path.parent()
                .unwrap()
                .canonicalize()
                .expect("member directory")
        })
        .collect();

    for (path, doc) in &mut documents {
        if path == &root_manifest {
            doc["workspace"]["package"]["version"] = value(version);
        }
        sync_dependency_tables(
            doc.as_table_mut(),
            path.parent().unwrap(),
            &release_paths,
            version,
        );
        write_if_changed(path, &doc.to_string());
    }

    let (rpm_deb, apk) = match version.split_once("-rc.") {
        Some((base, rc)) => (format!("{base}~rc{rc}"), format!("{base}_rc{rc}")),
        None => (version.to_string(), version.to_string()),
    };
    replace_line(
        &root.join("fastboop.spec"),
        "Version:",
        &format!("Version:        {rpm_deb}"),
    );
    replace_line(
        &root.join("fastboop.spec"),
        "%global upstream_version ",
        &format!("%global upstream_version {version}"),
    );
    replace_line(
        &root.join("APKBUILD"),
        "pkgver=",
        &format!("pkgver={apk}_git"),
    );
    replace_line(
        &root.join("APKBUILD"),
        "_upstream=",
        &format!("_upstream={version}"),
    );
    let path = root.join("debian/changelog");
    let changelog = fs::read_to_string(&path).expect("read Debian changelog");
    write_if_changed(&path, &prepend_changelog(&changelog, &rpm_deb, date));
}

fn read_manifest(path: &Path) -> DocumentMut {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
        .parse()
        .unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

fn sync_dependency_tables(
    table: &mut dyn TableLike,
    dir: &Path,
    release_paths: &BTreeSet<PathBuf>,
    version: &str,
) {
    for section in ["dependencies", "build-dependencies", "dev-dependencies"] {
        if let Some(dependencies) = table.get_mut(section).and_then(Item::as_table_like_mut) {
            for (_, item) in dependencies.iter_mut() {
                let Some(dependency) = item.as_table_like_mut() else {
                    continue;
                };
                let Some(path) = dependency.get("path").and_then(Item::as_str) else {
                    continue;
                };
                let path = dir.join(path).canonicalize().expect("dependency directory");
                if release_paths.contains(&path) {
                    dependency.insert("version", value(version));
                    if let Some(inline) = item.as_inline_table_mut() {
                        inline.fmt();
                    }
                }
            }
        }
    }
    if let Some(workspace) = table.get_mut("workspace").and_then(Item::as_table_like_mut) {
        sync_dependency_tables(workspace, dir, release_paths, version);
    }
    if let Some(targets) = table.get_mut("target").and_then(Item::as_table_like_mut) {
        for (_, target) in targets.iter_mut() {
            if let Some(target) = target.as_table_like_mut() {
                sync_dependency_tables(target, dir, release_paths, version);
            }
        }
    }
}

fn prepend_changelog(changelog: &str, version: &str, date: &str) -> String {
    if changelog.starts_with(&format!("fastboop ({version}) ")) {
        return changelog.to_string();
    }
    let maintainer = changelog
        .lines()
        .find_map(|line| line.strip_prefix(" -- "))
        .and_then(|trailer| trailer.split_once("  ").map(|(name, _)| name))
        .expect("Debian changelog maintainer trailer");
    format!("fastboop ({version}) UNRELEASED; urgency=medium\n\n  * New upstream release.\n\n -- {maintainer}  {date}\n\n{changelog}")
}

fn write_if_changed(path: &Path, updated: &str) {
    let original = fs::read_to_string(path).expect("read original file");
    if original != updated {
        fs::write(path, updated).unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
    }
}

pub fn publish(live: bool) {
    if live {
        util::run("tools/publish-crates.sh", &["--publish"]);
    } else {
        util::run("tools/publish-crates.sh", &["--dry-run"]);
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

    let path = "infra/k8s/live-version.txt";
    fs::write(path, format!("LIVE_VERSION={version}\n"))
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
    parts.len() == 3 && parts.iter().all(|part| valid_number(part)) && rc.is_none_or(valid_number)
}

fn valid_number(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|c| c.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'))
}

fn replace_line(path: &Path, prefix: &str, replacement: &str) {
    let text = fs::read_to_string(path).expect("read release metadata");
    assert_eq!(
        text.lines().filter(|line| line.starts_with(prefix)).count(),
        1,
        "expected one {prefix:?} line in {}",
        path.display()
    );
    let updated = replace_lines_preserving_endings(&text, |line| {
        line.starts_with(prefix).then(|| replacement.to_string())
    });
    write_if_changed(path, &updated);
}

fn replace_lines_preserving_endings(
    text: &str,
    mut replace: impl FnMut(&str) -> Option<String>,
) -> String {
    let mut updated = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let (line, line_ending) = split_line_ending(line);
        if let Some(replacement) = replace(line) {
            updated.push_str(&replacement);
        } else {
            updated.push_str(line);
        }
        updated.push_str(line_ending);
    }
    updated
}

fn split_line_ending(line: &str) -> (&str, &str) {
    if let Some(line) = line.strip_suffix("\r\n") {
        (line, "\r\n")
    } else if let Some(line) = line.strip_suffix('\n') {
        (line, "\n")
    } else {
        (line, "")
    }
}

fn die(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "fastboop-bump-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let fixture = Self(root);
            fixture.write(
                "Cargo.toml",
                r#"[workspace]
members = ["core", "app"]
exclude = ["vendor"]
[workspace.package]
version = "0.0.1-rc.21"
[workspace.dependencies]
fastboop-core = { path = "core", default-features = false } # keep this comment
[patch.crates-io]
fastboop-core = { path = "core" }
"#,
            );
            fixture.write(
                "core/Cargo.toml",
                r#"[package]
name = "fastboop-core"
version.workspace = true
"#,
            );
            fixture.write(
                "app/Cargo.toml",
                r#"[package]
name = "fastboop-cli"
version.workspace = true
[dependencies]
fastboop-core = { path = "../core", version = "0.0.1-rc.12", default-features = false }
external = { path = "../vendor", version = "0.0.1-rc.21" }
registry = "0.0.1-rc.21"
[dev-dependencies]
alias = { package = "fastboop-core", path = "../core", version = "=0.0.1-rc.17" }
[build-dependencies.fastboop-core]
path = "../core"
version = "0.0.1-rc.19"
[target.'cfg(unix)'.dependencies]
fastboop-core = { workspace = true }
[target.wasm32-unknown-unknown.dependencies]
alias = { package = "fastboop-core", path = "../core" }
"#,
            );
            fixture.write(
                "vendor/Cargo.toml",
                r#"[package]
name = "external"
version = "0.0.1-rc.21"
[dependencies]
fastboop-core = { path = "../core", version = "0.0.1-rc.12" }
"#,
            );
            fixture.write("fastboop.spec", "%global upstream_version 0.0.1-rc.21\nVersion:        0.0.1~rc21\nSource: v%{upstream_version}\n");
            fixture.write("APKBUILD", "pkgver=0.0.1_rc21_git\n_upstream=0.0.1-rc.21\n_gitrev=v$_upstream\n_smoorev=unchanged\n");
            fixture.write("debian/changelog", "fastboop (0.0.1~rc21) UNRELEASED; urgency=medium\n\n  * Original history.\n\n -- Sam Day <me@example.org>  Sun, 20 Sep 2026 00:00:00 +0000\n");
            fixture
        }

        fn write(&self, path: &str, text: &str) {
            let path = self.0.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }

        fn read(&self, path: &str) -> String {
            fs::read_to_string(self.0.join(path)).unwrap()
        }

        fn bump(&self, version: &str, date: &str) {
            let manifests = ["core/Cargo.toml", "app/Cargo.toml"].map(|path| self.0.join(path));
            bump_files(&self.0, &manifests, version, date);
        }

        fn snapshot(&self) -> Vec<String> {
            [
                "Cargo.toml",
                "core/Cargo.toml",
                "app/Cargo.toml",
                "vendor/Cargo.toml",
                "fastboop.spec",
                "APKBUILD",
                "debian/changelog",
            ]
            .map(|path| self.read(path))
            .to_vec()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn bump_repairs_workspace_dependencies_without_touching_external_sources() {
        let fixture = Fixture::new();
        let vendor = fixture.read("vendor/Cargo.toml");
        fixture.bump("0.0.1-rc.22", "Mon, 21 Sep 2026 00:00:00 +0000");
        let root = read_manifest(&fixture.0.join("Cargo.toml"));
        assert_eq!(
            root["workspace"]["package"]["version"].as_str(),
            Some("0.0.1-rc.22")
        );
        let dep = &root["workspace"]["dependencies"]["fastboop-core"];
        assert_eq!(dep["version"].as_str(), Some("0.0.1-rc.22"));
        assert_eq!(dep["default-features"].as_bool(), Some(false));
        assert!(fixture.read("Cargo.toml").contains("# keep this comment"));
        assert!(root["patch"]["crates-io"]["fastboop-core"]
            .get("version")
            .is_none());
        let app = read_manifest(&fixture.0.join("app/Cargo.toml"));
        for (section, name) in [
            ("dependencies", "fastboop-core"),
            ("dev-dependencies", "alias"),
            ("build-dependencies", "fastboop-core"),
        ] {
            assert_eq!(app[section][name]["version"].as_str(), Some("0.0.1-rc.22"));
        }
        assert_eq!(
            app["target"]["wasm32-unknown-unknown"]["dependencies"]["alias"]["version"].as_str(),
            Some("0.0.1-rc.22")
        );
        assert!(app["target"]["cfg(unix)"]["dependencies"]["fastboop-core"]
            .get("version")
            .is_none());
        assert_eq!(
            app["dependencies"]["external"]["version"].as_str(),
            Some("0.0.1-rc.21")
        );
        assert_eq!(
            app["dependencies"]["registry"].as_str(),
            Some("0.0.1-rc.21")
        );
        assert_eq!(fixture.read("vendor/Cargo.toml"), vendor);
    }

    #[test]
    fn rc_and_final_bumps_preserve_history_and_are_idempotent() {
        let fixture = Fixture::new();
        let original = fixture.read("debian/changelog");
        for (version, distro, apk) in [
            ("0.0.1-rc.22", "0.0.1~rc22", "0.0.1_rc22"),
            ("0.0.1", "0.0.1", "0.0.1"),
        ] {
            let previous = fixture.read("debian/changelog");
            fixture.bump(version, "Mon, 21 Sep 2026 00:00:00 +0000");
            assert!(fixture
                .read("fastboop.spec")
                .contains(&format!("Version:        {distro}\n")));
            assert!(fixture
                .read("fastboop.spec")
                .contains(&format!("%global upstream_version {version}\n")));
            assert!(fixture
                .read("APKBUILD")
                .contains(&format!("pkgver={apk}_git\n_upstream={version}\n")));
            assert!(fixture.read("APKBUILD").contains("_smoorev=unchanged"));
            let changelog = fixture.read("debian/changelog");
            assert!(
                changelog.starts_with(&format!("fastboop ({distro}) UNRELEASED; urgency=medium\n"))
            );
            assert!(changelog.ends_with(&previous));
            assert!(changelog
                .contains(" -- Sam Day <me@example.org>  Mon, 21 Sep 2026 00:00:00 +0000\n"));
            let snapshot = fixture.snapshot();
            fixture.bump(version, "Tue, 22 Sep 2026 00:00:00 +0000");
            assert_eq!(fixture.snapshot(), snapshot);
        }
        assert!(fixture.read("debian/changelog").ends_with(&original));
    }

    #[test]
    fn version_validation_rejects_ambiguous_or_unsupported_versions() {
        for version in ["0.0.1-rc.22", "0.0.1", "12.34.56"] {
            assert!(valid_version(version), "{version}");
        }
        for version in [
            "",
            "v0.0.1",
            "0.0",
            "0.0.1-rc.",
            "0.0.1-rc.01",
            "01.0.1",
            "0.0.1-beta.1",
            "0.0.1+local",
        ] {
            assert!(!valid_version(version), "{version}");
        }
    }
}
