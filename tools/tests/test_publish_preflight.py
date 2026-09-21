"""Real Cargo package tests; registry reads are allowed, uploads are never made."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("preflight", TOOLS / "publish-preflight.py")
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class LockTests(unittest.TestCase):
    def setUp(self):
        self.versions = {"fastboop-cli": "99.0.0", "fastboop-core": "99.0.0"}
        self.workspace = {"package": [
            {"name": "fastboop-cli", "version": "99.0.0"},
            {"name": "fastboop-core", "version": "99.0.0"},
            {"name": "external", "version": "1.0.0", "source": preflight.CRATES_IO, "checksum": "abc"},
        ]}
        self.packaged = copy.deepcopy(self.workspace)
        self.packaged["package"][1].update(source=preflight.CRATES_IO, checksum="def")

    def verify(self):
        preflight.verify_cli_lock(self.workspace, self.packaged, self.versions)

    def test_siblings_become_registry_dependencies(self):
        self.verify()

    def test_rejects_path_git_and_alternate_registry_dependencies(self):
        for source in [None, "git+https://example.org/repo#abcdef", "registry+https://example.org/index"]:
            with self.subTest(source=source):
                dependency = self.packaged["package"][1]
                dependency.pop("source", None)
                if source:
                    dependency["source"] = source
                with self.assertRaisesRegex(ValueError, "not from crates.io"):
                    self.verify()

    def test_rejects_version_drift(self):
        self.packaged["package"][2]["version"] = "1.0.1"
        with self.assertRaisesRegex(ValueError, "absent from workspace"):
            self.verify()

    def test_rejects_an_older_release_sibling_even_if_locked(self):
        self.workspace["package"].append({"name": "fastboop-core", "version": "98.0.0"})
        self.packaged["package"][1]["version"] = "98.0.0"
        with self.assertRaisesRegex(ValueError, "differs from the release"):
            self.verify()

    def test_rejects_checksum_drift(self):
        self.packaged["package"][2]["checksum"] = "changed"
        with self.assertRaisesRegex(ValueError, "changed source or checksum"):
            self.verify()

    def test_requires_root_and_checksums(self):
        self.packaged["package"][1].pop("checksum")
        with self.assertRaisesRegex(ValueError, "no registry checksum"):
            self.verify()
        self.packaged["package"] = self.packaged["package"][2:]
        with self.assertRaisesRegex(ValueError, "missing.*release root"):
            self.verify()


class CargoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fastboop-publish-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = dict(os.environ)
        # Fixtures must use the repository's toolchain, even outside its tree.
        toolchain = (TOOLS.parent / "rust-toolchain.toml").read_text()
        self.write("rust-toolchain.toml", toolchain)
        self.env.pop("CARGO_TARGET_DIR", None)
        self.env.pop("CARGO_BUILD_TARGET", None)
        self.write("Cargo.toml", '[workspace]\nmembers = ["core", "cli"]\nresolver = "2"\n')
        self.write("core/Cargo.toml", '[package]\nname = "fastboop-core"\nversion = "99.0.0"\nedition = "2021"\n')
        self.write("core/src/lib.rs", "pub fn answer() -> u8 { 42 }\n")
        self.write("cli/Cargo.toml", '[package]\nname = "fastboop-cli"\nversion = "99.0.0"\nedition = "2021"\n[dependencies]\nfastboop-core = { path = "../core", version = "99.0.0" }\n')
        self.write("cli/src/main.rs", "fn main() { assert_eq!(fastboop_core::answer(), 42); }\n")
        self.run_command(["cargo", "generate-lockfile", "--offline"], success=True)

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def run_command(self, command, success):
        result = subprocess.run(command, cwd=self.root, env=self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        self.assertEqual(result.returncode == 0, success, result.stdout)
        return result.stdout

    def dry_run(self, success):
        return self.run_command(["bash", str(TOOLS / "publish-crates.sh"), "--dry-run"], success)

    def test_packages_and_compiles_unpublished_siblings_and_reads_cli_archive(self):
        # Exercise the metadata target_directory, rather than assuming ./target.
        self.env["CARGO_TARGET_DIR"] = str(self.root / "custom-target")
        output = self.dry_run(success=True)
        self.assertIn("Verifying fastboop-cli", output)
        self.assertIn("packaged CLI lockfile matches", output)
        self.assertTrue((self.root / "custom-target/package/fastboop-cli-99.0.0.crate").is_file())

    def test_compilation_failure_is_not_a_successful_dry_run(self):
        self.write("core/src/lib.rs", 'compile_error!("preflight must compile packaged code");\n')
        output = self.dry_run(success=False)
        self.assertIn("preflight must compile packaged code", output)
        self.assertNotIn("packaged CLI lockfile matches", output)

    def test_unpublished_external_dependency_is_not_hidden_by_workspace_patch(self):
        with (self.root / "Cargo.toml").open("a") as manifest:
            manifest.write('\nexclude = ["unpublished"]\n[patch.crates-io]\nitoa = { path = "unpublished" }\n')
        self.write("unpublished/Cargo.toml", '[package]\nname = "itoa"\nversion = "999.0.0"\nedition = "2021"\n')
        self.write("unpublished/src/lib.rs", "pub fn only_in_local_patch() {}\n")
        with (self.root / "cli/Cargo.toml").open("a") as manifest:
            manifest.write('itoa = "999.0.0"\n')
        self.run_command(["cargo", "generate-lockfile", "--offline"], success=True)
        output = self.dry_run(success=False)
        self.assertIn("itoa", output)
        self.assertIn("999.0.0", output)
        self.assertNotIn("packaged CLI lockfile matches", output)

    def test_missing_packaged_source_fails_even_when_workspace_builds(self):
        with (self.root / "core/Cargo.toml").open("a") as manifest:
            manifest.write('exclude = ["src/implementation.rs"]\n')
        self.write("core/src/lib.rs", 'include!("implementation.rs");\n')
        self.write("core/src/implementation.rs", "pub fn answer() -> u8 { 42 }\n")
        self.run_command(["cargo", "check", "--locked", "--offline"], success=True)
        output = self.dry_run(success=False)
        self.assertIn("implementation.rs", output)

    def test_config_patch_cannot_pass_as_a_registry_dependency(self):
        # Unlike manifest patches, Cargo config patches can reach verification.
        # The shipped CLI lockfile must still reject that local dependency.
        with (self.root / "Cargo.toml").open("a") as manifest:
            manifest.write('\nexclude = ["patched"]\n')
        self.write("patched/Cargo.toml", '[package]\nname = "itoa"\nversion = "1.0.18"\nedition = "2021"\n')
        self.write("patched/src/lib.rs", "pub fn only_in_local_patch() {}\n")
        self.write(".cargo/config.toml", '[patch.crates-io]\nitoa = { path = ' + json.dumps(str(self.root / "patched")) + ' }\n')
        with (self.root / "cli/Cargo.toml").open("a") as manifest:
            manifest.write('itoa = "=1.0.18"\n')
        self.write("cli/src/main.rs", "fn main() { itoa::only_in_local_patch(); }\n")
        self.run_command(["cargo", "generate-lockfile", "--offline"], success=True)
        self.run_command(["cargo", "check", "--locked", "--offline"], success=True)
        output = self.dry_run(success=False)
        self.assertIn("not from crates.io", output)


class ScriptFailureTests(unittest.TestCase):
    def test_package_failure_prevents_uploading(self):
        with tempfile.TemporaryDirectory(prefix="fastboop-publish-mock-") as tmp:
            root = Path(tmp)
            metadata = root / "metadata.json"
            metadata.write_text(json.dumps({"workspace_members": ["cli"], "packages": [
                {"id": "cli", "name": "fastboop-cli", "source": None, "publish": None,
                 "dependencies": []}
            ]}))
            fake = root / "cargo"
            fake.write_text('#!/bin/sh\ncase "$1" in\nmetadata) cat "$MOCK_METADATA";;\npackage) exit 42;;\n*) echo UNEXPECTED_UPLOAD; exit 97;;\nesac\n')
            fake.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", MOCK_METADATA=str(metadata))
            result = subprocess.run(["bash", str(TOOLS / "publish-crates.sh"), "--publish"],
                                    env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 42)
            self.assertNotIn("UNEXPECTED_UPLOAD", result.stdout)

    def test_planner_failure_prevents_packaging_and_uploading(self):
        with tempfile.TemporaryDirectory(prefix="fastboop-publish-mock-") as tmp:
            root = Path(tmp)
            # Mock only Cargo metadata; any subsequent Cargo invocation is a failure.
            fake = root / "cargo"
            fake.write_text('#!/bin/sh\nif [ "$1" = metadata ]; then cat "$MOCK_METADATA"; else echo UNEXPECTED_CARGO_COMMAND; exit 97; fi\n')
            fake.chmod(0o755)
            for mode in ["--dry-run", "--publish"]:
                for metadata in [
                    {"workspace_members": [], "packages": []},
                    {"workspace_members": ["a", "b"], "packages": [
                        {"id": name, "name": name, "source": None, "publish": None,
                         "dependencies": [{"name": other, "kind": None}]}
                        for name, other in [("a", "b"), ("b", "a")]]
                    },
                ]:
                    with self.subTest(mode=mode, metadata=metadata):
                        path = root / "metadata.json"
                        path.write_text(json.dumps(metadata))
                        env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", MOCK_METADATA=str(path))
                        result = subprocess.run(["bash", str(TOOLS / "publish-crates.sh"), mode],
                                                env=env, text=True, capture_output=True)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("publish preflight failed", result.stderr)
                        self.assertNotIn("UNEXPECTED_CARGO_COMMAND", result.stdout)


if __name__ == "__main__":
    unittest.main()
