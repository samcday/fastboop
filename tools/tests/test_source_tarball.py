"""Source tarball tests on throwaway local git repositories; nothing is fetched."""

import fnmatch
import io
import os
from pathlib import Path
import posixpath
import re
import subprocess
import tarfile
import tempfile
import time
import tomllib
import unittest

TOOLS = Path(__file__).resolve().parents[1]
REPO = TOOLS.parent
SCRIPT = TOOLS / "source-tarball.sh"
VERSION = "1.2.3-rc.4"
TOP = f"fastboop-{VERSION}"
COMMIT_DATE = "2001-02-03T04:05:06Z"
COMMIT_EPOCH = 981173106
SUBMODULE_COMMIT_DATE = "2000-01-02T03:04:05Z"


def git_env(commit_date=COMMIT_DATE):
    # Hermetic git: no caller hooks/GIT_DIR, user config (signing) or system config.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
        # Local submodule clones use the file transport, which git blocks by default.
        GIT_CONFIG_COUNT="1",
        GIT_CONFIG_KEY_0="protocol.file.allow",
        GIT_CONFIG_VALUE_0="always",
        GIT_AUTHOR_NAME="fastboop test",
        GIT_AUTHOR_EMAIL="test@example.invalid",
        GIT_AUTHOR_DATE=commit_date,
        GIT_COMMITTER_NAME="fastboop test",
        GIT_COMMITTER_EMAIL="test@example.invalid",
        GIT_COMMITTER_DATE=commit_date,
    )
    return env


class SourceTarballTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="fastboop-source-tarball-test-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

        # super/third_party/lib is a submodule, which nests lib/vendor/deep. Their
        # commits predate super's HEAD, whose date alone must reach the archive.
        self.env = git_env(SUBMODULE_COMMIT_DATE)
        deep = self.repo("deep", {"README": "deep v1\n"})
        lib = self.repo("lib", {"lib.txt": "lib v1\n", "run.sh": "#!/bin/sh\n"}, executable=["run.sh"])
        self.git(lib, "submodule", "add", "-q", str(deep), "vendor/deep")
        self.git(lib, "commit", "-qm", "add deep")
        self.lib_v1 = self.git(lib, "rev-parse", "HEAD")
        self.write(lib / "lib.txt", "lib v2\n")
        self.git(lib, "commit", "-qam", "v2")
        self.lib_v2 = self.git(lib, "rev-parse", "HEAD")

        self.env = git_env()
        self.super = self.repo("super", {
            ".gitattributes": (REPO / ".gitattributes").read_text(),
            "Cargo.toml": "[workspace]\n",
            "infra/tofu/terraform.tfstate": "encrypted\n",
            # git sorts trees as "name/", so git archive emits third_party.md
            # before third_party/: extraction order is not name order.
            "third_party.md": "notes\n",
        })
        self.git(self.super, "submodule", "add", "-q", str(lib), "third_party/lib")
        # Record lib v1 although the submodule clone also has v2.
        self.sub = self.super / "third_party/lib"
        self.git(self.sub, "checkout", "-q", self.lib_v1)
        self.git(self.super, "add", "third_party/lib")
        self.git(self.super, "submodule", "update", "-q", "--init", "--recursive")
        self.git(self.super, "commit", "-qm", "add lib")

    def write(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def git(self, cwd, *args):
        result = subprocess.run(["git", *args], cwd=cwd, env=self.env, text=True,
                                capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def repo(self, name, files, executable=()):
        path = self.root / name
        self.git(self.root, "init", "-q", "-b", "main", name)
        for relative, text in files.items():
            self.write(path / relative, text)
        for relative in executable:
            (path / relative).chmod(0o755)
        self.git(path, "add", ".")
        self.git(path, "commit", "-qm", "init")
        return path

    def run_script(self, outdir, success, env=None, **kwargs):
        result = subprocess.run(["bash", str(SCRIPT), VERSION, str(outdir)], cwd=self.super,
                                env=env or self.env, text=True, capture_output=True, **kwargs)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        tarball = outdir / f"{TOP}-src.tar.gz"
        if success:
            self.assertEqual(result.stdout.strip(), str(tarball))
        else:
            self.assertFalse(tarball.exists())
        return result, tarball

    def test_same_commit_gives_identical_bytes(self):
        _, first = self.run_script(self.root / "out-a", success=True)
        # Extraction timestamps, the caller's umask and timezone must not leak in.
        time.sleep(1.1)
        env = dict(self.env, TZ="Pacific/Kiritimati")
        _, second = self.run_script(self.root / "out-b", success=True, umask=0o077, env=env)
        self.assertEqual(first.read_bytes(), second.read_bytes())

        with tarfile.open(first) as archive:
            members = archive.getmembers()
            for member in members:
                with self.subTest(member=member.name):
                    self.assertTrue(member.name == TOP or member.name.startswith(f"{TOP}/"))
                    self.assertEqual((member.uid, member.gid, member.uname, member.gname), (0, 0, "", ""))
                    self.assertEqual(member.mtime, COMMIT_EPOCH)
                    self.assertIn(member.mode, (0o644, 0o755))

        # Each directory's entries are in byte order, whatever order readdir gives.
        children = {}
        for member in members:
            parent, child = posixpath.split(member.name)
            children.setdefault(parent, []).append(os.fsencode(child))
        for parent, names in children.items():
            with self.subTest(directory=parent):
                self.assertEqual(names, sorted(names))

    def test_submodules_are_archived_at_their_recorded_commits(self):
        # The clone's newer commit and uncommitted edits must not reach the archive.
        self.write(self.sub / "lib.txt", "dirty\n")
        self.write(self.sub / "untracked.txt", "untracked\n")
        self.write(self.super / "Cargo.toml", "dirty\n")
        _, tarball = self.run_script(self.root / "out", success=True)

        with tarfile.open(tarball) as archive:
            names = set(archive.getnames())

            def read(name):
                return archive.extractfile(f"{TOP}/{name}").read().decode()

            self.assertEqual(read("third_party/lib/lib.txt"), "lib v1\n")
            self.assertEqual(read("third_party/lib/vendor/deep/README"), "deep v1\n")
            self.assertEqual(read("Cargo.toml"), "[workspace]\n")
            self.assertEqual(archive.getmember(f"{TOP}/third_party/lib/run.sh").mode, 0o755)
        self.assertNotIn(f"{TOP}/third_party/lib/untracked.txt", names)
        self.assertFalse(any(name.startswith(f"{TOP}/infra") for name in names), names)

    def test_rejects_uninitialized_submodules(self):
        # Nested first: deinitializing lib would also hide vendor/deep.
        for superproject, path in [(self.sub, "vendor/deep"), (self.super, "third_party/lib")]:
            with self.subTest(path=path):
                self.git(superproject, "submodule", "deinit", "-q", "-f", path)
                result, _ = self.run_script(self.root / "out", success=False)
                display = "third_party/lib/vendor/deep" if path == "vendor/deep" else path
                self.assertRegex(result.stderr, rf"(?m)^-[0-9a-f]{{40}} {re.escape(display)}( |$)")
                self.assertIn("must be initialized", result.stderr)

    def test_rejects_submodule_checkout_that_differs_from_the_recorded_commit(self):
        self.git(self.sub, "checkout", "-q", self.lib_v2)
        result, _ = self.run_script(self.root / "out", success=False)
        self.assertIn(f"+{self.lib_v2} third_party/lib", result.stderr)

    def test_rejects_staged_but_uncommitted_submodule_bump(self):
        self.git(self.sub, "checkout", "-q", self.lib_v2)
        self.git(self.super, "add", "third_party/lib")
        result, _ = self.run_script(self.root / "out", success=False)
        self.assertIn(f"staged at {self.lib_v2} but committed at {self.lib_v1}", result.stderr)

    def test_rejects_committed_submodule_missing_from_the_index(self):
        # Status and foreach only list index entries; HEAD still has the gitlink.
        self.git(self.super, "rm", "-q", "--cached", "third_party/lib")
        result, _ = self.run_script(self.root / "out", success=False)
        self.assertIn(f"{TOP}/third_party/lib\n", result.stderr)
        self.assertIn("unpopulated submodule", result.stderr)


class RepositoryArchiveTests(unittest.TestCase):
    def test_archive_keeps_workspace_members_and_drops_infra(self):
        env = git_env()
        inside = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--is-inside-work-tree"],
                                env=env, capture_output=True, text=True)
        if inside.stdout.strip() != "true":
            self.skipTest("not a git checkout")
        # Contents come from HEAD; attributes also from the working tree, like a commit would.
        archive = subprocess.run(["git", "-C", str(REPO), "archive", "--worktree-attributes",
                                  "--format=tar", "HEAD"], env=env, capture_output=True, check=True)
        manifest = subprocess.run(["git", "-C", str(REPO), "show", "HEAD:Cargo.toml"],
                                  env=env, capture_output=True, text=True, check=True)
        with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
            names = tar.getnames()
        members = tomllib.loads(manifest.stdout)["workspace"]["members"]
        for member in ["."] + members:
            with self.subTest(member=member):
                pattern = "Cargo.toml" if member == "." else f"{member}/Cargo.toml"
                self.assertTrue(any(fnmatch.fnmatchcase(name, pattern) for name in names))
        self.assertIn("Cargo.lock", names)
        self.assertEqual([name for name in names if name == "infra" or name.startswith("infra/")], [])


if __name__ == "__main__":
    unittest.main()
