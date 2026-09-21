"""Plan crates.io publication and check the lockfile shipped to CLI users."""

import argparse
import collections
import json
from pathlib import Path
import sys
import tarfile
import tomllib

CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


def publishable_packages(metadata):
    members = set(metadata["workspace_members"])
    packages = {
        package["name"]: package
        for package in metadata["packages"]
        if package["id"] in members
        and package["source"] is None
        and (package["publish"] is None or "crates-io" in package["publish"])
    }
    if not packages:
        raise ValueError("no publishable workspace packages found")
    return packages


def publish_order(metadata):
    packages = publishable_packages(metadata)
    deps = {
        name: {
            dependency["name"]
            for dependency in package["dependencies"]
            if dependency["kind"] in (None, "build")
            and dependency["name"] in packages
        }
        for name, package in packages.items()
    }
    order = []
    while deps:
        ready = sorted(name for name, dependencies in deps.items() if not dependencies)
        if not ready:
            raise ValueError("publishable workspace dependencies contain a cycle")
        order.extend(ready)
        for name in ready:
            del deps[name]
        for dependencies in deps.values():
            dependencies.difference_update(ready)
    return order


def verify_cli_lock(workspace, packaged, versions):
    """Allow path-to-registry transitions, but no new versions or local sources."""
    expected = collections.defaultdict(list)
    for package in workspace["package"]:
        expected[package["name"], package["version"]].append(package)

    root = ("fastboop-cli", versions["fastboop-cli"])
    found_root = False
    for package in packaged["package"]:
        key = (package["name"], package["version"])
        label = f"{key[0]} {key[1]}"
        if key == root and "source" not in package:
            found_root = True
            continue
        if package.get("source") != CRATES_IO:
            raise ValueError(f"packaged CLI dependency {label} is not from crates.io")
        if not package.get("checksum"):
            raise ValueError(f"packaged CLI dependency {label} has no registry checksum")
        if key not in expected:
            raise ValueError(f"packaged CLI dependency {label} is absent from workspace Cargo.lock")
        if key[0] in versions and key[1] != versions[key[0]]:
            raise ValueError(f"packaged CLI dependency {label} differs from the release version")
        # A workspace path package is intentionally replaced by its registry
        # release. Already-registry packages must keep both source and checksum.
        if not any(
            "source" not in original
            or (
                original.get("source") == package["source"]
                and original.get("checksum") == package["checksum"]
            )
            for original in expected[key]
        ):
            raise ValueError(f"packaged CLI dependency {label} changed source or checksum")
    if not found_root:
        raise ValueError("packaged lockfile is missing the fastboop-cli release root")


def verify_archive(metadata):
    packages = publishable_packages(metadata)
    versions = {name: package["version"] for name, package in packages.items()}
    if "fastboop-cli" not in versions:
        raise ValueError("fastboop-cli is missing from the publish plan")
    stem = f"fastboop-cli-{versions['fastboop-cli']}"
    archive = Path(metadata["target_directory"]) / "package" / f"{stem}.crate"
    with tarfile.open(archive, "r:gz") as crate:
        lock = crate.extractfile(f"{stem}/Cargo.lock")
        if lock is None:
            raise ValueError(f"missing Cargo.lock in {archive}")
        packaged = tomllib.loads(lock.read().decode("utf-8"))
    with (Path(metadata["workspace_root"]) / "Cargo.lock").open("rb") as lock:
        workspace = tomllib.load(lock)
    verify_cli_lock(workspace, packaged, versions)
    print("==> packaged CLI lockfile matches workspace versions and crates.io sources")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["plan", "verify"])
    parser.add_argument("metadata", type=Path)
    args = parser.parse_args()
    try:
        metadata = json.loads(args.metadata.read_text())
        if args.mode == "plan":
            print("\n".join(publish_order(metadata)))
        else:
            verify_archive(metadata)
    except (ValueError, KeyError, OSError, tarfile.TarError) as error:
        sys.exit(f"publish preflight failed: {error}")


if __name__ == "__main__":
    main()
