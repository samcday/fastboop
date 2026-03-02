#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 --dry-run|--publish" >&2
    exit 2
}

if [[ $# -ne 1 ]]; then
    usage
fi

mode="$1"
case "$mode" in
    --dry-run | --publish) ;;
    *)
        usage
        ;;
esac

metadata_file="$(mktemp)"
cleanup_files=("$metadata_file")

cleanup() {
    rm -f "${cleanup_files[@]}"
}
trap cleanup EXIT

cargo metadata --format-version 1 >"$metadata_file"

mapfile -t packages < <(python - "$metadata_file" <<'PY'
import collections
import json
import pathlib
import sys

metadata_path = pathlib.Path(sys.argv[1])
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
root = pathlib.Path(".").resolve()


def in_repo(path: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


local_names = set()
packages = {pkg["name"]: pkg for pkg in metadata["packages"]}

for pkg in metadata["packages"]:
    manifest_path = pathlib.Path(pkg["manifest_path"]).resolve()
    if pkg.get("source") is not None:
        continue
    if pkg.get("publish") == []:
        continue
    if not in_repo(manifest_path):
        continue
    local_names.add(pkg["name"])

deps = {name: set() for name in local_names}
reverse = {name: set() for name in local_names}

for name in local_names:
    for dep in packages[name].get("dependencies", []):
        if dep.get("kind") in (None, "build") and dep["name"] in local_names:
            deps[name].add(dep["name"])
            reverse[dep["name"]].add(name)

indegree = {name: len(deps[name]) for name in local_names}
queue = collections.deque(sorted(name for name, degree in indegree.items() if degree == 0))
order = []

while queue:
    name = queue.popleft()
    order.append(name)
    for dependent in sorted(reverse[name]):
        indegree[dependent] -= 1
        if indegree[dependent] == 0:
            queue.append(dependent)

if len(order) != len(local_names):
    raise SystemExit("publish aborted: local publish graph has a cycle")

print("\n".join(order))
PY
)

if [[ ${#packages[@]} -eq 0 ]]; then
    echo "No local publishable packages found"
    exit 0
fi

echo "==> publish order: ${packages[*]}"

for package in "${packages[@]}"; do
    if [[ "$mode" == "--dry-run" ]]; then
        patch_file="$(mktemp)"
        cleanup_files+=("$patch_file")

        python - "$metadata_file" "$package" "$patch_file" <<'PY'
import json
import pathlib
import sys

metadata_path = pathlib.Path(sys.argv[1])
current_package = sys.argv[2]
patch_path = pathlib.Path(sys.argv[3])

metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
root = pathlib.Path(".").resolve()


def in_repo(path: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


local_packages = {}
for pkg in metadata["packages"]:
    manifest_path = pathlib.Path(pkg["manifest_path"]).resolve()
    if pkg.get("source") is not None:
        continue
    if pkg.get("publish") == []:
        continue
    if not in_repo(manifest_path):
        continue
    local_packages[pkg["name"]] = pkg

if current_package not in local_packages:
    raise SystemExit(f"package {current_package!r} is not a local publishable package")

needed = set()
stack = [
    dep["name"]
    for dep in local_packages[current_package].get("dependencies", [])
    if dep.get("kind") in (None, "build") and dep["name"] in local_packages
]

while stack:
    name = stack.pop()
    if name in needed:
        continue
    needed.add(name)
    for dep in local_packages[name].get("dependencies", []):
        if dep.get("kind") in (None, "build") and dep["name"] in local_packages:
            stack.append(dep["name"])

lines = ["[patch.crates-io]"]
for name in sorted(needed):
    manifest_path = pathlib.Path(local_packages[name]["manifest_path"]).resolve()
    lines.append(name + ' = { path = "' + manifest_path.parent.as_posix() + '" }')

patch_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

        echo "==> cargo package -p $package --locked --no-verify"
        cargo package -p "$package" --locked --no-verify --config "$patch_file"
        rm -f "$patch_file"
    else
        echo "==> cargo publish -p $package --locked --no-verify"
        if output="$(cargo publish -p "$package" --locked --no-verify 2>&1)"; then
            printf '%s\n' "$output"
            continue
        fi

        printf '%s\n' "$output" >&2
        if [[ "$output" == *"already uploaded"* || "$output" == *"already exists"* ]]; then
            echo "==> crate $package already published; continuing"
            continue
        fi

        exit 1
    fi
done
