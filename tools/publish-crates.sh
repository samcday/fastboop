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

is_already_uploaded_error() {
    local output="$1"
    [[ "$output" == *"already uploaded"* || "$output" == *"already exists"* ]]
}

extract_retry_after_epoch() {
    python -c '
import datetime
import email.utils
import re
import sys

text = sys.stdin.read()
text = re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", text)
match = re.search(
    r"Please try again after (?P<retry_after>.+?)(?: or email|\.)",
    text,
    flags=re.IGNORECASE,
)
if not match:
    raise SystemExit(1)

retry_after = match.group("retry_after").strip()

try:
    parsed = email.utils.parsedate_to_datetime(retry_after)
except Exception:
    raise SystemExit(1)

if parsed is None:
    raise SystemExit(1)

if parsed.tzinfo is None:
    parsed = parsed.replace(tzinfo=datetime.timezone.utc)

print(int(parsed.timestamp()))
'
}

require_stage0_provenance_sidecar() {
    local sidecar="crates/fastboop-stage0-generator/stage0-aarch64.sha256sum"
    if [[ ! -s "$sidecar" ]]; then
        echo "missing required stage0 provenance sidecar: $sidecar" >&2
        exit 1
    fi

    local checksum
    checksum="$(tr -d '[:space:]' < "$sidecar")"
    if [[ ! "$checksum" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "invalid stage0 provenance sidecar checksum in $sidecar" >&2
        exit 1
    fi
}

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
        if [[ "$package" == "fastboop-stage0-generator" ]]; then
            require_stage0_provenance_sidecar
        fi

        echo "==> cargo publish -p $package --locked --no-verify --allow-dirty"
        if output="$(cargo publish -p "$package" --locked --no-verify --allow-dirty 2>&1)"; then
            printf '%s\n' "$output"
            continue
        fi

        printf '%s\n' "$output" >&2
        if is_already_uploaded_error "$output"; then
            echo "==> crate $package already published; continuing"
            continue
        fi

        if retry_after_epoch="$(extract_retry_after_epoch <<<"$output")"; then
            now_epoch="$(date -u +%s)"
            wait_seconds=$((retry_after_epoch - now_epoch + 1))

            if (( wait_seconds > 0 )); then
                echo "==> crates.io rate limit for $package; waiting ${wait_seconds}s for scheduled retry"
                sleep "$wait_seconds"
            else
                echo "==> crates.io scheduled retry time already passed for $package; retrying now"
            fi

            echo "==> cargo publish -p $package --locked --no-verify --allow-dirty (scheduled retry)"
            if retry_output="$(cargo publish -p "$package" --locked --no-verify --allow-dirty 2>&1)"; then
                printf '%s\n' "$retry_output"
                continue
            fi

            printf '%s\n' "$retry_output" >&2
            if is_already_uploaded_error "$retry_output"; then
                echo "==> crate $package already published; continuing"
                continue
            fi
        fi

        exit 1
    fi
done
