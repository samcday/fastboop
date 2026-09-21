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

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
metadata_file="$(mktemp)"
packages_file="$(mktemp)"
cleanup() {
    rm -f "$metadata_file" "$packages_file"
}
trap cleanup EXIT

cargo metadata --locked --no-deps --format-version 1 >"$metadata_file"
# Keep this a foreground command: process substitution hides planner failures.
python3 "$script_dir/publish-preflight.py" plan "$metadata_file" >"$packages_file"
mapfile -t packages <"$packages_file"
echo "==> publish order: ${packages[*]}"

# Cargo stages sibling crates in a temporary registry and verifies their packaged
# contents together. Do not inject config patches or disable this compilation.
package_args=()
for package in "${packages[@]}"; do
    package_args+=(-p "$package")
done
echo "==> cargo package --registry crates-io --locked ${package_args[*]}"
cargo package --registry crates-io --locked "${package_args[@]}"
python3 "$script_dir/publish-preflight.py" verify "$metadata_file"

if [[ "$mode" == "--dry-run" ]]; then
    exit 0
fi

is_already_uploaded_error() {
    local output="$1"
    [[ "$output" == *"already uploaded"* || "$output" == *"already exists"* ]]
}

extract_retry_after_epoch() {
    python3 -c '
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

# All crates have passed the same preflight before the first upload.
for package in "${packages[@]}"; do
    echo "==> cargo publish --registry crates-io -p $package --locked --no-verify"
    if output="$(cargo publish --registry crates-io -p "$package" --locked --no-verify 2>&1)"; then
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

        echo "==> cargo publish --registry crates-io -p $package --locked --no-verify (scheduled retry)"
        if retry_output="$(cargo publish --registry crates-io -p "$package" --locked --no-verify 2>&1)"; then
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
done
