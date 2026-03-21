#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
gibblox_root="${repo_root}/gibblox"

if [[ ! -f "${gibblox_root}/Cargo.toml" ]]; then
  echo "missing ./gibblox checkout/worktree" >&2
  echo "create it first (for example: git clone https://github.com/samcday/gibblox ./gibblox)" >&2
  exit 1
fi

export FASTBOOP_STAGE0_CARGO="${repo_root}/tools/cargo-local-gibblox.sh"

# Pre-resolve workspace metadata with the local gibblox overlay before dx starts
# watching the tree, so Cargo.lock churn doesn't immediately trigger a rebuild.
"${repo_root}/tools/cargo-local-gibblox.sh" metadata --format-version=1 --no-deps >/dev/null

dx_args=("$@")
has_release=0
has_watch=0
for arg in "${dx_args[@]}"; do
  if [[ "${arg}" == "--release" || "${arg}" == "-r" ]]; then
    has_release=1
  fi
  if [[ "${arg}" == "--watch" || "${arg}" == --watch=* ]]; then
    has_watch=1
  fi
done

# dx can repeatedly rebuild in release mode when Cargo.lock churns under local patch
# overlays. Default release runs to a stable one-shot build unless --watch was set.
if [[ ${has_release} -eq 1 && ${has_watch} -eq 0 ]]; then
  dx_args+=("--watch=false")
fi

exec dx "${dx_args[@]}" --cargo-args="--config=${repo_root}/.cargo/config.gibblox-local.toml"
