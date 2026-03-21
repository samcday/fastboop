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

temp_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "${temp_dir}"
}
trap cleanup EXIT

link_root="${temp_dir}/gibblox"
ln -s "${gibblox_root}" "${link_root}"

config_path="${temp_dir}/config.gibblox-local.toml"
cat > "${config_path}" <<EOF
[patch.crates-io]
gobblytes-core = { path = "${link_root}/crates/gobblytes-core" }
gobblytes-erofs = { path = "${link_root}/crates/gobblytes-erofs" }
gobblytes-fat = { path = "${link_root}/crates/gobblytes-fat" }
gibblox-schema = { path = "${link_root}/crates/gibblox-schema" }
gibblox-android-sparse = { path = "${link_root}/crates/gibblox-android-sparse" }
gibblox-blockreader-messageport = { path = "${link_root}/crates/gibblox-blockreader-messageport" }
gibblox-cache = { path = "${link_root}/crates/gibblox-cache" }
gibblox-cache-store-opfs = { path = "${link_root}/crates/gibblox-cache-store-opfs" }
gibblox-cache-store-std = { path = "${link_root}/crates/gibblox-cache-store-std" }
gibblox-casync = { path = "${link_root}/crates/gibblox-casync" }
gibblox-casync-std = { path = "${link_root}/crates/gibblox-casync-std" }
gibblox-casync-web = { path = "${link_root}/crates/gibblox-casync-web" }
gibblox-core = { path = "${link_root}/crates/gibblox-core" }
gibblox-ext4 = { path = "${link_root}/crates/gibblox-ext4" }
gibblox-file = { path = "${link_root}/crates/gibblox-file" }
gibblox-http = { path = "${link_root}/crates/gibblox-http" }
gibblox-iso9660 = { path = "${link_root}/crates/gibblox-iso9660" }
gibblox-mbr = { path = "${link_root}/crates/gibblox-mbr" }
gibblox-pipeline = { path = "${link_root}/crates/gibblox-pipeline" }
gibblox-web-file = { path = "${link_root}/crates/gibblox-web-file" }
gibblox-web-worker = { path = "${link_root}/crates/gibblox-web-worker" }
gibblox-xz = { path = "${link_root}/crates/gibblox-xz" }
gibblox-zip = { path = "${link_root}/crates/gibblox-zip" }
EOF

export FASTBOOP_STAGE0_CARGO="${repo_root}/tools/cargo-local-gibblox.sh"

# Pre-resolve workspace metadata with the local gibblox overlay before dx starts
# watching the tree, so Cargo.lock churn doesn't immediately trigger a rebuild.
"${repo_root}/tools/cargo-local-gibblox.sh" metadata --format-version=1 --no-deps >/dev/null

dx_args=("$@")

# Normalize accidental `--release <command>` ordering into
# `<command> --release ...` so `dx` parses command-specific flags correctly.
normalized_args=()
release_prefix_flags=()
found_command=0
for arg in "${dx_args[@]}"; do
  if [[ ${found_command} -eq 0 && ( "${arg}" == "--release" || "${arg}" == "-r" ) ]]; then
    release_prefix_flags+=("${arg}")
    continue
  fi
  if [[ ${found_command} -eq 0 && "${arg}" != -* ]]; then
    found_command=1
    normalized_args+=("${arg}")
    if [[ ${#release_prefix_flags[@]} -gt 0 ]]; then
      normalized_args+=("${release_prefix_flags[@]}")
    fi
    continue
  fi
  normalized_args+=("${arg}")
done

if [[ ${found_command} -eq 1 && ${#release_prefix_flags[@]} -gt 0 ]]; then
  dx_args=("${normalized_args[@]}")
fi

has_release=0
has_watch=0
dx_command=""
for arg in "${dx_args[@]}"; do
  if [[ "${arg}" == "--release" || "${arg}" == "-r" ]]; then
    has_release=1
  fi
  if [[ "${arg}" == "--watch" || "${arg}" == --watch=* ]]; then
    has_watch=1
  fi
  if [[ -z "${dx_command}" && "${arg}" != -* ]]; then
    dx_command="${arg}"
  fi
done

# dx can repeatedly rebuild in release mode when Cargo.lock churns under local patch
# overlays. Default release runs to a stable one-shot build unless --watch was set.
if [[ "${dx_command}" == "serve" && ${has_release} -eq 1 && ${has_watch} -eq 0 ]]; then
  dx_args+=("--watch=false")
fi

exec dx "${dx_args[@]}" --cargo-args="--config=${config_path}"
