#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

roots=()
for name in gibblox smoo; do
  if [[ -f "${repo_root}/${name}/Cargo.toml" ]]; then
    roots+=("${name}")
  fi
done

if [[ ${#roots[@]} -eq 0 ]]; then
  cat >&2 <<EOF
no local checkouts found; expected at least one of ./gibblox or ./smoo at ${repo_root}
create one or both first, for example:
  git clone https://github.com/samcday/gibblox ${repo_root}/gibblox
  git clone https://github.com/samcday/smoo ${repo_root}/smoo
EOF
  exit 1
fi

temp_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "${temp_dir}"
}
trap cleanup EXIT

real_cargo="$(command -v cargo)"

config_path="${temp_dir}/config.local.toml"
{
  echo "[patch.crates-io]"
  for name in "${roots[@]}"; do
    link_root="${temp_dir}/${name}"
    ln -s "${repo_root}/${name}" "${link_root}"
    for crate_toml in "${link_root}"/crates/*/Cargo.toml; do
      [[ -f "${crate_toml}" ]] || continue
      crate_dir="$(dirname "${crate_toml}")"
      crate_name="$(basename "${crate_dir}")"
      echo "${crate_name} = { path = \"${crate_dir}\" }"
    done
  done
} > "${config_path}"

export FASTBOOP_STAGE0_CARGO="${repo_root}/tools/cargo-local.sh"

# Pre-resolve workspace metadata with the local overlay before dx starts
# watching the tree, so Cargo.lock churn doesn't immediately trigger a rebuild.
"${repo_root}/tools/cargo-local.sh" metadata --format-version=1 --no-deps >/dev/null

wrapper_dir="${temp_dir}/bin"
mkdir -p "${wrapper_dir}"
cat > "${wrapper_dir}/cargo" <<EOF
#!/usr/bin/env bash
exec "${real_cargo}" --config "${config_path}" "\$@"
EOF
chmod +x "${wrapper_dir}/cargo"
export PATH="${wrapper_dir}:${PATH}"

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
