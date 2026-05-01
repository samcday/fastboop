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

if [[ "${1:-}" == "clippy" ]]; then
  cargo clippy --config "${config_path}" "${@:2}"
else
  cargo --config "${config_path}" "$@"
fi
