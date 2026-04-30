#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

allow_local_deps="${FASTBOOP_ALLOW_LOCAL_DEPS:-false}"
case "${allow_local_deps}" in
  true | 1 | yes)
    allow_local_deps=true
    ;;
  false | 0 | no | "")
    allow_local_deps=false
    ;;
  *)
    printf 'invalid FASTBOOP_ALLOW_LOCAL_DEPS value: %s\n' "${allow_local_deps}" >&2
    exit 1
    ;;
esac

roots=()
missing_roots=()
for name in gibblox smoo; do
  if [[ -e "${repo_root}/${name}" ]]; then
    roots+=("${name}")
    if [[ ! -f "${repo_root}/${name}/Cargo.toml" ]]; then
      missing_roots+=("${name}")
    fi
  fi
done

cargo_cmd="cargo"
dx_cmd="dx"

if [[ ${#roots[@]} -gt 0 ]]; then
  if [[ "${allow_local_deps}" != true ]]; then
    printf 'local dependency checkout(s) are only allowed in draft PR CI: %s\n' "${roots[*]}" >&2
    exit 1
  fi

  if [[ ${#missing_roots[@]} -gt 0 ]]; then
    printf 'local dependency checkout(s) missing Cargo.toml: %s\n' "${missing_roots[*]}" >&2
    exit 1
  fi

  cargo_cmd="./tools/cargo-local.sh"
  dx_cmd="./tools/dx-local.sh"
  printf 'using local dependency checkout(s): %s\n' "${roots[*]}"
else
  printf 'no local dependency checkouts detected\n'
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    printf 'FASTBOOP_CARGO=%s\n' "${cargo_cmd}"
    printf 'FASTBOOP_DX=%s\n' "${dx_cmd}"
  } >> "${GITHUB_ENV}"
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    printf 'cargo=%s\n' "${cargo_cmd}"
    printf 'dx=%s\n' "${dx_cmd}"
    printf 'using_local=%s\n' "$([[ ${#roots[@]} -gt 0 ]] && printf true || printf false)"
  } >> "${GITHUB_OUTPUT}"
fi
