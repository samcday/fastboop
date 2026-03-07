#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

if [[ ! -f "${repo_root}/gibblox/Cargo.toml" ]]; then
  echo "missing ./gibblox checkout/worktree" >&2
  echo "create it first (for example: git clone https://github.com/samcday/gibblox ./gibblox)" >&2
  exit 1
fi

exec cargo --config "${repo_root}/.cargo/config.gibblox-local.toml" "$@"
