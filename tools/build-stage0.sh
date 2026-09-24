#!/usr/bin/env bash
# Build the static fastboop-stage0 payload for one target triple.
#
# This is the one stage0 build recipe shared by CI, distro packaging and local
# development. See docs/dev/STAGE0_DISTRIBUTION.md.
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: tools/build-stage0.sh [--target TRIPLE] [--out PATH] [-- CARGO_ARGS...]

Build fastboop-stage0 as a locked, static release binary for TRIPLE, verify
that the result is a static ELF for the target machine, optionally copy it to
PATH, and print the path of the verified binary on stdout.

Options:
  --target TRIPLE  Rust target triple. Defaults to $FASTBOOP_STAGE0_TARGET,
                   else aarch64-unknown-linux-musl.
  --out PATH       Copy the verified binary to PATH. An existing directory, or
                   a PATH ending in /, receives fastboop-stage0-TRIPLE.
                   Defaults to $FASTBOOP_STAGE0_OUT; unset means no copy.
  -- CARGO_ARGS    Extra arguments for cargo build, for example --frozen.

Environment:
  CARGO, RUSTC, READELF  Tools to run (default: cargo, rustc, readelf).
  CARGO_TARGET_DIR       Honoured as usual by cargo.
  CARGO_TARGET_<TRIPLE>_LINKER
                         Linker for TRIPLE (default: rust-lld).
EOF
}

log() {
    echo "==> $*" >&2
}

die() {
    echo "error: $*" >&2
    exit 1
}

target="${FASTBOOP_STAGE0_TARGET:-aarch64-unknown-linux-musl}"
out="${FASTBOOP_STAGE0_OUT:-}"
cargo_args=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            [[ $# -ge 2 ]] || die "--target needs a value"
            target="$2"
            shift 2
            ;;
        --target=*)
            target="${1#--target=}"
            shift
            ;;
        --out)
            [[ $# -ge 2 ]] || die "--out needs a value"
            out="$2"
            shift 2
            ;;
        --out=*)
            out="${1#--out=}"
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            cargo_args=("$@")
            break
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

[[ -n "$target" ]] || die "target triple is empty"

case "$target" in
    aarch64-*) expected_machine="AArch64" ;;
    x86_64-*) expected_machine="Advanced Micro Devices X86-64" ;;
    i?86-*) expected_machine="Intel 80386" ;;
    arm-* | armv*-* | thumbv*-*) expected_machine="ARM" ;;
    riscv32*-* | riscv64*-*) expected_machine="RISC-V" ;;
    *) die "no ELF machine known for target $target; extend tools/build-stage0.sh" ;;
esac

# Resolve --out against the caller's directory before moving to the workspace.
if [[ -n "$out" && "$out" != /* ]]; then
    out="$PWD/$out"
fi

cargo="${CARGO:-cargo}"
rustc="${RUSTC:-rustc}"
readelf="${READELF:-readelf}"

command -v "$readelf" >/dev/null || die "$readelf not found; install binutils or set READELF"

# Run from the workspace root so rust-toolchain.toml and .cargo/config.toml apply.
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$repo_root"

target_list="$("$rustc" --print target-list)"
grep -Fxq -- "$target" <<<"$target_list" || die "$rustc does not know target $target"

target_env="${target^^}"
target_env="${target_env//[-.]/_}"
linker_var="CARGO_TARGET_${target_env}_LINKER"
rustflags_var="CARGO_TARGET_${target_env}_RUSTFLAGS"
crt_static="-C target-feature=+crt-static"
unit_sep=$'\x1f'

export "${linker_var}=${!linker_var:-rust-lld}"

# Cargo takes rustflags from the first source that is set, even if empty:
# CARGO_ENCODED_RUSTFLAGS, then RUSTFLAGS, then target.<triple>.rustflags
# (which CARGO_TARGET_<TRIPLE>_RUSTFLAGS feeds). Append crt-static to the source
# that is in effect so it is not silently dropped, for example when CI exports
# RUSTFLAGS.
if [[ -v CARGO_ENCODED_RUSTFLAGS ]]; then
    CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS:+$CARGO_ENCODED_RUSTFLAGS$unit_sep}${crt_static// /$unit_sep}"
    export CARGO_ENCODED_RUSTFLAGS
    rustflags_source="CARGO_ENCODED_RUSTFLAGS"
elif [[ -v RUSTFLAGS ]]; then
    export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }$crt_static"
    rustflags_source="RUSTFLAGS"
else
    export "${rustflags_var}=${!rustflags_var:+${!rustflags_var} }$crt_static"
    rustflags_source="$rustflags_var"
fi

log "building fastboop-stage0 for $target"
log "$linker_var=${!linker_var}"
log "$rustflags_source=${!rustflags_source//$unit_sep/ }"
"$cargo" build \
    -p fastboop-stage0 \
    --release \
    --target "$target" \
    --locked \
    ${cargo_args[@]+"${cargo_args[@]}"}

metadata="$("$cargo" metadata --format-version 1 --no-deps --locked)"
target_dir="$(sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' <<<"$metadata")"
[[ -n "$target_dir" ]] || die "could not read target_directory from cargo metadata"
bin="$target_dir/$target/release/fastboop-stage0"

log "verifying $bin"
[[ -s "$bin" ]] || die "$bin is missing or empty"
if command -v file >/dev/null; then
    file "$bin" >&2
fi

header="$(LC_ALL=C "$readelf" -hW "$bin")" || die "$bin is not a readable ELF file"
elf_type="$(sed -n 's/^[[:space:]]*Type:[[:space:]]*\([A-Z]*\).*/\1/p' <<<"$header")"
case "$elf_type" in
    EXEC | DYN) ;;
    *) die "$bin has ELF type '$elf_type', expected an executable" ;;
esac
machine="$(sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p' <<<"$header")"
[[ "$machine" == "$expected_machine" ]] ||
    die "$bin is for machine '$machine', expected '$expected_machine'"

program_headers="$(LC_ALL=C "$readelf" -lW "$bin")"
if grep -Eq '^[[:space:]]*INTERP[[:space:]]' <<<"$program_headers"; then
    die "$bin has a PT_INTERP program header; it is dynamically linked"
fi
dynamic="$(LC_ALL=C "$readelf" -dW "$bin")"
if grep -F '(NEEDED)' <<<"$dynamic" >&2; then
    die "$bin needs the shared libraries listed above"
fi
log "static $elf_type ELF for $machine, no PT_INTERP, no DT_NEEDED"

result="$bin"
if [[ -n "$out" ]]; then
    if [[ -d "$out" || "$out" == */ ]]; then
        out="${out%/}/fastboop-stage0-$target"
    fi
    mkdir -p -- "$(dirname -- "$out")"
    cp -- "$bin" "$out"
    result="$out"
fi

printf '%s\n' "$result"
