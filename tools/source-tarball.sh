#!/usr/bin/env bash
# Build a reproducible, self-contained source tarball of the fastboop checkout in
# the current directory: the superproject's HEAD plus every (nested) submodule at
# the commit recorded by its superproject. GitHub's generated archives omit
# submodules, which the workspace's [patch.crates-io] table needs to build.
#
# Output: <outdir>/fastboop-<version>-src.tar.gz, rooted at fastboop-<version>/.
# The archive contents come only from commits (uncommitted changes are ignored),
# and file order, mtime (HEAD's committer date), owner and modes are normalized,
# so the same commit always yields the same bytes with the same tar and gzip.
set -euo pipefail

usage() {
    echo "usage: $0 <version> <outdir>" >&2
    exit 2
}

die() {
    echo "error: $*" >&2
    exit 1
}

if [[ $# -ne 2 ]]; then
    usage
fi

version="$1"
outdir="$2"
if [[ ! "$version" =~ ^[0-9A-Za-z][0-9A-Za-z._+~-]*$ ]]; then
    die "invalid version '$version'"
fi
if [[ "$(tar --version 2>/dev/null)" != *"GNU tar"* ]]; then
    die "GNU tar is required for reproducible archives"
fi

export LC_ALL=C
umask 022

mkdir -p -- "$outdir"
outdir="$(cd -- "$outdir" && pwd)"
repo_root="$(git rev-parse --show-toplevel)"
cd -- "$repo_root"

# '-' uninitialized, '+' checkout differs from the recorded commit, 'U' conflicted.
submodule_status="$(git submodule status --recursive)"
if bad="$(grep -E '^[-+U]' <<<"$submodule_status")"; then
    printf '%s\n' "$bad" >&2
    die "every submodule must be initialized and checked out at its recorded commit (git submodule update --init --recursive)"
fi

name="fastboop-${version}"
tarball="${outdir}/${name}-src.tar.gz"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
stage="$work/stage"
mkdir -- "$stage"

# git archive honors export-ignore from each archived commit's .gitattributes.
archive() {
    local repo="$1" commit="$2" prefix="$3"
    git -C "$repo" -c core.autocrlf=false archive --format=tar --prefix="$prefix" "$commit" \
        | tar -xf - -C "$stage"
}

archive "$repo_root" HEAD "${name}/"

# $sha1 comes from the superproject's index; require it to match the committed
# gitlink so that a staged but uncommitted submodule bump cannot leak in.
# NUL-separated records: displaypath, sha1, toplevel, sm_path.
# shellcheck disable=SC2016 # expanded by the shell git submodule foreach runs
git submodule --quiet foreach --recursive \
    'printf "%s\0%s\0%s\0%s\0" "$displaypath" "$sha1" "$toplevel" "$sm_path"' \
    >"$work/submodules"
mapfile -d '' -t records <"$work/submodules"
for ((i = 0; i < ${#records[@]}; i += 4)); do
    displaypath="${records[i]}"
    sha1="${records[i + 1]}"
    toplevel="${records[i + 2]}"
    sm_path="${records[i + 3]}"
    recorded="$(git -C "$toplevel" rev-parse --verify --quiet "HEAD:${sm_path}")" \
        || die "submodule $displaypath is not recorded in the committed tree"
    if [[ "$recorded" != "$sha1" ]]; then
        die "submodule $displaypath is staged at $sha1 but committed at $recorded"
    fi
    echo "==> $displaypath @ $sha1" >&2
    archive "$repo_root/$displaypath" "$sha1" "${name}/${displaypath}/"
done

# git archive writes each gitlink as an empty directory, and git cannot track
# other empty directories, so any left over is a submodule that was not filled.
empty="$(find "$stage" -type d -empty -print)"
if [[ -n "$empty" ]]; then
    printf '%s\n' "${empty//"$stage/"/}" >&2
    die "unpopulated submodule directories in the source tree"
fi

mtime="$(git show --no-patch --format=%ct HEAD)"
tar --create --file=- --directory="$stage" \
    --format=posix --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    --sort=name --mtime="@${mtime}" --owner=0 --group=0 --numeric-owner --mode=u=rwX,go=rX \
    -- "$name" \
    | gzip -9 -n >"$work/out.tar.gz"
mv -f -- "$work/out.tar.gz" "$tarball"
printf '%s\n' "$tarball"
