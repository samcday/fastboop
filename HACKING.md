# fastboop hacking notes

This file is for contributors. It captures architecture and operational details that do not belong in the human-facing `README.md`.

## Project shape

At a high level, fastboop:

1. Detects devices in supported vendor boot modes (currently fastboot flow in v0).
2. Matches/probes them using DevPro (`docs/dev/DEVICE_PROFILES.md`).
3. Consumes an unmodified rootfs artifact.
4. Synthesizes stage0 (`/init`) with BootProfile/CLI-provided kernel/module glue.
5. Boots ephemerally into RAM via vendor bootloader.

No flashing, no slot changes, no persistent writes.

## Architecture defaults

- Core traits/types live in `crates/fastboop-core` and are allocator-aware and cancellation-safe.
- Device/profile/state-machine logic stays platform-agnostic.
- Transport/adapters live in platform crates (`fastboot-rusb`, `fastboot-webusb`, desktop/web packages).
- Stage0 assembly lives in std crates; `fastboop-stage0` embeds `smoo-gadget-app` and launches it during PID1 flow.
- Protocol/type behavior must remain aligned with smoo invariants.

## Stage0 (current behavior)

Stage0 details are normative in `docs/dev/STAGE0.md`; this is the short operational view:

- PID1 is `fastboop-stage0`.
- Stage0 mounts core virtual filesystems and loads required modules.
- Stage0 configures gadget/FunctionFS and starts embedded `smoo-gadget-app` as a child process.
- Stage0 waits for exported block device, mounts lower EROFS + upper tmpfs overlay.
- Stage0 switches root and execs distro init (`/lib/systemd/systemd` or `/sbin/init`).

If gadget runtime fails before handoff, stage0 fails loudly.

## DevPro and boot constraints

- DevPro describes how to safely boot a device, not distro policy.
- BootProfile describes image-specific stage0 requirements such as kernel modules and MAC injection.
- Probe commands are read-only.
- Non-mutating invariant is hard: no flash/erase/format/set_active/oem/unlock flows.
- v0 supports one boot mechanism per profile.

See `docs/dev/DEVICE_PROFILES.md` for schema and semantics.

## Workspace map

- `cli/`: CLI entrypoints (`detect`, `stage0`, `boot`).
- `stage0/`: stage0 PID1 runtime binary.
- `crates/fastboop-stage0-generator/`: stage0 image synthesis.
- `crates/fastboop-core/`: core model/state-machine traits.
- `packages/*`: desktop/web/mobile/ui frontends.
- `devprofiles.d/`: device profile definitions.
- `smoo/`: checked-in smoo submodule used for development snapshot builds.
- `gibblox/`: checked-in gibblox submodule used for development snapshot builds.

Development builds intentionally use the checked-in `gibblox` and `smoo`
submodules via the root `[patch.crates-io]` table. After cloning fastboop, make
sure submodules are present:

```sh
git submodule update --init --recursive
cargo check --workspace --exclude fastboop-web
```

The versioned dependency declarations still describe the crates.io release
contract, but day-to-day fastboop CI and development use the pinned submodule
snapshots. Update the submodule pins and root patch table together when adding
or removing gibblox/smoo crates from the fastboop graph.

## Preparing a release version

Run `cargo xtask bump <X.Y.Z[-rc.N]>` from the workspace and review the diff
before opening a release PR. The command updates the shared Cargo version,
version requirements for path dependencies on members inheriting that version,
and the workspace lockfile. Cargo workspace membership bounds the changes;
excluded submodules and vendored manifests are not rewritten.

RPM and Debian use `X.Y.Z~rcN`, while Alpine uses `X.Y.Z_rcN` (with the existing
`_git` development suffix, removed by tag packaging). Source and asset URLs use
the separate upstream version `X.Y.Z-rc.N`. Alpine CI overrides the source ref
with the commit under test for development builds.

The bump prepends a dated Debian changelog entry using the existing maintainer
identity. Repeating the same version leaves that entry and its date unchanged.
This command prepares version metadata only; dependency publication, packaged
content verification, and distro build checks remain separate release gates.

`cargo xtask publish-dry-run` packages all publishable workspace crates together
with `cargo package --locked` and compiles their packaged contents. Cargo stages
unpublished sibling crates in a temporary registry; external dependencies must
be available from the registry. The script does not inject Cargo config patches
or skip verification. It also reads `Cargo.lock` directly from the CLI's `.crate`
archive and rejects non-crates.io dependencies, version drift from the workspace
lock, and changed registry checksums. The CLI itself is the only source-less
package allowed in its archive's lockfile.

Both dry-run and live publication run this preflight before any upload. Release
planning includes only packages allowed on crates.io, and packaging and uploads
explicitly select crates.io even if the caller configured another default registry.
Release CI starts the dry-run independently of distro packaging and requires it before
publishing the GitHub release. Until upstream dependencies are released and the
manifests point at them, a failed preflight is an outstanding release blocker.

For rc.22, desktop and Flatpak delivery are out of scope. Release CI excludes
`fastboop-desktop` from Cargo check/Clippy/tests and skips its Dioxus build;
ordinary development CI still checks it. Flatpak remains available through its
standalone workflow, but is neither required nor attached to releases.

Tag releases stage assets on a draft, publish crates to crates.io, and only then
make the GitHub release public and advance the live web version. An upload
failure leaves the GitHub release in draft; crates already uploaded cannot be
rolled back, and the publish script skips them on retry. Release PRs rehearse
asset assembly and verified packaging without publishing either crates or a
GitHub release.

The scripts require Python 3.11+ for `tomllib`. Run their regression suite with
`python3 -m unittest discover -s tools/tests -v`. Tests package small temporary
workspaces with the repository's Rust toolchain and may read the crates.io index;
they never upload crates. This includes verifying that a Cargo config patch
cannot hide a local dependency in the packaged CLI lockfile.

## Contributor workflow

- Read `AGENTS.md` and use its read-on-demand doc index.
- Keep diffs small and reviewable.
- Prefer async-first and avoid blocking unless justified.
- Keep logic crates `no_std + alloc`; isolate platform bindings to leaf crates.
- Use `tracing` for observability.

## Validation policy (tiered)

Use cheap checks continuously and reserve broad gates for the end of substantial work.

### Tier 0 (always, cheap)

- `cargo fmt`
- targeted `cargo check` for touched crate(s)

### Tier 1 (path-triggered during development)

Run checks based on changed paths:

- `packages/web/**` -> `dx build -p fastboop-web` (required)
- `packages/desktop/**` -> `dx build -p fastboop-desktop`
- `packages/mobile/**` or `packages/ui/**` -> run relevant package build/check
- `stage0/**` or `crates/fastboop-stage0-generator/**` -> targeted `cargo check` + relevant tests
- `cli/**` -> targeted `cargo check` + relevant tests
- `crates/**` core/schema/transport changes -> targeted checks for affected crates and dependents

### Tier 2 (end-of-session gate for substantial changes)

Run before handing off substantial work:

```sh
cargo fmt
cargo check --workspace
cargo clippy --workspace
cargo test --workspace
dx build -p fastboop-desktop
```

Also run `dx build -p fastboop-web` if `packages/web` was touched.

### Environmental failure handling

If a required check fails due to infrastructure/tooling instability (for example context/API errors from `dx`), do this:

1. retry once;
2. if it fails again with a non-code error signature, stop retrying;
3. report the check as blocked by environment and call out that verification is still required in a fresh session/CI.

### Reporting

- Report what was run and final pass/fail state.
- If any required check is skipped or blocked, state it explicitly and why.
