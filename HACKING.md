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
- `smoo-*` crates: consumed from crates.io (see upstream smoo docs for internals).
- `gibblox-*` crates: consumed from crates.io (see upstream gibblox docs for internals).

For local integration work across gibblox and/or smoo, clone either (or both) into
the repo root and run `./tools/cargo-local.sh ...`:

```sh
git clone https://github.com/samcday/gibblox ./gibblox
git clone https://github.com/samcday/smoo    ./smoo
./tools/cargo-local.sh check --workspace --exclude fastboop-web
```

The script discovers every `<root>/crates/*/Cargo.toml` it finds and emits a
`[patch.crates-io]` overlay fed to cargo via `--config`, so new gibblox/smoo
crates get picked up automatically without editing this repo. At least one of
`./gibblox` or `./smoo` must exist; either may be absent (the missing side
resolves from crates.io as usual). Workspace manifests and `Cargo.lock` are not
mutated.

For Dioxus commands that shell out to cargo, use `./tools/dx-local.sh ...` so
`dx` receives the overlay too (it also exports `FASTBOOP_STAGE0_CARGO` so the
stage0 nested build inherits the same patches).

For IDE integrations or direct invocations that want a static file, pass
`--config .cargo/config.local.toml` to cargo. Keep that file in sync with the
set of crates actually published by gibblox and smoo.

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
