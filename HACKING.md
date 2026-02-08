# fastboop hacking notes

This file is for contributors. It captures architecture and operational details that do not belong in the human-facing `README.md`.

## Project shape

At a high level, fastboop:

1. Detects devices in supported vendor boot modes (currently fastboot flow in v0).
2. Matches/probes them using DevPro (`docs/DEVICE_PROFILES.md`).
3. Consumes an unmodified rootfs artifact.
4. Synthesizes stage0 (`/init`) with required kernel/modules glue.
5. Boots ephemerally into RAM via vendor bootloader.

No flashing, no slot changes, no persistent writes.

## Architecture defaults

- Core traits/types live in `crates/fastboop-core` and are allocator-aware and cancellation-safe.
- Device/profile/state-machine logic stays platform-agnostic.
- Transport/adapters live in platform crates (`fastboot-rusb`, `fastboot-webusb`, desktop/web packages).
- Stage0 assembly lives in std crates; `fastboop-stage0` embeds `smoo-gadget-app` and launches it during PID1 flow.
- Protocol/type behavior must remain aligned with smoo invariants.

## Stage0 (current behavior)

Stage0 details are normative in `docs/STAGE0.md`; this is the short operational view:

- PID1 is `fastboop-stage0`.
- Stage0 mounts core virtual filesystems and loads required modules.
- Stage0 configures gadget/FunctionFS and starts embedded `smoo-gadget-app` as a child process.
- Stage0 waits for exported block device, mounts lower EROFS + upper tmpfs overlay.
- Stage0 switches root and execs distro init (`/lib/systemd/systemd` or `/sbin/init`).

If gadget runtime fails before handoff, stage0 fails loudly.

## DevPro and boot constraints

- DevPro describes how to safely boot a device, not distro policy.
- Probe commands are read-only.
- Non-mutating invariant is hard: no flash/erase/format/set_active/oem/unlock flows.
- v0 supports one boot mechanism per profile.

See `docs/DEVICE_PROFILES.md` for schema and semantics.

## Workspace map

- `cli/`: CLI entrypoints (`detect`, `stage0`, `boot`).
- `stage0/`: stage0 PID1 runtime binary.
- `crates/fastboop-stage0-generator/`: stage0 image synthesis.
- `crates/fastboop-core/`: core model/state-machine traits.
- `packages/*`: desktop/web/mobile/ui frontends.
- `devprofiles.d/`: device profile definitions.
- `smoo/`, `gibblox/`: sibling subtrees with their own agent docs.

## Contributor workflow

- Read `AGENTS.md` and use its read-on-demand doc index.
- Keep diffs small and reviewable.
- Prefer async-first and avoid blocking unless justified.
- Keep logic crates `no_std + alloc`; isolate platform bindings to leaf crates.
- Use `tracing` for observability.

Before finishing substantial code changes, run:

```sh
cargo fmt
cargo check --workspace
cargo clippy --workspace
cargo test --workspace
dx build -p fastboop-desktop
dx build -p fastboop-web
```

If any step is skipped, explain why.
