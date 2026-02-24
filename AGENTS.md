# fastboop agent guide

fastboop is a non-mutating live-boot pipeline for phones and pocket computers that expose vendor USB boot mode (v0: fastboot RAM boot). It does not flash and it does not manage install policy. fastboop identifies the device with DevPro rules, builds a stage0 payload from upstream rootfs artifacts, boots that payload ephemerally, then hands runtime storage/export plumbing to smoo so the device can continue into full userspace. gibblox is the rootfs/artifact access layer that lets this happen without repacking distro images.

## Session start (required)
- Read `AGENTS.md`.
- Read `HACKING.md`.
- If the task touches `infra/k8s/` or any `*.fastboop.win` infrastructure, read `docs/k8s-infra.yaml`.
- Then read only the docs relevant to the task from the index below.

## Read-on-demand index
- `docs/DEVICE_PROFILES.md`: DevPro schema, matching/probing semantics, boot constraints.
- `docs/STAGE0.md`: stage0 contract, PID1 flow, handoff behavior.
- `docs/DIOXUS.md`: Dioxus 0.7 usage in `packages/*`.
- `docs/k8s-infra.yaml`: required when touching `infra/k8s/` or any `*.fastboop.win` infrastructure.
- `smoo/AGENTS.md`: required when touching `smoo/` or behavior coupled to smoo protocol/runtime invariants.
- `gibblox/AGENTS.md`: required when touching `gibblox/` or any `gibblox-*` crate integration.
- Cross-domain changes must include all relevant docs before editing.

## Minimal working rules
- Keep diffs focused and reviewable.
- Preserve non-mutating behavior (no flash/erase/format/slot toggles/unlock paths).
- Keep platform-agnostic logic in core crates and platform bindings in leaf crates.
- Strict `no_std + alloc` boundary (do not introduce `std` unless user explicitly asks):
  - `crates/fastboop-core`
  - `crates/fastboop-schema` (no-std path)
  - `crates/fastboop-stage0-generator` (no-std path)
  - `smoo/crates/smoo-proto`
  - `smoo/crates/smoo-host-core`
  - `smoo/crates/smoo-host-session`
  - `gibblox/crates/gibblox-core`
  - `gibblox/crates/gibblox-cache`
  - `gibblox/crates/gibblox-iso9660`
  - and any crate declaring `#![no_std]` or `#![cfg_attr(not(feature = "std"), no_std)]`
- Prefer async-first code; justify blocking paths.
- Use `tracing` for new operationally relevant behavior.

## Validation
- Follow the tiered validation policy in `HACKING.md`.
- Run path-triggered checks for touched areas during development.
- Run the full end-of-session gate for substantial changes.
- `dx build -p fastboop-web` is required when `packages/web` is touched.
- If a required check is skipped or fails, state it explicitly and why.

## Priority
- User direction wins.
- If this file conflicts with user direction, follow the user and call out the deviation.
