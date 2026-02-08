# fastboop agent guide

fastboop is a non-mutating live-boot pipeline for phones and pocket computers that expose vendor USB boot mode (v0: fastboot RAM boot). It does not flash and it does not manage install policy. fastboop identifies the device with DevPro rules, builds a stage0 payload from upstream rootfs artifacts, boots that payload ephemerally, then hands runtime storage/export plumbing to smoo so the device can continue into full userspace. gibblox is the rootfs/artifact access layer that lets this happen without repacking distro images.

## Session start (required)
- Read `AGENTS.md`.
- Read `HACKING.md`.
- Then read only the docs relevant to the task from the index below.

## Read-on-demand index
- `docs/DEVICE_PROFILES.md`: DevPro schema, matching/probing semantics, boot constraints.
- `docs/STAGE0.md`: stage0 contract, PID1 flow, handoff behavior.
- `docs/DIOXUS.md`: Dioxus 0.7 usage in `packages/*`.
- `smoo/AGENTS.md`: required when touching `smoo/` or behavior coupled to smoo protocol/runtime invariants.
- `gibblox/AGENTS.md`: required when touching `gibblox/` or any `gibblox-*` crate integration.
- Cross-domain changes must include all relevant docs before editing.

## Minimal working rules
- Keep diffs focused and reviewable.
- Preserve non-mutating behavior (no flash/erase/format/slot toggles/unlock paths).
- Keep platform-agnostic logic in core crates and platform bindings in leaf crates.
- Prefer async-first code; justify blocking paths.
- Use `tracing` for new operationally relevant behavior.

## Validation
- For non-trivial code changes, run the standard checks listed in `HACKING.md` and report what was run.
- If a required check is skipped or fails, state it explicitly and why.

## Priority
- User direction wins.
- If this file conflicts with user direction, follow the user and call out the deviation.
