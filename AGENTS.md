# fastboop — session ground rules

This file keeps Codex sessions fast and predictable. Read it before coding.

## Roles
- **Developer**: the human user setting direction, approving designs, making commits.
- **ChatGPT**: refines prompts/designs, spots risks; keeps code snippets small.
- **Codex**: writes code/diffs, keeps builds green, follows this file.

## Kickoff checklist (each session)
- Read `AGENTS.md`, `README.md`, `docs/*.md` and skim `smoo/HACKING.md` for protocol invariants shared with smoo.
- Confirm workspace layout (`crates/*`) and no-std expectations for core logic crates.
- Use `rustfmt --edition 2021`; prefer async-first; avoid blocking unless justified.
- Target stable Rust (MSRV 1.88) and keep code `cargo build --workspace --locked` clean.
- Keep logic crates no_std + `alloc`; isolate std/platform bindings in leaf crates (CLI/web/host tooling).

## Architectural defaults
- Core traits/types live in `fastboop-core` and `fastboop-transport`; they must be allocator-aware and cancellation-safe.
- Device/profile/state-machine logic stays platform-agnostic; transports/adapters (fastboot, WebUSB, desktop libusb) live in std/wasm crates.
- Stage0 assembly lives in std crates; fastboop-stage0 embeds `smoo-gadget-app` directly, while protocol/types must stay aligned with smoo.
- Logging via `tracing`; tests should mock transports and preserve `(export_id, request_id)` discipline from smoo.

## Output expectations
- Prefer small, reviewable diffs; add brief rationale in the PR/commit message body when applicable.
- Unless explicitly impossible, do not end a turn without running and passing `cargo fmt`, `cargo check --workspace`, `cargo clippy --workspace`, and `cargo test --workspace` (or explaining why it failed/was skipped).
- Desktop + web builds must pass: `dx build -p fastboop-desktop` and `dx build -p fastboop-web`.
- Avoid introducing new tools/dependencies without a short justification and a confirmation from the Developer.
- If instructions in this file conflict with user directions, ask for clarification before proceeding.
