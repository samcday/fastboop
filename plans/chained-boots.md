# Chained Boots Plan (v0)

## Goal

Add first-class chained boot support so a Boot Profile can perform one non-terminal
fastboot "hop" (for example, vendor ABL -> aftermarket U-Boot) before continuing
into the normal stage0/rootfs boot flow.

The design should keep concerns clean:

- DevPro = current bootloader persona detection + safe boot constraints.
- Boot Profile = distro/channel policy for what to boot next.

This lets one physical device have multiple DevPros (vendor and aftermarket), with channel
policy choosing whether to chain through an intermediate bootloader.

## Why This Exists

- Some vendor bootloaders accept `download` but reject direct Linux boot payloads (`Volume Corrupt`).
- U-Boot is already known to work on affected hardware, so the simplest path is to boot U-Boot first,
  then continue from the new bootloader persona.
- A full "U-Boot boots Linux FIT from fastboot ramdisk" approach adds complexity and can still run into
  initrd-size constraints on picky bootloaders.

## Non-Goals (v0)

- No flashing, formatting, slot changes, or unlock flows.
- No local U-Boot build orchestration in fastboop.
- No full-auto web chaining (browser pairing/permission model does not allow it).
- No cross-tab/multi-origin sharedworker session sharing in this pass.

## Model

### Device Profiles (DevPro)

Do not add launch-mode policy to DevPro.

Instead, support separate DevPros for separate observed bootloader personas on the same hardware,
for example:

- `google-sargo-abl`
- `google-sargo-uboot`

Each DevPro remains factual: USB match/probe rules, fastboot bootimg constraints,
and stage0 hints for that specific persona.

### Boot Profiles

Add explicit non-terminal chain behavior to Boot Profiles.

Proposed shape (illustrative):

```yaml
id: sargo-vendor-hop
display_name: Sargo vendor -> U-Boot hop

chain:
  payload:
    xz:
      http: https://example.invalid/u-fastboop/sargo/u-boot-nodtb.bin.gz.xz
  next_device_profile: google-sargo-uboot
  next_boot_profile: sargo-live
```

Semantics:

- `chain` is a top-level non-terminal mode.
- `payload` is a raw artifact source resolved through gibblox pipeline layers.
- `next_device_profile` is required and tells fastboop what to wait for after the hop.
- `next_boot_profile` is required and identifies the exact profile to run after the hop.
- If `chain` is present, `rootfs`, `kernel`, and `dtbs` must be absent.

Terminal profiles keep existing behavior (stage0/rootfs boot and smoo host lifecycle)
and continue to use `rootfs` with optional `kernel`/`dtbs` overrides.

## Runtime Contract

For a chain step:

1. Resolve chain payload bytes via existing artifact resolver.
2. Build a boot image using the current DevPro bootimg constraints:
   - kernel = chain payload bytes
   - ramdisk = empty
   - dtb handling follows current DevPro kernel encoding rules (append or header dtb)
3. `fastboot download` + `fastboot boot`.
4. Do not start smoo host.
5. Transition session state to "waiting for next device profile".
6. Continue boot flow only when the `next_device_profile` appears.

Terminal step is the existing stage0 path and ends in normal smoo host serving.

## End-to-End Flow (CLI/Desktop)

1. Detect/probe initial device as today.
2. Select compatible Boot Profile as today.
3. If profile is terminal: unchanged flow.
4. If profile is chain:
   - execute chain fastboot hop,
   - switch expected DevPro to `next_device_profile`,
   - require `next_boot_profile` for the resumed selection,
   - loop back to waiting/probing.
5. Allow at most one chain step; if the next selected profile is also chain, fail with
   an explicit depth-limit error.

Guardrails:

- max chain depth = 1 (single-hop chaining only)
- explicit errors for missing `next_device_profile`, missing `next_boot_profile`, or
  unresolved `next_boot_profile`

## Web UX Contract (v0)

Web cannot be fully automatic across chained personas because the browser may require
user gesture and pairing for the next USB identity.

Add an explicit chained-boot waiting UI state:

- show that a chain hop completed,
- show expected next DevPro ID,
- instruct user to reconnect/pair the next device,
- provide a "Pair next device" action,
- continue automatically once the expected profile is detected.

Notes:

- If the next USB device is already authorized, watcher events may resolve it without extra action.
- If not authorized, user interaction is required.
- This state is required groundwork for future advanced web/session ideas.

## Implementation Workstreams

### 1) Schema + Codec

- `crates/fastboop-schema/src/lib.rs`
  - add top-level `chain` mode alongside `rootfs`/`kernel`/`dtbs`
  - add chain payload + next-profile fields
  - enforce mutual exclusion: `chain` vs `rootfs`/`kernel`/`dtbs`
- `crates/fastboop-schema/src/bin.rs`
  - encode/decode new fields
  - bump boot profile binary format version
- `crates/fastboop-core/src/bootprofile.rs`
  - validate chain profile invariants
  - require non-empty `next_boot_profile`
  - validate chain payload pipeline source

### 2) CLI Chain State Machine

- `cli/src/commands/boot.rs`
  - refactor single-pass boot into a loop that can execute chain then continue
  - add phase/event for waiting on next chained device
  - resolve/select `next_boot_profile` explicitly after chained-device detection
  - skip stage0/smoo host during chain steps
- `cli/src/boot_ui.rs`
  - add boot phase label for chained-device wait state

### 3) Artifact Resolution Plumbing

- `cli/src/commands/mod.rs`
  - add helper(s) to resolve chain payload source bytes via `open_artifact_source()`
  - keep existing rootfs/kernel/dtbs override path unchanged for terminal profiles

### 4) Desktop/Web Session Phases

- `packages/desktop/src/views/session.rs`
- `packages/web/src/views/session.rs`
  - add a session phase representing chained wait state + expected next DevPro
- `packages/desktop/src/views/device_boot.rs`
- `packages/web/src/views/device_boot.rs`
  - execute chain step and transition to new phase
  - resume flow when expected next device is detected
- `packages/web/src/views/device.rs`
  - render dedicated chained waiting screen and pairing action

### 5) Docs

- `docs/dev/BOOT_PROFILES.md`
  - document chain vs terminal profile semantics
  - document `chain` fields and constraints
- `docs/dev/DEVICE_PROFILES.md`
  - document multi-persona DevPro pattern (vendor vs aftermarket bootloader)

## Validation Plan

During development:

- `cargo fmt`
- `cargo check -p fastboop-schema -p fastboop-core -p fastboop-cli`
- `cargo check -p fastboop-desktop -p fastboop-web` (or equivalent workspace checks)

Required path-triggered checks:

- `dx build -p fastboop-desktop` when desktop package is touched
- `dx build -p fastboop-web` when web package is touched

Device smoke:

- channel containing:
  - chain profile for vendor DevPro -> aftermarket DevPro,
  - terminal profile for aftermarket DevPro
- verify chained wait/resume behavior and successful terminal boot

Web smoke:

- verify chained waiting screen appears,
- verify manual pairing can continue chain,
- verify clear failure if wrong/unexpected profile is paired.

## Risks and Mitigations

- Misconfigured next profile or illegal second chain step:
  - enforce single-hop depth limit + explicit diagnostics.
- Browser pairing friction:
  - explicit web chained wait UI with actionable pairing guidance.
- Payload/bootimg mismatch for chain step:
  - document payload contract and report payload source + profile IDs in errors.

## Follow-Ups (Post-v0)

- Decouple boot-profile compatibility matching from `stage0.devices` semantics.
- Better web handoff ergonomics and richer chained-step status telemetry.
- Explore cross-tab/session handoff patterns (including sharedworker experiments) for
  advanced multi-export workflows.
