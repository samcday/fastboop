# Contributors Introduction

fastboop is a non-mutating live-boot pipeline for fastboot-class devices.

At a high level, a boot session is:

1. detect USB device
2. match and probe with a Device Profile (DevPro)
3. build stage0 from rootfs artifacts
4. boot ephemerally over fastboot
5. hand off runtime block export to smoo

No flashing, no slot switching, no persistent install actions.

## Hard Rules

- Keep the non-mutating invariant: no `flash`, `erase`, `format`, `set_active`, `oem`, or unlock/lock flows.
- Keep platform-agnostic behavior in core crates and transport/platform details in leaf crates.
- Respect `no_std + alloc` boundaries in core/proto crates.
- Prefer async-first code paths.

## Where Things Live

- `devprofiles.d/`: built-in Device Profile YAML files.
- `crates/fastboop-schema/`: DevPro + Boot Profile schema types.
- `crates/fastboop-core/`: matching/probing/validation/runtime profile logic.
- `crates/fastboop-stage0-generator/`: stage0 synthesis from rootfs + profile inputs.
- `stage0/`: PID1 runtime that runs on device.
- `cli/`: contributor-facing commands (`detect`, `stage0`, `boot`, `bootprofile`).

## Quick Contributor Loop

```sh
cargo fmt
cargo check -p fastboop-cli
cargo check -p fastboop-core
```

Then run path-specific checks from `HACKING.md` for whatever you touched.

## Start Here Next

- [Device Profiles](DEVICE_PROFILES.md)
- [Boot Profiles](BOOT_PROFILES.md)
- [Stage0](STAGE0.md)
