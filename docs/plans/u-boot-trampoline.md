# U-Boot Trampoline Plan (v0)

## Goal

Add a first-class U-Boot trampoline boot path for devices (like `google-sargo`) where
direct Linux Android boot images are rejected by ABL, while preserving the existing
direct-kernel path for devices that already work.

The trampoline artifact must be sourced through the existing gibblox artifact pipeline
(HTTP, casync, file, and nested wrappers/selectors), not built locally by fastboop.

## Why This Exists

- On sargo, fastboop can successfully `download` but `boot` fails with:
  - `Error verifying the received boot.img: Volume Corrupt`
- This failure reproduces with and without `arm64_text_offset` kernel shim.
- A known-good manual path is:
  - booting gzipped `u-boot-nodtb.bin` with appended sargo DTB via fastboot,
  - then letting U-Boot continue boot flow.

Conclusion: we need an explicit trampoline mode, not only Linux `Image` header patching.

## Non-Goals

- No flashing, formatting, slot switching, or any other mutating behavior.
- No in-tree U-Boot build orchestration in fastboop.
- No deprecation/compat shims (project is unreleased).

## Proposed Data Model

### Device Profile (DevPro)

Add an explicit launch mode for Android boot image assembly:

- `direct` (default): current behavior.
- `u_boot_fit` (new): stage1 kernel is U-Boot trampoline; stage2 Linux payload is carried in FIT.

Proposed shape (illustrative):

```yaml
boot:
  fastboot_boot:
    android_bootimg:
      header_version: 0
      page_size: 4096
      kernel_offset: 0x00008000

      launch:
        u_boot_fit:
          fit_config: fastboop
```

Notes:

- `fit_config` defaults to `fastboop`.
- Existing `kernel.shims` remains valid and applies to the stage2 Linux kernel payload.

### Boot Profile

Add optional trampoline artifact source:

- `trampoline`: `BootProfileArtifactSource`

This is intentionally a raw artifact source (no path), so it can be fetched from arbitrary
gibblox pipelines and wrappers.

Proposed shape (illustrative):

```yaml
id: sargo-mainline
rootfs:
  ostree:
    erofs:
      casync:
        index: https://example.invalid/rootfs.caibx

trampoline:
  xz:
    http: https://example.invalid/u-boot-sargo-nodtb.bin.gz.xz
```

## Runtime Contract

`u_boot_fit` mode assumes the trampoline U-Boot artifact is configured to boot a FIT from
ramdisk memory, using the configured FIT config name.

Expected default contract:

- U-Boot executes equivalent of: `bootm ${ramdisk_addr_r}#fastboop`

If a trampoline image does not satisfy that contract, fastboop will still boot stage1,
but handoff will fail inside U-Boot.

## End-to-End Flow (u_boot_fit)

1. Resolve channel + boot profile as today.
2. Resolve stage2 Linux kernel/dtb/initrd as today (including kernel shims and DT overlays).
3. Build FIT payload in-memory containing:
   - kernel (stage2 Linux kernel bytes),
   - ramdisk (stage0 initrd),
   - fdt (selected DTB after overlays/injection),
   - one default config (`fit_config`, default `fastboop`).
4. Resolve `boot_profile.trampoline` via gibblox artifact resolver.
5. Assemble stage1 Android boot image:
   - kernel = trampoline artifact bytes (plus DTB append if DevPro encoding requests it),
   - ramdisk = FIT payload,
   - cmdline = existing cmdline assembly logic.
6. Send with existing fastboot download + boot transport.

## Implementation Workstreams

### 1) Schema + Codec

- `crates/fastboop-schema/src/lib.rs`
  - add DevPro launch mode for Android bootimg,
  - add `BootProfile{Manifest}.trampoline`.
- `crates/fastboop-schema/src/bin.rs`
  - include trampoline field in binary profile codec structs.
- `crates/fastboop-core/src/bootprofile.rs`
  - validate trampoline artifact pipeline with existing depth/selector constraints.

### 2) Artifact Resolution Plumbing

- `cli/src/commands/mod.rs`
  - extend `BootProfileSourceOverrides` to carry trampoline bytes,
  - resolve `boot_profile.trampoline` via `open_artifact_source()`.

### 3) FIT Builder

- `crates/fastboop-stage0-generator`
  - add a small deterministic FIT builder module for one kernel/ramdisk/fdt config,
  - avoid external `mkimage` dependency.

### 4) Boot Assembly Path

- `cli/src/commands/boot.rs`
  - branch on DevPro launch mode:
    - `direct`: unchanged,
    - `u_boot_fit`: use trampoline + FIT flow.
- keep direct path behavior and defaults stable.

### 5) Stage0 Command Behavior

- `cli/src/commands/stage0.rs`
  - when `u_boot_fit` mode is selected, continue producing stage2 artifacts,
    but do not confuse trampoline artifact with stage2 kernel override.

### 6) Sargo DevPro Update

- `devprofiles.d/google-sargo.yaml`
  - switch launch mode to `u_boot_fit`.
  - keep `arm64_text_offset` shim for stage2 kernel initially.

### 7) Docs

- `docs/dev/DEVICE_PROFILES.md`
  - describe launch modes (`direct`, `u_boot_fit`) and stage2 shim semantics.
- `docs/dev/BOOT_PROFILES.md`
  - document `trampoline` artifact sourcing via gibblox.

## Validation Plan

During development:

- `cargo fmt`
- `cargo check -p fastboop-schema -p fastboop-core -p fastboop-stage0-generator -p fastboop-cli`
- `cargo test -p fastboop-core bootprofile`
- `cargo test -p fastboop-stage0-generator`

Device smoke gate (sargo):

- `fastboop-cli boot --device-profile google-sargo <channel>` with trampoline-enabled boot profile.
- verify fastboot no longer fails with `Volume Corrupt` at stage1 boot verification.

## Risks and Mitigations

- Trampoline env/bootcmd mismatch:
  - mitigate by documenting strict runtime contract and surfacing explicit errors/logging.
- FIT compatibility variance across U-Boot builds:
  - start with minimal FIT layout matching U-Boot docs/examples; add hashes only if required.
- Schema complexity creep:
  - keep launch mode narrow (`u_boot_fit` only) for v0.

## Follow-Ups (Post-v0)

- Desktop/web boot path parity for trampoline mode.
- Optional trampoline compatibility probe or manifest metadata.
- Optional alternate handoff mechanisms if specific boards need non-`bootm` contracts.
