# Boot Profiles

Think of [Stage0](STAGE0.md) as the cursed initrd and Boot Profiles as the cursed config blob for it.

Boot Profiles describe where boot artifacts come from and how stage0 should be adjusted per image/device.
Use them when a plain rootfs path/URL is not enough.

v0 now supports two profile modes:

- terminal mode (`rootfs` + optional `kernel`/`dtbs`): builds stage0 and starts smoo host.
- chain mode (`chain`): performs one non-terminal fastboot hop, then resumes with a required next boot profile.

## Source of Truth

- Schema types: [`crates/fastboop-schema/src/lib.rs`](https://github.com/samcday/fastboop/blob/main/crates/fastboop-schema/src/lib.rs)
- Codec + validation: [`crates/fastboop-core/src/bootprofile.rs`](https://github.com/samcday/fastboop/blob/main/crates/fastboop-core/src/bootprofile.rs)
- Artifact pipeline schema/codec: [`gibblox-pipeline`](https://github.com/samcday/gibblox/tree/main/crates/gibblox-pipeline)
- CLI tooling: [`cli/src/commands/bootprofile.rs`](https://github.com/samcday/fastboop/blob/main/cli/src/commands/bootprofile.rs)

## Two Representations

- Manifest (`BootProfileManifest`): YAML/JSON authoring format.
- Compiled (`BootProfile`): binary format used by runtime commands.

`fastboop boot` and `fastboop stage0` accept a compiled Boot Profile as the `ROOTFS` input.

## Minimal Manifest

```yaml
id: local-erofs
display_name: Local EROFS image

rootfs:
  erofs:
    file: ./artifacts/rootfs.ero

stage0:
  extra_modules:
    - ff-memless
```

## Chain Manifest (Single-Hop)

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

## Maximal Manifest (Pipeline-Heavy)

```yaml
id: generic-edge-phone
display_name: Generic edge image

rootfs:
  ext4:
    mbr:
      index: 1
      android_sparseimg:
        xz:
          http: https://downloads.example.com/images/generic-edge.img.xz

kernel:
  path: /vmlinuz
  fat:
    mbr:
      index: 0
      android_sparseimg:
        xz:
          http: https://downloads.example.com/images/generic-edge.img.xz

dtbs:
  path: /dtbs
  fat:
    mbr:
      index: 0
      android_sparseimg:
        xz:
          http: https://downloads.example.com/images/generic-edge.img.xz

extra_cmdline: console=ttyMSM0,115200n8
```

## Validation Highlights

- `rootfs` schema supports `erofs`, `ext4`, and `fat` (terminal mode).
- Stage0 lower-root currently accepts `erofs` and `ext4`; use `fat` for kernel/dtbs source pipelines.
- `chain` is top-level and mutually exclusive with `rootfs`, `kernel`, and `dtbs`.
- `chain.next_device_profile` and `chain.next_boot_profile` are required and must be non-empty.
- Runtime chaining is single-hop (`max depth = 1`); a second chain step is rejected.
- Artifact pipeline validation/limits come from `gibblox-pipeline` (`MAX_PIPELINE_DEPTH=16`).
- GPT/MBR selector steps must choose exactly one selector field.
- `kernel.path` and `dtbs.path` (if present) must be non-empty.
- `dt_overlays` compile/decompile requires `dtc`.

## How To Bang On It

```sh
# compile manifest -> binary
cargo run -p fastboop-cli -- bootprofile create ./profile.yaml -o /tmp/profile.fbp

# compile + materialize android sparse index hints
cargo run -p fastboop-cli -- bootprofile create ./profile.yaml --optimize-pipeline-hints -o /tmp/profile.fbp

# inspect binary -> yaml
cargo run -p fastboop-cli -- bootprofile show /tmp/profile.fbp

# exercise stage0 path through compiled profile
cargo run -p fastboop-cli -- stage0 /tmp/profile.fbp --device-profile <id> > /tmp/stage0.cpio
```
