# Boot Profiles

Boot Profiles describe where boot artifacts come from and how stage0 should be adjusted per image/device.

Use them when a plain rootfs path/URL is not enough and you need explicit artifact pipelines,
overlay injection, or per-device stage0 tuning.

## Source of Truth

- Schema types: `crates/fastboop-schema/src/lib.rs`
- Codec + validation: `crates/fastboop-core/src/bootprofile.rs`
- CLI tooling: `cli/src/commands/bootprofile.rs`

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
    - usb_f_fs
```

## Validation Highlights

- Stage0 switchroot currently supports `erofs` and `ext4` rootfs types.
- Artifact pipeline depth is capped.
- GPT/MBR selector steps must choose exactly one selector field.
- `kernel.path` and `dtbs.path` (if present) must be non-empty.
- `dt_overlays` compile/decompile requires `dtc`.

## How To Bang On It

```sh
# compile manifest -> binary
cargo run -p fastboop-cli -- bootprofile create ./profile.yaml -o /tmp/profile.fbp

# inspect binary -> yaml
cargo run -p fastboop-cli -- bootprofile show /tmp/profile.fbp

# exercise stage0 path through compiled profile
cargo run -p fastboop-cli -- stage0 /tmp/profile.fbp --device-profile <id> > /tmp/stage0.cpio
```
