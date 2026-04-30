# Boot Profiles

Think of [Stage0](STAGE0.md) as the cursed initrd and Boot Profiles as the cursed config blob for it.

Boot Profiles describe where boot artifacts come from and how stage0 should be adjusted per image/device.
Use them when a plain rootfs path/URL is not enough.

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
    content:
      digest: sha512:11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
      size_bytes: 123456789

stage0:
  kernel_modules:
    - ff-memless
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
          content:
            digest: sha512:11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
            size_bytes: 987654321

kernel:
  path: /vmlinuz
  fat:
    mbr:
      index: 0
      android_sparseimg:
        xz:
          http: https://downloads.example.com/images/generic-edge.img.xz
          content:
            digest: sha512:11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
            size_bytes: 987654321

dtbs:
  path: /dtbs
  fat:
    mbr:
      index: 0
      android_sparseimg:
        xz:
          http: https://downloads.example.com/images/generic-edge.img.xz
          content:
            digest: sha512:11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
            size_bytes: 987654321

extra_cmdline: console=ttyMSM0,115200n8

stage0:
  kernel_modules:
    - dwc3
    - dwc3-qcom
  inject_mac:
    bluetooth: qcom,wcn3990-bt
    wifi: qcom,wcn3990-wifi
  devices:
    oneplus-fajita:
      dt_overlays:
        - |
          /dts-v1/;
          /plugin/;
          / {
            fragment@0 {
              target-path = "/";
              __overlay__ {
                fastboop-example;
              };
            };
          };
      extra_cmdline: clk_ignore_unused
      stage0:
        kernel_modules:
          - gcc-sdm845
```

## Validation Highlights

- `rootfs` schema supports `erofs`, `ext4`, and `fat`.
- Stage0 lower-root currently accepts `erofs` and `ext4`; use `fat` for kernel/dtbs source pipelines.
- `stage0.kernel_modules` and `stage0.inject_mac` may be global or scoped under `stage0.devices.<device-profile-id>.stage0`; device-specific values append modules and override MAC injection fields.
- Artifact pipeline validation/limits come from `gibblox-pipeline` (`MAX_PIPELINE_DEPTH=16`).
- Terminal stages (`http`, `casync`, `file`) must include `content` metadata (`digest`, `size_bytes`). `bootprofile create` auto-populates `content` for bare local `file` sources by hashing the referenced path, so hand-authored manifests pointing at `pmbootstrap export` output (or any other local artifact) can omit it.
- Wrapper stages (`xz`, `android_sparseimg`, `mbr`, `gpt`) may include optional `content` metadata.
- GPT/MBR selector steps must choose exactly one selector field.
- `kernel.path` and `dtbs.path` (if present) must be non-empty.
- `dt_overlays` compile/decompile requires `dtc`.

## How To Bang On It

```sh
# compile manifest -> binary
cargo run -p fastboop-cli -- bootprofile create ./profile.yaml -o /tmp/profile.fbp

# compile and immediately generate optimize sidecar
cargo run -p fastboop-cli -- bootprofile create ./profile.yaml -o /tmp/profile.fbp --optimize

# create+optimize using local content-matching artifact overrides
cargo run -p fastboop-cli -- bootprofile create ./profile.yaml -o /tmp/profile.fbp --optimize --local-artifact ./artifacts/rootfs.ero

# inspect binary -> yaml
cargo run -p fastboop-cli -- bootprofile show /tmp/profile.fbp

# materialize pipeline-hints sidecar from compiled profile
cargo run -p fastboop-cli -- bootprofile optimize /tmp/profile.fbp -o /tmp/profile.fph

# allow local replacement for content-matching stages while optimizing
cargo run -p fastboop-cli -- bootprofile optimize /tmp/profile.fbp -o /tmp/profile.fph --local-artifact ./artifacts/rootfs.ero

# exercise stage0 path through compiled profile
cargo run -p fastboop-cli -- stage0 /tmp/profile.fbp --device-profile <id> > /tmp/stage0.cpio
```
