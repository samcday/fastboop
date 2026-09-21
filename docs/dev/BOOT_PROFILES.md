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
        inject_mac:
          bluetooth: qcom,wcn3990-bt
          wifi: qcom,wcn3990-wifi
```

## Validation Highlights

- `rootfs` schema supports `erofs`, `ext4`, and `fat`.
- Stage0 lower-root currently accepts `erofs` and `ext4`; use `fat` for kernel/dtbs source pipelines. Supplied-initrd profiles may also export a FAT root (including OSTree-over-FAT); the supplied initramfs owns filesystem support.
- `stage0.kernel_modules` may be global or scoped under `stage0.devices.<device-profile-id>.stage0`; device-specific modules append to global modules.
- `stage0.devices.<device-profile-id>.stage0.inject_mac` is device-scoped only. It identifies target nodes by `compatible` string for the selected device DTB.
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

## Booting a supplied initramfs (native)

Set `boot: initrd` to boot the image's own kernel and prepared initramfs.
Both artifact sources are required. Each names a file inside an EROFS, ext4,
or FAT pipeline, just like the existing kernel source:

```yaml
id: supplied-initrd
boot: initrd
rootfs:
  ext4:
    file: ./rootfs.ext4
kernel:
  path: /boot/vmlinuz
  ext4:
    file: ./boot-artifacts.ext4
initrd:
  path: /boot/initramfs.img
  ext4:
    file: ./boot-artifacts.ext4
dtbs:
  path: /boot/dtbs
  ext4:
    file: ./boot-artifacts.ext4
extra_cmdline: rd.smoo.cow.size=2G rd.smoo.rootfstype=ext4
```

The initramfs must already contain smoo's root-storage dracut module, gadget
binary, the device's required kernel modules, and the components needed to mount
the root with a disposable dm-snapshot/brd COW layer. Image preparation owns those
contents and any SELinux policy. Fastboop passes the initramfs bytes unchanged,
including their compression, and never reads or injects a stage0 binary.
The initramfs is read in bounded chunks, stopping at a positive DevPro
`limits.max_initrd_bytes`, or 512 MiB when that limit is absent or zero.
Oversized files fail during reading, before the whole artifact is allocated.

Fastboop resolves the profile's inputs, normalizes the kernel to the DevPro's
encoding, applies supplied DT overlays/MAC settings, and constructs a new Android
boot image using the device's geometry. It then uses its existing fastboot RAM
boot and smoo host lifecycle. The root export remains read-only.

The generated command line selects `root=/dev/smoo-root`, enables
`rd.smoo=1`, `rd.smoo.force_root=1` and `rd.smoo.cow=1`, and sets
`rd.smoo.root` from the same identity and geometry used for host export
registration. `rd.smoo.mimic_fastboot` matches the host's
`--impersonate-fastboot` setting. Conflicting or duplicate values for these
arguments fail preparation. Image-specific settings such as the COW size, root
filesystem type and OSTree arguments belong in `extra_cmdline`.
Explicit smoo queue/depth/max-I/O CLI options become the corresponding
`rd.smoo.*` arguments.

```sh
fastboop bootprofile create ./supplied-initrd.yaml -o /tmp/supplied-initrd.fbp

# Prepare and inspect a payload without accessing USB:
fastboop boot /tmp/supplied-initrd.fbp --device-profile <device> \
  --system-time=false --output /tmp/boot.img

# RAM boot the same inputs and keep serving the root:
fastboop boot /tmp/supplied-initrd.fbp --device-profile <device>
```

Stage0-only options (`--stage0`, `--augment`, `--require-module`,
`--serial`, `--ostree`, and `stage0.kernel_modules`) are rejected for this
strategy. Host firstboot credentials are not injected into a supplied initramfs.
Native boot checks these options against the channel's candidate profiles before
waiting for USB or opening artifact pipelines. If device detection is needed to
choose between stage0 and initrd profiles, it checks the selected profile again
before reading artifacts.
The existing `--abl-exorcist` stage0 option is also unsupported here; shim
composition is a separate feature. Web boot currently reports that this strategy
requires native fastboop.
`fastboop stage0` rejects a selected supplied-initrd profile before opening its
root, kernel, or initrd artifact pipelines.

The added fields change the intentionally unstable v0 binary profile layout.
Regenerate compiled profiles and channel records with the matching fastboop
version.
