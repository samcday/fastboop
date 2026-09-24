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
fastboop boot /tmp/supplied-initrd.fbp --device-profile <device> \
  --smoo-serial <runtime-usb-serial>
```

Stage0-only options (`--stage0`, `--augment`, `--require-module`,
`--serial`, `--ostree`, and `stage0.kernel_modules`) are rejected for this
strategy. Host firstboot credentials are not injected into a supplied initramfs.
Native boot checks these options against the channel's candidate profiles before
waiting for USB or opening artifact pipelines. If device detection is needed to
choose between stage0 and initrd profiles, it checks the selected profile again
before reading artifacts.
Web boot currently reports that this strategy requires native fastboop.
`fastboop stage0` rejects a selected supplied-initrd profile before opening its
root, kernel, or initrd artifact pipelines.

### Native runtime device selection

Native boot retains an exact runtime USB descriptor serial for smoo discovery
and every reconnect. Generated stage0 uses the effective `stage0.serial` from
the BootProfile, its device-specific settings, and `--cmdline-append`, in that
order (the last nonempty assignment wins). Without that setting, it uses
`--smoo-serial SERIAL` or the selected fastboot device's USB serial.
`--smoo-serial` must agree with any effective `stage0.serial`; conflicting
values fail before booting. Both options can supply a runtime identity when
the bootloader exposes no USB serial.
Invalid or conflicting stage0 serial settings are checked before waiting for
USB when no candidate profile can accept them. After reopening a channel,
fastboop derives the final strategy and serial from the profile snapshot used
to build the payload. When augmenting a stage0 initrd, the selected serial
replaces its previous `/etc/stage0/stage0.serial` entry.

For `boot: initrd`, `--smoo-serial SERIAL` is required when actually booting.
When the profile candidates already determine a supplied-initrd boot, a missing
selector is reported before waiting for USB. Mixed strategies are checked again
after device detection; output-only builds do not require a selector.
It must name the unique serial that the prepared initramfs exposes at runtime;
fastboop does not assume it equals the bootloader's USB serial or `getvar serialno`.
This option selects the runtime gadget; it does not modify a supplied initrd or
configure its gadget. Image preparation must provide a distinct gadget serial
for each device. The old single-target setup with a shared default gadget serial
is not sufficient for reliable multi-device operation. `--output` can still
build a payload without a runtime selector or connected device.

Discovery waits for the requested serial even if another gadget appears first,
and rejects duplicate matching serials rather than choosing the first device.
It retains and claims the inspected USB handle without enumerating again. If
that device disconnects before claiming, discovery retries with the same serial;
the claim cannot substitute a newly arrived device.
The serial must be nonempty ASCII without surrounding whitespace or control
characters, and must remain stable across gadget restarts. Discovery ignores
disconnected and unconfigured devices. It skips any other device it cannot
inspect, such as a new node that udev has not yet made accessible, and still
inspects the rest of the scan. While a device that exposes a smoo interface
cannot be opened or its serial cannot be read, discovery claims no device,
because the skipped device may carry the same serial; it retries after a
cancellable delay, with no timeout, until that device is readable or removed.
A device whose descriptors cannot be read is skipped without holding back the
claim. A device that keeps failing inspection for about two seconds is reported
once per bus/address with a warning that says whether it blocks the claim, with
a udev/uaccess hint for access denial.
Duplicate serials and invalid selectors still stop serving. Failures to create
the USB context or enumerate devices retry when transient (I/O, timeout, busy,
disconnect) and otherwise stop serving. Native library consumers must retain `NativeBootEnvironment::smoo_host_options()`
when handing a prepared boot to a background host task; low-level host options
also require a nonempty serial. The desktop retains these options for generated
stage0 boots. Supplied-initrd boots requiring an explicit serial currently use
the CLI/native API; the desktop has no runtime-serial input yet.

These checks use USB descriptors, not authenticated hardware identity. Devices
must have unique serials; concurrent replacement with an identically configured
gadget cannot be distinguished through this interface.

### Supplied initramfs with an ABLX shim

Pass `--abl-exorcist /path/to/abl-exorcist.bin` to use a raw, device-appropriate
arm64 shim from abl-exorcist v0.0.1. For `boot: initrd`, fastboop normalizes the
supplied Linux kernel to a raw Image and uses the portable assembler to create
an `ABLXRD1` ramdisk containing its LZ4-compressed kernel and the byte-for-byte
unchanged initramfs. The shim occupies the Android kernel section, encoded as
specified by the DevPro (gzip for sargo). DTBs retain the DevPro's appended or
separate-section placement. All inputs are separate artifacts; no existing
Android boot image is read or repacked.

Fastboop encloses the complete command line, including the device arguments and
generated smoo root/export arguments, in one `<S> ... <E>` pair for the shim's
bootloader-argument filtering. Do not supply these markers yourself; marker
strings in caller-provided arguments are rejected. Payload size limits apply
to the encoded shim, complete ABLXRD1 container, and final Android boot image.
Linux kernel decompression has a separate 256 MiB ceiling in this mode.

```sh
# The profile supplies the prepared smoo-aware initrd, kernel, root, and DTB.
fastboop boot /tmp/supplied-initrd.fbp --device-profile google-sargo \
  --abl-exorcist /path/to/abl-exorcist.bin --system-time=false \
  --output /tmp/boot.img

# Omit --output to RAM boot and serve the read-only root export through smoo.
```

The built-in sargo profile uses ramdisk address `0x04000000`. Image producers
remain responsible for preparing smoo/dracut support and SELinux policy; adding
the shim does not modify the supplied initramfs. Stage0 profiles retain their
existing ABLX kernel-wrap behavior.

The added fields change the intentionally unstable v0 binary profile layout.
Regenerate compiled profiles and channel records with the matching fastboop
version.

## Profile bundle codec

`encode_channel_profile_bundle` and `decode_channel_profile_bundle` use the
same binary-safe profile representations as individual profile records. The
unreleased bundle payload layout changed to support nonempty bundles; regenerate
any saved bundles with the matching fastboop version. No legacy decoder is kept.

Bundles have a standalone codec and format discriminator. Native boot intake
currently accepts concatenated `encode_dev_profile` / `encode_boot_profile`
records, not bundle bytes; fixing the bundle codec does not add a new boot input
format.
