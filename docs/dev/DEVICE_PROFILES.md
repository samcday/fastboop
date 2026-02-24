# Device Profiles

Device Profiles (`DevPro`s) are fastboop's hardware playbook: they tell fastboop how to recognize a device and how to boot it safely without touching persistent storage.

If you want concrete examples, start with the bundled profiles in [`devprofiles.d/`](https://github.com/samcday/fastboop/tree/main/devprofiles.d). Those built-ins are always loaded by fastboop (CLI, desktop, and web).

For local authoring and iteration, `fastboop-cli` also loads profiles from:

- colon-separated directories listed in `$FASTBOOP_SCHEMA_PATH`
- `$XDG_CONFIG_HOME/fastboop/devpro` (or `~/.config/fastboop/devpro`)
- `/usr/share/fastboop/devpro`

`DevPro`s describe how to locate a particular device in its bootloader state, capture the constraints of that environment, and define [Stage0](STAGE0.md) requirements. There is no distro, installer, or user policy here.

## Minimal Shape

```yaml
id: oneplus-fajita
display_name: OnePlus 6T
devicetree_name: qcom/sdm845-oneplus-fajita

match:
  - fastboot:
      vid: 0x18d1
      pid: 0xd00d

probe:
  - fastboot.getvar: product
    equals: sdm845
  - fastboot.getvar: partition-type:aging
    exists:

boot:
  fastboot_boot:
    android_bootimg:
      header_version: 2
      page_size: 4096
      kernel_offset: 0x00008000

      kernel:
        encoding: image.gz

stage0:
  kernel_modules:
    # This is the core set for a working UDC.
    - dwc3
    - dwc3-qcom
    - dwc3-qcom-legacy
    - phy-qcom-qusb2
    - nvmem_qfprom
    - i2c-qcom-geni
    - pinctrl-sdm845
    - gcc-sdm845
    - qnoc-sdm845

    # This isn't required for UDC, but needs to load
    # early to avoid deferred-probe timeouts on arm-smmu.
    - gpucc-sdm845
```

## Match

`match` is the cheap USB prefilter used before deeper probing.

For fastboot profiles, this is primarily USB VID/PID tuples. fastboop uses these tuples to decide which
devices to probe, and web targets use the same tuples when requesting USB device access.

`match` is not the final identity check; `probe` is.

Guidelines:

- List the exact VID/PID pair(s) used by this profile's bootloader mode.
- Similar devices may share the same VID/PID, we disambiguate in `probe`.

## Probe

`probe` is the authoritative identity check.

Probe steps are evaluated in order and should be read-only checks (`fastboot getvar ...`).
If any required step fails, the profile does not match.

Current probe primitives in schema are:

- `equals`
- `not_equals`
- `exists`
- `not_exists`

Practical guidance:

- Put highly discriminating checks early to fail fast.
- Use multiple checks when one getvar is ambiguous across sibling devices.

## Boot

`boot` describes what the bootloader will accept for ephemeral RAM boot.

For current fastboop flows, this is `boot.fastboot_boot.android_bootimg`.
This section captures concrete constraints (for example `header_version`, `page_size`, kernel encoding)
so payload generation can be deterministic.

Treat this as a hardware contract, not distro policy:

- Include fields required by the target bootloader.
- Keep values factual to observed device behavior.
- Avoid adding logic that belongs in Boot Profiles or stage0 generation.

## Stage0 Hints

`stage0.kernel_modules` lists module requirements needed for reliable gadget/runtime bring-up.
Keep this list focused: enough for consistent boot/handoff, not a generic module wishlist.

As always, keep profiles non-mutating: no write/flash semantics.

## Building a new Device Profile

Start from a profile for a similar device in [`devprofiles.d/`](https://github.com/samcday/fastboop/tree/main/devprofiles.d). Copy it to `~/.config/fastboop/devpro/your-device.yaml` and update the `id:` + `display_name:` + `devicetree_name:` fields.

Ensure `match` + `probe` match your device. Test with the real device:

```sh
RUST_LOG=trace fastboop detect --device-profile your-device
```

Smoke-test payload generation with `fastboop boot` or `fastboop stage0` (if you have a rootfs to test with):

```
# generate just the stage0 payload:
fastboop stage0 --device-profile your-device rootfs.img

# or the entire boot artifact:
fastboop boot rootfs.img --device-profile your-device --output /tmp/boot.img
```

## Source of Truth

- Schema types: [`crates/fastboop-schema/src/lib.rs`](https://github.com/samcday/fastboop/blob/main/crates/fastboop-schema/src/lib.rs)
- Built-in profiles (latest on main): [`devprofiles.d/`](https://github.com/samcday/fastboop/tree/main/devprofiles.d)
- Profile loading logic: [`cli/src/devpros.rs`](https://github.com/samcday/fastboop/blob/main/cli/src/devpros.rs)
