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

`match` is the cheap first-pass filter used before deeper probing.

Use it to narrow candidates fast (usually USB VID/PID for fastboot devices), not to prove final identity.
Think of `match` as "could be this family" and `probe` as "yes, this exact target."

Guidelines:

- Keep match conditions broad enough to catch valid devices in that family.
- Keep match conditions strict enough to avoid probing every random fastboot handle.
- Prefer stable identifiers (VID/PID) over brittle assumptions.

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
- Do not add mutating commands; probing must stay safe and repeatable.

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

## How To Bang On It

```sh
# ensure schema and profile code still type-checks
cargo check -p fastboop-core

# with hardware in fastboot mode, verify match+probe flow
cargo run -p fastboop-cli -- detect --wait 5

# offline: ensure this profile can drive payload assembly
cargo run -p fastboop-cli -- boot <rootfs-or-bootprofile> --device-profile <id> --output /tmp/boot.img
```

## Source of Truth

- Schema types: [`crates/fastboop-schema/src/lib.rs`](https://github.com/samcday/fastboop/blob/main/crates/fastboop-schema/src/lib.rs)
- Built-in profiles (latest on main): [`devprofiles.d/`](https://github.com/samcday/fastboop/tree/main/devprofiles.d)
- Profile loading logic: [`cli/src/devpros.rs`](https://github.com/samcday/fastboop/blob/main/cli/src/devpros.rs)
