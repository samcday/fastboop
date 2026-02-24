# Device Profiles

Device Profiles (DevPro) describe how to identify and safely boot a specific device class.

They are hardware-facing only: identity checks, bootloader constraints, and stage0 boot requirements.
They are not distro policy, installer policy, or user preference storage.

## Source of Truth

- Schema types: `crates/fastboop-schema/src/lib.rs`
- Built-in profiles: `devprofiles.d/*.yaml`
- Runtime profile load path order:
  - `FASTBOOP_SCHEMA_PATH` (colon-separated)
  - `$XDG_CONFIG_HOME/fastboop/devpro` (or `~/.config/fastboop/devpro`)
  - `/usr/share/fastboop/devpro`

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

boot:
  fastboot_boot:
    android_bootimg:
      header_version: 2
      page_size: 4096
      kernel:
        encoding: image.gz

stage0:
  kernel_modules: [dwc3, phy-qcom-qusb2]
```

## Authoring Rules

- `match` is a cheap candidate filter (usually VID/PID).
- `probe` is ordered and read-only (`fastboot getvar` checks).
- `boot.fastboot_boot.android_bootimg` records what the bootloader accepts.
- `stage0.kernel_modules` lists modules needed to bring up gadget/runtime reliably.
- Keep it non-mutating: no write/flash semantics in profiles.

## How To Bang On It

```sh
# ensure schema and profile code still type-checks
cargo check -p fastboop-core

# with hardware in fastboot mode, verify match+probe flow
cargo run -p fastboop-cli -- detect --wait 5

# offline: ensure this profile can drive payload assembly
cargo run -p fastboop-cli -- boot <rootfs-or-bootprofile> --device-profile <id> --output /tmp/boot.img
```
