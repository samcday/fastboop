# fastboop

**fastboop** is a tool for booting arbitrary Linux installatioons on pocket computers that expose a **non‑mutating USB bootloader interface** (most commonly Android's `fastboot`), *without flashing or permanently modifying the device*.

It is designed to work from the web, desktop, or CLI, and pairs with [smoo] to bridge from a vendor bootloader into a fully‑featured Linux environment.

---

## What fastboop does

At a high level:

1. Detects a device connected in a supported vendor boot mode (e.g. fastboot)
2. Identifies the device using a declarative **Device Profile**
3. Takes an **unmodified rootfs artifact** (distro rootfs, live media, or bespoke image)
4. Synthesizes a minimal **stage0 initrd** that:
   - boots the device kernel
   - loads only the kernel modules required to bring up USB gadget mode
   - starts `smoo` as `/init`
5. Uses the vendor bootloader to **ephemerally boot** the generated payload into RAM

From that point on, **smoo** takes over and serves the rest of the rootfs / live media to the device.

No flashing. No slot changes. No persistent writes.

---

## Relationship to the ecosystem

fastboop is meant to be used *by* distros, not replace them.

Example use cases:
- “Boot Fedora Workstation on supported phones from a browser”
- “Bring pmOS up on new hardware without flashing”
- “Ephemeral rescue or diagnostics environments”

fastboop is the glue between **vendor bootloaders**, **upstream distros**, and [smoo].

---

## What fastboop does *not* do

- Installation
- Partitioning
- Flashing
- Bootloader unlocking
- Slot management
- Distro‑specific install logic

Many of those concerns belong to the kernel/userland of the booted environment (e.g. Anaconda/Calamares), not in fastboop.

If a device cannot be booted non‑mutatingly, it is out of scope.

---

## Core concepts

### Device Profiles

A `DeviceProfile` describes:

- How to recognize a device over USB (VID/PID, protocol)
- How to confirm identity (probe steps like `fastboot getvar`)
- What boot payload format the device accepts
- Size and format constraints for ephemeral boot

A DeviceProfile describes *how a device boots*, not *what is booted*.

---

### Stage0

**Stage0** is a minimal initramfs synthesized by fastboop per device and per rootfs.

It contains:
- `smoo-gadget` (started as `/init`)
- a small userspace (typically `busybox`)
- only the kernel modules and firmware required to bring up:
  - USB Device Controller (UDC)
  - FunctionFS / gadget support
  - optional ublk support

Stage0 is intentionally tiny and device‑specific.

---

### Rootfs artifacts

fastboop consumes **unmodified** upstream artifacts, such as:

- Fedora / Debian / Arch rootfs images
- Live media (e.g. `.iso`, via ranged reads)
- Custom or bespoke root filesystems

The rootfs must contain:
- a usable kernel
- matching kernel modules
- the drivers required for USB gadget mode on the target device

fastboop extracts what it needs and does not repack or fork the distro.

---

### smoo

**smoo** is responsible for what happens *after* stage0 boots:

- exposing block devices or filesystems over USB
- serving live media or rootfs content
- enabling kexec / pivot / handoff into the full system

fastboop does **not** build or link smoo; it just hands off to a smoo payload (prebuilt) once the boot command has been issued.

---

## Execution environments

The same fastboop core logic is intended to run in:

- **Web** (WebUSB + ranged HTTP + IndexedDB cache)
- **Desktop** (libusb, sandboxed or unsandboxed)
- **CLI** (libusb + hotplug)

The transport layer is thin; fastboop core is a state machine driven by device events.

---

## Status

fastboop is under active design and early implementation.

Expect:
- breaking changes
- incomplete device coverage
- rapid iteration on the DeviceProfile schema and stage0 builder

If this sounds unstable: correct. That is intentional.

---

[smoo]: https://github.com/samcday/smoo
