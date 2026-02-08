# fastboop

**fastboop** is a tool to ephemerally boot (live) Linux installations on pocket computers that expose a **non‑mutating USB-enabled bootloader interface** (i.e fastboot), *without flashing or permanently modifying the device*.

It is designed to work from the web, desktop, or CLI.

---

## What fastboop does

At a high level:

1. Detects a device connected in a supported vendor boot mode (e.g. fastboot)
2. Identifies the device using a declarative [`DeviceProfile` (DevPro)][devpro]
3. Takes an **unmodified rootfs artifact** (distro rootfs, live media, or bespoke image)
4. Synthesizes a minimal **stage0 initrd** that:
   - boots the device kernel
   - loads only the kernel modules required to bring up USB gadget mode
   - starts `fastboop-stage0` as `/init` (embedding `smoo-gadget-app`)
5. Uses the vendor bootloader to **ephemerally boot** the generated payload into RAM

From that point on, stage0 brings up smoo, waits for the exported block device, mounts an ephemeral overlay root, and execs the target userspace init.

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

### DevPro (device profiles)

A DevPro describes:

- How to recognize a device over USB (VID/PID, protocol)
- How to confirm identity (probe steps like `fastboot getvar`)
- What boot payload format the device accepts
- Size and format constraints for ephemeral boot

A DevPro describes *how a device boots*, not *what is booted*.

---

### Stage0

**Stage0** is a productionized initramfs synthesized by fastboop per device and per rootfs. It targets well-understood platforms we want to make boring: bring up the gadget stack deterministically, run embedded smoo gadget runtime, mount the exported rootfs with an ephemeral overlay, and hand off to the distro init.

Stage0 is **not** a rescue or bring-up environment. Spicy debugging (LED/morse-code, shells, busybox) is out of scope. It assumes the host just booted it over USB (e.g. `fastboot boot`) and should immediately bring up smoo.

Runtime model:
- `fastboop-stage0` runs as PID 1, logging to `/dev/kmsg`
- stage0 spawns embedded `smoo-gadget-app` as a child process
- minimal virtual filesystems mounted (`/proc`, `/sys`, `/dev`, `/run`)
- host-generated module list loaded deterministically (no `modprobe`)
- stage0 waits for smoo-exported block device, mounts erofs+overlay root, then execs `/sbin/init` (or systemd)

Stage0 must not include BusyBox or general shells/toolboxes by default, must not rely on package managers or distro tooling, and must not touch persistent storage.

Advanced users/distro integrators can build their own initrd (e.g. with mkosi) containing busybox/bash/etc and whatever smoo variant they want; fastboop’s stage0 is the boring production path.

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

fastboop uses [gibblox][] to extract what it needs and does not repack or fork the distro.

---

### smoo

**smoo** is responsible for data-plane storage/export services that stage0 depends on:

- exposing block devices or filesystems over USB
- serving live media or rootfs content
- serving the block export that stage0 mounts as lower root

fastboop stage0 currently embeds and links `smoo-gadget-app` directly, then launches it during PID1 flow.

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
- rapid iteration on the DevPro schema and stage0 builder

If this sounds unstable: correct. That is intentional.

---

[gibblox]: https://github.com/samcday/gibblox
[smoo]: https://github.com/samcday/smoo
[devpro]: ./docs/DEVICE_PROFILES.md
