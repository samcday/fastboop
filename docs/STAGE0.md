# Stage0 — fastboop v0

This document freezes the **v0 assumptions** for *stage0* in fastboop.

If you are implementing stage0 and feel the urge to add features:
stop.
Stage0 exists to do one job and then get out of the way.

---

## Purpose

**Stage0** is a productionized, minimal initramfs synthesized by fastboop whose sole purpose is to:

> Boot the device kernel, start **smoo-gadget** as PID 1, and hand off immediately.

Stage0 targets **well-tested, understood platforms** that we want to make boring. It assumes the host just booted it over the same USB link (e.g. `fastboot boot`) and should bring up smoo right away.

Stage0 is **not** a distro.
Stage0 is **not** an installer.
Stage0 is **not** a rescue or bring-up shell.
Stage0 is **not** persistent.

---

## Scope (hard limits)

Stage0 must do *only* the following:

1. Mount minimal virtual filesystems (`/proc`, `/sys`, `/dev`)
2. Load a host-generated kernel module list deterministically (no `modprobe`)
3. Start `smoo-gadget` as PID 1 (or immediately exec into it), logging to `/dev/console`
4. Keep running `smoo-gadget`; if it exits, stage0 has failed loudly

Anything beyond this is out of scope for v0.

---

## Non-goals

Stage0 must **not**:

- Touch persistent storage
- Partition disks
- Mount the target rootfs
- Contain distro logic
- Run installers
- Provide interactive shells or general toolboxes
- Handle user configuration
- Perform network configuration beyond what smoo requires
- Act as a bring-up/rescue environment or carry “spicy” debugging (LED/morse code)

If you think stage0 should do one of these things, the answer is no.

---

## Inputs to stage0 generation

Stage0 is generated **per device and per rootfs**.

fastboop provides stage0 generation with:

1. **DevPro-derived requirements**
   - Which kernel modules must be present for this device
   - Optional firmware hints
   - Kernel command line additions

2. **Rootfs artifact**
   - Source of the kernel image
   - Source of kernel modules (`/usr/lib/modules/<kver>` or equivalent)
   - Source of firmware blobs (if present)

3. **Boot constraints**
   - Maximum payload sizes
   - Accepted boot image format (e.g. android boot.img)

---

## Userspace contents

Stage0 userspace is intentionally hermetic and minimal.

It contains:

- `smoo-gadget` (running as PID 1)
- minimal directory layout to support module loading + FunctionFS:
  - `/sbin`
  - `/lib`
  - `/lib/modules`
  - `/dev`
  - `/proc`
  - `/sys`

Stage0 **must not** rely on:
- package managers
- dynamic linking to rootfs libraries
- distro-specific tooling
- busybox/bash/general toolboxes

All binaries included in stage0 must be self-contained and directly required to get smoo running.

---

## Kernel modules

Stage0 includes **only** the kernel modules required to:

- initialize the USB Device Controller (UDC)
- support USB gadget framework
- enable FunctionFS
- optionally enable `ublk` if required by smoo

Module selection rules:

- The required module set is provided by the DevPro
- Dependencies are resolved via `modules.dep`
- Modalias-based auto-discovery is explicitly out of scope for v0

If a required module is missing from the rootfs, stage0 generation must fail explicitly.

---

## Firmware handling

Firmware inclusion is conservative:

- Firmware is included only if explicitly referenced by selected modules
- Missing firmware may be treated as:
  - fatal (for known-critical firmware), or
  - warning (for optional firmware)

The policy decision is made by fastboop, not stage0 runtime logic.

---

## Init sequence (conceptual)

The `/init` entrypoint performs, in order:

1. Mount `/proc`, `/sys`, `/dev`
2. Set up logging to `/dev/console` (PID 1 behavior)
3. Load required kernel modules (in dependency order) from the host-provided list
4. Exec `smoo-gadget`

There is no init system.
There is no service supervision.
There is no fallback path.

If `smoo-gadget` exits, stage0 has failed.

---

## Error philosophy

Stage0 failures must be:

- deterministic
- early
- loud

Examples:
- missing kernel modules
- payload exceeds size limits
- incompatible kernel version
- smoo-gadget missing or not executable

Silent degradation is forbidden.

---

## Relationship to smoo

Stage0 exists **only** to get smoo running.

Once `smoo-gadget` is executing:
- fastboop’s responsibilities are complete
- all further boot, handoff, and filesystem logic belongs to smoo

Stage0 must not attempt to anticipate or replicate smoo behavior.

Advanced users or distro integrators can build their own initrd (e.g. with mkosi) containing shells/toolboxes and a different smoo variant if they need a debug path. fastboop’s stage0 remains the boring production path.

---

## Summary (the box)

- Stage0 = minimal initramfs
- Purpose = bring up USB gadget + exec smoo
- Inputs = DevPro + rootfs + boot constraints
- Outputs = ephemeral boot payload
- Lifetime = seconds

If stage0 is doing more than this:
it is wrong.
