# Stage0 — fastboop v0

This document freezes the **v0 assumptions** for *stage0* in fastboop.

If you are implementing stage0 and feel the urge to add features:
stop.
Stage0 exists to do one job and then get out of the way.

---

## Purpose

**Stage0** is a productionized initramfs synthesized by fastboop whose purpose is to:

> Boot the device kernel, run embedded **smoo-gadget-app** under stage0 PID1 supervision, mount the exported root, and exec distro init.

Stage0 targets **well-tested, understood platforms** that we want to make boring. It assumes the host just booted it over the same USB link (e.g. `fastboot boot`) and should bring up smoo right away.

Stage0 is **not** a distro.
Stage0 is **not** an installer.
Stage0 is **not** a rescue or bring-up shell.
Stage0 is **not** persistent.

---

## Scope (hard limits)

Stage0 must do *only* the following:

1. Mount minimal virtual filesystems (`/proc`, `/sys`, `/dev`, `/run`)
2. Load a host-generated kernel module list deterministically (no `modprobe`)
3. Configure gadget stack + FunctionFS, then spawn embedded `smoo-gadget-app`
4. Wait for smoo-exported block device and mount root (`erofs` lower + tmpfs `overlay` upper)
5. Exec distro init (`/lib/systemd/systemd` or `/sbin/init`)

Anything beyond this is out of scope for v0.

---

## Non-goals

Stage0 must **not**:

- Touch persistent storage
- Partition disks
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
   - Kernel command line additions

2. **Rootfs artifact**
   - Source of the kernel image
   - Source of kernel modules (`/usr/lib/modules/<kver>` or equivalent)

3. **Boot constraints**
   - Maximum payload sizes
   - Accepted boot image format (e.g. android boot.img)

---

## Userspace contents

Stage0 userspace is intentionally hermetic and minimal.

It contains:

- `fastboop-stage0` (running as PID 1)
- embedded `smoo-gadget-app` runtime
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

Stage0 does not include firmware. Any firmware needed beyond the minimal UDC
path must be provided in an `--augment` cpio or in the main rootfs.

---

## Init sequence (conceptual)

The `/init` entrypoint performs, in order:

1. Mount `/proc`, `/sys`, `/dev`
2. Set up logging to `/dev/kmsg` (PID 1 behavior)
3. Load required kernel modules (in dependency order) from the host-provided list
4. Configure gadget + spawn `smoo-gadget-app`
5. Wait for exported block device and mount overlay root
6. Exec distro init

There is no full init system inside stage0.
There is explicit supervision of the gadget child process.
There is no interactive fallback path.

If the gadget child exits unexpectedly before handoff, stage0 has failed.

---

## OSTree deployment handoff (v0)

If kernel cmdline contains `ostree=`, stage0 performs an OSTree-compatible
handoff before execing distro init:

- resolve `ostree=` in the mounted root and require it to point at a deployment
  symlink target
- switch root into the resolved deployment path
- bind-mount physical root onto the deployment's `/sysroot`
- bind-mount stateroot `/var` onto the deployment's `/var`
- bind-mount `/boot` into deployment `/boot` when the shared-boot layout is
  detected (`/boot/loader` symlink)

This compatibility mode is intentionally limited to `ostree=` path resolution
and mount layout. It does not parse `prepare-root.conf` and does not implement
composefs policy.

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
- embedded smoo runtime failing before root handoff

Silent degradation is forbidden.

---

## Relationship to smoo

Stage0 exists **only** to get smoo running.

Once stage0 has launched smoo and switched root:
- smoo continues serving the block export path
- userspace boot and system lifecycle belong to the booted distro

Stage0 must not attempt to anticipate or replicate smoo behavior.

Advanced users or distro integrators can build their own initrd (e.g. with mkosi) containing shells/toolboxes and a different smoo variant if they need a debug path. fastboop’s stage0 remains the boring production path.

---

## Summary (the box)

- Stage0 = minimal initramfs
- Purpose = bring up USB gadget, launch embedded smoo, mount root, exec init
- Inputs = DevPro + rootfs + boot constraints
- Outputs = ephemeral boot payload
- Lifetime = seconds

If stage0 is doing more than this:
it is wrong.
