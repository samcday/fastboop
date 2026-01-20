# DevPro (device profiles) — fastboop v0

This document freezes the **v0 assumptions** for DevPro in fastboop.

If you are reading this while implementing code: you are allowed to stop thinking.
This is the box. Stay inside it.

---

## Example DevPro (v0 schema sketch)

Target shape for a single fastboot-boot DevPro:

```yaml
id: "acme-phone-1"
display_name: "Acme Phone 1"

match:
  protocol: fastboot
  usb:
    vendor_id: 0x18d1
    product_ids: [0x0d02]

probe:
  - fastboot.getvar: product
    equals: "acme1"
  - fastboot.getvar: secure
    exists:

boot:
  fastboot-boot:
    bootimg:
      header_version: 2
      page_size: 4096
      base: 0x00000000

    limits:
      max_kernel_bytes: 16777216
      max_initrd_bytes: 67108864
      max_total_bytes: 83886080

    kernel:
      encoding:
        type: image+dtb
        compress: gzip
        append_dtb: true

    cmdline_append: "console=ttyMSM0,115200n8"
```

This is descriptive: it states what the vendor bootloader accepts and how to prove identity. It does not add logic beyond match → probe → fastboot RAM boot.

---

## Purpose

A **DevPro** describes **how a specific class of device can be booted non‑mutatingly** from a vendor bootloader over USB.

A DevPro answers exactly one question:

> “If I am holding a USB handle to a device in vendor boot mode, can I safely boot *something* into RAM, and if so, how?”

A DevPro does **not** describe:
- what OS or distro is booted
- how installation works
- how persistent storage is modified
- how stage0 is implemented internally

---

## Non‑mutating invariant (hard rule)

fastboop **must never** perform persistent actions.

Disallowed forever in v0:
- `flash`, `erase`, `format`
- slot changes (`set_active`)
- unlock / lock
- AVB / verity toggles
- vendor `oem` commands

Allowed:
- read‑only probe commands (e.g. `fastboot getvar`)
- ephemeral RAM boot (`fastboot boot`)

If a device cannot be booted this way, it is **out of scope**.

---

## DevPro responsibilities

A DevPro contains:

1. **Match rules**
   - How to cheaply identify candidate devices (USB VID/PID, protocol)

2. **Probe rules**
   - How to confirm the exact device identity
   - Optional capture of informational fields (bootloader version, product name)

3. **Boot description**
   - Which non‑mutating boot mechanism is used
   - What payload format is accepted
   - Size / layout constraints enforced by the vendor bootloader

That is all.

---

## What DevPro explicitly does *not* contain

A DevPro must **not** include:

- rootfs selection logic
- distro‑specific behavior
- package names
- kernel module lists
- stage0 construction rules
- user choices (desktop environment, locale, etc.)

Those belong elsewhere.

---

## v0: single boot mechanism

In v0, each DevPro describes **exactly one** boot mechanism.

There is no `oneOf`, no fallback matrix, no multi‑format negotiation.

If a device needs a different format later, that is a **breaking schema change**.

---

## v0 boot mechanism: fastboot RAM boot

The only supported boot mechanism in v0 is:

- **Fastboot ephemeral boot** (`fastboot boot <payload>`)

This implies:
- the payload is staged entirely in RAM
- control transfers immediately to the payload
- the vendor bootloader remains unmodified

---

## Payload description (conceptual)

A DevPro describes the **outer container format** accepted by the device.

For v0, this is assumed to always be an **Android boot image**.

Inner details (kernel encoding, compression) are nested *under* the container,
because they describe how the kernel is placed *inside* the boot image.

Conceptual shape:

```yaml
boot:
  method: fastboot-boot

  payload:
    android_bootimg:
      header_version: 2
      page_size: 4096
      base: 0x00008000        # only if relevant

      limits:
        max_kernel_bytes: ...
        max_initrd_bytes: ...
        max_total_bytes: ...

      kernel:
        encoding:
          type: image+dtb
          compress: gzip
          append_dtb: true

      initrd:
        compress: gzip
```

This schema describes **what the device accepts**, not how fastboop builds it.

---

## Match and probe semantics

### Match

Match rules are cheap filters applied before opening the device:

- protocol (e.g. fastboot)
- USB VID/PID pairs
- optional interface constraints

Match rules are used to:
- build WebUSB `requestDevice()` filters
- limit libusb enumeration
- reduce unnecessary probe attempts

### Probe

Probe rules are ordered, fail‑fast checks:

- typically `fastboot getvar <name>`
- expected values must match
- probes may capture informational strings

If any probe step fails, the DevPro does not match the device.

Probe steps must be read‑only.

---

## Chaining and re‑enumeration (future)

Some devices may require chaining into a better bootloader (e.g. U‑Boot or lk2nd) first.

This is **not required for v0**, but DevPro design must not block it.

Assumption:
- fastboop core is a state machine
- devices may disappear and re‑enumerate
- DevPro matching/probing may occur multiple times per session

Chaining is expressed as a boot *session*, not by mutating the device.

---

## Error handling philosophy

DevPro failures should be:
- explicit
- explainable
- surfaced to the caller/UI

Examples:
- “Device matches VID/PID but failed probe”
- “Payload exceeds max_total_bytes”
- “Boot mechanism not supported by this profile”

Silent fallback is forbidden.

---

## Summary (the mental model)

- DevPro = **how to boot a device safely**
- Rootfs + stage0 = **what is booted**
- fastboop = **glue between vendor bootloader and smoo**
- smoo = **everything after `/init`**

If you find yourself wanting to add more logic to DevPro:
stop.
You are probably about to violate v0.
