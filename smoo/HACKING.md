# smoo — architectural & contributor notes

This document defines the internal architecture and invariants that all contributors + agents must follow.

---

## 1. Architecture Overview

smoo consists of two halves:

* **Host** (desktop/CLI/web): provides block data to be read/written.
* **Gadget** (device with UDC): exposes a synthetic block device via **ublk**, serviced entirely over USB using **FunctionFS**.

USB interface has **4 endpoints**:

| Endpoint      | Direction     | Purpose             |
| ------------- | ------------- |---------------------|
| Bulk OUT      | host → gadget | read payloads       |
| Bulk IN       | gadget → host | write payloads      |
| Interrupt OUT | host → gadget | control: `Response` |
| Interrupt IN  | gadget → host | control: `Request`  |

Control messages:

* ≤ 1024 bytes
* fixed-size LE structs keyed by `(export_id, request_id)`
* pipelined; multiple requests may be in flight per export
* Responses may return out-of-order; request_id used for matching

Bulk transfers:

* carry payload bytes
* must be block-aligned

---

## 2. End-to-End I/O Flow

1. ublk on gadget emits a command
2. gadget → host: send `Request` on interrupt IN
3. host dispatches to `BlockSource`
4. host performs bulk transfers as needed
5. host → gadget: send `Response` on interrupt OUT
6. gadget completes ublk request

**Invariant:** each ublk request maps to one logical Request/Response pair.
Gadgets MAY replay a Request after a link/session reset; the wire may see
duplicates, but ublk completes exactly once. Hosts/gadgets SHOULD keep queues
full: multiple outstanding requests per export and across exports are expected
(bounded by queue depth), using `(export_id, request_id)` as the uniqueness key
while in flight.

---

## 3. ublk Behaviour (gadget side)

* registers a ublk queue with:

  * **logical block size** (must match BlockSource)
  * **queue depth** (configurable later)
* maps each ublk command → protocol Request
* completes requests deterministically

Error handling:

* transport failures or link loss → keep ublk I/O outstanding; park in-flight
  requests and replay when the link/session returns (no timeouts)
* export removal or shutdown → complete outstanding I/O with `errno`
* fatal errors → gadget tears down ublk cleanly

---

## 4. USB Protocol (control + data)

Protocol handshake (`Ident`):
* a setup IN message (from gadget -> host)
* fixed-size, LE
* fields:
  * protocol version (major + minor)

Control-plane (`Request` / `Response`):

* fixed-size, LE
* fields:

  * export_id
  * op: read/write/flush/discard
  * request_id (unique per export while in flight)
  * LBA
  * byte length (block-aligned)
  * flags (future)
* MUST fit in one interrupt transfer
* Responses carry the same `(export_id, request_id)` and MAY arrive out-of-order

Data (bulk):

* write path: host → gadget (bulk OUT)
* read path: gadget → host (bulk IN)
* MUST send exactly the payload size described in Request
* Bulk ordering follows interrupt serialization per direction, filtered to
  payload-bearing messages. For gadget → host, bulk IN payloads must appear in
  the same order as their corresponding Requests were written to interrupt IN.
  For host → gadget, bulk OUT payloads must appear in the same order as their
  corresponding Responses were written to interrupt OUT.

---

## 5. DMA-BUF Fast Path

If FunctionFS DMA-BUF support exists, the gadget:

* allocates dma-buf buffers from system dma-heap
* attaches them to FunctionFS' bulk endpoint file descriptors (`FUNCTIONFS_DMABUF_ATTACH` ioctl)
* initiates read/write transfers using these buffers (`FUNCTIONFS_DMABUF_TRANSFER` ioctl)
* copies the dma-bufs dma sync fences after transfer (`DMA_BUF_IOCTL_EXPORT_SYNC_FILE`)
* `poll`s the fence to detect completion

Properties:

* gracefully falls back if system dma-heap not present, or buffer attachments to FunctionFS endpoints fail
* nearly zero-copy
* lower CPU load
* higher throughput

---

## 6. Fallback Path (non-DMA-BUF)

If DMA-BUF fast path is unavailable:

* gadget uses classic `read()`/`write()` on bulk ep fds
* incurs at most one extra copy
* MUST preserve identical semantics to DMA-BUF mode

---

## 7. Host-Side Abstractions

### 7.1 `Transport`

Responsible for shuttling control + payload data.

**Requirements:**

* MUST correlate interrupt + bulk transfers by `(export_id, request_id)`; do not
  drop or duplicate
* MUST allow pipelining (multiple outstanding Requests per export); Responses
  may be delivered out-of-order
* MUST preserve bulk ordering as defined in the USB protocol section above
* MUST be cancellation-safe
* MUST be async-first (Tokio)
* MAY block internally if safe
* Each `read_bulk` / `write_bulk` MUST correspond to one payload for one
  `(export_id, request_id)` pair

Implementations:

* `smoo-host-transport-rusb`
* `smoo-host-transport-webusb`

### 7.2 `BlockSource`

Backs actual storage.

**Requirements:**

* MUST expose `block_size()`
* MUST match gadget ublk block size
* MUST support async `read()` / `write()` of block-aligned regions
* SHOULD avoid copies
* MAY wrap:

  * files
  * raw devices
  * future WebUSB fetch backends

---



## 7.3 Gadget Lifecycle & Recovery (EP0 + ublk)

### EP0 Control Protocol

Two vendor control requests:

* **IDENT (IN)**: idempotent, side‑effect‑free. Returns protocol version and capability flags.
* **CONFIG_EXPORTS (OUT)**: authoritative replace of the complete export set. Payload describes all exports for this host session.

### Export Mapping

Each export entry includes:

* `export_id` (u32)
* `block_size`
* `size_bytes`
* flags (optional)

Gadget maps `export_id` → ublk device. CONFIG_EXPORTS creates/removes ublk devices to match payload. Successful CONFIG_EXPORTS MUST update the state file.

### Gadget Crash Recovery

On restart:

* If state file exists → RECOVERING: reattach ublk devices. If any fail, delete state file → COLD.
* If no state file → COLD.
* Recovery MUST NOT remove/modify ublk devices until complete.

### Host Restart Semantics

Host restart = new session:

* Host re-issues IDENT + CONFIG_EXPORTS.
* Gadget treats this as a session boundary for the data plane: forget on-wire
  in-flight requests/responses and replay any outstanding ublk I/O when the
  link returns.
* Gadget only rebuilds ublk devices when the export list/geometry changes;
  otherwise keep existing devices and update the state file to match the new
  CONFIG_EXPORTS payload.

### Transport Loss & Replay

* Requests are never timed out by the gadget.
* Link loss or data-plane I/O errors cause the gadget to drop transport state,
  park in-flight ublk requests, and wait for the link to recover.
* Once the host re-establishes the session (IDENT/CONFIG_EXPORTS) and the link
  is Online, parked requests are replayed with the same `(export_id, request_id)`.

### FunctionFS Events

Gadget MUST drain ep0 events continuously:

* **BIND/UNBIND**
* **ENABLE/DISABLE**
* **SUSPEND/RESUME**
* **SETUP** (IDENT/CONFIG_EXPORTS)

Failure to service ep0 promptly leads to EP0 STALL + possible gadget reset.


## 8. Development & Testing

* Toolchain: Rust stable (MSRV 1.88)
* Logging: `tracing`
* Tests: `cargo test --all`

  * uses mock transports
  * USB loopback via `dummy_hcd`
* CLIs are thin wrappers; logic in libraries
* Agents MUST uphold:

  * cancellation safety
  * `(export_id, request_id)` matching guarantees
  * all invariants in this document
