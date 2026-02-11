# smoo USB wire protocol

This document describes the on‑wire control/data protocol between the gadget
(device) and host. It is authoritative for message layout, sizes, and
constraints. All fields are little‑endian unless noted.

## Control plane (interrupt endpoints)

### Request (gadget → host)
Fixed 28 bytes.

| offset | size | field        | notes                                                     |
| ------ | ---- | ------------ | --------------------------------------------------------- |
| 0      | 1    | op           | `OpCode` (0=Read,1=Write,2=Flush,3=Discard)               |
| 1..3   | 3    | reserved     | zero                                                      |
| 4..8   | 4    | request_id   | u32, unique **per export** while in flight                |
| 8..12  | 4    | export_id    | u32, must be non‑zero                                     |
| 12..20 | 8    | lba          | starting logical block address                            |
| 20..24 | 4    | num_blocks   | block count (not bytes)                                   |
| 24..28 | 4    | flags        | currently zero                                            |

### Response (host → gadget)
Fixed 28 bytes.

| offset | size | field        | notes                                                     |
| ------ | ---- | ------------ | --------------------------------------------------------- |
| 0      | 1    | op           | echoes request op                                         |
| 1      | 1    | status       | 0=OK, else errno/host status byte                         |
| 2..3   | 2    | reserved     | zero                                                      |
| 4..8   | 4    | request_id   | echoes request request_id                                 |
| 8..12  | 4    | export_id    | echoes request export_id                                  |
| 12..20 | 8    | lba          | echoes request lba                                        |
| 20..24 | 4    | num_blocks   | block count serviced/attempted                            |
| 24..28 | 4    | flags        | currently zero                                            |

### CONFIG_EXPORTS (host → gadget, ep0 OUT)

bmRequestType: `0x41` (vendor, interface, OUT)  
bRequest: `0x02`  
Payload is versioned v0:

Header (8 bytes):
| offset | size | field    | notes                  |
| ------ | ---- | -------- | ---------------------- |
| 0..2   | 2    | version  | must be 0              |
| 2..4   | 2    | count    | number of entries      |
| 4..8   | 4    | flags    | must be zero           |

Entry (24 bytes) repeated `count` times:
| offset | size | field      | notes                                  |
| ------ | ---- | ---------- | -------------------------------------- |
| 0..4   | 4    | export_id  | u32, non‑zero, unique                  |
| 4..8   | 4    | block_size | bytes; power‑of‑two, 512..=65536       |
| 8..16  | 8    | size_bytes | total bytes; multiple of block_size    |
| 16..24 | 8    | reserved   | must be zero                           |

Payload length = 8 + 24 * count. Maximum count: 32.

Applying CONFIG_EXPORTS replaces the entire export set; anything not present
must be torn down by the gadget.

### IDENT (host → gadget, ep0 IN)

bmRequestType: `0xC1` (vendor, interface, IN)  
bRequest: `0x01`  
Payload: 8 bytes: `SMOO` magic + major/minor u16.

### STATUS (device → host, ep0 IN)

bmRequestType: `0xA1` (vendor, interface, IN)  
bRequest: `0x03`  
Payload: 16 bytes, versioned v0:
| offset | size | field        |
| ------ | ---- | ------------ |
| 0..2   | 2    | version (0)  |
| 2..4   | 2    | flags (bit0=export_active) |
| 4..8   | 4    | export_count |
| 8..16  | 8    | session_id   |

## Data plane (bulk endpoints)

Bulk payloads are block‑aligned and sized according to `num_blocks *
block_size` for the associated export. Each Request maps to exactly one
Response; Responses may be returned out‑of‑order. Multiple Requests per
export MAY be in flight simultaneously, and a host is expected to keep
queues full (e.g. queue_depth × export_count outstanding). Matching is done
by the composite key `(export_id, request_id)`.

Bulk ordering follows interrupt serialization per direction, filtered to
messages that carry payloads. For gadget → host, bulk IN payloads MUST be sent
in the order their Requests were written to interrupt IN (ignoring Requests
without payloads). For host → gadget, bulk OUT payloads MUST be sent in the
order their Responses were written to interrupt OUT (ignoring Responses
without payloads). Example: Requests [Read1, Write2, Read2, Write1] on
interrupt IN imply bulk IN order [Write2, Write1]; Responses [Write2, Write1,
Read1, Read2] on interrupt OUT imply bulk OUT order [Read1, Read2].

## Constraints & invariants

- `export_id` is the primary key for all control/data paths; `(export_id,
  request_id)` identifies an in‑flight I/O.
- `request_id` MUST NOT be reused for an export until its Response is
  observed; reuse may be monotonic or wraparound after completion.
- `num_blocks` is always in units of `block_size` for that export; neither
  Requests nor Responses carry byte lengths.
- All reserved fields must be zero; gadgets/hosts should reject payloads that
  violate version/flags/length checks.
- CONFIG_EXPORTS is an authoritative replace; partial/batch updates are not
  supported.

## Recovery & replay

- Requests are not timed out by the gadget.
- If the link resets or a new host session is observed (IDENT/CONFIG_EXPORTS),
  the gadget may drop transport state and replay outstanding ublk I/O. Duplicate
  Requests with the same `(export_id, request_id)` can appear on the wire.
- Unexpected responses may be ignored by the gadget.
