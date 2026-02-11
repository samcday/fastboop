# WARNING: UNTESTED, VIBE-DRIVEN PLAYBOOK

This document is **untested** and **100% vibed out**. Question every step, verify every assumption, and treat this as a starting point rather than ground truth.

# SMOO Wireshark Capture and Dissection Guide

This guide explains how to capture USB traffic for a smoo session, decode it with the Lua dissector, and export analysis-friendly artifacts.

The dissector referenced here is:

- `smoo/tools/wireshark/smoo.lua`

## 1) Capture a Session

Start capture before triggering a session so `CONFIG_EXPORTS` is included in the trace (this lets the dissector learn per-export block sizes).

```bash
sudo modprobe usbmon
lsusb -t
# choose bus number from lsusb -t output, example: 3
BUS=3
TS=$(date +%Y%m%d-%H%M%S)
sudo dumpcap -i "usbmon${BUS}" -s 0 -B 64 -w "/tmp/smoo-${TS}.pcapng"
```

Notes:

- Use `usbmon0` instead of `usbmon<bus>` if bus assignment may change during the run.
- Keep one file per repro run (`good` and `bad` separately).
- Stop capture immediately after the observed failure/hang.

## 2) Decode with Lua Dissector

```bash
tshark -r /tmp/smoo-<ts>.pcapng \
  -X lua_script:/var/home/sam/src/fastboop/smoo/tools/wireshark/smoo.lua \
  -Y "smoo"
```

If your endpoint addresses differ from defaults, edit `CONFIG` in:

- `smoo/tools/wireshark/smoo.lua`

Default assumptions in the dissector:

- interrupt IN: `0x81`
- interrupt OUT: `0x01`
- bulk IN: `0x82`
- bulk OUT: `0x02`

## 3) Fast Triage Filters

In Wireshark display filter or tshark `-Y`, use:

- `smoo.bulk.len_mismatch == 1`
- `smoo.bulk.orphan == 1`
- `smoo.response.status > 0`
- `smoo.request.request_id == 0 || smoo.response.request_id == 0 || smoo.bulk.request_id == 0`

These are useful to quickly spot:

- mismatched bulk lengths
- bulk transfers with no inferred request mapping
- explicit non-zero response status
- first-request path behavior

## 4) Export CSV for Model-Friendly Analysis

```bash
tshark -r /tmp/smoo-<ts>.pcapng \
  -X lua_script:/var/home/sam/src/fastboop/smoo/tools/wireshark/smoo.lua \
  -Y "smoo" \
  -T fields \
  -e frame.number -e frame.time_epoch -e usb.bus_id -e usb.device_address \
  -e usb.endpoint_address -e usb.transfer_type -e usb.data_len \
  -e smoo.request.op -e smoo.request.export_id -e smoo.request.request_id -e smoo.request.lba -e smoo.request.num_blocks \
  -e smoo.response.op -e smoo.response.status -e smoo.response.export_id -e smoo.response.request_id \
  -e smoo.bulk.dir -e smoo.bulk.export_id -e smoo.bulk.request_id -e smoo.bulk.expected_len -e smoo.bulk.actual_len \
  -e smoo.bulk.len_mismatch -e smoo.bulk.orphan -e smoo.note \
  -E header=y -E separator=, -E quote=d > /tmp/smoo-<ts>-events.csv
```

## 5) Bundle Artifacts per Repro

For each repro run, keep a folder with:

- raw capture: `*.pcapng`
- dissector export: `*-events.csv`
- host trace logs (for web path, include `?log=trace` runs)
- gadget logs (kernel/serial)
- metadata file with:
  - git commit SHA
  - browser + version
  - VID/PID
  - scenario description (`good`/`bad`, web/desktop, etc.)

This combination makes diffing between successful and failing sessions much easier.

## 6) Practical Caveats

- Bulk payloads are not tagged on the wire; mapping is inferred by order/length.
- If many reads have identical lengths, mis-association can be hidden.
- For forensic runs, lower queue depth/concurrency if possible to make ordering easier to reason about.

## 7) LBA Correlation Tip for Kernel Sector Errors

If kernel logs report sector-level failures (512-byte sectors), derive protocol LBA with:

```text
proto_lba = sector / (block_size / 512)
```

Example: with `block_size=4096`, divide sector by `8`.
