# SMOO Wireshark Lua dissector

This Lua postdissector annotates USB captures with SMOO protocol fields and
tries to match bulk transfers to Requests.

## Install

Option A: Wireshark GUI
- Preferences -> Protocols -> Lua -> enable Lua
- Preferences -> Lua -> "Personal Lua Plugins" and add this file

Option B: tshark/wireshark CLI
- `tshark -X lua_script:tools/wireshark/smoo.lua -r /path/to/capture.pcapng`
- `wireshark -X lua_script:tools/wireshark/smoo.lua /path/to/capture.pcapng`

## Capture

Typical Linux capture with usbmon:
- `sudo modprobe usbmon`
- `lsusb -t` to find the bus
- `sudo tcpdump -i usbmon<bus> -w /tmp/smoo.pcapng`

## Defaults

The script assumes the default endpoint addresses:
- interrupt IN: 0x81
- interrupt OUT: 0x01
- bulk IN: 0x82
- bulk OUT: 0x02

You can override these in `tools/wireshark/smoo.lua` by editing the `CONFIG`
section.

The script also assumes a default block size of 4096 bytes, but will learn
export block sizes if it sees a CONFIG_EXPORTS control transfer in the capture.

## Notes

Bulk payloads are not tagged on the wire, so the script infers which Request a
bulk transfer belongs to by order/length. This is useful for spotting reordering
or size mismatches, but if all reads are the same size it may not reveal a swap.
