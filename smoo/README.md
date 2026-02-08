# smoo

**smoo** is an *inverted* mass‑storage USB protocol. The device sees a block device whose data comes from the host.

It uses the [ublk][] driver and [FunctionFS][ffs] to implement the device side of the protocol in user-space.  It can
make use of [FunctionFS DMA-BUF support][ffs-dmabuf] for a (nearly) zero-copy data path.

The host implementation supports `rusb` (for CLI and desktop apps) and WebUSB (for WASM + web targets).

It is implemented in async-first Rust, mostly by robots.

"UMS" backwards is "SMU". Which sounds like smoo. So there you go.

## Quickstart

```
# This project does not yet have a tagged release.
# You must build it from source. Twice.
# Once on the host computer, and once on the device connected over USB.
# (you might be missing some dependencies, see below)
cargo build

# On the device side:
sudo modprobe ublk-drv
sudo ./target/debug/smoo-gadget-cli --no-dma-buf

# on the host side
dd if=/dev/urandom of=random.img bs=4096 count=512
sudo ./target/debug/smoo-host-cli --file random.img

# the device will now see a /dev/ublkb0 device
# it will return data matching the contents of random.img on the host.
# you can confirm this easily:
# from host: sha256sum random.img
# from gadget: dd if=/dev/ublkb0 | sha256sum
```

### Development prerequisites

 * Alpine: `apk add linux-headers clang-dev`
 * Debian: `sudo apt build-dep ./`
 * Fedora: `sudo dnf build-dep --spec ./smoo.spec`
 * Others: idk pls expand here

## Status

This is an early prototype. It requires a recent Linux kernel with [FunctionFS][ffs], and [ublk][] support enabled. It
should work on any device with a UDC, and is tested primarily on SDM670/SDM845 pocket computers.

## Development

See **HACKING.md** for architecture and implementation details.

[ublk]: https://docs.kernel.org/block/ublk.html
[ffs]: https://docs.kernel.org/usb/functionfs.html
[ffs-dmabuf]: https://docs.kernel.org/usb/functionfs.html#dmabuf-interface
