# smoo-host-core

This is a no-std crate that handles the main "host driver loop".

The `Transport` trait provides a generic interface to push/pull data to/from the USB device (there is a
`RusbTransport` impl in `smoo-host-transport-rusb` and a `WebUsbTransport` in `smoo-host-transport-webusb`).

The `BlockSource` trait abstracts the underlying block data. `smoo-host-blocksources` provides simple 
implementations backed by files and block devices. `smoo-host-blocksource-http` dispatches to a simple HTTP API (where
the basic read path translates to CDN-friendly `Range:` requests and can run in the browser using `fetch`) and can be
composed with `smoo-host-blocksource-indexeddb` to keep the downloaded blocks cached locally.

`SmooHost` is the core driver that ties both traits together. It performs the USB Ident handshake through the selected
`Transport`, pulls `Request` messages, issues the matching operations on a `BlockSource`, and responds with protocol
`Response`s. The implementation is fully async + `no_std`, so it can run on WASM (with `bindgen-futures`) or on
desktop CLIs using Tokio/async-std runtimes.
