# fastboop single-page WebUSB example

This is the smallest browser-side shape of the unified fastboop flow:

1. request a WebUSB fastboot device;
2. probe it against built-in DevPros;
3. build stage0 from a raw EROFS rootfs URL with no BootProfile selection;
4. issue `fastboot boot`;
5. hand the same rootfs reader to smoo in a web worker.

The flow is non-mutating: it does not flash, erase, format, unlock, or switch
slots.

## Browser Requirements

Use a browser with WebUSB support from a secure context. `localhost` is treated
as secure by Chromium-family browsers, so serving this directory locally is fine.

The rootfs URL must be browser-readable with range requests. Same-origin files
served from this example directory are the easiest path while experimenting.

## Build Stage0 Sidecar

The web app fetches a target-device stage0 ELF sidecar at
`assets/stage0/fastboop-stage0-aarch64-unknown-linux-musl`.

```sh
cargo build --release --target aarch64-unknown-linux-musl -p fastboop-stage0
install -Dm755 \
  target/aarch64-unknown-linux-musl/release/fastboop-stage0 \
  examples/single-page-web/assets/stage0/fastboop-stage0-aarch64-unknown-linux-musl
```

The sidecar is ignored by git.

## Build Example Rootfs

The `rootfs/` mkosi config builds a minimal Fedora `arm64` tree and packs it as
`assets/rootfs/rootfs.ero` with `mkfs.erofs`.

```sh
mkosi -C examples/single-page-web/rootfs -f build
```

This requires mkosi, erofs-utils, Fedora package tooling, and whatever user-mode
emulation your host needs for foreign-architecture package scripts.

The mkosi output is intentionally a demo artifact path. For a real device, the
rootfs must contain a kernel, modules, and DTB matching the selected built-in
DevPro. The stage0 generator searches common kernel/module paths and DTB names
from the selected DevPro.

Generated rootfs artifacts are ignored by git.

## Build Web App

WebUSB types currently require `web_sys_unstable_apis`.
The `wasm-bindgen` CLI must match the workspace `wasm-bindgen` crate version.
For this workspace, use `wasm-bindgen-cli` `0.2.105`.

```sh
RUSTFLAGS='--cfg=web_sys_unstable_apis' \
  cargo build -p fastboop-web-single-page-example --target wasm32-unknown-unknown

wasm-bindgen \
  --target web \
  --out-dir examples/single-page-web/pkg \
  target/wasm32-unknown-unknown/debug/fastboop-web-single-page-example.wasm
```

Serve the directory and open `http://localhost:8080`:

```sh
python3 -m http.server 8080 --directory examples/single-page-web
```

## Inputs

The page defaults to local relative URLs:

- `assets/rootfs/rootfs.ero`
- `assets/stage0/fastboop-stage0-aarch64-unknown-linux-musl`

You can replace either with an absolute HTTP(S) URL. The example does not load
or select BootProfiles; `WebBootStage0Config.boot_profile` is always `None`.
