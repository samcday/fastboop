# web-host

Minimal WebUSB host demo for smoo. It wires the existing WebUSB transport + HTTP blocksource into a tiny browser UI.

## Build

```
rustup target add wasm32-unknown-unknown
wasm-pack build --target web examples/web-host
```

## Run

1. Serve `examples/web-host` over HTTP (e.g. `cd examples/web-host && python -m http.server 8080`).
2. Open `http://localhost:8080/` in a browser that supports WebUSB.
3. Enter an HTTP backing URL (must support Range requests) and click **Connect**.
4. Approve the WebUSB device prompt. The demo will start pumping requests via `requestAnimationFrame`.

The demo stays intentionally minimal—no caching, no workers, and a single export.
