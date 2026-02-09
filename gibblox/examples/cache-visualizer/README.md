# GreedyCBR Cache Visualizer

A minimal WASM test harness for observing `GreedyCachedBlockReader` behavior in browser contexts.

## Purpose

This tool helps debug and visualize the greedy cache warming behavior, specifically:
- Whether background workers (hot + 4 sweep) spawn and make progress
- Whether yielding logic (`yield_every_n_batches`) prevents task starvation
- Real-time observation of worker activity via tracing logs
- Debugging cooperative multitasking issues with `wasm_bindgen_futures::spawn_local`

## What it does

1. Accepts a rootfs URL (via input or URL fragment)
2. Constructs a `HttpBlockReader` → `CachedBlockReader` → `GreedyCachedBlockReader` pipeline
3. Spawns 5 background workers (1 hot worker + 4 sweep workers) using `spawn_local`
4. Captures all `tracing` output (TRACE, DEBUG, INFO levels)
5. Displays logs in real-time via requestAnimationFrame loop
6. Shows basic stats (total blocks, elapsed time, log count)

## Build

Ensure you have `wasm-pack` installed:

```bash
cargo install wasm-pack
```

Build the example:

```bash
# From gibblox/examples/cache-visualizer/
wasm-pack build --target web
```

This generates `pkg/` with the compiled WASM and JS bindings.

## Run

Serve the directory with any HTTP server:

```bash
# Python 3
python -m http.server 8080

# Or Node.js http-server
npx http-server -p 8080

# Or any other static file server
```

Then navigate to:
```
http://localhost:8080/
```

The default URL is `https://bleeding.fastboop.win/sdm845-live-fedora/20260208.ero` (~500MB).

You can also pass a URL via fragment:
```
http://localhost:8080/#https://example.com/rootfs.ero
```

## What to look for

### ✅ Workers are functioning correctly if:

- Log shows all 5 workers starting:
  ```
  [DEBUG] hot worker started
  [DEBUG] sweep worker started (forward)
  [DEBUG] sweep worker started (backward)
  [DEBUG] sweep worker started (forward)
  [DEBUG] sweep worker started (backward)
  ```
- Continuous stream of worker activity:
  ```
  [TRACE] hot worker warming window
  [TRACE] hot worker ensured cached
  [TRACE] sweep worker ensured cached
  ```
- Workers make steady progress through quarters
- No long pauses or stalls

### ❌ Workers are stalling if:

- Log shows workers start but then go silent
- Only a few "ensured cached" messages before stopping
- Sweep workers stop mid-quarter
- Long gaps between log entries

## Architecture

- **lib.rs**: Rust/WASM entrypoint with tracing capture
- **index.html**: Standalone HTML with embedded JS for RAF-based rendering
- **Tracing**: Dual-layer setup (console + custom log buffer capture)
- **State**: Thread-local storage for reader state and log buffer

## Greedy Config

The visualizer uses a web-optimized config:

```rust
GreedyConfig {
    yield_every_n_batches: Some(4),  // Yield every 4 batches
    hot_batch_size: 1024,             // ~512KB batches
    sweep_chunk_size: 2048,           // ~1MB chunks
    ..Default::default()
}
```

This should provide enough yielding for cooperative multitasking without excessive overhead.

## Future enhancements (Phase 2+)

- Add `CacheStats` API to gibblox-cache for aggregate metrics
- Visualize cache hit/miss ratio, blocks cached, in-flight count
- Add progress bars showing sweep worker quarter completion
- Phase 3: Block-level bitmap visualization with color-coded grid

## Troubleshooting

**"Failed to load" error:**
- Check browser console for detailed error
- Ensure URL is valid and supports CORS + Range requests
- Check network tab to see if HTTP requests are failing

**No logs appearing:**
- Check browser console for JS errors
- Verify WASM loaded successfully (check network tab)
- Try clearing OPFS cache (see browser DevTools → Application → Storage)

**Workers not spawning:**
- This is exactly what we're trying to debug!
- The logs will show if workers are created but not making progress
- Look for "worker started" messages vs "ensured cached" activity
