# Milestone 4: Wasm edge component (frontdoor-edge)

Build a WASI Preview 2 HTTP component that serves fastboop web releases with disk-based caching. This is the wasmCloud edge vertical slice — same web release serving logic as frontdoor-server, but running as a wasm component.

Working directory: `/var/home/sam/src/fastboop/infra/frontdoor`

## Architecture

The edge component is a simple caching reverse proxy:
1. Receive HTTP request
2. Parse version + file path from URL
3. Check local disk cache for the file
4. **Cache hit**: serve from disk with correct headers
5. **Cache miss**: fetch from origin (`https://www.fastboop.win/...`), write to disk cache, serve response

Uses `wstd` crate for ergonomic async HTTP handling and `std::fs` for disk caching (which maps to WASI filesystem on the wasm32-wasip2 target).

## Files to create

### `crates/frontdoor-edge/Cargo.toml`

```toml
[package]
name = "frontdoor-edge"
version.workspace = true
edition.workspace = true

[lib]
crate-type = ["cdylib"]

[dependencies]
frontdoor-core = { path = "../frontdoor-core", default-features = false }
wstd = "0.6"

[profile.release]
lto = true
opt-level = "s"
strip = true
```

Note: `frontdoor-core` is `no_std` and compiles fine as a dependency of the wasm component.

### `crates/frontdoor-edge/wit/world.wit`

```wit
package fastboop:frontdoor-edge;

world edge-cache {
  export wasi:http/incoming-handler@0.2.2;
}
```

The `wstd` crate handles the outgoing-handler and filesystem imports implicitly through its own bindings. We only need to declare the export.

### `crates/frontdoor-edge/src/lib.rs`

Implement a caching edge proxy:

```rust
use wstd::http::{Body, Client, Request, Response, StatusCode};
use std::path::{Path, PathBuf};
use std::fs;

const CACHE_DIR: &str = "/cache";
const ORIGIN: &str = "https://www.fastboop.win";

#[wstd::http_server]
async fn main(req: Request<Body>) -> Result<Response<Body>, wstd::http::Error> {
    let path = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    // Health check
    if path == "/healthz" {
        return Ok(Response::new("ok\n".into()));
    }

    // Parse version path
    match frontdoor_core::version::parse_version_path(path) {
        Some((version, relative)) => serve_cached(version, relative, path).await,
        None => {
            // Not a versioned path - proxy directly to origin
            proxy_to_origin(path).await
        }
    }
}
```

#### `serve_cached(version, relative, full_path)` logic:

1. Compute cache path: `{CACHE_DIR}/{version}/{relative}`
   - If `relative` is empty, use `index.html`
   - If `relative` ends with `/`, append `index.html`

2. Check if the cache file exists using `std::fs::metadata`

3. **Cache hit**:
   - Read the file with `std::fs::read`
   - Determine content-type from file extension using `frontdoor_core::content_type::content_type_for_ext`
   - Determine cache-control using `frontdoor_core::content_type::cache_control_for_ext`
   - Return response with body, content-type, cache-control, content-length headers

4. **Cache miss**:
   - Fetch from origin: `{ORIGIN}{full_path}`
   - If origin returns non-200, pass through the error status
   - Read the full response body
   - Create parent directories with `std::fs::create_dir_all`
   - Write to cache file with `std::fs::write`
   - Return the response with correct content-type and cache-control headers

#### Important implementation details:

- Use `wstd::http::Client::new()` for making outgoing requests
- The origin URL is `https://www.fastboop.win{path}` where path includes the leading `/`
- File extension extraction: split the relative path on `.` to get the extension for content_type_for_ext
- For SPA fallback: if the cache miss origin returns 200, cache it. If it returns 404/503, pass through without caching.
- Path safety: reject any relative path containing `..` components (return 400)
- Keep it simple — no LRU eviction in the edge component (that's a future enhancement)

### Updating workspace `Cargo.toml`

The workspace `members` already includes `crates/*` which catches frontdoor-edge. But `default-members` should NOT include it (it only builds for wasm32-wasip2). Verify the current config already excludes it:

```toml
default-members = ["crates/frontdoor-core", "crates/frontdoor-server"]
```

This is already correct from Milestone 1.

## Validation

```sh
cd /var/home/sam/src/fastboop/infra/frontdoor

# Verify default build still works (excludes edge)
cargo build

# Build the wasm component
cargo build -p frontdoor-edge --target wasm32-wasip2 --release

# Check for clippy warnings
cargo clippy -p frontdoor-edge --target wasm32-wasip2 -- -D warnings
```

All must pass. The wasm binary should appear at:
`target/wasm32-wasip2/release/frontdoor_edge.wasm`

## Important constraints
- The crate MUST be a `cdylib` — this produces a .wasm component
- Use `wstd` v0.6 for HTTP handling — do NOT use `wit-bindgen` directly
- The `#[wstd::http_server]` proc-macro replaces the need for manual `wit-bindgen::generate!`
- `std::fs` works on wasm32-wasip2 (maps to WASI filesystem calls)
- `frontdoor-core` is no_std but compiles fine as a dependency here
- Edition 2024
- Do NOT add `wasm32-wasip2` to the default build targets — it's built explicitly with `--target`
- Keep the component simple — this is a proof-of-concept vertical slice
