# gibblox agent guide

gibblox is the read-only block access layer used by fastboop/smoo. It provides
`BlockReader`-based transport, caching, and composition primitives across native
and wasm targets.

the initial 0.0.1 target for fastboop is an EROFS hosted on a `Accept-Ranges:`
CDN. possibly wrapped in an iso9601. fastboop needs to read the erofs and
extract artifacts from it. smoo just wants to serve it as a block device.

## Session start (required)
- Read this file.
- Then read only the crates/docs relevant to the task.

## Read-on-demand index
- `crates/gibblox-core/*`: core traits/errors and cross-crate invariants.
- `crates/gibblox-http/*`: HTTP range reader behavior (native + wasm).
- `crates/gibblox-cache/*`: cache file format, cache read/write behavior.
- `crates/gibblox-cache-store-std/*`: native cache storage backend.
- `crates/gibblox-cache-store-opfs/*`: wasm OPFS cache storage backend.
- `crates/gibblox-paged-lru/*`: in-memory page cache semantics.
- `crates/gibblox-blockreader-messageport/*`: worker/main-thread bridging for wasm.

## Working rules
- Keep behavior read-only: no write/format/mutate semantics in `BlockReader` paths.
- Keep core crates platform-agnostic (`no_std + alloc` where intended).
- Isolate platform bindings (`std`, `wasm-bindgen`, filesystem/web APIs) in leaf crates.
- Prefer async-first implementations; justify any blocking path.
- Add `tracing` for operationally relevant new behavior.
- Keep diffs focused and reviewable.

## Validation
- Run targeted checks for touched crates during development.
  - `cargo fmt`
  - `cargo check -p <touched-crate>` (and key dependents)
  - `cargo test -p <touched-crate>` when relevant tests exist
- If a required check is skipped or fails, state it explicitly and why.

## Priority
- User direction wins.
- If this file conflicts with direct user instructions, follow the user and call out the deviation.
