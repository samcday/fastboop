# gibblox

`༼;´༎ຶ ۝ ༎ຶ༽つ ┳━┳`  pl0x gib bl0x.

gibblox fetches blocks of data. Maybe they're on another computer. Maybe they're wrapped in
GPT/MBR part tables. Or nested in an EroFS inside an ext4 inside an ISO9660. gibblox doesn't
give a flying fuck. gibblox just gives blocks.

This project is primarily intended to serve [smoo][] and [fastboop][]. Maybe you have some
other boring-ass use case that calls for some blocks. gibblox doesn't discriminate.
gibblox has a vision for a perfectly just and fair block-ocracy. You will be assimilated.
To gibblox you will always be just another block.

## Goals
- Provide a single, read-only `BlockReader` abstraction for block-aligned I/O.
- Support HTTP Range reads on native and wasm targets.
- Offer a file-backed cache layer with in-flight coalescing.
- Keep core crates `no_std + alloc` where practical.

## Crates
- `gibblox-core`: core traits and error types.
- `gibblox-iso9660`: ISO9660 file-backed block reader.
- `gibblox-http`: HTTP Range-backed block reader (native + wasm).
- `gibblox-cache`: cache layer and cache file format logic.
- `gibblox-cache-store-std`: XDG-friendly filesystem cache backend for native CLI/desktop apps.
- `gibblox-cache-store-opfs`: OPFS cache backend for wasm web apps.

## Usage (native)
```rust
use gibblox_core::{BlockReader, ReadContext};
use gibblox_cache::CachedBlockReader;
use gibblox_cache_store_std::StdCacheOps;
use gibblox_http::HttpBlockReader;

# async fn example() -> anyhow::Result<()> {
let source = HttpBlockReader::new("https://example.com/rootfs.img".parse()?, 4096).await?;
let cache = StdCacheOps::open_default_for_reader(&source).await?;
let source = CachedBlockReader::new(source, cache).await?;
let mut buf = vec![0u8; 4096];
source.read_blocks(0, &mut buf, ReadContext::FOREGROUND).await?;
# Ok(())
# }
```

## Tests
```bash
cargo test --workspace
```

## Status
Early-stage: API and crate layout are still moving. Expect breaking changes.

[smoo]: https://github.com/samcday/smoo
[fastboop]: https://github.com/samcday/fastboop
