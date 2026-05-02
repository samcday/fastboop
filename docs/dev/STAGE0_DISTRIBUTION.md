# Stage0 Distribution

This document defines how static stage0 binaries are produced and consumed across CI, release assets, and downstream packaging.

## Artifact Contract

Release assets include first-class stage0 static binaries:

- `fastboop-stage0-x86_64-unknown-linux-musl`
- `fastboop-stage0-aarch64-unknown-linux-musl`

For tag `vX.Y.Z` (or `vX.Y.Z-rc.N`), assets are published alongside other release artifacts:

- `https://github.com/samcday/fastboop/releases/download/vX.Y.Z/fastboop-stage0-x86_64-unknown-linux-musl`
- `https://github.com/samcday/fastboop/releases/download/vX.Y.Z/fastboop-stage0-aarch64-unknown-linux-musl`

Checksums are recorded in release `SHA256SUMS`.

## Generator Input

`crates/fastboop-stage0-generator` does not build, download, or embed stage0 at Cargo build time.

Callers supply the target-device `fastboop-stage0` bytes when synthesizing an initrd. If an existing initrd already contains `/init`, the supplied stage0 bytes are optional. Otherwise, generation fails fast instead of silently producing an initrd without PID1.

This keeps Cargo builds policy-friendly and avoids nested Cargo invocations from library build scripts.

## CLI Loading

The CLI loads stage0 at runtime before calling the generator.

Explicit controls:

- `--stage0 <PATH>` on `fastboop boot` and `fastboop stage0`
- `FASTBOOP_STAGE0_PATH=/path/to/fastboop-stage0`

Prebuilt CLI release binaries include the AArch64 musl stage0 as a final fallback so `cargo binstall fastboop-cli` works without a sidecar file. Source builds keep this fallback disabled unless `fastboop-cli` is built with `--features embed-stage0` and `FASTBOOP_STAGE0_EMBED_PATH` points at the stage0 binary during compilation.

Local development fallback paths include:

- `target/aarch64-unknown-linux-musl/release/fastboop-stage0`
- `target/aarch64-unknown-linux-gnu/release/fastboop-stage0`
- `target/release/fastboop-stage0`
- `target/debug/fastboop-stage0`

Package-style sidecar paths include target-device payload locations under:

- `/usr/lib/fastboop/stage0/`
- `/usr/local/lib/fastboop/stage0/`
- `/app/lib/fastboop/stage0/`

Release tarballs may also place `fastboop-stage0-*` beside `fastboop` or under a sibling `stage0/` directory.

## CI and Release Flow

- `.github/workflows/ci.yml` builds stage0 static artifacts in a dedicated `stage0-static` matrix.
- `.github/workflows/release.yml` runs `stage0-preflight` before downstream packaging jobs.
- `stage0-preflight` verifies both required stage0 artifacts exist and are static/static-pie linked.
- Release asset fan-in includes stage0 binaries and `SHA256SUMS`.

## Downstream Packaging

Strict package builds should install stage0 as a data payload for target devices, not as a host executable helper.

Preferred sidecar layout:

- `/usr/lib/fastboop/stage0/fastboop-stage0-aarch64-unknown-linux-musl`
- `/usr/lib/fastboop/stage0/fastboop-stage0-aarch64-unknown-linux-gnu` when a distro build intentionally produces a GNU-linked payload

Flatpak builds use the same layout under `/app/lib/fastboop/stage0/`.

The sidecar payload target does not need to match the host package architecture.

## Armv7 Status

Issue #13 allows `armv7-unknown-linux-musleabihf` or documented equivalent. Current release gating intentionally uses x86_64+aarch64 only.

Reason: upstream `io-uring` target checks currently block reliable armv7 stage0 static artifact production in CI without additional architecture-specific work. Armv7 remains deferred follow-up scope.
