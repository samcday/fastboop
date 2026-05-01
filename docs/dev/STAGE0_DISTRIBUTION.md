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

## CI and Release Flow

- `.github/workflows/ci.yml` builds stage0 static artifacts in a dedicated `stage0-static` matrix.
- `.github/workflows/release.yml` runs `stage0-preflight` before downstream packaging jobs.
- `stage0-preflight` verifies both required stage0 artifacts exist and are static/static-pie linked.
- Release asset fan-in includes stage0 binaries and `SHA256SUMS`.

## Downstream Packaging

- **Debian workflow**: downloads `fastboop-stage0-aarch64` artifact and exports `FASTBOOP_STAGE0_EMBED_PATH` before package build.
- **Alpine workflow**: same release-mode artifact flow via `FASTBOOP_STAGE0_EMBED_PATH`.
- **RPM spec**: exports `FASTBOOP_STAGE0_EMBED_PATH` when either:
  - `--define 'fastboop_stage0_embed_path /path/to/fastboop-stage0-aarch64-unknown-linux-musl'` is passed, or
  - `%{_sourcedir}/fastboop-stage0-aarch64-unknown-linux-musl` exists.

If no prebuilt stage0 path is provided, packaging falls back to nested sub-build behavior only when the local source repo includes the stage0 workspace sources.

## Armv7 Status

Issue #13 allows `armv7-unknown-linux-musleabihf` or documented equivalent. Current release gating intentionally uses x86_64+aarch64 only.

Reason: upstream `io-uring` target checks currently block reliable armv7 stage0 static artifact production in CI without additional architecture-specific work. Armv7 remains deferred follow-up scope.
