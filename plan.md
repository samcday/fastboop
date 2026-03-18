# fastboop pipeline content-digest + local-artifact plan

## Context

We want content-addressed local short-circuiting for boot/runtime paths while keeping optimize focused and deterministic.

Core design decisions:

- Reintroduce content digest metadata in the main pipeline schema.
- Keep `bootprofile optimize` focused on a single compiled boot profile input (no channel-mode optimize).
- Require `content` metadata on terminal transport stages (`http`, `casync`, `file`).
- Keep `content` optional on wrapper stages (`xz`, `android_sparseimg`, `mbr`, `gpt`).
- Add `--local-artifact <PATH>` matching by `(sha512,size)` to short-circuit stage materialization.

## Goals

1. Make terminal stages self-describing and verifiable via required content metadata.
2. Enable `--local-artifact` replacement by digest without fragile source-id conventions.
3. Use optimize pass to hydrate missing wrapper-stage digest metadata and acceleration hints.
4. Keep wire format v0-breaking and clean (no compatibility shims).
5. Keep `bootprofile create` ergonomic via a simple `--optimize` delegation flow.

## Non-goals

- No `etag` support in this phase.
- No optimize-over-channel mode in this phase.
- No migration aliases for old schema variants.

## Schema changes

### New content metadata object

Add a reusable content descriptor for pipeline stages:

- `digest: String` (format `sha512:<hex>` for 0.0.1)
- `size_bytes: u64`

Validation rules:

- `digest` must use `sha512:` prefix.
- Hex payload must be exactly 128 lowercase hex chars (or canonicalized to lowercase at encode time; pick one and enforce consistently).
- `size_bytes` must be present.

### Placement

- Required on terminal source structs:
  - `PipelineSourceHttp`
  - `PipelineSourceCasync`
  - `PipelineSourceFile`
- Optional on wrapper structs:
  - `PipelineSourceXz`
  - `PipelineSourceAndroidSparseImg`
  - `PipelineSourceMbr`
  - `PipelineSourceGpt`

### Validation behavior

- `validate_pipeline` hard-fails if any terminal stage is missing `content`.
- Wrapper-stage `content` is optional and validated when present.

## DigestingReader design

Introduce a `DigestingReader` wrapper (std path) that composes with existing `BlockReader` layering.

Responsibilities:

- Wrap a reader and track SHA-512 over bytes returned by reads.
- Track byte count observed.
- Expose finalized `PipelineSourceContent` (`sha512:<hex>`, `size_bytes`) after full traversal.

Design intent:

- During optimize, every pipeline stage can be wrapped.
- A top-level full read naturally hydrates digest state for all wrapped inner stages.

## Optimize behavior

`bootprofile optimize` remains bootprofile-only and computes aftermarket hints/metadata.

Flow:

1. Decode + validate compiled boot profile.
2. Traverse rootfs/kernel/dtbs pipelines.
3. Wrap stages with `DigestingReader` and fully consume each selected pipeline output.
4. Write back hydrated optional `content` for wrapper stages that were missing.
5. Compute/update acceleration hints (existing sparse index hints + any new digest-oriented hints).
6. Emit pipeline-hints sidecar output.

Notes:

- Terminal stage required content must still be present in source profile.
- Optimize hydrates additional data; it is not a substitute for missing required terminal metadata.

## Runtime local artifact short-circuit

CLI flag:

- `--local-artifact <PATH>` (repeatable).

Behavior:

1. Canonicalize each path.
2. Hash full file once to `(sha512,size_bytes)`.
3. Build resolver map keyed by digest+size.
4. During `open_artifact_source`, if current stage has matching `content`, replace with `FileReader(local_path)`.

Properties:

- Works regardless of source type when stage metadata exists.
- Can skip whole remote/decompression/subpartition subtrees when matching at a higher stage.

## `bootprofile create --optimize`

Reintroduce a simple optimize toggle on create:

- `bootprofile create ... --optimize`

Behavior:

1. Run normal create and write compiled `.fbp` output.
2. Delegate to optimize flow for the newly written profile.
3. Produce sidecar hints alongside boot profile output (naming policy to be implemented consistently, e.g. explicit `--optimize-output` or deterministic sibling path).

## Implementation phases

### Phase 1: schema + validation (gibblox)

1. Add `PipelineSourceContent` type and serde/bin support.
2. Add required/optional fields to pipeline stage structs.
3. Update `validate_pipeline` with hard-fail required terminal content checks.
4. Add unit tests for digest format + requiredness.

### Phase 2: digesting reader + optimize hydration (fastboop + gibblox as needed)

1. Implement `DigestingReader` utility.
2. Integrate in optimize traversal for rootfs/kernel/dtbs pipelines.
3. Persist hydrated wrapper-stage content metadata during optimize pass.
4. Keep sparse hint generation intact.

### Phase 3: local artifact matching (fastboop CLI)

1. Add `--local-artifact` to `boot`, `stage0`, and `bootprofile optimize`.
2. Build local digest map at command start.
3. Integrate stage-level digest match in `ArtifactReaderResolver::open_artifact_source`.
4. Add tracing for short-circuit events.

### Phase 4: create delegation UX

1. Add `--optimize` to `bootprofile create`.
2. Delegate to optimize after successful create write.
3. Ensure deterministic sidecar output location/flags.

## Test plan

### Schema tests

1. Terminal stage missing `content` fails validation.
2. Wrapper stage missing `content` is accepted.
3. Invalid digest prefix/length/charset fails.
4. Valid `sha512:<hex>` passes.

### Optimize tests

1. Optimize computes digests for wrapped outputs and hydrates optional wrapper content.
2. Sparse hint behavior remains correct.
3. Output hints remain deterministic and duplicate-identity-safe.

### Runtime tests

1. Matching `--local-artifact` short-circuits stage to `FileReader`.
2. Non-match falls back to normal source handling.
3. Multiple local artifacts and duplicate digest handling are deterministic.

## Validation commands (per touched area)

- `cargo fmt`
- `cargo check -p gibblox-pipeline`
- `cargo test -p gibblox-pipeline`
- `FASTBOOP_STAGE0_CARGO="$PWD/tools/cargo-local-gibblox.sh" ./tools/cargo-local-gibblox.sh check -p fastboop-cli`
- `FASTBOOP_STAGE0_CARGO="$PWD/tools/cargo-local-gibblox.sh" ./tools/cargo-local-gibblox.sh test -p fastboop-cli`

## Open implementation detail to settle during coding

- Sidecar naming/output policy for `bootprofile create --optimize` delegation (explicit output arg vs deterministic sibling default) should be finalized in code/docs together.
