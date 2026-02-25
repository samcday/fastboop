# Gibblox Pipeline Adoption Plan

## Goal

Adopt `gibblox-pipeline` for BootProfile artifact pipeline schema + binary encoding,
remove duplicated BootProfile pipeline definitions/validation from fastboop, and use
published `gibblox-*` crates from crates.io.

## Scope

- Switch fastboop/smoo workspace consumers from in-tree `gibblox/` paths to
  crates.io `gibblox-*` dependencies.
- Refactor BootProfile schema to use `gibblox-pipeline` types.
- Refactor BootProfile binary representation to embed
  `gibblox_pipeline::bin::PipelineSourceBin`.
- Bump BootProfile binary format version and intentionally break old decoding.
- Remove duplicated BootProfile pipeline validation logic in favor of
  `gibblox_pipeline::validate_pipeline`.
- Update docs/tests and regenerate committed `.bootpro` artifacts.

## Non-Goals

- No migration path or compatibility decode for previous BootProfile binary format.
- No behavior change to non-mutating boot/install invariants.

## Implementation Steps

1. **Dependency Source Flip**
   - Update Cargo manifests in fastboop/smoo workspace members to use
     crates.io `gibblox-*` versions.

2. **Schema Refactor (`fastboop-schema`)**
   - Add `gibblox-pipeline` dependency.
   - Replace BootProfile artifact source type definitions with re-exports from
     `gibblox_pipeline`.
   - Keep existing BootProfile top-level schema (`rootfs`, `kernel`, `dtbs`,
     `stage0`) while delegating pipeline shape to gibblox.

3. **Binary Refactor (`fastboop-schema::bin`)**
   - Bump `BOOT_PROFILE_BIN_FORMAT_VERSION` to `2`.
   - Replace local `BootProfileArtifactSourceBin` with
     `gibblox_pipeline::bin::PipelineSourceBin` in BootProfile bin structs.

4. **Core Validation Refactor (`fastboop-core`)**
   - Delegate pipeline validation to `gibblox_pipeline::validate_pipeline`.
   - Keep fastboop-specific checks only:
     - rootfs filesystem must support stage0 switchroot (`erofs`/`ext4`)
     - non-empty `kernel.path` / `dtbs.path`.

5. **Docs + Fixtures**
   - Update BootProfile docs and channel plan format-version notes.
   - Regenerate tracked `.bootpro` artifacts with the new v2 format.

6. **Validation**
   - `cargo fmt`
   - targeted `cargo check`/`cargo test` for touched crates
   - `dx build -p fastboop-desktop`
   - `dx build -p fastboop-web`

## Expected Outcome

- BootProfile pipeline schema + bin encoding are sourced from gibblox.
- BootProfile binary format is v2-only (no v1 compatibility path).
- Duplicated pipeline parsing/validation code in fastboop is significantly reduced.
