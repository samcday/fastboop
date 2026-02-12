# Kernel tree boot with synthesized modules export

## Goal

Enable:

```sh
fastboop boot https://example/rootfs.ero --kernel
```

when the remote rootfs has no kernel modules, by sourcing kernel artifacts from a local kernel build tree and exporting a synthesized modules filesystem through smoo.

## Clarified requirements

- `--kernel` means kernel artifacts come from the local kernel build tree (developer machine context).
- Rootfs remains remote (EROFS URL) and is still exported as the primary runtime backing.
- A second export contains synthesized kernel modules and is mounted by stage0 into the final lowerdir stack.
- Export order is a hard contract for this iteration:
  - export 0 (`/dev/ublkb0`) = rootfs
  - export 1 (`/dev/ublkb1`) = modules image
- Modules image format for now: ext4, created with host tooling (`mkfs.ext4`).
- Assume CLI can run with privileges (`sudo`) for this path.
- No flashing, formatting of device storage, slot toggles, unlocks, or other mutating behavior.

## High-level flow

1. User runs `fastboop boot <rootfs-url> --kernel` from a kernel tree.
2. CLI discovers local kernel outputs (`vmlinuz`/Image, dtbs, modules metadata).
3. CLI synthesizes a temporary modules tree via kernel build system (`modules_install`).
4. CLI builds a temporary ext4 image containing `/usr/lib/modules/<kver>`.
5. CLI starts smoo host with ordered exports: rootfs first, modules image second.
6. Stage0 mounts `/dev/ublkb0` as root lower and `/dev/ublkb1` as modules lower, then assembles overlay lowerdirs.
7. Stage0 continues handoff to userspace with modules visible at `/usr/lib/modules/<kver>`.

## Implementation plan

### 1) CLI: `--kernel` contract and kernel tree inputs

Files:

- `cli/src/commands/boot.rs`
- `cli/src/commands/stage0.rs`

Changes:

- Add/extend `--kernel` semantics for `boot` so it selects local kernel-tree mode.
- Validate required local artifacts and produce actionable errors when missing.
- Thread kernel-tree context into stage0 build and smoo export preparation.

Acceptance:

- `fastboop boot <url> --kernel` enters kernel-tree path without requiring modules in remote rootfs.

### 2) CLI: synthesize modules filesystem image (ext4)

Files:

- `cli/src/commands/boot.rs` (or a dedicated helper module)
- `cli/Cargo.toml` (only if helper deps are needed)

Changes:

- Run:
  - `make -s kernelrelease`
  - `make -s modules_install INSTALL_MOD_PATH=<tmp>`
- Build ext4 image from the staged install tree using host tools (`mkfs.ext4`).
- Ensure final image presents the path expected by runtime and stage0 (`/usr/lib/modules/<kver>`).
- Keep image lifecycle ephemeral (tmpdir-scoped) and cleaned up on exit.

Acceptance:

- Image is generated deterministically for a given kernel tree and contains modules directory for the detected `kernelrelease`.

### 3) smoo host: ordered multi-export registration

Files:

- `cli/src/smoo_host.rs`

Changes:

- Extend host setup from single export to explicit ordered export list.
- Register rootfs export first, synthesized ext4 modules export second.
- Preserve current rootfs export behavior for non-`--kernel` mode.

Acceptance:

- CONFIG_EXPORTS payload includes two entries in stable order under `--kernel`.

### 4) stage0: consume modules export by ordered ublk device

Files:

- `stage0/src/main.rs`
- `crates/fastboop-stage0-generator/src/lib.rs`

Changes:

- Add stage0 boot arg signaling whether modules export is expected (for `--kernel` mode).
- Under modules-export mode:
  - mount `/dev/ublkb0` as root lower source
  - mount `/dev/ublkb1` as modules lower source
  - include modules path in final lowerdir composition so `/usr/lib/modules/<kver>` resolves in final root
- Fail clearly if modules export is required but unavailable/mount fails.

Acceptance:

- Stage0 successfully composes final root with modules visible when `--kernel` is used.

## Operational notes

- Current assumption is privileged CLI execution; document this in command help and failure messages.
- Keep temporary artifacts under one run-scoped directory for easy cleanup and post-mortem debugging.
- Emit `tracing` spans around kernelrelease detection, modules install, ext4 image creation, export registration, and stage0 mount steps.

## Validation plan

During development (path-focused):

- `cargo check -p fastboop-cli -p fastboop-stage0 -p fastboop-stage0-generator`

End-of-session gate:

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets`
- `cargo test --workspace`

Manual smoke (kernel-tree mode):

- Run `fastboop boot <rootfs-url> --kernel` in a kernel tree with built kernel/dtbs/modules.
- Verify stage0 log indicates both `/dev/ublkb0` and `/dev/ublkb1` mounted.
- Verify `/usr/lib/modules/<kver>` exists in the booted userspace.

## Follow-up (not in this change)

- Unprivileged modules image build path (no `sudo`), likely via user namespaces + loopback alternatives, or in-process filesystem image writers.
- Optional dynamic export discovery fallback if strict ordering is ever relaxed.
