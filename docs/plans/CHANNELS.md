# Channels Plan (v0)

## Goal

Move fastboop from a positional `rootfs` artifact model to a single `channel` input that can represent:

- a rootfs/image artifact (local file or URL)
- a profile bundle stream (DevProfiles + BootProfiles)

The runtime sniffs the channel and decides what it is, instead of relying on file extensions or separate command flows.

## First Pass Focus (Current)

- CLI-only delivery (`fastboop boot` first, `stage0` where practical).
- Support two channel shapes in boot flow:
  - naked artifact channel (recursive unwrap/sniff as today)
  - bootprofile-leading stream (one or more `.bootpro` records, optionally followed by artifact bytes)
- DevProfiles embedded in channel stream are explicitly out of scope for this first pass.
- Desktop/web integration is tracked but not part of first-pass implementation gating.

This plan tracks the ongoing BootProfile direction from `fastboop-boot-profiles` and issue `#20`.

## Non-negotiables

- Keep fastboop non-mutating (no flash/erase/format/slot toggles/unlock paths).
- Keep existing DevPro and Stage0 invariants.
- Keep behavior deterministic and fail loudly on invalid inputs.

## Target Behavior

Given one `channel` input:

1. Open it as a readable source (path/URL/stream).
2. Sniff initial bytes for profile-bundle magic + `format_version`.
3. If profile bundle:
   - parse all profiles
   - validate entries
   - load DevProfiles + BootProfiles into session-scoped in-memory state
   - constrain device matching/probing to bundle DevProfiles only
   - after selecting a device/profile, show only compatible BootProfiles for that device
   - report load/validation results to user/UI
   - do not persist profile records locally
4. If not a profile bundle:
   - run the "I am Feeling Lucky" unwrap/sniff pipeline (xz/sparse/zip/gpt/mbr/filesystem)
   - discover kernel/modules/stage0 inputs from resulting filesystem providers
   - treat channel as a generic artifact input (no channel-constrained device/profile list)

First-pass stream rule:

- If the stream starts with a boot profile record, continue consuming boot profile records from the head, then keep processing the remaining bytes as channel artifact input via the same recursive unwrap/sniff pipeline.
- Bootprofile-head parsing must be forward-only and side-effect free.

## Stream Classification Contract (Draft v1)

To reduce ambiguity and regressions, channel sniffing uses a fixed probe order over a bounded prefix read.

- Prefix window: first `64 KiB` (`CHANNEL_SNIFF_PREFIX_LEN` in `fastboop-core`).
- Probe order (first match wins):
  1. Profile bundle v1 (`FBCH` magic + `format_version=1`)
  2. XZ (`FD 37 7A 58 5A 00`)
  3. ZIP (`PK\x03\x04`, `PK\x05\x06`, `PK\x07\x08`)
  4. Android sparse (`0xED26FF3A` LE)
  5. GPT (`EFI PART` at LBA1 / offset 512)
  6. ISO9660 (`CD001` at sector 16 descriptor)
  7. EROFS (superblock magic `0xE0F5E1E2` at offset 1024)
  8. ext4 (`0xEF53` at offset 1080)
  9. FAT (`FAT12/16/32` markers + `0x55AA`)
  10. MBR (`0x55AA` + non-empty partition entry type)

Notes:

- Wrappers/containers are intentionally tested before filesystems.
- FAT is checked before generic MBR to avoid false positives on FAT boot sectors.
- Unknown/unsupported formats fail explicitly; no silent fallback.

## Scope

- Replace `rootfs` / `rootfs_artifact` input naming with `channel` across:
  - CLI (`boot`, `stage0`, and related help text/errors)
  - desktop/web boot config models and forms
  - shared UI data structs
- Add channel sniff/dispatch path in core.
- Add session-scoped profile-bundle loading/selection path with no local persistence (later phase).
- Add CLI first-pass support for bootprofile-leading stream handling.
- Keep artifact unwrap path working for existing known formats.
- Add a simple multi-filesystem coalescing abstraction as the final phase.

## Out of Scope (for this iteration)

- Full policy engine for artifact ranking beyond deterministic heuristics.
- Complex union/overlay semantics between filesystems.
- Any mutating install workflow.
- Channel-stream DevProfile ingestion/selection in first-pass CLI rollout.

## Phased Rollout

### Phase 0: CLI First Pass (In Progress)

- Wire `fastboop boot` to accept:
  - naked artifact channels
  - bootprofile-leading streams
- Implement stream-head bootprofile parsing and continue artifact detection on remaining bytes.
- Keep behavior deterministic:
  - if multiple bootprofiles are discovered, require explicit selection policy/flag or fail with clear list
  - no persistent writes
- Descope channel-stream DevProfiles in this phase.

Deliverable: CLI can boot from either plain artifact channels or bootprofile-leading streams without local persistence.

### Phase 1: Surface Migration (`rootfs` -> `channel`)

- Rename user-facing parameters and config fields to `channel`.
- Project is unreleased: do not add compatibility aliases or deprecation warnings.
- Session startup requires a non-empty `channel` in CLI/desktop/web flows.

Deliverable: all frontends treat channel as the single source input.

### Phase 2: Core Channel Intake and Sniffing

- Add a shared channel open API (path/URL with existing reader stack).
- Implement ordered sniff dispatcher with bounded recursion and cycle guards.
- Probe by magic/signature first, not filename extension.
- Keep existing open paths (including casync/EROFS behavior) behind the new entrypoint.

Phase gate:

- New stream classifier must pass fixture harness parity tests before becoming default path.

Deliverable: one core entrypoint that classifies channel as profile-bundle or artifact pipeline input.

### Phase 3: Profile Bundle Session Runtime (Non-Persistent)

- Reuse/adapt BootProfile schema/codec work from `fastboop-boot-profiles`.
- Define bundle framing contract (magic + `format_version` + payload table).
- Implement bundle session behavior:
  - validate all records
  - build an in-memory session model (`DevProfiles`, `BootProfiles`)
  - constrain device probe/match to in-session DevProfiles
  - provide BootProfile selection filtered by selected device compatibility
  - partial success reporting (accepted/rejected counts + reasons)
  - no persistent writes (bundle handling is side-effect free)

Compatibility rule for BootProfile selection (v0):

- If `boot_profile.stage0.devices` is empty, the BootProfile is treated as compatible with all known devices.
- Otherwise, the BootProfile is compatible only when `selected_device_profile.id` exists as a key in `boot_profile.stage0.devices`.

Phase gate:

- Bundle handling must be deterministic and side-effect free.
- Invalid or partially invalid bundles must never modify host state.
- Given the same bundle + selected device profile id, BootProfile compatibility output is deterministic.

Deliverable: starting a session from a profile-bundle channel constrains detection and exposes only compatible BootProfile variants without writing local state.

### Phase 4: Artifact "Feeling Lucky" Pipeline

- Build recursive unwrap chain for known wrappers/containers:
  - xz
  - Android sparse
  - zip
  - iso9660
  - gpt/mbr partitions
- Expose discovered filesystem providers as ordered candidates.
- Preserve and improve explicit failure reasons (wrong format, missing kernel/modules, unsupported nesting).

Deliverable: channel artifact inputs continue to boot with improved sniffing and less extension coupling.

### Phase 5 (Last Phase / Victory Lap): Simple Coalescing Filesystem

Keep this intentionally simple and late.

Add a `Filesystem` implementation that aggregates providers in order:

- `CoalescingFilesystem([FS1, FS2, FS3, ...])`
- For lookup/open calls:
  - try FS1
  - if not found, try FS2
  - then FS3, etc.
- Return first successful match.

This is enough to support mixed-source discovery such as:

- kernel in boot partition/provider
- modules in rootfs partition/provider

without introducing advanced union semantics.

Notes:

- Ordering is the policy. Start with deterministic heuristics and keep it transparent.
- No cross-filesystem merge logic beyond first-hit fallback.
- If needed, `read_dir` can be minimal (first provider only) in v1 of this phase.

Deliverable: stage0 generator can resolve required files across multiple providers with first-hit fallback behavior.

## Derisk Harness

We maintain deterministic, generated fixtures (not checked in) and classify them in tests.

- Fixture generator script: `tools/channels/generate-fixtures.sh`
- Default output dir (gitignored): `build/channels-fixtures`
- Core fixture test: `crates/fastboop-core/tests/channel_stream_fixture_harness.rs`

Fixture set includes:

- profile bundle v1 header sample
- xz/zip wrappers
- Android sparse header sample
- GPT/MBR signature samples
- ISO9660 descriptor sample
- EROFS/ext4/FAT filesystem images built via `mkfs.*`

## Validation Plan

At minimum during development:

- Tier 0:
  - `cargo fmt`
  - targeted `cargo check` for touched crates
- Tier 1 path-triggered checks:
  - `dx build -p fastboop-web` if `packages/web` changes
  - `dx build -p fastboop-desktop` if `packages/desktop` changes
  - relevant crate/package checks for core/cli changes

For substantial implementation phases, run Tier 2 gate from `HACKING.md` before handoff.

## Acceptance Criteria

- User can provide one `channel` input in CLI session startup flows for first pass.
- Profile-bundle channels load DevProfiles/BootProfiles in-memory for that session only.
- Device matching for a profile-bundle session is constrained to channel DevProfiles.
- BootProfile options shown after device/profile selection include only compatible variants (`stage0.devices = {}` means compatible with all known devices).
- Naked artifact channels are treated as generic artifacts (assumed bootable for any matched device; no channel-provided profile constraints).
- Bootprofile-leading streams continue artifact recursive unwrap/detection on trailing bytes after parsed bootprofile records.
- Existing artifact types still boot through channel intake.
- Coalescing filesystem resolves kernel/modules from different providers using first-hit fallback order.
- No mutating device actions are introduced.
