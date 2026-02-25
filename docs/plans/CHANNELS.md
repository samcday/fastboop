# Channels Plan (v0)

## Goal

Move fastboop from a positional `rootfs` artifact model to a single `channel` input.

Core model:

- A channel is just a stream of bytes.
- We do in-band autodetection on that stream.
- We do not model a separate concrete "bundle" container type.
- In later phases, we may accept out-of-band hints (for example mime-type), but byte-stream detection remains authoritative.

## First Pass Focus (Current)

- [x] CLI-first delivery (`fastboop boot`, `fastboop stage0`).
- [x] Support naked artifact channels (recursive unwrap/sniff).
- [x] Support bootprofile-leading streams (`.bootpro` records at stream head).
- [x] Channel-stream DevProfile records are wired in core/CLI and startup intake paths.
- [x] Desktop/web parity tracking is active.
- [ ] Desktop/web parity is complete enough to gate this first pass.

This plan tracks the ongoing channel direction from issue `#20` and related bootprofile work.

## Non-negotiables

- Keep fastboop non-mutating (no flash/erase/format/slot toggles/unlock paths).
- Keep existing DevPro and Stage0 invariants.
- Keep behavior deterministic; fail loudly only when no valid channel content can be accepted.
- Preserve conventional-commit history hygiene across this track (each logical checkpoint should land as a focused `feat`/`fix`/`refactor` commit with intent-first message).

## Target Behavior

Given one `channel` input:

1. Open it as a readable source (path/URL/stream).
2. Attempt profile-record scan from stream head, forward-only, in best-effort/lossy mode:
   - if next bytes decode as BootProfile binary record, accept and continue
   - if next bytes decode as DevProfile binary record, accept and continue
   - if next bytes are not a known profile-record header, stop scan and treat remaining bytes as artifact tail
3. Validation/error boundary:
   - if record decode/validation fails before any valid record is accepted, fail
   - if one or more valid records were already accepted, stop at first invalid/truncated/non-decodable record and continue with trailing bytes; emit warning
   - trailing zero-padding bytes from block-rounded reads are treated the same as other trailing junk: warning-only after at least one accepted record
4. Session handling:
   - accepted records are loaded into session-scoped in-memory state only
   - no local persistence
   - if DevProfiles were accepted from channel, constrain probe/match to those DevProfiles
   - BootProfile choices are filtered by selected device compatibility
5. Artifact handling:
   - remaining bytes (if any) run through the recursive unwrap/sniff pipeline
   - if no profile records are accepted at head, run unwrap/sniff from offset 0 as usual

Example this model must support:

- prepend one or more DevProfile/BootProfile binary records to a normal `.xz` rootfs artifact
- treat the whole byte stream as one valid channel

## Record + Stream Classification Contract (Draft v1)

Channel intake is split into two deterministic parts:

1. Profile-record head scan (offset-relative, forward-only)
2. Artifact classifier (bounded prefix + fixed probe order)

Profile-record headers:

- BootProfile v1: `FBOOPROF` magic + `format_version=1`
- DevProfile v1: `FBOODEVP` magic + `format_version=1`

Artifact classifier:

- Prefix window: first `64 KiB` (`CHANNEL_SNIFF_PREFIX_LEN` in `fastboop-core`).
- Probe order (first match wins):
  1. XZ (`FD 37 7A 58 5A 00`)
  2. ZIP (`PK\x03\x04`, `PK\x05\x06`, `PK\x07\x08`)
  3. Android sparse (`0xED26FF3A` LE)
  4. GPT (`EFI PART` at LBA1 / offset 512)
  5. ISO9660 (`CD001` at sector 16 descriptor)
  6. EROFS (superblock magic `0xE0F5E1E2` at offset 1024)
  7. ext4 (`0xEF53` at offset 1080)
  8. FAT (`FAT12/16/32` markers + `0x55AA`)
  9. MBR (`0x55AA` + non-empty partition entry type)

Notes:

- Wrappers/containers are intentionally tested before filesystems.
- FAT is checked before generic MBR to avoid false positives on FAT boot sectors.
- Unknown/unsupported formats fail explicitly; no silent fallback.

## Scope

- Replace `rootfs` / `rootfs_artifact` naming with `channel` across CLI + desktop + web + shared UI structs.
- Keep and extend channel sniff/dispatch path in core.
- Add profile-record head scanning support for mixed BootProfile/DevProfile streams.
- Add session-scoped loading of accepted profile records (no local persistence).
- Keep artifact unwrap path working for existing known formats.
- Keep simple multi-filesystem coalescing as the final phase.
- `fastboop-core` now owns byte-level channel stream-head scan (`boot+dev`) and boot-profile selection logic; CLI/desktop/web already consume these helpers, with a single reusable intake entrypoint still queued for phase 2.

## Out of Scope (for this iteration)

- Full policy engine for artifact ranking beyond deterministic heuristics.
- Complex union/overlay semantics between filesystems.
- Any mutating install workflow.
- Out-of-band channel hint protocol (mime-types, sidecar manifests, etc.) beyond future design notes.

## Phased Rollout

### Phase 0: CLI First Pass (Mostly Landed)

- `fastboop boot` and `fastboop stage0` accept channel artifact intake.
- Bootprofile-leading streams at channel head are parsed and validated.
- Trailing bytes continue through artifact unwrap/sniff.
- Deterministic selection and explicit `--boot-profile` behavior are in place.

Deliverable: CLI can boot from either plain artifact channels or bootprofile-leading streams, without local persistence.

Status:

- [x] CLI `boot`/`stage0` channel artifact intake through recursive unwrap/sniff.
- [x] CLI bootprofile-leading stream head parsing.
- [x] CLI boot profile compatibility uses `stage0.devices` rule (`{}` => all devices).
- [x] CLI explicit `--boot-profile` selection.
- [x] CLI stream EOF/tail detection uses exact channel byte size.
- [x] BootProfile schema/validation supports casync `.caibx` sources (including nested GPT selection).
- [x] Channel-stream DevProfile record ingestion (core parser + CLI/session constraint wiring).
- [ ] Desktop/web parity with CLI channel intake behavior.
  - [x] Desktop/web startup intake now uses best-effort/lossy profile stream-head parsing semantics (warning-only when trailing junk appears after accepted records).
  - [x] Desktop/web startup now retains channel stream-head metadata for session use and probe filtering.
  - [x] Desktop/web probe candidate filtering now narrows to BootProfile-referenced device IDs (`stage0.devices`) unless wildcard/all-device behavior applies.
  - [x] Desktop/web session boot config now displays the selected BootProfile and requires an explicit pick when multiple compatible profiles exist.
  - [ ] Desktop/web UI boot flows still have partial BootProfile rootfs source support when booting without trailing artifact payload (desktop: HTTP-only; web: HTTP/casync plus wrapper pipelines `xz`/`android_sparseimg`/`mbr`/`gpt`, with `file` limited to `web-file://` handles due browser sandbox constraints, and OSTree deployment auto-detection now wired for web BootProfile `rootfs.ostree` no-tail flow).

### Phase 1: Surface Migration (`rootfs` -> `channel`)

- Rename user-facing parameters and config fields to `channel`.
- Project is unreleased: do not add compatibility aliases or deprecation warnings.
- Session startup requires non-empty `channel` in CLI/desktop/web.

Deliverable: all frontends treat channel as the single source input.

Status:

- [x] User-facing startup/config inputs in CLI/desktop/web are channel-first.
- [x] `rootfs`/`rootfs_artifact` compatibility aliases were intentionally not added.
- [x] Session startup requires a non-empty `channel` in CLI/desktop/web.

### Phase 2: Core Channel Intake Unification

- Provide one shared channel intake entrypoint for CLI/desktop/web.
- Keep profile-record scan + artifact unwrap logic consistent across frontends.
- Keep probe-by-signature behavior (not extension-driven).

Phase gate:

- Shared path passes fixture parity tests and replaces duplicated CLI intake code.
- [x] Core stream-head scan and selection module exists in `fastboop-core`.
- [x] CLI resolves profile stream head and selection through core module (`read_boot_profile_stream_head`, `select_boot_profile_for_device`).
- [ ] Desktop and web adopt the same core helpers.
  - [x] Desktop/web now consume `read_channel_stream_head` output and use core BootProfile compatibility rules for runtime selection.
  - [ ] Shared reusable channel-intake entrypoint (single implementation across CLI/desktop/web) is still pending.

Deliverable: one reusable channel intake stack for all runtimes.

### Phase 3: DevProfile Records in Channel Streams

- Finalize DevProfile binary framing contract (magic + format version).
- Implement DevProfile decode/validate functions parallel to BootProfile binary path.
- Support mixed/interleaved stream heads (`devpro`, `bootpro`, `devpro`, ...).
- Build session model from accepted head records:
  - accepted DevProfiles
  - accepted BootProfiles
  - accepted/rejected counters and reasons
- Constrain matching/probing to channel DevProfiles when present.
- Keep all handling side-effect free and non-persistent.

Status:

- [x] DevProfile binary framing contract is finalized (`FBOODEVP` + `format_version=1`).
- [x] DevProfile prefix decode support is implemented in `fastboop-core` stream-head parsing.
- [x] Mixed/interleaved stream heads (`devpro+bootpro`, `bootpro+devpro`) are exercised and deterministic.
- [x] Session intake now carries accepted DevProfiles + BootProfiles + consumed bytes + warning count.
- [ ] Rejected-record counters/reason details are still warning-count based (not fully structured yet).
- [ ] Probe narrowing by channel DevProfiles is not yet uniformly enforced across every frontend probe path.
- [x] Handling remains in-memory and non-persistent.

Compatibility rule for BootProfile selection (v0):

- If `boot_profile.stage0.devices` is empty, the BootProfile is compatible with all known devices.
- Otherwise, compatible only when `selected_device_profile.id` exists in `boot_profile.stage0.devices`.

Phase gate:

- [x] Mixed profile-record streams are deterministic.
- [x] Invalid first record fails; invalid later record warns and stops head scan.
- [x] Given same channel + selected device profile id, compatibility output is deterministic.

Deliverable: channel streams can carry mixed DevProfiles/BootProfiles at head and affect session behavior without host mutation.

### Phase 4: Artifact "Feeling Lucky" Pipeline

- Keep recursive unwrap chain for known wrappers/containers:
  - xz
  - Android sparse
  - zip
  - iso9660
  - gpt/mbr partitions
- Expose discovered filesystem providers as ordered candidates.
- Preserve and improve explicit failure reasons (wrong format, missing kernel/modules, unsupported nesting).

Status:

- [x] CLI recursive unwrap chain handles xz/android sparse/zip plus partition-backed payloads.
- [x] Signature-first sniffing (not extension-driven) is used for channel classification.
- [x] Ordered filesystem providers are discovered for GPT/MBR partition inputs.
- [x] Failure modes are explicit for unsupported format/nesting paths.
- [ ] Full unwrap parity across CLI/desktop/web remains in progress.

Deliverable: artifact tails (or naked artifacts) continue to boot with robust sniffing and low extension coupling.

### Phase 5 (Last Phase / Victory Lap): Simple Coalescing Filesystem

Keep this intentionally simple and late.

Add a `Filesystem` implementation that aggregates providers in order:

- `CoalescingFilesystem([FS1, FS2, FS3, ...])`
- lookup/open calls:
  - try FS1
  - if not found, try FS2
  - then FS3, etc.
- return first successful match

This supports mixed-source discovery (for example kernel from one provider and modules from another) without complex union semantics.

Notes:

- Ordering is policy; keep it deterministic and transparent.
- No cross-filesystem merge logic beyond first-hit fallback.
- `read_dir` may remain minimal in v1 of this phase.

Status:

- [x] `Stage0CoalescingFilesystem` is implemented for CLI stage0/boot build paths.
- [x] lookup/open follows deterministic first-hit fallback order.
- [x] `read_dir` remains intentionally minimal (first provider).
- [ ] Shared coalescing implementation across all runtimes is still pending.

Deliverable: stage0 generator resolves required files across multiple providers with first-hit fallback.

### Phase 6: Documentation Pass (User + Developer)

Goal: cover channel behavior thoroughly for both end users and contributors.

Status:

- [x] Channel planning/spec baseline exists in `docs/plans/CHANNELS.md`.
- [ ] User docs: add a channel-first walkthrough in `docs/user/` (CLI + desktop + web launch patterns).
- [ ] User docs: replace remaining rootfs-first examples with channel-first examples.
- [ ] User docs: document supported channel sources and examples (artifact-only, bootprofile-leading, mixed profile heads).
- [ ] User docs: add troubleshooting for stream-head warnings/errors and boot-profile selection outcomes.
- [ ] Developer docs: document stream-head contract (record framing, scan boundaries, fail/warn rules).
- [ ] Developer docs: document shared-vs-frontend-specific intake behavior and current parity gaps.
- [ ] Developer docs: document fixture generation/regeneration flow and expected fixture matrix.
- [ ] Developer docs: document deterministic compatibility/selection rules (`stage0.devices` behavior).

Deliverable: user + developer docs fully explain channel intake semantics, constraints, and known limitations.

## Derisk Harness

We maintain deterministic generated fixtures (not checked in) and classify them in tests.

- [x] Fixture generator script: `tools/channels/generate-fixtures.sh`
- [x] Default output dir (gitignored): `build/channels-fixtures`
- [x] Core fixture test: `crates/fastboop-core/tests/channel_stream_fixture_harness.rs`

Fixture set should include:

- [ ] bootprofile binary header sample
- [ ] devprofile binary header sample
- [ ] mixed head streams (`bootpro+devpro+artifact`, `devpro+bootpro+artifact`)
- [ ] invalid-head cases (truncated record first, truncated record after valid record)
- [x] xz/zip wrappers
- [x] Android sparse header sample
- [x] GPT/MBR signature samples
- [x] ISO9660 descriptor sample
- [x] EROFS/ext4/FAT filesystem images built via `mkfs.*`

## Validation Plan

At minimum during development:

- [ ] Tier 0: `cargo fmt`
- [ ] Tier 0: targeted `cargo check` for touched crates
- [ ] Tier 1: `dx build -p fastboop-web` if `packages/web` changes
- [ ] Tier 1: `dx build -p fastboop-desktop` if `packages/desktop` changes
- [ ] Tier 1: relevant crate/package checks for core/cli changes

For substantial implementation phases, run Tier 2 gate from `HACKING.md` before handoff.

## Acceptance Criteria

- [x] User provides one `channel` input in CLI session startup flows.
- [x] Channel streams with leading profile records load accepted records into memory only.
- [x] Mixed/interleaved DevProfile + BootProfile record heads are supported.
- [x] If the first record is invalid, fail loudly.
- [x] If an invalid record appears after at least one valid record, warn and continue with trailing bytes (including block-padding zeros).
- [x] Naked artifact channels remain valid and are processed as generic artifacts.
- [x] BootProfile options after device/profile selection include only compatible variants (`stage0.devices = {}` means all devices).
- [ ] Existing artifact types still boot through channel intake with full CLI/desktop/web parity.
- [x] Coalescing filesystem resolves kernel/modules from different providers using deterministic first-hit fallback order (CLI path).
- [x] No mutating device actions are introduced.
