# Release Machinery Plan (first pass)

## Goal

Stand up a reliable `0.0.1-rc.N` -> `0.0.1` release pipeline for fastboop that:

- publishes GitHub Releases with downstream-consumable artifacts (`.deb`, `.apk`, binary tarballs),
- supports rehearsal via `release/v*` PRs before tagging,
- keeps crates.io publishing sane while `smoo` and `gibblox` are being peeled back to canonical repos.

This first pass is intentionally pragmatic: artifact release orchestration now, full crates.io automation after subtree split work lands.

## Current State (baseline)

- `.github/workflows/release.yml` is tag-only and only creates a release shell.
- `.github/workflows/ci.yml` builds/tests and can upload release binaries only on `release: published` events.
- `.github/workflows/debian.yml` builds `.deb` artifacts for CI contexts.
- `.github/workflows/alpine.yml` builds `.apk` artifacts and uploads on `release: published`.
- `just bump` exists, but it is not yet semver-rc aware for distro-specific version formats.

## First-Pass Decisions

- Keep a **single orchestrator** in fastboop (`.github/workflows/release.yml`) that decides release mode and coordinates artifact jobs.
- Use **two modes**:
  - `tag` mode: triggered by `v*` tags, creates/publishes the real GitHub Release.
  - `pr` mode: triggered by `release/v*` PRs from same repo, builds and verifies release payload without publishing.
- Treat `-rc.N` as prerelease everywhere release metadata needs it.
- Defer cross-workspace crates.io publishing (`fastboop` + vendored `smoo` + vendored `gibblox`) until canonical repo prereleases exist and dependency edges are clean.

## Release Contract

### Version and ref forms

- Release branch: `release/vX.Y.Z` or `release/vX.Y.Z-rc.N`
- Release tag: `vX.Y.Z` or `vX.Y.Z-rc.N`
- Prerelease detection: semver suffix `-rc.N`

### Mode gate

Release orchestration is enabled only when:

- event is `push` and ref is a matching `v*` tag, or
- event is `pull_request` and head ref matches `release/vX.Y.Z(-rc.N)?` from the same repository.

### Artifact set (first pass)

- static CLI binaries bundled as tarballs (at least `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`)
- Debian packages: `debs/*.deb`
- Alpine packages: `packages/*.apk`
- packaging metadata: `APKBUILD`
- checksum manifest for uploaded artifacts (`SHA256SUMS`)

PR mode verifies this full set exists. Tag mode uploads the same set to the GitHub Release.

## Scope (first pass)

1. **Release orchestrator upgrade**
   - Replace current minimal `.github/workflows/release.yml` with phrog-style gate + fan-out + fan-in structure.
   - Include `pass` job and publish-only-on-success behavior.

2. **Artifact fan-out wiring**
   - Reuse existing build logic from current CI/debian/alpine workflows where practical.
   - If reuse needs `workflow_call`, refactor those workflows minimally to support both standalone CI and orchestration.

3. **PR rehearsal behavior**
   - `release/v*` PRs run the release pipeline in dry-run style:
     - no GitHub Release publication,
     - no crates.io publication,
     - artifact completeness verification only.

4. **Tag publish behavior**
   - `v*` tags create draft release (prerelease flag derived from version),
   - upload artifacts,
   - publish draft only after all required jobs are green.

5. **Version bump helper hardening**
   - Upgrade `just bump` semantics to map semver prerelease forms correctly:
     - Cargo: `0.0.1-rc.1`
     - RPM/APK version fields: `0.0.1_rc1` where required by packaging constraints
     - Debian changelog version: `0.0.1~rc1`

## Out of Scope (first pass)

- Enabling crates.io publish for all vendored subtree crates from fastboop.
- Full `release-plz` ownership in this repository.
- Auto-generated release PRs/issues as the source of truth for versioning.
- Any compatibility shims/migration aliases (project remains unreleased policy).

## release-plz / release-please Positioning

For this repo shape, use them as helpers, not the conductor:

- **Now (first pass):** orchestrated GitHub release + packaging assets in fastboop; crates publishing deferred.
- **During subtree peel-out:** publish `smoo` and `gibblox` prereleases from canonical repos.
- **After peel-out stabilizes:** introduce `release-plz` where dependency graph and publish order are clean.

Rationale: fastboop currently has many path-linked edges into vendored workspaces; reliable crates.io automation needs canonical published versions first.

## Implementation Sketch

Target job graph in `.github/workflows/release.yml`:

1. `gate` -> decide `enabled`, `mode`, `prerelease`
2. `release` -> create draft (tag mode) or skip creation (PR mode)
3. `build-binaries`, `debian`, `alpine` -> produce artifacts
4. `publish-assets` -> upload to release in tag mode; verify payload in PR mode
5. `pass` -> aggregate required checks
6. `publish-release` -> undraft release after successful `pass` (tag mode only)

## Secrets and Access

- `RELEASE_GITHUB_TOKEN` for release/tag operations that need elevated permissions.
- `GITHUB_TOKEN` for normal artifact and PR operations.
- `CARGO_REGISTRY_TOKEN` is intentionally not required in first pass (no crates publish yet).

## Validation Plan

For release-machinery edits:

- Tier 0:
  - `cargo fmt`
  - targeted checks only if Rust code changes
- Workflow verification:
  - syntax sanity via CI run on a throwaway `release/v0.0.1-rc.1` PR branch
  - confirm PR mode verifies complete artifact set
  - confirm tag mode creates draft, uploads assets, then publishes after pass

If workflow behavior cannot be fully verified in-session (no remote actions execution), report explicitly and leave an operator checklist.

## Acceptance Criteria

- A `release/v0.0.1-rc.1` PR exercises full release artifact flow without publishing a release.
- A `v0.0.1-rc.1` tag produces a GitHub prerelease with all expected assets.
- A `v0.0.1` tag produces a non-prerelease GitHub release with the same artifact families.
- Pipeline fails loudly when any artifact family is missing.
- No crates.io publish side effects occur from fastboop first-pass machinery.

## Follow-up After Canonical Repo RCs

Once `smoo` and `gibblox` canonical prereleases are in place and fastboop consumes registry versions where needed:

- add publish dry-runs in PR mode,
- add real crates.io publish in tag mode,
- decide whether `release-plz` becomes authoritative for version/changelog/publish automation.
