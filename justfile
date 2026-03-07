# fastboop development tasks

# Unified target-aware validation for developers, CI, and automation.
check:
    #!/usr/bin/env bash
    set -euo pipefail

    echo "==> rustfmt"
    cargo fmt --all --check

    echo "==> root workspace (host target)"
    cargo check --workspace --exclude fastboop-web

    echo "==> root wasm targets"
    cargo check -p fastboop-fastboot-webusb --target wasm32-unknown-unknown
    cargo check -p fastboop-web --target wasm32-unknown-unknown

# Same as `check`, but with local ./gibblox crate overlays.
check-local-gibblox:
    #!/usr/bin/env bash
    set -euo pipefail

    local_cargo="$(pwd)/tools/cargo-local-gibblox.sh"
    export FASTBOOP_STAGE0_CARGO="$local_cargo"

    echo "==> rustfmt"
    "$local_cargo" fmt --all --check

    echo "==> root workspace (host target, local gibblox)"
    "$local_cargo" check --workspace --exclude fastboop-web

    echo "==> root wasm targets (local gibblox)"
    "$local_cargo" check -p fastboop-fastboot-webusb --target wasm32-unknown-unknown
    "$local_cargo" check -p fastboop-web --target wasm32-unknown-unknown

# Generate deterministic channel stream fixtures under build/
channels-fixtures:
    tools/channels/generate-fixtures.sh

# Run channel stream fixture harness tests
channels-test:
    tools/channels/generate-fixtures.sh
    cargo test -p fastboop-core channel_stream:: -- --nocapture
    cargo test -p fastboop-core generated_fixtures_match_expected_stream_kinds -- --nocapture

# Bump version across all packaging files
bump version:
    #!/usr/bin/env bash
    set -euo pipefail

    version="{{version}}"

    if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
      echo "version must match X.Y.Z or X.Y.Z-rc.N" >&2
      exit 1
    fi

    cargo_version="$version"
    rpm_apk_version="$version"
    debian_version="$version"

    old_cargo_version="$(python - <<'PY'
    from pathlib import Path
    import re

    text = Path("Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', text, flags=re.MULTILINE)
    if match is None:
        raise SystemExit("unable to parse workspace version from Cargo.toml")
    print(match.group(1))
    PY
    )"

    if [[ "$version" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-rc\.([0-9]+)$ ]]; then
      base="${BASH_REMATCH[1]}"
      rc="${BASH_REMATCH[2]}"
      rpm_apk_version="${base}_rc${rc}"
      debian_version="${base}~rc${rc}"
    fi

    echo "Bumping fastboop to ${cargo_version}"
    echo "  - RPM/APK version: ${rpm_apk_version}"
    echo "  - Debian version:  ${debian_version}"

    # Cargo.toml workspace version
    sed -i "s/^version = \".*\"/version = \"${cargo_version}\"/" Cargo.toml

    # RPM spec
    sed -i "s/^Version:        .*/Version:        ${rpm_apk_version}/" fastboop.spec

    # Alpine APKBUILD (set base version, keep _git suffix for dev builds)
    sed -i "s/^pkgver=.*_git$/pkgver=${rpm_apk_version}_git/" APKBUILD

    # Debian changelog (add new entry)
    sed -i "1s/.*/fastboop (${debian_version}) UNRELEASED; urgency=medium/" debian/changelog

    # Local publishable crates pin each in-workspace path dependency to exact version.
    # Keep those in sync with the workspace version before touching the lockfile.
    python - "$old_cargo_version" "$cargo_version" <<'PY'
    import pathlib
    import sys

    old_version, new_version = sys.argv[1], sys.argv[2]
    needle = f'version = "={old_version}"'
    replacement = f'version = "={new_version}"'

    for manifest in pathlib.Path(".").rglob("Cargo.toml"):
        if "target" in manifest.parts:
            continue

        text = manifest.read_text(encoding="utf-8")
        updated_lines = []
        changed = False

        for line in text.splitlines(keepends=True):
            if "path =" in line and needle in line:
                line = line.replace(needle, replacement)
                changed = True
            updated_lines.append(line)

        if changed:
            manifest.write_text("".join(updated_lines), encoding="utf-8")
    PY

    # Update lockfile without drifting transitive dependencies
    cargo update -p fastboop-cli --precise "$cargo_version"

    echo "Done. Files updated:"
    echo "  Cargo.toml"
    echo "  fastboop.spec"
    echo "  APKBUILD"
    echo "  debian/changelog"
    echo ""
    echo "Next steps:"
    echo "  1. Review changes: git diff"
    echo "  2. Commit: git commit -am 'v${cargo_version}'"
    echo "  3. Tag: git tag v${cargo_version}"
    echo "  4. Push: git push && git push --tags"

# Validate local publishable crates can be packaged in publish order
publish-dry-run:
    tools/publish-crates.sh --dry-run

# Publish local crates to crates.io in publish order
publish:
    tools/publish-crates.sh --publish

# Set live www.fastboop.win release version
www-live version:
    #!/usr/bin/env bash
    set -euo pipefail

    version="{{version}}"
    if ! [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
      echo "version must match vX.Y.Z or vX.Y.Z-rc.N" >&2
      exit 1
    fi

    printf '%s\n' "$version" > infra/k8s/fastboop-web/live-version.txt
    echo "Updated infra/k8s/fastboop-web/live-version.txt -> $version"
