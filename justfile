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

    echo "Bumping fastboop to {{version}}"

    # Cargo.toml workspace version
    sed -i 's/^version = ".*"/version = "{{version}}"/' Cargo.toml

    # RPM spec
    sed -i 's/^Version:        .*/Version:        {{version}}/' fastboop.spec

    # Alpine APKBUILD (set base version, keep _git suffix for dev builds)
    sed -i 's/^pkgver=.*_git$/pkgver={{version}}_git/' APKBUILD

    # Debian changelog (add new entry)
    sed -i '1s/.*/fastboop ({{version}}) UNRELEASED; urgency=medium/' debian/changelog

    # Update lockfile
    cargo generate-lockfile

    echo "Done. Files updated:"
    echo "  Cargo.toml"
    echo "  fastboop.spec"
    echo "  APKBUILD"
    echo "  debian/changelog"
    echo ""
    echo "Next steps:"
    echo "  1. Review changes: git diff"
    echo "  2. Commit: git commit -am 'v{{version}}'"
    echo "  3. Tag: git tag v{{version}}"
    echo "  4. Push: git push && git push --tags"

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
