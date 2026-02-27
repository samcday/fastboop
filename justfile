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

    version="{{version}}"

    if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
      echo "version must match X.Y.Z or X.Y.Z-rc.N" >&2
      exit 1
    fi

    cargo_version="$version"
    rpm_apk_version="$version"
    debian_version="$version"

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
    #!/usr/bin/env bash
    set -euo pipefail

    metadata_file="$(mktemp)"
    trap 'rm -f "$metadata_file"' EXIT

    cargo metadata --format-version 1 >"$metadata_file"

    mapfile -t packages < <(python - "$metadata_file" <<'PY'
    import collections
    import json
    import pathlib
    import sys

    metadata_path = pathlib.Path(sys.argv[1])
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    root = pathlib.Path(".").resolve()

    def in_repo(path: pathlib.Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    local_names = set()
    packages = {pkg["name"]: pkg for pkg in metadata["packages"]}

    for pkg in metadata["packages"]:
        manifest_path = pathlib.Path(pkg["manifest_path"]).resolve()
        if pkg.get("source") is not None:
            continue
        if pkg.get("publish") == []:
            continue
        if not in_repo(manifest_path):
            continue
        local_names.add(pkg["name"])

    deps = {name: set() for name in local_names}
    reverse = {name: set() for name in local_names}

    for name in local_names:
        for dep in packages[name].get("dependencies", []):
            if dep.get("kind") in (None, "build") and dep["name"] in local_names:
                deps[name].add(dep["name"])
                reverse[dep["name"]].add(name)

    indegree = {name: len(deps[name]) for name in local_names}
    queue = collections.deque(sorted(name for name, degree in indegree.items() if degree == 0))
    order = []

    while queue:
        name = queue.popleft()
        order.append(name)
        for dependent in sorted(reverse[name]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                queue.append(dependent)

    if len(order) != len(local_names):
        raise SystemExit("publish-dry-run aborted: local publish graph has a cycle")

    print("\n".join(order))
    PY
    )

    for package in "${packages[@]}"; do
        patch_file="$(mktemp)"
        python - "$metadata_file" "$package" "$patch_file" <<'PY'
    import json
    import pathlib
    import sys

    metadata_path = pathlib.Path(sys.argv[1])
    current_package = sys.argv[2]
    patch_path = pathlib.Path(sys.argv[3])

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    root = pathlib.Path(".").resolve()

    def in_repo(path: pathlib.Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    local_packages = {}
    for pkg in metadata["packages"]:
        manifest_path = pathlib.Path(pkg["manifest_path"]).resolve()
        if pkg.get("source") is not None:
            continue
        if pkg.get("publish") == []:
            continue
        if not in_repo(manifest_path):
            continue
        local_packages[pkg["name"]] = pkg

    if current_package not in local_packages:
        raise SystemExit(f"package {current_package!r} is not a local publishable package")

    needed = set()
    stack = [
        dep["name"]
        for dep in local_packages[current_package].get("dependencies", [])
        if dep.get("kind") in (None, "build") and dep["name"] in local_packages
    ]

    while stack:
        name = stack.pop()
        if name in needed:
            continue
        needed.add(name)
        for dep in local_packages[name].get("dependencies", []):
            if dep.get("kind") in (None, "build") and dep["name"] in local_packages:
                stack.append(dep["name"])

    lines = ["[patch.crates-io]"]
    for name in sorted(needed):
        manifest_path = pathlib.Path(local_packages[name]["manifest_path"]).resolve()
        lines.append(name + ' = { path = "' + manifest_path.parent.as_posix() + '" }')

    patch_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    PY

        echo "==> cargo package -p $package --locked"
        cargo package -p "$package" --locked --config "$patch_file"
        rm -f "$patch_file"
    done

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
