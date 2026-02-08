# fastboop development tasks

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
