# fastboop development tasks

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
