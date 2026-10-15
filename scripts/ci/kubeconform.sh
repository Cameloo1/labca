#!/usr/bin/env bash
# Run the pinned kubeconform image on the repo. Works in CI and in Git Bash with Docker Desktop.
# The repo root is mounted at /work, so callers pass paths relative to the repo root.
# The image ships its own CA bundle for the schema downloads.
set -euo pipefail
cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1
exec docker run --rm -v "$(pwd -W 2>/dev/null || pwd):/work" -w /work ghcr.io/yannh/kubeconform:v0.7.0@sha256:85dbef6b4b312b99133decc9c6fc9495e9fc5f92293d4ff3b7e1b30f5611823c "$@"
