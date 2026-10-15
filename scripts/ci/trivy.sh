#!/usr/bin/env bash
# Run the pinned trivy image on the repo. Works in CI and in Git Bash with Docker Desktop.
# The repo root is mounted at /work, so callers pass paths relative to the repo root.
set -euo pipefail
cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1
exec docker run --rm -v "$(pwd -W 2>/dev/null || pwd):/work" -w /work aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 "$@"
