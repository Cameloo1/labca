#!/usr/bin/env bash
# Run the pinned kube-linter image on the repo. Works in CI and in Git Bash with Docker Desktop.
# The repo root is mounted at /work, so callers pass paths relative to the repo root.
# The image ships no CA certificates, and kube-linter downloads schemas over HTTPS, so a
# CA bundle is mounted read-only. It defaults to the Linux system bundle (present on the
# CI runner); set KUBE_LINTER_CA_FILE to a PEM bundle path where that file does not exist.
set -euo pipefail
cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1
ca_file="${KUBE_LINTER_CA_FILE:-/etc/ssl/certs/ca-certificates.crt}"
ca_args=()
if [ -f "$ca_file" ]; then
  ca_args=(-v "${ca_file}:/etc/ssl/certs/ca-certificates.crt:ro")
fi
exec docker run --rm -v "$(pwd -W 2>/dev/null || pwd):/work" -w /work "${ca_args[@]}" stackrox/kube-linter:v0.8.3@sha256:f2bfce7879206d32f69ab6572c376f916643f54ca291ac38cf7d01ef591ff3f9 "$@"
