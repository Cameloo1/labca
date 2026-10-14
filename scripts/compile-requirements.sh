#!/usr/bin/env bash
# Compile requirements.in and requirements-dev.in into hashed lock files.
# pip-compile resolves for the platform it runs on, so this runs inside a pinned
# Linux container. Pass --upgrade to refresh pinned versions.
set -euo pipefail
cd "$(dirname "$0")/.."

UPGRADE=""
if [ "${1:-}" = "--upgrade" ]; then
  UPGRADE="--upgrade"
fi

MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$(pwd -W 2>/dev/null || pwd):/src" -w /src -e HOME=/tmp -e UPGRADE="$UPGRADE" \
  python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 \
  bash -c '
    set -euo pipefail
    python -m venv /tmp/pt
    /tmp/pt/bin/pip install -q pip-tools==7.6.1
    FLAGS="--generate-hashes --allow-unsafe --strip-extras --no-emit-index-url --quiet $UPGRADE"
    /tmp/pt/bin/pip-compile $FLAGS --output-file requirements.txt requirements.in
    /tmp/pt/bin/pip-compile $FLAGS --output-file requirements-dev.txt requirements-dev.in
  '
