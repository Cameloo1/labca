#!/usr/bin/env bash
# Create a throwaway dev KEK at .dev-keks/dev-1 when it is absent.
# This KEK protects throwaway dev data only. It must be readable by UID 10001
# inside the container, so the directory is 0755 and the file is 0644.
# The value is never printed.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${ENV:-}" = "prod" ]; then
  echo "error: refusing to create a dev KEK when ENV=prod" >&2
  exit 1
fi

mkdir -p .dev-keks
chmod 0755 .dev-keks
if [ ! -f .dev-keks/dev-1 ]; then
  head -c 32 /dev/urandom | base64 > .dev-keks/dev-1
  echo "created .dev-keks/dev-1"
else
  echo ".dev-keks/dev-1 already exists"
fi
chmod 0644 .dev-keks/dev-1
