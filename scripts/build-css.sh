#!/usr/bin/env bash
# Build app/static/css/app.css with the Tailwind standalone CLI (no Node needed).
# The CLI binary is downloaded once into .cache/tailwind/ and verified by sha256.
set -euo pipefail
cd "$(dirname "$0")/.."

TAILWIND_VERSION="3.4.19"
TAILWIND_SHA256="4af3198c015616ea7d6617974ec3d70d987ecc00c1ca8463b0a30fd65cc7c06e"
TAILWIND_URL="https://github.com/tailwindlabs/tailwindcss/releases/download/v${TAILWIND_VERSION}/tailwindcss-linux-x64"

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "build-css.sh supports x86_64 Linux only (the pinned binary is tailwindcss-linux-x64). Run it in the runner container." >&2
  exit 1
fi

DIR=".cache/tailwind/v${TAILWIND_VERSION}"
BIN="$DIR/tailwindcss-linux-x64"
mkdir -p "$DIR"

if [ ! -f "$BIN" ]; then
  curl -fsSL --retry 3 -o "$BIN" "$TAILWIND_URL"
fi

if ! echo "${TAILWIND_SHA256}  ${BIN}" | sha256sum -c --quiet -; then
  rm -f "$BIN"
  echo "Tailwind CLI checksum mismatch; deleted $BIN." >&2
  exit 1
fi
chmod +x "$BIN"

mkdir -p app/static/css
"$BIN" -c tailwind.config.js -i app/static/src/input.css -o app/static/css/app.css --minify
