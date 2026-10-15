#!/usr/bin/env bash
# Smoke test for the labca and labca-mtls-demo images.
# Usage: LABCA_IMAGE=labca:wp10 DEMO_IMAGE=labca-mtls-demo:wp10 bash scripts/image-smoke.sh
# The KEK and SECRET_KEY are generated at run time and never printed.
set -euo pipefail

: "${LABCA_IMAGE:?set LABCA_IMAGE}"
: "${DEMO_IMAGE:?set DEMO_IMAGE}"

# Stop Git Bash on Windows from rewriting container paths.
export MSYS_NO_PATHCONV=1
umask 077

SUFFIX="$$-$(date +%s)"
VOLUME="labca-smoke-data-$SUFFIX"
CONTAINER="labca-smoke-serve-$SUFFIX"
KEKDIR=""
if [ -d /dev/shm ]; then
  KEKDIR="$(mktemp -d /dev/shm/labca-smoke-kek.XXXXXX 2>/dev/null)" || KEKDIR=""
fi
if [ -z "$KEKDIR" ]; then
  KEKDIR="$(mktemp -d)"
fi

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker volume rm -f "$VOLUME" >/dev/null 2>&1 || true
  rm -rf "$KEKDIR"
}
trap cleanup EXIT

fail() {
  echo "IMAGE SMOKE: FAIL: $*" >&2
  if docker inspect "$CONTAINER" >/dev/null 2>&1; then
    echo "--- last 20 log lines ---" >&2
    docker logs --tail 20 "$CONTAINER" >&2 || true
  fi
  exit 1
}

# 1. Users and demo usage exit code.
uid="$(docker run --rm --entrypoint id "$LABCA_IMAGE" -u)"
[ "$uid" = "10001" ] || fail "labca image runs as uid $uid, expected 10001"
demo_user="$(docker inspect -f '{{.Config.User}}' "$DEMO_IMAGE")"
[ "$demo_user" = "65532:65532" ] || fail "demo image user is $demo_user, expected 65532:65532"
demo_rc=0
docker run --rm "$DEMO_IMAGE" >/dev/null 2>&1 || demo_rc=$?
[ "$demo_rc" = "2" ] || fail "demo image exit code $demo_rc, expected 2"

# 2. Volume and KEK directory.
docker volume create "$VOLUME" >/dev/null
head -c 32 /dev/urandom | base64 > "$KEKDIR/smoke-1"
chmod 0444 "$KEKDIR/smoke-1"
chmod 0755 "$KEKDIR"
if command -v cygpath >/dev/null 2>&1; then
  HOST_KEKDIR="$(cygpath -m "$KEKDIR")"
else
  HOST_KEKDIR="$KEKDIR"
fi

SECRET_KEY="$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 48)"
[ "${#SECRET_KEY}" -eq 48 ] || fail "could not generate SECRET_KEY"
# Passed by name only, so the value never appears in a docker command line.
export SECRET_KEY

run_flags=(
  --read-only --tmpfs /tmp
  -v "$VOLUME:/data"
  -v "$HOST_KEKDIR:/run/secrets/labca-kek:ro"
  -e ENV=prod
  -e SECRET_KEY
  -e ENABLE_API_DOCS=false
  -e ADMIN_AUTH_MODE=localhost_only
  -e PUBLIC_BASE_URL=https://labca.example.test
  -e DATABASE_URL=sqlite:////data/labca.db
  -e LABCA_KEK_DIR=/run/secrets/labca-kek
  -e LABCA_ACTIVE_KEK_ID=smoke-1
  -e LOG_FORMAT=json
)

# 3. Migrate.
if ! docker run --rm "${run_flags[@]}" "$LABCA_IMAGE" migrate >/dev/null; then
  fail "migrate failed"
fi

# 4. Serve.
docker run -d --name "$CONTAINER" "${run_flags[@]}" -p 127.0.0.1:18000:8000 "$LABCA_IMAGE" serve >/dev/null \
  || fail "could not start serve"

healthy=0
for _ in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18000/health || true)"
  if [ "$code" = "200" ]; then
    healthy=1
    break
  fi
  sleep 1
done
[ "$healthy" = "1" ] || fail "/health did not return 200 within 30s"

ready="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18000/ready || true)"
[ "$ready" = "200" ] || fail "/ready returned $ready, expected 200"
admin="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18000/ || true)"
[ "$admin" = "403" ] || fail "/ returned $admin, expected 403"

# 5. CLI.
status="$(docker run --rm "${run_flags[@]}" "$LABCA_IMAGE" cli kek status)" || fail "cli kek status failed"
echo "$status" | grep -q '"active_kek_id": "smoke-1"' || fail "cli kek status did not report smoke-1"

# 6. Done.
echo "IMAGE SMOKE: PASS"
