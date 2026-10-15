#!/usr/bin/env bash
# Run the Playwright UI tests, one test per fresh LabCA instance.
# The setup wizard redirects to /cas once any CA exists, so the setup tests cannot
# share a database. Each test node ID therefore gets its own temp SQLite database,
# migrated to head, and its own uvicorn process.
#
# The pages load the Tailwind Play CDN script. When it loads, it injects CSS whose text
# contains strings such as "line " that tests/ui/test_error_ui.py treats as traceback
# markers. The browser therefore runs with an unreachable proxy for everything except
# localhost, so the tests do not depend on internet access or on third-party CSS.
# Keep it after WP-06 removes the CDN script: UI tests must never make network calls.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${UI_PORT:-8000}"
SERVER_PID=""
TMP_DIR=""

stop_server() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi
}

cleanup() {
  stop_server
  if [ -n "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
    TMP_DIR=""
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

python -m playwright install chromium

mapfile -t NODE_IDS < <(python -m pytest -m ui --collect-only -q tests/ui | grep '::' || true)

PASSED=0
FAILED=0

for NODE_ID in "${NODE_IDS[@]}"; do
  [ -n "$NODE_ID" ] || continue
  TMP_DIR="$(mktemp -d)"
  export DATABASE_URL="sqlite:///$TMP_DIR/labca-ui.db"
  export API_TOKEN_CREATION_SECRET="ui-test-secret"
  export ENV="test"
  LABCA_KEK_UI_TEST="$(python -c 'import base64, os; print(base64.b64encode(os.urandom(32)).decode())')"
  export LABCA_KEK_UI_TEST
  export LABCA_ACTIVE_KEK_ID="ui-test"

  python -m alembic upgrade head
  python -m uvicorn app.main:app --host 127.0.0.1 --port "$PORT" >"$TMP_DIR/server.log" 2>&1 &
  SERVER_PID=$!

  READY=0
  python - "$PORT" <<'PY' || READY=1
import sys
import time
import urllib.request

url = f"http://127.0.0.1:{sys.argv[1]}/health"
deadline = time.time() + 30
while time.time() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            if resp.status == 200:
                sys.exit(0)
    except Exception:
        time.sleep(0.5)
sys.exit(1)
PY

  export TEST_BASE_URL="http://127.0.0.1:$PORT"
  if [ "$READY" -eq 0 ] && HTTP_PROXY="http://127.0.0.1:9" HTTPS_PROXY="http://127.0.0.1:9" NO_PROXY="127.0.0.1,localhost" python -m pytest -m ui "$NODE_ID"; then
    PASSED=$((PASSED + 1))
  else
    FAILED=$((FAILED + 1))
    echo "Server log (last 50 lines) for $NODE_ID:"
    tail -n 50 "$TMP_DIR/server.log" || true
  fi

  stop_server
  rm -rf "$TMP_DIR"
  TMP_DIR=""
done

echo "UI tests: $PASSED passed, $FAILED failed"
if [ "$FAILED" -gt 0 ] || [ "$((PASSED + FAILED))" -eq 0 ]; then
  exit 1
fi
