#!/usr/bin/env bash
# End-to-end test of the LabCA platform on a throwaway k3d cluster.
# Usage: bash scripts/e2e.sh
# Inputs (all optional): E2E_CLUSTER, E2E_K3S_IMAGE, E2E_BUSYBOX_IMAGE, LABCA_IMAGE,
# DEMO_IMAGE, E2E_SKIP_BUILD, E2E_KEEP_CLUSTER, E2E_WORK, E2E_TIMEOUT.
# Secrets are generated at run time, written only into YAML piped to kubectl, and never printed.
set -euo pipefail

# Stop Git Bash on Windows from rewriting container paths such as /tmp/x.
export MSYS_NO_PATHCONV=1
umask 077

E2E_CLUSTER="${E2E_CLUSTER:-labca-e2e}"
E2E_K3S_IMAGE="${E2E_K3S_IMAGE:-rancher/k3s:v1.35.5-k3s1@sha256:2074403abe1bded11ef3dde09d457e13be8e0b64c218b1c4f8269b4565cfbc65}"
E2E_BUSYBOX_IMAGE="${E2E_BUSYBOX_IMAGE:-busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e}"
LABCA_IMAGE="${LABCA_IMAGE:-labca:e2e}"
DEMO_IMAGE="${DEMO_IMAGE:-labca-mtls-demo:e2e}"
E2E_SKIP_BUILD="${E2E_SKIP_BUILD:-0}"
E2E_KEEP_CLUSTER="${E2E_KEEP_CLUSTER:-0}"
E2E_WORK="${E2E_WORK:-.cache/e2e}"
E2E_TIMEOUT="${E2E_TIMEOUT:-300}"

HOST_HEADER="labca.e2e.test"
PF_PORT=18080
NODE_CONTAINER="k3d-${E2E_CLUSTER}-server-0"
CER_CONTAINER="labca-e2e-cer-$$"

# Always run from the repo root so every path below is relative.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

CLUSTER_CREATED=0
PF_PID=""
STEPS=()
START_SECONDS=$SECONDS

log() { echo "[e2e] $*"; }

fail() {
  echo "E2E: FAIL: $*" >&2
  exit 1
}

# expect_eq <what> <expected> <observed>
expect_eq() {
  [ "$2" = "$3" ] || fail "$1: expected '$2', observed '$3'"
}

step_pass() {
  STEPS+=("$1")
  log "PASS: $1"
}

# ---------------------------------------------------------------- diagnostics and cleanup

diagnostics() {
  [ "$CLUSTER_CREATED" = "1" ] && [ -f "$E2E_WORK/kubeconfig" ] || return 0
  echo "---------------- e2e diagnostics ----------------" >&2
  {
    kubectl get nodes,pods,svc,ingress,networkpolicy,jobs,cronjobs -A -o wide || true
    kubectl describe pods -n labca-system || true
    kubectl describe pods -n mtls-demo || true
    local ns pod
    for ns in labca-system mtls-demo; do
      for pod in $(kubectl get pods -n "$ns" -o name 2>/dev/null | tr -d '\r'); do
        echo "--- logs $ns/$pod ---"
        kubectl logs -n "$ns" "$pod" --all-containers --prefix --tail=200 || true
      done
    done
    echo "--- events ---"
    kubectl get events -A --sort-by=.lastTimestamp 2>/dev/null | tail -n 80 || true
  } >&2 || true
}

cleanup() {
  local rc=$?
  trap - EXIT
  set +e
  if [ "$rc" -ne 0 ]; then
    diagnostics
  fi
  if [ -n "$PF_PID" ]; then
    kill "$PF_PID" >/dev/null 2>&1
    wait "$PF_PID" >/dev/null 2>&1
  fi
  docker rm -f "$CER_CONTAINER" >/dev/null 2>&1
  if [ "$CLUSTER_CREATED" = "1" ] && [ "$E2E_KEEP_CLUSTER" != "1" ]; then
    k3d cluster delete "$E2E_CLUSTER" >/dev/null 2>&1
    rm -f "$E2E_WORK/kubeconfig"
  fi
  # The ceremony output holds a test issuing key.
  rm -rf "$E2E_WORK/cer"
  if [ "$rc" -ne 0 ]; then
    echo "E2E: FAIL (exit $rc)" >&2
  fi
  exit "$rc"
}
trap cleanup EXIT

# ---------------------------------------------------------------- helpers

# poll <what> <timeout_seconds> <command...>: run the command every 2 seconds until it succeeds.
poll() {
  local what="$1" timeout="$2"
  shift 2
  local deadline=$((SECONDS + timeout))
  while ! "$@" >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      fail "timed out after ${timeout}s waiting for: $what"
    fi
    sleep 2
  done
}

# Secret generators. Tracing is switched off inside so values can never reach a trace.
rand_b64() {
  { set +x; } 2>/dev/null
  head -c "$1" /dev/urandom | base64 | tr -d '\n'
}

b64_of() {
  { set +x; } 2>/dev/null
  printf '%s' "$1" | base64 | tr -d '\n'
}

create_secrets() {
  { set +x; } 2>/dev/null
  local kek kek_data secret_key token_secret
  kek="$(rand_b64 32)"
  kek_data="$(b64_of "$kek")"
  secret_key="$(rand_b64 48)"
  token_secret="$(rand_b64 32)"
  printf 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: labca-kek\n  namespace: labca-system\ntype: Opaque\ndata:\n  kek-2026a: %s\n' \
    "$kek_data" | kubectl apply -f - >/dev/null
  printf 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: labca-app\n  namespace: labca-system\ntype: Opaque\nstringData:\n  SECRET_KEY: "%s"\n  API_TOKEN_CREATION_SECRET: "%s"\n  CF_ACCESS_AUD: ""\n' \
    "$secret_key" "$token_secret" | kubectl apply -f - >/dev/null
}

labca_pod() {
  kubectl -n labca-system get pod -l app.kubernetes.io/name=labca \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null | tr -d '\r'
}

labca_started() {
  local v
  v="$(kubectl -n labca-system get pod -l app.kubernetes.io/name=labca \
    -o jsonpath='{.items[0].status.containerStatuses[?(@.name=="labca")].started}' 2>/dev/null | tr -d '\r')" || return 1
  [ "$v" = "true" ]
}

# http_get <path> <body_file> <header_file>: prints the status code.
http_get() {
  curl -sS -H "Host: $HOST_HEADER" -D "$3" -o "$2" -w '%{http_code}' "http://127.0.0.1:${PF_PORT}$1" | tr -d '\r'
}

header_value() {
  grep -i "^$2:" "$1" | head -n 1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'
}

load_image() {
  local img="$1" name="${1%%:*}" tag="${1##*:}"
  if docker save --help 2>&1 | grep -q -- '--platform'; then
    docker save --platform linux/amd64 "$img" \
      | docker exec -i "$NODE_CONTAINER" ctr -n k8s.io images import --platform linux/amd64 - >/dev/null
  else
    docker save "$img" | docker exec -i "$NODE_CONTAINER" ctr -n k8s.io images import - >/dev/null
  fi
  if ! docker exec "$NODE_CONTAINER" ctr -n k8s.io images ls -q | tr -d '\r' | grep -Fxq "docker.io/library/${name}:${tag}"; then
    fail "image docker.io/library/${name}:${tag} is not present in the node containerd after import"
  fi
}

# ---------------------------------------------------------------- step 1: tools and work dir

for tool in docker k3d kubectl jq openssl curl; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool not found on PATH: $tool"
done
mkdir -p "$E2E_WORK"
rm -rf "$E2E_WORK/cer"
rm -f "$E2E_WORK/kubeconfig"
step_pass "1 tool check and work directory"

# ---------------------------------------------------------------- step 2: images

if [ "$E2E_SKIP_BUILD" != "1" ]; then
  log "building images"
  docker build -t "$LABCA_IMAGE" .
  docker build -t "$DEMO_IMAGE" mtls-demo
fi
docker image inspect "$LABCA_IMAGE" >/dev/null 2>&1 || fail "image not found locally: $LABCA_IMAGE"
docker image inspect "$DEMO_IMAGE" >/dev/null 2>&1 || fail "image not found locally: $DEMO_IMAGE"
# The ci overlay uses these names.
[ "$LABCA_IMAGE" = "labca:e2e" ] || docker tag "$LABCA_IMAGE" labca:e2e
[ "$DEMO_IMAGE" = "labca-mtls-demo:e2e" ] || docker tag "$DEMO_IMAGE" labca-mtls-demo:e2e
step_pass "2 images"

# ---------------------------------------------------------------- step 3: cluster

if k3d cluster get "$E2E_CLUSTER" >/dev/null 2>&1; then
  log "deleting existing cluster $E2E_CLUSTER"
  k3d cluster delete "$E2E_CLUSTER"
fi
CLUSTER_CREATED=1
k3d cluster create "$E2E_CLUSTER" \
  --image "$E2E_K3S_IMAGE" \
  --k3s-arg "--disable=servicelb@server:0" \
  --k3s-arg "--secrets-encryption@server:0" \
  --no-lb --wait --timeout 180s \
  --kubeconfig-update-default=false --kubeconfig-switch-context=false
if k3d kubeconfig write "$E2E_CLUSTER" --output "$E2E_WORK/kubeconfig" >/dev/null 2>&1; then
  :
else
  k3d kubeconfig get "$E2E_CLUSTER" > "$E2E_WORK/kubeconfig"
fi
export KUBECONFIG="$E2E_WORK/kubeconfig"

load_image labca:e2e
load_image labca-mtls-demo:e2e

# The HelmChartConfig CRD appears a few seconds after the server starts.
poll "HelmChartConfig CRD and traefik-config apply" 120 kubectl apply -f deploy/k3s/traefik-config.yaml
poll "deployment/traefik in kube-system" "$E2E_TIMEOUT" kubectl -n kube-system get deployment traefik
traefik_is_clusterip() {
  [ "$(kubectl -n kube-system get svc traefik -o jsonpath='{.spec.type}' | tr -d '\r')" = "ClusterIP" ]
}
poll "svc/traefik type ClusterIP" "$E2E_TIMEOUT" traefik_is_clusterip
kubectl -n kube-system rollout status deployment/traefik --timeout "${E2E_TIMEOUT}s"
expect_eq "svc/traefik type" "ClusterIP" \
  "$(kubectl -n kube-system get svc traefik -o jsonpath='{.spec.type}' | tr -d '\r')"
step_pass "3 cluster, image load, traefik"

# ---------------------------------------------------------------- step 4: ceremony (test mode)

# Throwaway container, never runs in the cluster. If /tmp were not writable by UID 10001
# at docker cp time, add --user 0:0 here.
docker create --name "$CER_CONTAINER" --entrypoint python "$LABCA_IMAGE" \
  /tmp/ceremony.py init --mode test --out /tmp/cer \
  --issuing-cdp https://labca.e2e.test/pki/root/crl.der >/dev/null
docker cp pki/ceremony/ceremony.py "$CER_CONTAINER:/tmp/ceremony.py"
docker start -a "$CER_CONTAINER" >/dev/null
docker cp "$CER_CONTAINER:/tmp/cer" "$E2E_WORK/cer"
docker rm "$CER_CONTAINER" >/dev/null
for f in root-ca.pem root-crl.der issuing-ca.pem chain.pem issuing-ca.key.pem; do
  [ -s "$E2E_WORK/cer/$f" ] || fail "ceremony output missing or empty: $f"
done
step_pass "4 ceremony in test mode"

# ---------------------------------------------------------------- step 5: deploy

kubectl apply -k deploy/kustomize/overlays/ci >/dev/null
create_secrets
kubectl -n labca-system create configmap labca-pki-static \
  --from-file=root-ca.pem="$E2E_WORK/cer/root-ca.pem" \
  --from-file=root-crl.der="$E2E_WORK/cer/root-crl.der" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n mtls-demo create configmap labca-trust-bundle \
  --from-file=trust-bundle.pem="$E2E_WORK/cer/root-ca.pem" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
step_pass "5 deploy overlays/ci, secrets, configmaps"

# ---------------------------------------------------------------- step 6: labca up, not ready

poll "labca container started" "$E2E_TIMEOUT" labca_started
POD="$(labca_pod)"
[ -n "$POD" ] || fail "no labca pod found"
ready_out="$(kubectl -n labca-system exec "$POD" -c labca -- python -c "
import urllib.request, urllib.error
try:
    r = urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=5)
    print(r.status, r.read().decode())
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode())
" | tr -d '\r')"
case "$ready_out" in
  503*workload_issuer_missing*) ;;
  *) fail "/ready before import: expected 503 with workload_issuer_missing, observed '$ready_out'" ;;
esac
step_pass "6 labca started, /ready is 503 workload_issuer_missing"

# ---------------------------------------------------------------- step 7: import the PKI

for f in root-ca.pem issuing-ca.pem chain.pem; do
  kubectl exec -i "$POD" -n labca-system -c labca -- sh -c "cat > /tmp/$f" < "$E2E_WORK/cer/$f"
done
kubectl exec "$POD" -n labca-system -c labca -- /app/docker-entrypoint.sh cli ca import-root-cert \
  --name "LabCA Offline Root CA 2026" --cert /tmp/root-ca.pem
kubectl exec -i "$POD" -n labca-system -c labca -- /app/docker-entrypoint.sh cli ca import \
  --name "LabCA Workload Issuing CA 1" --cert /tmp/issuing-ca.pem --chain /tmp/chain.pem --key-stdin \
  < "$E2E_WORK/cer/issuing-ca.key.pem"
# Overwrite the test issuing key with zeros, then remove it.
key_size="$(wc -c < "$E2E_WORK/cer/issuing-ca.key.pem" | tr -d ' \r')"
head -c "$key_size" /dev/zero > "$E2E_WORK/cer/issuing-ca.key.pem"
rm -f "$E2E_WORK/cer/issuing-ca.key.pem"
kubectl -n labca-system wait --for=condition=Ready pod -l app.kubernetes.io/name=labca \
  --timeout "${E2E_TIMEOUT}s"
step_pass "7 PKI import through exec stdin, labca Ready"

# ---------------------------------------------------------------- step 8: workloads

for d in demo-server demo-client; do
  if ! kubectl -n mtls-demo rollout status "deployment/$d" --timeout "${E2E_TIMEOUT}s"; then
    log "$d not ready, restarting once"
    kubectl -n mtls-demo rollout restart "deployment/$d"
    kubectl -n mtls-demo rollout status "deployment/$d" --timeout "${E2E_TIMEOUT}s" \
      || fail "deployment/$d did not become ready"
  fi
done
# demo-client calls every 15 seconds. The verifier's first scenario needs a recorded call, so
# wait until demo-server has one (read through the API server service proxy).
server_has_call() {
  kubectl get --raw "/api/v1/namespaces/mtls-demo/services/demo-server:status/proxy/status.json" \
    | jq -e '.last_authorized_call != null'
}
poll "demo-server to record an authorized call from demo-client" "$E2E_TIMEOUT" server_has_call
step_pass "8 demo-server and demo-client rolled out, first authorized call recorded"

# ---------------------------------------------------------------- step 9: verifier

kubectl -n mtls-demo create job --from=cronjob/mtls-verifier e2e-1 >/dev/null
job_deadline=$((SECONDS + E2E_TIMEOUT))
while :; do
  succeeded="$(kubectl -n mtls-demo get job e2e-1 -o jsonpath='{.status.succeeded}' | tr -d '\r')"
  failed="$(kubectl -n mtls-demo get job e2e-1 -o jsonpath='{.status.failed}' | tr -d '\r')"
  [ "${succeeded:-0}" = "1" ] && break
  if [ "${failed:-0}" -ge 1 ]; then
    kubectl -n mtls-demo logs -l job-name=e2e-1 --all-containers --tail=200 || true
    fail "verifier Job e2e-1 failed"
  fi
  [ "$SECONDS" -lt "$job_deadline" ] || fail "verifier Job e2e-1 did not finish within ${E2E_TIMEOUT}s"
  sleep 2
done
kubectl -n mtls-demo get configmap mtls-status -o jsonpath='{.data.results\.json}' > "$E2E_WORK/results.json"
jq -e '.all_passed == true and (.scenarios | length) >= 5 and all(.scenarios[]; .passed == true)' \
  "$E2E_WORK/results.json" >/dev/null \
  || fail "results.json: expected all_passed true with at least 5 passing scenarios, observed: $(jq -c '[.all_passed, (.scenarios | map({name, passed}))]' "$E2E_WORK/results.json" | tr -d '\r')"
jq -r '.scenarios[] | "  \(.name): \(.observed)"' "$E2E_WORK/results.json" | tr -d '\r'
step_pass "9 verifier all_passed"

# ---------------------------------------------------------------- step 10: ingress and public PKI

kubectl -n kube-system port-forward svc/traefik "${PF_PORT}:80" >"$E2E_WORK/port-forward.log" 2>&1 &
PF_PID=$!
pf_ready() { curl -s -o /dev/null -H "Host: $HOST_HEADER" "http://127.0.0.1:${PF_PORT}/healthz"; }
poll "port-forward to traefik" 60 pf_ready

B="$E2E_WORK/body.bin"
H="$E2E_WORK/headers.txt"

code="$(http_get /pki/index.json "$B" "$H")"
expect_eq "GET /pki/index.json status" "200" "$code"
case "$(header_value "$H" content-type)" in
  application/json*) ;;
  *) fail "GET /pki/index.json Content-Type: expected application/json*, observed '$(header_value "$H" content-type)'" ;;
esac
jq -e '.cas | length >= 1' "$B" >/dev/null || fail "GET /pki/index.json: expected .cas with at least 1 entry"

code="$(http_get /pki/issuing/crl.der "$E2E_WORK/crl.der" "$H")"
expect_eq "GET /pki/issuing/crl.der status" "200" "$code"
expect_eq "GET /pki/issuing/crl.der Content-Type" "application/pkix-crl" "$(header_value "$H" content-type)"

code="$(http_get /pki/issuing/chain.pem "$B" "$H")"
expect_eq "GET /pki/issuing/chain.pem status" "200" "$code"
expect_eq "GET /pki/issuing/chain.pem Content-Type" "application/x-pem-file" "$(header_value "$H" content-type)"

code="$(http_get /pki/trust-bundle.pem "$B" "$H")"
expect_eq "GET /pki/trust-bundle.pem status" "200" "$code"
tr -d '\r' < "$B" > "$E2E_WORK/trust-bundle.norm"
tr -d '\r' < "$E2E_WORK/cer/root-ca.pem" > "$E2E_WORK/root-ca.norm"
cmp -s "$E2E_WORK/trust-bundle.norm" "$E2E_WORK/root-ca.norm" \
  || fail "GET /pki/trust-bundle.pem: expected content identical to cer/root-ca.pem"

code="$(http_get / "$B" "$H")"
expect_eq "GET / status" "200" "$code"
code="$(http_get /cas "$B" "$H")"
expect_eq "GET /cas status (routed to demo-server)" "404" "$code"
code="$(http_get /api/v1/workload/sign "$B" "$H")"
expect_eq "GET /api/v1/workload/sign status (routed to demo-server)" "404" "$code"

status_ok() {
  curl -sS -H "Host: $HOST_HEADER" "http://127.0.0.1:${PF_PORT}/status.json" \
    | jq -e '.verifier.all_passed == true'
}
poll "/status.json with verifier.all_passed true (ConfigMap volume refresh)" 120 status_ok
step_pass "10 ingress routing and public PKI"

# ---------------------------------------------------------------- step 11: CRL proof

crl_out="$(openssl crl -inform DER -in "$E2E_WORK/crl.der" -CAfile "$E2E_WORK/cer/chain.pem" -noout 2>&1)" \
  || fail "CRL signature check failed: $crl_out"
printf '%s\n' "$crl_out" | grep -q 'verify OK' || fail "CRL signature: expected 'verify OK', observed '$crl_out'"
crl_text="$(openssl crl -inform DER -in "$E2E_WORK/crl.der" -noout -text)"
serial_count="$(printf '%s\n' "$crl_text" | grep -c 'Serial Number:' || true)"
[ "$serial_count" -ge 1 ] || fail "CRL: expected at least one revoked Serial Number, observed $serial_count"
# The revoked serial is the lowercase hex without padding in the observed text of
# revoked_identity_rejected ("serial <hex> revoked at CRL ...").
rev_serial="$(jq -r '.scenarios[] | select(.name == "revoked_identity_rejected") | .observed' "$E2E_WORK/results.json" \
  | tr -d '\r' | sed -n 's/^serial \([0-9a-fA-F]*\) revoked.*/\1/p' | head -n 1)"
if [ -n "$rev_serial" ]; then
  want="$(printf '%s' "$rev_serial" | tr 'a-f' 'A-F' | sed 's/^0*//')"
  have="$(printf '%s\n' "$crl_text" | sed -n 's/^ *Serial Number: *//p' | tr -d ':\r' | tr 'a-f' 'A-F' | sed 's/^0*//')"
  printf '%s\n' "$have" | grep -Fxq "$want" || fail "CRL: expected revoked serial $want, observed: $(printf '%s' "$have" | tr '\n' ' ')"
else
  log "revoked serial not exposed in results.json observed; asserted the revoked count only"
fi
step_pass "11 CRL signature and content"

# ---------------------------------------------------------------- step 12: negative checks

# NetworkPolicy. The positive control is the verifier result in step 9: the demo images have no
# shell, so no allowed pod exists to run a wget from.
np_out="$(kubectl -n default run np-probe --image "$E2E_BUSYBOX_IMAGE" --restart=Never --rm -i --quiet \
  --pod-running-timeout="${E2E_TIMEOUT}s" --command -- sh -c \
  'if wget -q -T 5 -O- http://labca.labca-system.svc.cluster.local:8000/health >/dev/null 2>&1; then echo REACHED; else echo BLOCKED; fi' \
  | tr -d '\r')"
printf '%s\n' "$np_out" | grep -qx 'BLOCKED' || fail "NetworkPolicy probe: expected BLOCKED, observed '$np_out'"

# RBAC.
can_i() { # can_i <expected yes|no> <sa> <verb> <resource> <namespace>
  local expected="$1" sa="$2" verb="$3" res="$4" ns="$5" out
  out="$(kubectl auth can-i "$verb" "$res" -n "$ns" --as="system:serviceaccount:$sa" 2>/dev/null | tr -d '\r')" || true
  expect_eq "can-i $sa $verb $res -n $ns" "$expected" "$out"
}
can_i no  mtls-demo:demo-client get secrets mtls-demo
can_i yes mtls-demo:mtls-verifier patch configmaps/mtls-status mtls-demo
can_i no  mtls-demo:mtls-verifier get configmaps/mtls-status mtls-demo
can_i no  mtls-demo:mtls-verifier patch configmaps/labca-trust-bundle mtls-demo
can_i no  mtls-demo:mtls-verifier get secrets mtls-demo
can_i yes labca-system:labca create tokenreviews.authentication.k8s.io labca-system
can_i no  labca-system:labca get secrets labca-system

# Pod Security Admission.
psa_rc=0
psa_out="$(kubectl -n mtls-demo run psa-probe --image "$E2E_BUSYBOX_IMAGE" --restart=Never --privileged \
  --command -- true 2>&1 | tr -d '\r')" || psa_rc=$?
[ "$psa_rc" -ne 0 ] || fail "PSA: expected the privileged pod to be rejected, but it was created"
case "$psa_out" in
  *'violates PodSecurity "restricted'*) ;;
  *) fail "PSA: expected a message containing 'violates PodSecurity \"restricted', observed '$psa_out'" ;;
esac
if kubectl -n mtls-demo get pod psa-probe >/dev/null 2>&1; then
  fail "PSA: pod psa-probe exists after a rejected create"
fi
step_pass "12 NetworkPolicy, RBAC, PSA negatives"

# ---------------------------------------------------------------- step 13: summary

echo
echo "================ e2e summary ================"
for s in "${STEPS[@]}"; do
  echo "PASS  $s"
done
echo "runtime: $((SECONDS - START_SECONDS))s"
echo "E2E: PASS"
