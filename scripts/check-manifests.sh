#!/usr/bin/env bash
# Render the manifests and run schema, lint, security, and contract checks.
# Tool commands can be replaced with KUBECONFORM, KUBE_LINTER, TRIVY, and PYTEST.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT=".cache/rendered"
KUBECONFORM="${KUBECONFORM:-kubeconform}"
KUBE_LINTER="${KUBE_LINTER:-kube-linter}"
TRIVY="${TRIVY:-trivy}"
PYTEST="${PYTEST:-python -m pytest}"

bash scripts/render-manifests.sh "$OUT"

FILES=("$OUT/ci.yaml" "$OUT/prod.yaml" "$OUT/prod-access.yaml")

for f in "${FILES[@]}"; do
  echo "== kubeconform $f"
  # KUBE_VERSION defaults to 1.35.0. If the schema set for it is missing,
  # set KUBE_VERSION to the newest available version and record that in the report.
  $KUBECONFORM -strict -summary -kubernetes-version "${KUBE_VERSION:-1.35.0}" -schema-location default "$f"
done

for f in "${FILES[@]}"; do
  echo "== kube-linter $f"
  $KUBE_LINTER lint --config .kube-linter.yaml "$f"
done

echo "== trivy config $OUT"
# KSV-0109 matches the key names KUBE_SA_TOKEN_FILE (a file path) and
# WORKLOAD_TOKEN_AUDIENCE (the string "labca") in the labca-config ConfigMap.
# Neither holds a secret. Real secret values are kept out of the manifests by
# the contract test (no Secret objects) and by gitleaks.
IGNORE="$OUT/../trivyignore.yaml"
cat > "$IGNORE" <<'EOF'
misconfigurations:
  - id: KSV-0109
    paths:
      - "ci.yaml"
      - "prod.yaml"
      - "prod-access.yaml"
    statement: "False positive on the key names KUBE_SA_TOKEN_FILE and WORKLOAD_TOKEN_AUDIENCE; the values are a path and a public audience string."
    # Review this entry again by then (at most 90 days per entry).
    expired_at: 2027-01-13
EOF
$TRIVY config --severity HIGH,CRITICAL --exit-code 1 --ignorefile "$IGNORE" "$OUT/"

echo "== contract tests"
$PYTEST -q -p no:cacheprovider -m manifests tests/test_manifests_contract.py

echo "MANIFESTS: PASS"
