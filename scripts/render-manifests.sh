#!/usr/bin/env bash
# Render the Kustomize overlays into OUTDIR (ci.yaml, prod.yaml, prod-access.yaml).
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: render-manifests.sh OUTDIR" >&2
  exit 2
fi

cd "$(dirname "$0")/.."
OUTDIR="${1%/}"
KUBECTL="${KUBECTL:-kubectl}"

rm -rf "$OUTDIR/prod-access-src"
mkdir -p "$OUTDIR"

"$KUBECTL" kustomize deploy/kustomize/overlays/ci > "$OUTDIR/ci.yaml"
"$KUBECTL" kustomize deploy/kustomize/overlays/prod > "$OUTDIR/prod.yaml"

# Third render: prod plus the admin-access component, with the deploy-time
# values a real overlay would supply, so the component is validated too.
SRC="$OUTDIR/prod-access-src"
mkdir -p "$SRC"
# Kustomize only accepts relative paths, so compute them from SRC to the repo.
REL="$(realpath --relative-to="$SRC" "$PWD")"
cat > "$SRC/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - $REL/deploy/kustomize/overlays/prod
components:
  - $REL/deploy/kustomize/components/admin-access
patches:
  - target:
      kind: Ingress
      name: labca-admin
    patch: |-
      - op: replace
        path: /spec/rules/0/host
        value: labca-admin.camelon.app
configMapGenerator:
  - name: labca-config
    namespace: labca-system
    behavior: merge
    literals:
      - CF_ACCESS_TEAM_DOMAIN=example.cloudflareaccess.com
      - ADMIN_EMAILS=admin@example.invalid
EOF
"$KUBECTL" kustomize "$SRC" > "$OUTDIR/prod-access.yaml"
echo "rendered: $OUTDIR/ci.yaml $OUTDIR/prod.yaml $OUTDIR/prod-access.yaml"
