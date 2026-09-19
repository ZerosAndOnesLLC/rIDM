#!/usr/bin/env bash
# Lint the chart with every value set in ci/ and validate what it renders
# against the Kubernetes schemas (CRDs such as ServiceMonitor are skipped).
# Also checks that a release without its required values refuses to render.
# Needs helm and kubeconform on PATH.
set -euo pipefail
chart="$(cd "$(dirname "$0")/ridm" && pwd)"
k8s="${KUBERNETES_VERSION:-1.33.0}"
for values in "$chart"/ci/*.yaml; do
  echo "== $(basename "$values")"
  helm lint "$chart" -f "$values" --strict
  helm template ridm "$chart" -f "$values" \
    | kubeconform -strict -summary -ignore-missing-schemas -kubernetes-version "$k8s"
done
if helm template ridm "$chart" >/dev/null 2>&1; then
  echo "FAIL: the chart rendered without publicUrl, database, cache and master key"
  exit 1
fi
echo "ok: incomplete values refused"
