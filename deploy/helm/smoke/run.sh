#!/usr/bin/env bash
# Smoke test for the Helm chart: a throwaway kind cluster, Postgres and Valkey
# in it, the chart installed from a locally built image, then checks through
# a port-forward, an upgrade (the migration hook again) and an uninstall.
#
#   docker build -f api/Dockerfile -t ridm:smoke .
#   RIDM_IMAGE=ridm:smoke deploy/helm/smoke/run.sh
#
# KEEP_CLUSTER=1 leaves the cluster up for a look afterwards, with the
# kubeconfig path printed (kind delete cluster --name "$CLUSTER" removes it).
# Your own kubeconfig and current context are never touched.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
chart="$root/deploy/helm/ridm"
: "${RIDM_IMAGE:?set RIDM_IMAGE to a locally built image, e.g. ridm:smoke}"
CLUSTER="${CLUSTER:-ridm-helm-smoke}"
NS=ridm
PORT="${PORT:-18080}"
repo="${RIDM_IMAGE%:*}"
tag="${RIDM_IMAGE##*:}"
pf=""
# A kubeconfig of its own, so the caller's current context is left alone.
KUBECONFIG="$(mktemp)"
export KUBECONFIG

log() { printf '\n== %s\n' "$*"; }
cleanup() {
  status=$?
  [ -n "$pf" ] && kill "$pf" 2>/dev/null || true
  if [ "$status" -ne 0 ]; then
    log "failed; state of the namespace"
    kubectl -n "$NS" get pods,jobs,events --sort-by=.lastTimestamp 2>/dev/null | tail -40 || true
    kubectl -n "$NS" logs -l app.kubernetes.io/name=ridm --all-containers --tail=80 2>/dev/null || true
  fi
  if [ -z "${KEEP_CLUSTER:-}" ]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
    rm -f "$KUBECONFIG"
  else
    echo "cluster kept; KUBECONFIG=$KUBECONFIG"
  fi
  exit "$status"
}
trap cleanup EXIT

log "cluster $CLUSTER"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --wait 120s
kind load docker-image "$RIDM_IMAGE" --name "$CLUSTER"

log "postgres and valkey"
kubectl create namespace "$NS"
kubectl -n "$NS" create configmap postgres-init \
  --from-file=init-app-role.sh="$root/deploy/postgres/init-app-role.sh"
kubectl -n "$NS" apply -f "$here/deps.yaml"
kubectl -n "$NS" rollout status deploy/postgres --timeout=180s
kubectl -n "$NS" rollout status deploy/valkey --timeout=180s
kubectl -n "$NS" create secret generic smoke-master-key \
  --from-literal=key="$(openssl rand -hex 32)"

log "helm lint and install"
helm lint "$chart" -f "$here/values.yaml" --strict
helm install ridm "$chart" -n "$NS" -f "$here/values.yaml" \
  --set image.repository="$repo" --set image.tag="$tag" \
  --wait --timeout 5m
kubectl -n "$NS" get pods -o wide
# Replicas starting together take turns at the one-time start-up work
# (bootstrap, built-in clients); none may have crashed on a race.
restarts="$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=ridm \
  -o jsonpath='{range .items[*]}{.status.containerStatuses[0].restartCount}{"\n"}{end}' | sort -u)"
[ "$restarts" = 0 ] || { echo "FAIL pods restarted during install: $restarts"; exit 1; }
echo "ok   no restarts on first install"

# A port-forward holds one pod, so it is reopened after every rollout.
forward() {
  [ -n "$pf" ] && kill "$pf" 2>/dev/null || true
  kubectl -n "$NS" port-forward svc/ridm "$PORT:80" >/dev/null 2>&1 &
  pf=$!
  for _ in $(seq 1 30); do curl -sf "localhost:$PORT/healthz" >/dev/null && return; sleep 1; done
  echo "FAIL port-forward never answered"; exit 1
}

log "checks"
forward
host=(-H "Host: ridm.smoke.test")
expect() { # expect <status> <path> [grep pattern]
  local body code
  body="$(mktemp)"
  code="$(curl -s -o "$body" -w '%{http_code}' "${host[@]}" "localhost:$PORT$2")"
  if [ "$code" != "$1" ] || { [ -n "${3:-}" ] && ! grep -q "$3" "$body"; }; then
    echo "FAIL $2: HTTP $code (wanted $1${3:+ containing $3})"; head -c 400 "$body"; echo
    exit 1
  fi
  echo "ok   $2 -> $code"
}
expect 200 /readyz '"database":"ok"'
expect 200 /t/master/.well-known/openid-configuration '"issuer":"https://ridm.smoke.test/t/master"'
expect 200 /t/master/.well-known/jwks.json '"keys"'
expect 200 /login/ 'Content-Security-Policy'
expect 200 /console/ '<html'
expect 308 /account
# The pods run as the DML-only role; the hook Job and its Secret are gone.
kubectl -n "$NS" get secret ridm-migrate >/dev/null 2>&1 && { echo "FAIL migration secret left behind"; exit 1; }
kubectl -n "$NS" get job ridm-migrate >/dev/null 2>&1 && { echo "FAIL migration job left behind"; exit 1; }
# The bootstrap administrator exists.
kubectl -n "$NS" exec deploy/postgres -- psql -U ridm -d ridm -tAc \
  "SET app.bypass_rls='on'; SELECT count(*) FROM users WHERE email='admin@ridm.smoke.test'" | grep -qx 1 \
  || { echo "FAIL bootstrap admin missing"; exit 1; }
echo "ok   bootstrap administrator"

log "upgrade (migration hook again, rolling restart)"
helm upgrade ridm "$chart" -n "$NS" -f "$here/values.yaml" \
  --set image.repository="$repo" --set image.tag="$tag" \
  --set env.RETENTION_DAYS=14 --wait --timeout 5m
[ "$(kubectl -n "$NS" get configmap ridm -o jsonpath='{.data.RETENTION_DAYS}')" = 14 ] \
  || { echo "FAIL upgrade did not change the configuration"; exit 1; }
forward
expect 200 /readyz '"database":"ok"'

log "uninstall"
kill "$pf" 2>/dev/null || true; pf=""
helm uninstall ridm -n "$NS" --wait
kubectl -n "$NS" wait --for=delete pod -l app.kubernetes.io/instance=ridm --timeout=90s
left="$(kubectl -n "$NS" get all,secrets,configmaps -l app.kubernetes.io/instance=ridm -o name)"
[ -z "$left" ] || { echo "FAIL left behind: $left"; exit 1; }
echo "ok   nothing of the release left"
log "chart smoke test passed"
