#!/usr/bin/env bash
# Run the OpenID conformance plans against a running rIDM.
#
#   OP_ISSUER=http://localhost:8092/t/master OP_UI_URL=http://localhost:3112 \
#   OP_USER=alice OP_PASSWORD=secret conformance/run.sh [plan ...]
#
# Needs: the suite up (conformance/docker-compose.yml), python3 with `requests`,
# the tenant with open dynamic client registration allowing authorization_code
# and refresh_token, and a user who can sign in with a password (no forced change).
set -euo pipefail
cd "$(dirname "$0")"
: "${OP_ISSUER:?}" "${OP_UI_URL:?}" "${OP_USER:?}" "${OP_PASSWORD:?}"
export CONFORMANCE_SERVER="${CONFORMANCE_SERVER:-https://localhost:18443/}"
export DISABLE_SSL_VERIFY=1
export CONFORMANCE_DEV_MODE=1

for i in $(seq 1 60); do
  curl -ksf "${CONFORMANCE_SERVER}api/runner/available" >/dev/null 2>&1 && break
  sleep 3
done
curl -ksf "${CONFORMANCE_SERVER}api/runner/available" >/dev/null

config="$(mktemp)"
OP_ISSUER="$OP_ISSUER" OP_UI_URL="$OP_UI_URL" OP_USER="$OP_USER" OP_PASSWORD="$OP_PASSWORD" \
  envsubst '$OP_ISSUER $OP_UI_URL $OP_USER $OP_PASSWORD' < ridm-oidcc.json > "$config"

plans=("$@")
if [ "${#plans[@]}" -eq 0 ]; then
  plans=(
    "oidcc-config-certification-test-plan"
    "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client]"
    "oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=dynamic_client]"
    "oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=dynamic_client]"
    "oidcc-frontchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=dynamic_client]"
  )
fi
args=()
for p in "${plans[@]}"; do args+=("$p" "$config"); done
mkdir -p results
# The suite's own HtmlUnit browser cannot run rIDM's pages: a headless
# Chromium inside the suite's network visits every URL the tests leave pending.
PW_IMAGE="${PW_IMAGE:-mcr.microsoft.com/playwright:v1.63.0-noble}"
docker rm -f conformance-driver >/dev/null 2>&1 || true
# The driver verifies the suite's certificate against the CA certs.sh issued it
# from (`nginx` is one of its names). DRIVER_INSECURE_TLS=1 gives that up, for a
# rig whose certificates came from somewhere else.
tls=(-v "$PWD/certs:/certs:ro" -e NODE_EXTRA_CA_CERTS=/certs/ca.crt)
if [ "${DRIVER_INSECURE_TLS:-0}" = "1" ]; then
  echo "DRIVER_INSECURE_TLS=1: the driver will not verify the suite's certificate" >&2
  tls=(-e NODE_TLS_REJECT_UNAUTHORIZED=0)
fi
docker run -d --name conformance-driver --network conformance_default \
  -v "$PWD/driver.mjs:/driver.mjs:ro" -v "$PWD/../ui/node_modules:/node_modules:ro" \
  "${tls[@]}" \
  -e NODE_PATH=/node_modules -e CONFORMANCE_SERVER=https://nginx:8443/ \
  -e OP_USER="$OP_USER" -e OP_PASSWORD="$OP_PASSWORD" \
  "$PW_IMAGE" node /driver.mjs >/dev/null
trap 'docker logs conformance-driver > results/driver.log 2>&1 || true; docker rm -f conformance-driver >/dev/null 2>&1 || true' EXIT
# The runner needs httpx; keep it in a local virtualenv.
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv && .venv/bin/pip install -q httpx pyparsing
fi
.venv/bin/python suite/run-test-plan.py --expected-failures-file expected-failures.json \
  --expected-skips-file expected-skips.json --export-dir results --verbose "${args[@]}"
