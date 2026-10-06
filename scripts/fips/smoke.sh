#!/usr/bin/env bash
# smoke.sh <image>: boot a FIPS image (api/Dockerfile.fips) and check what
# docs/src/deploy/fips.md promises, on a host that isn't in FIPS mode (CI,
# a laptop):
#
#   1. without FIPS_ALLOW_NON_FIPS_HOST it refuses to start;
#   2. with it, it starts, logs the FIPS module, and serves /healthz over TLS;
#   3. the listener refuses ChaCha20 and plain X25519, and accepts AES-GCM
#      over P-256, P-384 and X25519MLKEM768.
#
# It starts its own Postgres and Valkey on a throwaway Docker network and
# removes everything afterwards.
set -euo pipefail

image="${1:?usage: smoke.sh <image>}"
name="ridm-fips-smoke-$$"
net="$name"
work="$(mktemp -d)"
port="${FIPS_SMOKE_PORT:-18443}"

cleanup() {
  docker rm -f "$name-api" "$name-pg" "$name-valkey" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; docker logs "$name-api" 2>&1 | tail -40 || true; exit 1; }

docker network create "$net" >/dev/null
docker run -d --name "$name-pg" --network "$net" \
  -e POSTGRES_USER=ridm -e POSTGRES_PASSWORD=ridm -e POSTGRES_DB=ridm \
  postgres:18.6-alpine >/dev/null
docker run -d --name "$name-valkey" --network "$net" valkey/valkey:9.1.2-alpine3.24 >/dev/null
for _ in $(seq 1 60); do
  docker exec "$name-pg" pg_isready -U ridm -d ridm >/dev/null 2>&1 && break
  sleep 1
done

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/key.pem" -out "$work/cert.pem" -days 1 -subj /CN=localhost 2>/dev/null
# The image runs as uid 65532: it must be able to enter the directory and read both.
chmod 755 "$work"
chmod 644 "$work/key.pem" "$work/cert.pem"

env_args=(
  -e DATABASE_URL="postgres://ridm:ridm@$name-pg:5432/ridm"
  -e REDIS_URL="redis://$name-valkey:6379"
  -e BIND_ADDR=0.0.0.0:8443
  -e PUBLIC_URL="https://localhost:$port"
  -e UI_URL="https://localhost:$port"
  -e MIGRATE_ON_START=true
  -e MASTER_KEY="$(openssl rand -hex 32)"
  -e TLS_CERT=/certs/cert.pem -e TLS_KEY=/certs/key.pem
  -e SMTP_HOST=localhost -e SMTP_PORT=1025 -e SMTP_SECURITY=none -e SMTP_FROM=ridm@localhost
)

# 1. No override: refused.
set +e
out="$(docker run --rm --network "$net" -v "$work:/certs:ro" "${env_args[@]}" "$image" 2>&1)"
code=$?
set -e
[ "$code" -ne 0 ] || fail "started on a non-FIPS host without FIPS_ALLOW_NON_FIPS_HOST"
grep -q "the host is not in FIPS mode" <<<"$out" || fail "refused, but not for the host check: $out"
echo "ok: refuses a non-FIPS host without the override"

# 2. With the override: starts and serves.
docker run -d --name "$name-api" --network "$net" -p "127.0.0.1:$port:8443" \
  -v "$work:/certs:ro" "${env_args[@]}" -e FIPS_ALLOW_NON_FIPS_HOST=true "$image" >/dev/null
for _ in $(seq 1 90); do
  curl -skf "https://127.0.0.1:$port/healthz" >/dev/null && break
  docker inspect -f '{{.State.Running}}' "$name-api" | grep -q true || fail "the server exited"
  sleep 1
done
curl -skf "https://127.0.0.1:$port/healthz" >/dev/null || fail "/healthz never answered"
docker logs "$name-api" 2>&1 | grep -q "the AWS-LC FIPS module passed its self-test" \
  || fail "no FIPS self-test line in the log"
echo "ok: starts with the override, self-test logged, /healthz over TLS"

# 3. Ciphers and groups.
probe() {
  echo | timeout 10 openssl s_client -connect "127.0.0.1:$port" "$@" 2>&1 | grep -q '^New, TLS'
}
expect_ok() { probe "${@:2}" || fail "refused: $1"; echo "ok: accepts $1"; }
expect_no() { if probe "${@:2}"; then fail "accepted: $1"; fi; echo "ok: refuses $1"; }

expect_ok "TLS 1.3 AES-256-GCM over P-256" -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -groups P-256
expect_ok "TLS 1.3 over P-384" -tls1_3 -groups P-384
expect_ok "TLS 1.3 over X25519MLKEM768" -tls1_3 -groups X25519MLKEM768
expect_ok "TLS 1.2 ECDHE-ECDSA-AES256-GCM" -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384
expect_no "TLS 1.3 ChaCha20" -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256
expect_no "TLS 1.3 over plain X25519" -tls1_3 -groups X25519
expect_no "TLS 1.2 ECDHE-ECDSA-CHACHA20" -tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305

echo "FIPS smoke passed"
