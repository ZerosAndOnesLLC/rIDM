#!/usr/bin/env bash
# Smoke test for the production compose stack behind each reverse proxy.
#
# Generates a throwaway CA and a certificate for ridm.test and
# login.acme.test, secrets with ../init.sh, starts deploy/production/compose.yml
# from an image already built (RIDM_TLS_MODE=files), then, for each proxy in
# turn, checks through it over https:
#
#   * plain http is redirected to https;
#   * discovery names the https issuer, JWKS and the embedded pages answer,
#     with rIDM's framing headers and exactly one HSTS header;
#   * /metrics is not reachable from outside;
#   * the client address rIDM records is not one the caller forged in
#     X-Forwarded-For, nor the proxy's own (its per-address rate-limit
#     counters in Valkey name the address it saw);
#   * a 20 MiB body reaches /admin/ (bulk import accepts 32 MiB);
#   * a host the proxy does not serve gets nothing from rIDM;
#
# then gives the `master` tenant the custom domain login.acme.test and checks,
# behind each proxy again, that the domain is served as the tenant with its
# own issuer;
#
# and, once, that Postgres and Valkey publish no port, that no secret appears
# in `docker inspect`, and that the server does not hold the migrator's URL.
#
#   docker build -f api/Dockerfile -t ridm:smoke .
#   RIDM_IMAGE=ridm:smoke deploy/production/smoke/run.sh [caddy|nginx|traefik ...]
#
# It binds ports 80 and 443 (custom domains are matched by the Host header,
# port included, so they are only checked on 443). KEEP_STACK=1 leaves the
# containers up afterwards. Logs of a failed run land in target/proxy-smoke.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
prod="$(cd "$here/.." && pwd)"
root="$(cd "$prod/../.." && pwd)"
: "${RIDM_IMAGE:?set RIDM_IMAGE to a locally built image, e.g. ridm:smoke}"
proxies=("$@")
[ "${#proxies[@]}" -gt 0 ] || proxies=(caddy nginx traefik)

out="$root/target/proxy-smoke"
domain=ridm.test
custom=login.acme.test
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-ridm-proxy-smoke}"
export RIDM_IMAGE
export RIDM_DOMAIN="$domain"
export RIDM_CUSTOM_DOMAINS="$custom"
export RIDM_TLS_MODE=files
export RIDM_HTTP_PORT="${RIDM_HTTP_PORT:-80}"
export RIDM_HTTPS_PORT="${RIDM_HTTPS_PORT:-443}"
export RIDM_SECRETS_DIR="$out/secrets"
export RIDM_CERTS_DIR="$out/certs"
export BOOTSTRAP_ADMIN_EMAIL=admin@ridm.test
proxy_address="${RIDM_PROXY_ADDRESS:-172.30.53.10}"
forged=203.0.113.9

log() { printf '\n== %s\n' "$*"; }
fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# The caller's .env (deploy/production/.env) must not leak into this run.
compose() {
  docker compose --env-file /dev/null -f "$prod/compose.yml" "$@"
}

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    log "failed; logs in $out/logs"
    mkdir -p "$out/logs"
    compose --profile '*' ps -a >"$out/logs/ps.txt" 2>&1 || true
    for s in postgres valkey migrate ridm caddy nginx traefik; do
      compose --profile '*' logs --no-color "$s" >"$out/logs/$s.log" 2>&1 || true
    done
    tail -n 30 "$out/logs/ridm.log" "$out/logs/"{caddy,nginx,traefik}.log 2>/dev/null || true
  fi
  if [ -z "${KEEP_STACK:-}" ]; then
    compose --profile '*' down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT

rm -rf "$out"
mkdir -p "$out/certs"

log "certificates"
(
  cd "$out/certs"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=rIDM smoke CA" \
    -keyout ca.key -out ca.pem 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$domain" \
    -keyout privkey.pem -out leaf.csr 2>/dev/null
  printf 'subjectAltName=DNS:%s,DNS:%s\nextendedKeyUsage=serverAuth\n' "$domain" "$custom" >leaf.ext
  openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
    -extfile leaf.ext -out leaf.pem 2>/dev/null
  cat leaf.pem ca.pem >fullchain.pem
  chmod 644 privkey.pem
)

log "secrets"
"$prod/init.sh"

log "database, cache, migrations, server"
compose up -d --no-build --wait --wait-timeout 180 ridm

log "stack-wide checks"
for s in postgres valkey; do
  published="$(compose ps --format '{{range .Publishers}}{{if .PublishedPort}}{{.PublishedPort}} {{end}}{{end}}' "$s")"
  [ -z "$published" ] || fail "$s publishes port(s) on the host: $published"
done
ridm_container="$(compose ps -q ridm)"
inspect="$(docker inspect "$ridm_container")"
for f in "$RIDM_SECRETS_DIR"/*; do
  value="$(head -n 1 "$f")"
  [ -n "$value" ] || continue
  if grep -qF -- "$value" <<<"$inspect"; then
    fail "the value of $(basename "$f") is visible in docker inspect"
  fi
done
if grep -q 'migrator_database_url' <<<"$inspect"; then
  fail "the server is given the migrator's database URL"
fi
echo "ok: backends unpublished, secrets out of inspect, no migrator URL in the server"

valkey() {
  compose exec -T valkey sh -c \
    'REDISCLI_AUTH="$(cat /run/secrets/valkey_password)" valkey-cli --no-auth-warning "$@"' \
    valkey "$@"
}

https="https://$domain"
[ "$RIDM_HTTPS_PORT" = 443 ] || https="$https:$RIDM_HTTPS_PORT"
curl_tls() {
  curl -sS --max-time 20 --cacert "$RIDM_CERTS_DIR/ca.pem" \
    --resolve "$domain:$RIDM_HTTPS_PORT:127.0.0.1" \
    --resolve "$custom:$RIDM_HTTPS_PORT:127.0.0.1" \
    --resolve "other.test:$RIDM_HTTPS_PORT:127.0.0.1" "$@"
}
# header NAME < headers: the value of every NAME header, one per line.
header() { tr -d '\r' | awk -v n="$(tr 'A-Z' 'a-z' <<<"$1")" -F': ' 'tolower($1) == n { print $2 }'; }

check_proxy() {
  local proxy="$1" status headers body keys jwks

  # Plain http goes to https.
  headers="$(curl -sS --max-time 10 -o /dev/null -D - \
    --resolve "$domain:$RIDM_HTTP_PORT:127.0.0.1" \
    "http://$domain:$RIDM_HTTP_PORT/t/master/.well-known/openid-configuration")"
  status="$(head -n 1 <<<"$headers" | awk '{print $2}')"
  case "$status" in 301 | 302 | 307 | 308) ;; *) fail "$proxy: http answered $status, not a redirect" ;; esac
  header location <<<"$headers" | grep -q "^https://$domain" ||
    fail "$proxy: http redirects to $(header location <<<"$headers")"
  echo "ok: http -> https ($status)"

  # Discovery and JWKS over https.
  body="$(curl_tls -f "$https/t/master/.well-known/openid-configuration")"
  [ "$(jq -r .issuer <<<"$body")" = "https://$domain/t/master" ] ||
    fail "$proxy: issuer is $(jq -r .issuer <<<"$body")"
  jwks="$(jq -r .jwks_uri <<<"$body")"
  curl_tls -f "${jwks/#https:\/\/$domain\//$https/}" | jq -e '.keys | length > 0' >/dev/null ||
    fail "$proxy: no signing keys at $jwks"
  echo "ok: discovery issuer https://$domain/t/master, JWKS"

  # The embedded pages, with rIDM's headers passed through unchanged.
  headers="$(curl_tls -f -o /dev/null -D - "$https/console/")"
  [ "$(header x-frame-options <<<"$headers")" = DENY ] || fail "$proxy: /console/ framing"
  [ "$(header strict-transport-security <<<"$headers" | wc -l)" -eq 1 ] ||
    fail "$proxy: expected exactly one HSTS header, got: $(header strict-transport-security <<<"$headers")"
  headers="$(curl_tls -f -o /dev/null -D - "$https/login/")"
  [ "$(header x-frame-options <<<"$headers")" = SAMEORIGIN ] || fail "$proxy: /login/ framing"
  echo "ok: /console/ and /login/ with their framing headers, one HSTS header"

  # /metrics stays private.
  status="$(curl_tls -o /dev/null -w '%{http_code}' "$https/metrics")"
  [ "$status" != 200 ] || fail "$proxy: /metrics is public"
  echo "ok: /metrics answers $status"

  # The client address: a forged X-Forwarded-For must not be what rIDM
  # records, and neither may the proxy's own address.
  valkey --scan --pattern 'ridm:rl:ip:*' | while read -r k; do valkey del "$k" >/dev/null; done
  # (/token is rate-limited per address; the refusal does not matter.)
  curl_tls -o /dev/null -H "X-Forwarded-For: $forged" -d grant_type=client_credentials \
    "$https/t/master/token"
  keys="$(valkey --scan --pattern 'ridm:rl:ip:*')"
  [ -n "$keys" ] || fail "$proxy: no per-address counter was written"
  if grep -qF "$forged" <<<"$keys"; then
    fail "$proxy: rIDM recorded the forged address ($keys)"
  fi
  if grep -qxF "ridm:rl:ip:$proxy_address" <<<"$keys"; then
    fail "$proxy: rIDM recorded the proxy's address as the client"
  fi
  echo "ok: client address $(sed 's/^ridm:rl:ip://' <<<"$keys" | tr '\n' ' ')(forged $forged ignored)"

  # A bulk-import-sized body reaches rIDM (which refuses it unauthenticated).
  head -c $((20 * 1024 * 1024)) /dev/zero >"$out/body.bin"
  status="$(curl_tls -o /dev/null -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' --data-binary "@$out/body.bin" \
    "$https/admin/tenants/master/users/import" || true)"
  case "$status" in 413 | 000) fail "$proxy: a 20 MiB body to /admin/ got $status" ;; esac
  echo "ok: 20 MiB to /admin/ reached rIDM ($status)"

  # A host this proxy does not serve reaches nothing of rIDM's.
  status="$(curl_tls -k -o /dev/null -w '%{http_code}' \
    "https://other.test:$RIDM_HTTPS_PORT/t/master/.well-known/openid-configuration" 2>/dev/null || true)"
  [ "$status" != 200 ] || fail "$proxy: an unknown host was served"
  echo "ok: unknown host refused (${status})"
}

check_custom_domain() {
  local proxy="$1" body
  body="$(curl_tls -f "https://$custom/.well-known/openid-configuration")"
  [ "$(jq -r .issuer <<<"$body")" = "https://$custom" ] ||
    fail "$proxy: custom domain issuer is $(jq -r .issuer <<<"$body")"
  curl_tls -f -o /dev/null "https://$custom/login/" || fail "$proxy: no /login/ on $custom"
  echo "ok: https://$custom is tenant master, issuer https://$custom"
}

up_proxy() {
  compose --profile "$1" up -d --no-build --wait --wait-timeout 120 "$1"
}
down_proxy() {
  compose --profile "$1" rm -sf "$1" >/dev/null
}

for proxy in "${proxies[@]}"; do
  log "proxy: $proxy"
  up_proxy "$proxy"
  check_proxy "$proxy"
  down_proxy "$proxy"
done

# A tenant with a custom domain takes it as its issuer on every host, so the
# domain goes in only now. The superuser is not subject to row level
# security; the cached tenant document goes with a flush and a restart.
if [ "$RIDM_HTTPS_PORT" = 443 ]; then
  log "custom domain $custom for tenant master"
  compose exec -T postgres psql -v ON_ERROR_STOP=1 -qU ridm -d ridm -c \
    "UPDATE tenants SET settings = settings || '{\"custom_domain\": \"$custom\"}' WHERE slug = 'master'" \
    >/dev/null
  valkey flushall >/dev/null
  compose restart ridm >/dev/null
  compose up -d --no-build --wait --wait-timeout 120 ridm
  for proxy in "${proxies[@]}"; do
    log "proxy: $proxy, custom domain"
    up_proxy "$proxy"
    check_custom_domain "$proxy"
    down_proxy "$proxy"
  done
fi

log "all passed: ${proxies[*]}"
