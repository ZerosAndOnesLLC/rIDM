#!/usr/bin/env bash
# Smoke-test the example applications against the docker-compose stack.
#
# Starts deploy/docker-compose.yml (profile `prod`, with compose.yml beside
# this script on top) from an image already built, bootstraps the first
# administrator and a token with `ridm bootstrap --issue-token`, sets up the
# demo tenant with examples/setup.sh, runs all three examples and rIDM's
# sign-in pages on the host, then signs users in with headless Chromium
# (smoke.mjs). CI runs it in the `examples-smoke` job; locally:
#
#   docker build -f api/Dockerfile -t ridm:smoke .
#   (cd ui && npm ci && npx playwright install chromium)
#   RIDM_IMAGE=ridm:smoke examples/smoke/run.sh
#
# Every port can be moved so the run coexists with a development stack:
# RIDM_HTTP_PORT (8080), RIDM_PG_PORT (5432), RIDM_VALKEY_PORT (6379),
# UI_PORT (3110), SPA_PORT (3100), WEB_PORT (3200), ORDERS_PORT (8081).
# KEEP_STACK=1 leaves the containers up afterwards; SKIP_BUILD=1 reuses the
# binaries and the two static exports already built.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

export RIDM_HTTP_PORT="${RIDM_HTTP_PORT:-8080}"
export RIDM_PG_PORT="${RIDM_PG_PORT:-5432}"
export RIDM_VALKEY_PORT="${RIDM_VALKEY_PORT:-6379}"
UI_PORT="${UI_PORT:-3110}"
SPA_PORT="${SPA_PORT:-3100}"
WEB_PORT="${WEB_PORT:-3200}"
ORDERS_PORT="${ORDERS_PORT:-8081}"
export RIDM_IMAGE="${RIDM_IMAGE:-ridm:ci}"
export MASTER_KEY="${MASTER_KEY:-$(openssl rand -hex 32)}"
export UI_URL="http://localhost:$UI_PORT"
PROJECT="${COMPOSE_PROJECT:-ridm-smoke}"
LOGS="${SMOKE_LOGS:-$ROOT/target/smoke}"
BIN="${CARGO_TARGET_DIR:-$ROOT/target}/debug"
DEMO_PASSWORD="Demo-Passw0rd!2026"

API="http://localhost:$RIDM_HTTP_PORT"
SPA_URL="http://localhost:$SPA_PORT"
WEB_URL="http://localhost:$WEB_PORT"
ORDERS_URL="http://localhost:$ORDERS_PORT"

mkdir -p "$LOGS"
rm -f "$LOGS"/*.log "$LOGS"/*.png
# `ridm` and the examples read a `.env` from the working directory upwards;
# a developer's must not leak into this run.
WORK="$(mktemp -d)"
cd "$WORK"

compose() {
  docker compose -p "$PROJECT" -f "$ROOT/deploy/docker-compose.yml" -f "$HERE/compose.yml" \
    --profile prod "$@"
}

# Background processes each lead their own process group, so stopping one
# stops what it started (npx → node, for instance).
groups=()
start() {
  local name="$1"
  shift
  setsid "$@" >"$LOGS/$name.log" 2>&1 &
  groups+=("$!")
}

cleanup() {
  local status=$?
  for g in "${groups[@]}"; do kill -- "-$g" 2>/dev/null || true; done
  if [ "$status" -ne 0 ]; then
    compose logs --no-color api migrate >"$LOGS/stack.log" 2>&1 || true
    echo "examples smoke failed; logs and screenshots in $LOGS" >&2
  fi
  if [ "${KEEP_STACK:-}" != 1 ]; then compose down -v >/dev/null 2>&1 || true; fi
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT

wait_for() {
  local url="$1" what="$2"
  for _ in $(seq 1 90); do
    if curl -sf -o /dev/null "$url"; then return 0; fi
    sleep 2
  done
  echo "$what did not answer at $url" >&2
  return 1
}

echo "==> stack from $RIDM_IMAGE"
compose down -v >/dev/null 2>&1 || true
compose up -d --no-build
wait_for "$API/readyz" "rIDM"

if [ -z "${SKIP_BUILD:-}" ]; then
  echo "==> binaries and static exports"
  cargo build --locked --manifest-path "$ROOT/Cargo.toml" -p ridm-cli -p ridm-example-axum-api -p ridm-example-confidential-client
  # rIDM's sign-in pages, hosted apart from the API as a static export: the
  # layout NEXT_PUBLIC_API_URL exists for (credentialed CORS to the API).
  (cd "$ROOT/ui" && NEXT_PUBLIC_API_URL="$API" npm run build >"$LOGS/ui-build.log" 2>&1)
  (cd "$ROOT/examples/nextjs-spa" &&
    { [ -d node_modules ] || npm ci; } &&
    NEXT_PUBLIC_RIDM_ISSUER="$API/t/demo" NEXT_PUBLIC_API_URL="$ORDERS_URL" \
      npm run build >"$LOGS/spa-build.log" 2>&1)
fi

echo "==> first administrator and a token (ridm bootstrap --issue-token)"
# The server's own configuration, as the DML-only role the API itself uses.
TOKEN="$(
  printf 'Lantern-Harbour-%s\n' "$(openssl rand -hex 8)" |
    env -i PATH="$PATH" \
      DATABASE_URL="postgres://ridm_app:ridm_app@127.0.0.1:$RIDM_PG_PORT/ridm" \
      REDIS_URL="redis://127.0.0.1:$RIDM_VALKEY_PORT" \
      PUBLIC_URL="$API" MASTER_KEY="$MASTER_KEY" \
      "$BIN/ridm" bootstrap --no-migrate --email admin@smoke.test --password-stdin \
      --issue-token examples-smoke --token-days 1
)"
case "$TOKEN" in rpat_*) ;; *)
  echo "bootstrap printed no token" >&2
  exit 1
  ;;
esac

echo "==> demo tenant (examples/setup.sh)"
SETUP="$(
  RIDM="$BIN/ridm" RIDM_URL="$API" RIDM_TOKEN="$TOKEN" DEMO_PASSWORD="$DEMO_PASSWORD" \
    SPA_URL="$SPA_URL" WEB_URL="$WEB_URL" "$ROOT/examples/setup.sh"
)"
# The secret is printed once, for the operator; keep it out of the CI log.
printf '%s\n' "$SETUP" | grep -v ' secret: '
WEB_SECRET="$(printf '%s\n' "$SETUP" | sed -n 's/^client orders-web secret: //p')"
if [ -z "$WEB_SECRET" ]; then
  echo "setup.sh printed no secret for orders-web" >&2
  exit 1
fi
# Re-running it is a no-op, as its header promises.
RIDM="$BIN/ridm" RIDM_URL="$API" RIDM_TOKEN="$TOKEN" DEMO_PASSWORD="$DEMO_PASSWORD" \
  SPA_URL="$SPA_URL" WEB_URL="$WEB_URL" "$ROOT/examples/setup.sh" >/dev/null
"$BIN/ridm" --url "$API" --tenant demo --token "$TOKEN" tenant diff --exit-code \
  -f <(sed -e "s#http://localhost:3100#$SPA_URL#g" -e "s#http://localhost:3200#$WEB_URL#g" \
    "$ROOT/examples/demo-tenant.json") >/dev/null

echo "==> examples"
start orders-api env RIDM_ISSUER="$API/t/demo" RIDM_AUDIENCE=https://orders.example \
  RIDM_ALLOW_HTTP=true BIND_ADDR="127.0.0.1:$ORDERS_PORT" \
  CORS_ORIGINS="$SPA_URL,$WEB_URL" "$BIN/ridm-example-axum-api"
start web env RIDM_ISSUER="$API/t/demo" RIDM_CLIENT_ID=orders-web \
  RIDM_CLIENT_SECRET="$WEB_SECRET" RIDM_ALLOW_HTTP=true BASE_URL="$WEB_URL" \
  BIND_ADDR="127.0.0.1:$WEB_PORT" API_URL="$ORDERS_URL" \
  "$BIN/ridm-example-confidential-client"
start spa python3 -m http.server "$SPA_PORT" --bind 127.0.0.1 \
  --directory "$ROOT/examples/nextjs-spa/out"
start ui python3 -m http.server "$UI_PORT" --bind 127.0.0.1 --directory "$ROOT/ui/out"
wait_for "$ORDERS_URL/healthz" "the orders API"
wait_for "$WEB_URL/healthz" "the web app"
wait_for "$SPA_URL/" "the SPA"
wait_for "$UI_URL/login/" "rIDM's sign-in pages"

echo "==> browser"
UI_URL="$UI_URL" WEB_URL="$WEB_URL" SPA_URL="$SPA_URL" ORDERS_URL="$ORDERS_URL" \
  DEMO_PASSWORD="$DEMO_PASSWORD" SMOKE_SHOTS="$LOGS" node "$HERE/smoke.mjs"
