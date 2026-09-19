#!/usr/bin/env bash
# Upgrade test: the previous release's image on the docker-compose stack,
# then this build over the same volumes, then the previous image again against
# the migrated database.
#
#   1. FROM (the last release) starts on empty volumes, migrates, and the first
#      administrator is bootstrapped; the master tenant's signing keys are noted.
#   2. TO (this build) replaces it: the compose `migrate` one-shot applies the
#      new migrations as the schema owner, the server starts (its start-up check
#      refuses a master key that does not decrypt the stored keys), answers
#      /readyz, and still publishes every key FROM published, so tokens signed
#      before the upgrade keep verifying. The administrator is still there and
#      every applied migration succeeded.
#   3. FROM starts once more against the migrated database, without its own
#      migrate step: the release before must keep working on the new schema
#      (the one-release migration rule, docs' *Upgrading*), which is what a
#      rolling update runs through while old and new pods serve side by side.
#      A release that breaks this says so under "Upgrade notes" in CHANGELOG.md;
#      ALLOW_BREAKING_SCHEMA=1 then skips this step.
#
#   docker build -f api/Dockerfile -t ridm:ci .
#   TO_IMAGE=ridm:ci deploy/upgrade-smoke/run.sh
#
# FROM_IMAGE defaults to the published image of the newest release tag below
# this build's version (git tags v*, pre-releases skipped); if it cannot be
# pulled, it is built from that tag. With no earlier release the test has
# nothing to upgrade from and passes with a notice. Ports: RIDM_HTTP_PORT
# (18180), RIDM_PG_PORT (15532), RIDM_VALKEY_PORT (16479). KEEP_STACK=1 leaves
# the containers up; logs of a failed run land in target/upgrade-smoke.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${TO_IMAGE:?set TO_IMAGE to the image under test, e.g. ridm:ci}"
export RIDM_HTTP_PORT="${RIDM_HTTP_PORT:-18180}"
export RIDM_PG_PORT="${RIDM_PG_PORT:-15532}"
export RIDM_VALKEY_PORT="${RIDM_VALKEY_PORT:-16479}"
export MASTER_KEY="${MASTER_KEY:-$(openssl rand -hex 32)}"
export COOKIE_SECURE=false
PROJECT="${COMPOSE_PROJECT:-ridm-upgrade}"
LOGS="$root/target/upgrade-smoke"
API="http://localhost:$RIDM_HTTP_PORT"
ADMIN=admin@upgrade.test
work=""

log() { printf '\n== %s\n' "$*"; }
compose() {
  docker compose -p "$PROJECT" -f "$root/deploy/docker-compose.yml" --profile prod "$@"
}
psql_q() {
  compose exec -T postgres psql -U ridm -d ridm -tAc "SET app.bypass_rls='on'; $1" | tail -n 1
}
cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    mkdir -p "$LOGS"
    compose logs --no-color migrate api >"$LOGS/stack.log" 2>&1 || true
    echo "upgrade test failed; logs in $LOGS" >&2
  fi
  [ "${KEEP_STACK:-}" = 1 ] || compose down -v >/dev/null 2>&1 || true
  if [ -n "$work" ]; then git -C "$root" worktree remove --force "$work" >/dev/null 2>&1 || true; fi
  exit "$status"
}
trap cleanup EXIT

# The newest release tag below this build's version.
previous_tag() {
  local current
  current="$(sed -n '/^\[workspace.package\]/,/^\[/{s/^version *= *"\(.*\)"/\1/p}' "$root/Cargo.toml")"
  git -C "$root" tag --list 'v*' --sort=-v:refname |
    { grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true; } |
    while read -r t; do
      [ "$t" = "v$current" ] && continue
      # sort -V puts the lower of the two first.
      [ "$(printf '%s\n%s\n' "${t#v}" "$current" | sort -V | head -n 1)" = "${t#v}" ] && { echo "$t"; break; }
    done
}

if [ -z "${FROM_IMAGE:-}" ]; then
  tag="$(previous_tag)"
  if [ -z "$tag" ]; then
    echo "no release before this version (git tags v*): nothing to upgrade from; skipped"
    exit 0
  fi
  FROM_IMAGE="ghcr.io/zerosandonesllc/ridm:${tag#v}"
  if ! docker pull -q "$FROM_IMAGE" >/dev/null 2>&1; then
    log "cannot pull $FROM_IMAGE; building $tag from source"
    work="$(mktemp -d)"
    git -C "$root" worktree add --detach "$work" "$tag" >/dev/null
    FROM_IMAGE="ridm:upgrade-from-${tag#v}"
    docker build -q -f "$work/api/Dockerfile" -t "$FROM_IMAGE" "$work" >/dev/null
  fi
fi
echo "from $FROM_IMAGE"
echo "to   $TO_IMAGE"

wait_ready() {
  for _ in $(seq 1 60); do
    curl -sf -o /dev/null "$API/readyz" && { echo "ok   /readyz ($1)"; return 0; }
    sleep 2
  done
  echo "FAIL $1 never became ready" >&2
  return 1
}
kids() {
  curl -sf "$API/t/master/.well-known/jwks.json" |
    python3 -c 'import json,sys; print("\n".join(sorted(k["kid"] for k in json.load(sys.stdin)["keys"])))'
}
check_discovery() {
  curl -sf "$API/t/master/.well-known/openid-configuration" | grep -q '"issuer"' ||
    { echo "FAIL discovery ($1)" >&2; return 1; }
  echo "ok   discovery ($1)"
}

log "1. $FROM_IMAGE on empty volumes"
compose down -v >/dev/null 2>&1 || true
RIDM_IMAGE="$FROM_IMAGE" compose up -d --no-build
wait_ready from
printf 'Upgrade-Smoke-%s\n' "$(openssl rand -hex 8)" |
  RIDM_IMAGE="$FROM_IMAGE" compose run --rm -T --no-deps api \
    bootstrap --email "$ADMIN" --password-stdin --no-must-change
check_discovery from
before="$(kids)"
[ -n "$before" ] || { echo "FAIL no signing keys published by $FROM_IMAGE" >&2; exit 1; }
echo "ok   keys: $(tr '\n' ' ' <<<"$before")"
migrations_before="$(psql_q 'SELECT count(*) FROM _sqlx_migrations')"

log "2. upgrade to $TO_IMAGE"
RIDM_IMAGE="$TO_IMAGE" compose up -d --no-build
[ "$(docker inspect -f '{{.State.ExitCode}}' "$(compose ps -a -q migrate)")" = 0 ] ||
  { echo "FAIL migrate step of $TO_IMAGE" >&2; exit 1; }
wait_ready to
check_discovery to
after="$(kids)"
missing="$(comm -23 <(echo "$before") <(echo "$after"))"
[ -z "$missing" ] || { echo "FAIL keys no longer published: $missing" >&2; exit 1; }
echo "ok   every signing key from before is still published"
[ "$(psql_q "SELECT count(*) FROM users WHERE email='$ADMIN'")" = 1 ] ||
  { echo "FAIL the bootstrap administrator is gone" >&2; exit 1; }
echo "ok   bootstrap administrator"
[ "$(psql_q 'SELECT count(*) FROM _sqlx_migrations WHERE NOT success')" = 0 ] ||
  { echo "FAIL a migration is recorded as failed" >&2; exit 1; }
migrations_after="$(psql_q 'SELECT count(*) FROM _sqlx_migrations')"
echo "ok   migrations: $migrations_before before, $migrations_after after"

if [ "${ALLOW_BREAKING_SCHEMA:-}" = 1 ]; then
  log "3. skipped (ALLOW_BREAKING_SCHEMA=1: this release's upgrade notes say it breaks the one before)"
else
  log "3. $FROM_IMAGE again, on the migrated database"
  RIDM_IMAGE="$FROM_IMAGE" compose up -d --no-build --no-deps api
  wait_ready "from, after the upgrade"
  check_discovery "from, after the upgrade"
  [ -z "$(comm -23 <(echo "$before") <(kids))" ] ||
    { echo "FAIL $FROM_IMAGE no longer publishes its keys" >&2; exit 1; }
  echo "ok   the previous release still serves on the new schema"
fi
log "upgrade test passed"
