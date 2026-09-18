#!/usr/bin/env bash
# Set up the `demo` tenant the examples expect.
#
# Needs a running rIDM and RIDM_TOKEN exported: an admin token (a personal
# access token) with `ridm:tenants:*`, `ridm:users:*` and `ridm:roles:*` — see
# examples/README.md. Safe to re-run: the import is a
# reconciliation, and the users are created only once (their password is reset
# to $DEMO_PASSWORD on every run).
set -euo pipefail

TENANT="${TENANT:-demo}"
# A fixed password so the getting-started guide can name it. This tenant is for
# local development; nothing here belongs on a server anyone else can reach.
DEMO_PASSWORD="${DEMO_PASSWORD:-Demo-Passw0rd!2026}"
RIDM="${RIDM:-ridm}"
URL="${RIDM_URL:-http://localhost:8090}"
# Where the two browser-facing examples run. The document registers
# http://localhost:3100 and :3200; other origins are substituted on the way in,
# so the document stays the one source of truth whatever the ports.
SPA_URL="${SPA_URL:-http://localhost:3100}"
WEB_URL="${WEB_URL:-http://localhost:3200}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v "$RIDM" >/dev/null 2>&1; then
  if [ -x "$HERE/../target/debug/ridm" ]; then
    RIDM="$HERE/../target/debug/ridm"
  else
    echo "ridm is not on PATH; run 'cargo build -p ridm-cli' first" >&2
    exit 2
  fi
fi

if [ -z "${RIDM_TOKEN:-}" ]; then
  cat >&2 <<'EOF'
RIDM_TOKEN is not set.

Mint a personal access token in the account console (`ridm login` stores
one in its profile, but the `curl` below cannot read that) and export it:

  export RIDM_TOKEN=rpat_...

Both `ridm` and the one `curl` below read it.
EOF
  exit 2
fi

api() {
  local method="$1" path="$2"
  curl -fsS -X "$method" "$URL/admin/tenants/$TENANT$path" \
    -H "Authorization: Bearer $RIDM_TOKEN" "${@:3}"
}

# The id of the user `$1`, or nothing if there is no such user.
user_id_of() {
  api GET "/users?search=$1" | python3 -c "
import json, sys
body = json.load(sys.stdin)
rows = body if isinstance(body, list) else body['items']
match = [r['id'] for r in rows if r['username'] == '$1']
print(match[0] if match else '')"
}

role_id_of() {
  api GET "/roles" | python3 -c "
import json, sys
body = json.load(sys.stdin)
rows = body if isinstance(body, list) else body['items']
print([r['id'] for r in rows if r['name'] == '$1'][0])"
}

echo "==> tenant $TENANT"
"$RIDM" --url "$URL" tenant show "$TENANT" >/dev/null 2>&1 ||
  "$RIDM" --url "$URL" tenant create "$TENANT" --name "Example Orders Co."

echo "==> configuration (resource server, scopes, roles, clients)"
sed -e "s#http://localhost:3100#${SPA_URL%/}#g" -e "s#http://localhost:3200#${WEB_URL%/}#g" \
  "$HERE/demo-tenant.json" |
  "$RIDM" --url "$URL" --tenant "$TENANT" tenant import -f - --yes

echo "==> users"
for pair in "dana:orders-manager" "sam:orders-reader"; do
  username="${pair%%:*}"
  role="${pair##*:}"

  user_id="$(user_id_of "$username")"
  if [ -z "$user_id" ]; then
    "$RIDM" --url "$URL" --tenant "$TENANT" user create "$username" \
      --email "$username@example.com" --email-verified >/dev/null
    user_id="$(user_id_of "$username")"
  fi
  # Set on every run, so a re-run is also "put the demo back how it was".
  # `--skip-policy` because the password history refuses the same password
  # twice, which would make the second run fail for no useful reason.
  printf '%s' "$DEMO_PASSWORD" |
    "$RIDM" --url "$URL" --tenant "$TENANT" user reset "$username" \
      --password-stdin --no-must-change --skip-policy >/dev/null

  # `ridm` has no role-assignment command yet, so this one step goes straight
  # to the admin API. Assigning a role twice is not an error.
  api PUT "/users/$user_id/roles/$(role_id_of "$role")" -o /dev/null
  echo "    $username → $role"
done

cat <<EOF

Done. The examples expect:

  RIDM_ISSUER=$URL/t/$TENANT
  RIDM_AUDIENCE=https://orders.example

Sign in as dana (may place orders) or sam (may only see them), both with the
password $DEMO_PASSWORD. If the import printed a secret for \`orders-web\`,
that is the confidential client's — it is shown once. To mint a new one:

  $RIDM --url $URL --tenant $TENANT client create --help
EOF
