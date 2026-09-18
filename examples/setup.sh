#!/usr/bin/env bash
# Set up the `demo` tenant the examples expect.
#
# Needs a running rIDM and a `ridm` login with `ridm:tenants:*`, `ridm:users:*`
# and `ridm:roles:*` — see examples/README.md. Safe to re-run: the import is a
# reconciliation, and the users are skipped if they already exist.
set -euo pipefail

TENANT="${TENANT:-demo}"
RIDM="${RIDM:-ridm}"
URL="${RIDM_URL:-http://localhost:8090}"
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

Mint a personal access token in the account console (or with `ridm login`,
which stores one) and export it:

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
  api GET "/users?q=$1" | python3 -c "
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
"$RIDM" --url "$URL" --tenant "$TENANT" tenant import -f "$HERE/demo-tenant.json" --yes

echo "==> users"
for pair in "dana:orders-manager" "sam:orders-reader"; do
  username="${pair%%:*}"
  role="${pair##*:}"

  user_id="$(user_id_of "$username")"
  if [ -z "$user_id" ]; then
    "$RIDM" --url "$URL" --tenant "$TENANT" user create "$username" \
      --email "$username@example.com" --email-verified --temporary-password
    user_id="$(user_id_of "$username")"
  else
    echo "    $username already exists"
  fi

  # `ridm` has no role-assignment command yet, so this one step goes straight
  # to the admin API. Assigning a role twice is not an error.
  api PUT "/users/$user_id/roles/$(role_id_of "$role")" -o /dev/null
  echo "    $username → $role"
done

cat <<EOF

Done. The examples expect:

  RIDM_ISSUER=$URL/t/$TENANT
  RIDM_AUDIENCE=https://orders.example

Sign in as dana (may place orders) or sam (may only see them). If the import
printed a secret for \`orders-web\`, that is the confidential client's — it is
shown once. To mint a new one:

  $RIDM --url $URL --tenant $TENANT client create --help
EOF
