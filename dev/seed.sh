#!/usr/bin/env bash
# Seed a development server with data worth looking at.
#
#   demo  the tenant the example applications use (examples/setup.sh):
#         the orders API, two clients, users dana and sam.
#   acme  a tenant for working on the consoles: a profile schema, a group
#         tree whose groups carry roles, one client of each kind, and
#         $ACME_USERS users (default 120, enough to page through) spread
#         across the groups, a few of them disabled or not yet verified.
#
# Needs a running rIDM and an owner's token in RIDM_TOKEN (`make token`
# writes one to target/dev/token, which `make seed` reads). Re-runnable: the
# tenant documents are reconciliations, and users that already exist are
# reported and left alone.
set -euo pipefail

URL="${RIDM_URL:-http://localhost:8090}"
ACME_USERS="${ACME_USERS:-120}"
# Local-only: the same password the demo tenant's users get, for the first
# five acme users, so the account console can be signed in to without mail.
DEMO_PASSWORD="${DEMO_PASSWORD:-Demo-Passw0rd!2026}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$HERE/.."
RIDM="${RIDM:-$ROOT/target/debug/ridm}"

if [ ! -x "$RIDM" ]; then
  echo "no CLI at $RIDM; run 'cargo build -p ridm-cli' first" >&2
  exit 2
fi
if [ -z "${RIDM_TOKEN:-}" ]; then
  echo "RIDM_TOKEN is not set; 'make token' mints one (see GETTING-STARTED.md)" >&2
  exit 2
fi
export RIDM_URL="$URL" RIDM_TOKEN

echo "### demo"
RIDM="$RIDM" DEMO_PASSWORD="$DEMO_PASSWORD" "$ROOT/examples/setup.sh" | sed -n '/^==>/p;/→/p'

echo
echo "### acme"
echo "==> tenant acme"
"$RIDM" tenant show acme >/dev/null 2>&1 ||
  "$RIDM" tenant create acme --name "Acme Corporation" >/dev/null
echo "==> configuration (profile schema, groups, roles, clients)"
"$RIDM" --tenant acme tenant import -f "$HERE/acme-tenant.json" --yes |
  grep -v '^\s*$' | sed 's/^/    /'

echo "==> $ACME_USERS users"
python3 - "$ACME_USERS" "$DEMO_PASSWORD" <<'EOF' |
import json, sys

count, password = int(sys.argv[1]), sys.argv[2]
first = ["ada", "alan", "barbara", "claude", "donald", "edsger", "frances",
         "grace", "hedy", "ivan", "john", "katherine", "ken", "leslie",
         "margaret", "niklaus", "radia", "shafi", "tim", "whitfield"]
last = ["lovelace", "turing", "liskov", "shannon", "knuth", "dijkstra",
        "allen", "hopper", "lamarr", "sutherland", "backus", "johnson",
        "thompson", "lamport", "hamilton", "wirth", "perlman", "goldwasser",
        "berners-lee", "diffie"]
# Leaf group names, weighted roughly like a company of this size.
teams = (["platform"] * 3 + ["mobile"] * 2 + ["engineering"] + ["sales"] * 3
         + ["support"] * 3 + ["finance"] + ["operations"] * 2 + ["contractors"])
department = {"platform": "engineering", "mobile": "engineering",
              "engineering": "engineering", "contractors": "engineering"}

users = []
for i in range(count):
    f, l = first[i % len(first)], last[(i * 7 + i // len(first)) % len(last)]
    username = f"{f}.{l}" if i < len(first) * len(last) else f"{f}.{l}.{i}"
    team = teams[i % len(teams)]
    groups = [team] if team == "contractors" else ["staff", team]
    user = {
        "username": username,
        "email": f"{username}@acme.test",
        "email_verified": i % 17 != 5,
        "locale": ["en", "en", "de", "fr"][i % 4],
        "groups": groups,
        "attributes": {
            "department": department.get(team, team),
            "employee_id": f"E{10000 + i:05d}",
            "start_date": f"20{18 + i % 8}-{1 + i % 12:02d}-{1 + i % 28:02d}",
        },
    }
    if i % 23 == 11:
        user["status"] = "disabled"
    if i < 5:
        user["password"] = password
    users.append(user)
json.dump(users, sys.stdout)
EOF
  curl -fsS -X POST "$URL/admin/tenants/acme/users/import" \
    -H "Authorization: Bearer $RIDM_TOKEN" -H 'content-type: application/json' \
    --data-binary @- |
  python3 -c "
import json, sys
r = json.load(sys.stdin)
taken = lambda e: 'already in use' in e['error']
existing = sum(map(taken, r['errors']))
print(f\"    {r['created']} created, {existing} already there, {r['failed'] - existing} failed\")
for e in r['errors']:
    if not taken(e):
        print(f\"    row {e['row']} ({e.get('username')}): {e['error']}\")
"

cat <<EOF

Seeded. Sign in to the account console as one of these, password $DEMO_PASSWORD:

  demo  dana, sam          $URL/t/demo
  acme  ada.lovelace, alan.hopper, barbara.hamilton, claude.turing,
        donald.lamarr      $URL/t/acme

The acme users without a password can still sign in with a magic link;
the mail lands in Mailpit.
EOF
