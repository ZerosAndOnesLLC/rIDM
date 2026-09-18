# Getting started locally

From nothing to a running rIDM with an admin console, a demo tenant and three
example applications signing in against it. Everything here is local; none of
these credentials belongs on a machine anyone else can reach.

The [README](README.md#development) covers what each piece is. This file is the
short path to having it all on screen at once.

## The short way: `make`

With `.env` set up as in step 1 below, the `Makefile` does most of this page:

```bash
make setup     # Postgres, Valkey, Mailpit; migrations; first admin; target/dev/token
make api       # terminal 1: the API on 8090   (make watch: restart on every change)
make ui        # terminal 2: the UI on 3110, hot reload
make seed      # the demo tenant for the examples, plus `acme` for console work
```

`make` alone lists every target. `make token` mints a fresh admin token for the CLI
(`export RIDM_URL=http://localhost:8090 RIDM_TOKEN=$(cat target/dev/token)`); if the
owner of your database is not called `admin`, say who: `make token ADMIN=root`. The
sections below are what those targets run, for when you want the pieces one at a time.

`make seed` loads two tenants. **`demo`** is what section 3 describes. **`acme`**
([`dev/acme-tenant.json`](dev/acme-tenant.json)) is for working on the consoles: a
profile schema (department, employee ID, start date), a group tree under `staff` whose
groups carry roles, one client of each type, and 120 users with profile attributes and
group memberships, a few disabled or unverified. `ada.lovelace`, `alan.hopper`,
`barbara.hamilton`, `claude.turing` and `donald.lamarr` have the password
`Demo-Passw0rd!2026`; the rest sign in by magic link, into Mailpit.

### Hot reload

- **UI**: `next dev` reloads a page as you save it; nothing to restart.
- **API**: `make watch` (needs [`watchexec`](https://github.com/watchexec/watchexec):
  `cargo binstall watchexec-cli`) rebuilds and restarts the server when Rust, SQL or
  TOML under `api/` or `crates/` changes. A restart does not apply a new migration —
  `make migrate` does, as the schema owner — and signed-in browser sessions survive it:
  the server keeps none of its state in memory alone.
- **Slow spots**: a debug build is fast at the two costly things rIDM does, RSA key
  generation and argon2 hashing, because `Cargo.toml` compiles just those crates
  optimised. The API's start-up time grows with the number of tenants (each gets its
  console clients checked); a database that test runs have filled with hundreds of
  tenants takes tens of seconds to start, and `make reset` empties it.

## 1. Infrastructure and the server

Requirements: Rust 1.98+ (pinned in `rust-toolchain.toml`), Node.js 24, Docker,
`sqlx-cli`.

```bash
cp .env.example .env                           # set MASTER_KEY, then the lines below
docker compose --env-file .env -f deploy/docker-compose.yml up -d postgres valkey mailpit
DATABASE_URL=postgres://ridm_migrator:ridm_migrator@localhost:5432/ridm \
  sqlx migrate run --source api/migrations

UI_URL=http://localhost:3110 cargo run -p ridm-api
```

`--env-file .env` matters: given `-f deploy/docker-compose.yml`, compose looks
for its `.env` in `deploy/`, not in the repository root, and the compose file
refuses to start anything without `MASTER_KEY`. Naming `mailpit` starts it even
though it belongs to the `dev` profile.

This guide runs the API on **port 8090**, not the built-in default of 8080, so
it can sit next to the compose stack's own API container (which publishes 8080)
and so the URLs match the defaults the example applications and `API_PROXY`
use. Put these in `.env` (the API reads it at startup):

```bash
BIND_ADDR=127.0.0.1:8090
PUBLIC_URL=http://localhost:8090
SMTP_HOST=localhost                            # Mailpit
SMTP_PORT=1025
SMTP_FROM="rIDM <no-reply@ridm.local>"
SMTP_SECURITY=none
BOOTSTRAP_ADMIN_EMAIL=admin@ridm.local
BOOTSTRAP_ADMIN_PASSWORD=ChangeMe-Now-1234
```

`UI_URL` is the one flag worth setting deliberately: in development the pages
are served by `next dev` rather than by the API, and it is where rIDM sends a
browser to sign in. The built-in console clients register their redirect URIs
from it, so changing it later re-registers them on the next start.

With `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` set before the
first start, rIDM creates the first global administrator — user `admin` in
the `master` tenant (`BOOTSTRAP_ADMIN_USERNAME` to choose another name) — and
asks it to change the password at first sign-in.

The migrations above run as the schema owner, `ridm_migrator`; the API itself
connects as the DML-only `ridm_app` and with `MIGRATE_ON_START=false` (the
default) only warns at startup when migrations are pending. After pulling new
code, run the `sqlx migrate run` line again.

## 2. The UI

```bash
cd ui && npm install
API_PROXY=http://localhost:8090 npx next dev -p 3110
```

`API_PROXY` makes the dev server proxy `/t`, `/admin` and `/.well-known` to the
API, so the pages call it same-origin exactly as they do in embedded mode and
session cookies work without CORS.

That is the setup for working on the pages. To run them the way the container image
does, compiled into the API and served on its own origin, build the export once and
start the API with the feature and without `UI_URL`; the consoles are then at
<http://localhost:8090/console/> and `/account/`:

```bash
cd ui && NEXT_PUBLIC_API_URL= npm run build && cd ..
cargo run -p ridm-api --features embedded-ui
```

| Page | URL | For |
|------|-----|-----|
| Admin console | <http://localhost:3110/console/> | tenants, users, roles, clients, keys, sessions, audit |
| Account console | <http://localhost:3110/account/> | what an end user sees: profile, password, MFA, sessions, consents, tokens |
| Sign-in pages | <http://localhost:3110/login/> | reached through an application, not visited directly |
| Mailpit | <http://localhost:8025> | every mail rIDM sends locally |
| OpenAPI | <http://localhost:8090/docs/> | Swagger UI over the admin API, when `DOCS_ENABLED=true` |

### Signing in to the admin console

The console asks which tenant to sign in through. Global administrators use
**`master`**; a tenant's own administrators use their tenant's slug. From
`master` the tenant switcher (or the `t` key) reaches every other tenant.

If nobody knows the bootstrap password — likely on a database that has been
around a while — reset it with the CLI:

```bash
cargo build -p ridm-cli
export RIDM_URL=http://localhost:8090 RIDM_TOKEN=rpat_...   # see below
printf 'a-password-of-your-own' |
  ./target/debug/ridm --tenant master user reset admin --password-stdin --no-must-change
```

### Getting an admin token for the CLI

`make token` is the quick way: it runs `ridm bootstrap --issue-token`, which mints a
personal access token for the owner straight through the database and writes it to
`target/dev/token`:

```bash
make token ADMIN=admin
export RIDM_URL=http://localhost:8090 RIDM_TOKEN=$(cat target/dev/token)
```

Otherwise `ridm login` asks you to paste one (or runs the device grant for a client
you registered for it; see the [README](README.md#command-line-administration-ridm)).
Sign in to the account console at <http://localhost:3110/account/?tenant=master> and
mint a personal access token under Security, or insert one directly for a user who
already holds the permissions:

```bash
TOKEN="rpat_$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')"
HASH=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)
psql "$DATABASE_URL" -c "SET app.bypass_rls='on';
  INSERT INTO personal_access_tokens (id, tenant_id, user_id, name, token_hash, scopes, expires_at)
  SELECT gen_random_uuid(), t.id, u.id, 'local-dev', decode('$HASH','hex'),
         ARRAY['ridm:tenants:read','ridm:tenants:write','ridm:tenants:create',
               'ridm:tenants:import','ridm:users:read','ridm:users:write',
               'ridm:roles:read','ridm:roles:write','ridm:clients:read','ridm:clients:write'],
         now() + interval '30 days'
  FROM tenants t JOIN users u ON u.tenant_id = t.id AND u.username = 'admin'
  WHERE t.slug = 'master';"
echo "$TOKEN"
```

`token_hash` is the raw SHA-256 **bytes** of the whole `rpat_…` string, and the
scopes must name permissions the user actually holds — they are narrowed at use,
so `ridm:*` is not a shortcut. The `SET` and the `INSERT` have to travel in one
statement, because `app.bypass_rls` is transaction-local. Revoke it when you are
done:

```sql
UPDATE personal_access_tokens SET revoked_at = now() WHERE name = 'local-dev';
```

## 3. The demo tenant and the example apps

```bash
export RIDM_URL=http://localhost:8090 RIDM_TOKEN=rpat_...
examples/setup.sh
```

That creates the tenant `demo` from
[`examples/demo-tenant.json`](examples/demo-tenant.json) — the orders resource
server with `orders:read` and `orders:write`, the matching scopes, the
`orders-reader` and `orders-manager` roles, and the two clients — then creates
two users and gives them one role each. It is re-runnable, and it prints the
confidential client's secret once.

Then, in three more terminals:

```bash
# the orders API (resource server)
RIDM_ISSUER=http://localhost:8090/t/demo \
RIDM_AUDIENCE=https://orders.example \
RIDM_ALLOW_HTTP=true \
cargo run -p ridm-example-axum-api

# the single-page app
cd examples/nextjs-spa && npm install && npm run dev

# the server-side web app
RIDM_ISSUER=http://localhost:8090/t/demo \
RIDM_CLIENT_ID=orders-web \
RIDM_CLIENT_SECRET=<what setup.sh printed> \
RIDM_ALLOW_HTTP=true \
cargo run -p ridm-example-confidential-client
```

| Application | URL | What it shows |
|-------------|-----|---------------|
| Single-page app | <http://localhost:3100/> | a public client: PKCE, no secret, tokens in memory, silent re-authentication on reload |
| Server-side web app | <http://localhost:3200/> | a confidential client: a secret, a session cookie, refresh rotation, back-channel logout |
| Orders API | <http://localhost:8081/healthz> | the resource server both of them call |

Sign in as:

| User | Password | Role | What you get |
|------|----------|------|--------------|
| `dana` | `Demo-Passw0rd!2026` | `orders-manager` | may place orders |
| `sam` | `Demo-Passw0rd!2026` | `orders-reader` | may only see them; placing one is refused `403 insufficient_scope` |

Both are set by `setup.sh` (`DEMO_PASSWORD=… examples/setup.sh` to choose your
own). They exist to be signed in as on a laptop and nowhere else.

**If port 3100 or 3200 is taken**, run the app anywhere — the SPA derives its
redirect URI from the address it is served on, the web app from `BASE_URL` —
and set the tenant up for that address instead:

```bash
SPA_URL=http://localhost:3101 examples/setup.sh     # WEB_URL=… for the web app
```

`setup.sh` substitutes the origins into `demo-tenant.json` on the way in, so the
document stays the source of truth and every later run keeps the new port. The
orders API allows the two origins in `CORS_ORIGINS`
(`http://localhost:3100,http://localhost:3200` by default); give it the new one too.

## 4. Things worth doing once it is all up

- Sign in on <http://localhost:3200/>, then open the SPA: it picks the session
  up silently through `prompt=none`, without a click.
- Reload the SPA. Its tokens live in memory, so this is the silent path again.
- Sign out of one and reload the other: RP-initiated logout ended the SSO
  session, so the silent attempt now fails and the sign-in button comes back.
- Give `sam` the `orders-manager` role in the console, sign in again, and the
  "Place order" form appears — the next access token carries `orders:write`.
- Revoke `dana`'s session from the console's user page. rIDM revokes the
  session's refresh tokens and sends a back-channel logout to the web app on
  :3200, which is signed out on its next page load; the SPA keeps its access
  token until it expires, then its refresh is refused and it falls back to
  signed-out.
- `ridm --tenant demo tenant diff -f examples/demo-tenant.json` after changing
  something in the console, to see the configuration document as a diff.

## Ports, in one place

| Port | What |
|------|------|
| 5432 | Postgres |
| 6379 | Valkey |
| 8090 | rIDM API run from source (`BIND_ADDR`, `PUBLIC_URL`; the built-in default is 8080) |
| 8080 | rIDM API container, when the compose `dev` or `prod` profile runs it |
| 3110 | rIDM UI in development (`UI_URL`) |
| 8025 | Mailpit web UI (1025 is its SMTP port) |
| 8081 | example orders API |
| 3100 | example SPA |
| 3200 | example web app |

The compose file in `deploy/` reads `RIDM_PG_PORT`, `RIDM_VALKEY_PORT`,
`RIDM_HTTP_PORT`, `RIDM_MAILPIT_UI_PORT` and `RIDM_MAILPIT_SMTP_PORT` from the
file `--env-file` names if you need to move anything; change the URLs above to
match.
