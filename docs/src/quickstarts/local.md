# Run rIDM locally

From an empty checkout to a running server, the admin console, a global
administrator and a demo tenant with users you can sign in as. Everything here
is for a laptop: the passwords are written down on purpose, and none of them
belongs on a machine anyone else can reach.

This page builds from source, since it is about working on rIDM. To run a release
instead, see [Releases and verification](../deploy/releases.md).

## What you need

| Tool | Version | Why |
|------|---------|-----|
| Rust | 1.98 or later (`rust-toolchain.toml` pins 1.98.1) | the server and the `ridm` CLI |
| Node.js | 24 | the consoles and sign-in pages, served by `next dev` |
| Docker with Compose v2 | any recent | Postgres, Valkey and Mailpit |
| `curl`, `jq`, `python3`, `openssl` | any | the setup script and the examples below |

## The short way

The repository's `Makefile` runs the steps below. With `.env` written as in
[step 1](#1-configure):

```bash
make setup     # step 2 and 3, the first administrator, and an admin token
make api       # step 4, in one terminal (make watch restarts it on every change)
make ui        # step 5, in another; next dev reloads pages as you edit them
make seed      # step 7, plus a second tenant, acme, with 120 users to page through
```

`make setup` gets its token from `ridm bootstrap --issue-token` (see
[The ridm command line](../admin/cli.md#a-token-without-a-browser)) and writes it
to `target/dev/token`, which is what `make seed` uses; step 6 is only needed for
a token of your own choosing. `make` alone lists every target. The rest of this
page is what those targets do, one step at a time.

## Ports

The server's own default listen address is `0.0.0.0:8080`, and the compose file
publishes a containerised API on 8080 too. This page runs the API on **8090**
instead, because that is what `examples/setup.sh` and the example applications
default to; with 8090 none of them needs an override.

| Port | What |
|------|------|
| 5432 | Postgres (`RIDM_PG_PORT` moves it) |
| 6379 | Valkey (`RIDM_VALKEY_PORT`) |
| 8025 | Mailpit web UI (`RIDM_MAILPIT_UI_PORT`); SMTP on 1025 (`RIDM_MAILPIT_SMTP_PORT`) |
| 8090 | rIDM API (`PUBLIC_URL`, `BIND_ADDR`) |
| 3110 | rIDM UI under `next dev` (`UI_URL`) |

If a port is taken, set the matching `RIDM_*_PORT` variable in `.env` and adjust
the URLs below to match.

## 1. Configure

```bash
git clone https://github.com/ZerosAndOnesLLC/rIDM.git
cd rIDM
cp .env.example .env
openssl rand -hex 32        # the master key; paste it into .env
```

Then edit `.env` so these lines read as follows (the rest of `.env.example` can
stay as it is):

```bash
MASTER_KEY=<the 64 hex characters from openssl>
PUBLIC_URL=http://localhost:8090
BIND_ADDR=127.0.0.1:8090
UI_URL=http://localhost:3110
COOKIE_SECURE=false
DOCS_ENABLED=true

# First global administrator, created on the first start.
BOOTSTRAP_ADMIN_EMAIL=admin@ridm.local
BOOTSTRAP_ADMIN_PASSWORD=Local-Admin-Passw0rd

# Outbound mail goes to Mailpit.
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_FROM="rIDM <no-reply@ridm.local>"
SMTP_SECURITY=none
```

Why each one matters:

- `MASTER_KEY` encrypts signing keys and other secrets at rest. The server
  refuses to start without it; losing it makes those secrets unreadable. See
  [Signing keys and the master key](../concepts/keys.md).
- `PUBLIC_URL` is the externally visible base URL. Every tenant's issuer is
  derived from it as `{PUBLIC_URL}/t/{slug}`, so the demo tenant's issuer will be
  `http://localhost:8090/t/demo`.
- `UI_URL` is where the sign-in pages and consoles are served. In development
  that is `next dev` on 3110, not the API. The built-in console clients register
  their redirect URIs from it, so changing it later re-registers them on the
  next start.
- `COOKIE_SECURE=false` is needed on plain `http://`; browsers drop `Secure`
  cookies there. The session cookie is then `ridm_session_{slug}` rather than
  the `__Host-ridm_session_{slug}` a secure deployment uses.
- `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` must be set together.
  The password has to satisfy the `master` tenant's policy (at least 12
  characters by default).
- `SMTP_FROM` is required whenever `SMTP_HOST` is set.

Every variable is described in [Server configuration](../reference/configuration.md).

## 2. Start Postgres, Valkey and Mailpit

```bash
docker compose --env-file .env -f deploy/docker-compose.yml --profile dev \
  up -d postgres valkey mailpit
```

`--env-file .env` matters: Compose otherwise looks for `.env` next to the
compose file in `deploy/`, and the file refuses to load without `MASTER_KEY`.
Naming the three services starts only them; the containerised API services
(`api`, `api-dev`) and the one-shot `migrate` service stay down.

On its first start the Postgres container creates two roles
(`deploy/postgres/init-app-role.sh`): `ridm_migrator`, which owns the schema, and
`ridm_app`, which has DML privileges only and is what the API connects as. The
split exists because Postgres superusers bypass row level security, which is what
keeps tenants apart, and a table owner can switch it off.

## 3. Apply the migrations

Run them as the schema owner. `DATABASE_URL` on the command line wins over the
one in `.env`:

```bash
DATABASE_URL=postgres://ridm_migrator:ridm_migrator@localhost:5432/ridm \
  cargo run -p ridm-api -- migrate
```

With `sqlx-cli` installed, `sqlx migrate run --source api/migrations` against the
same URL does the same.

The server itself leaves the schema alone: with `MIGRATE_ON_START=false` (the
default in `.env.example`), it only logs a warning at startup when migrations
are pending. After pulling new code, run this step again before restarting.

## 4. Start the server

```bash
cargo run -p ridm-api
```

It reads `.env`, connects as `ridm_app`, and on the first start creates the
global administrator: user **`admin`** (set `BOOTSTRAP_ADMIN_USERNAME` to choose
another name) in the `master` tenant, holding the `ridm:owner` role, with the
email and password from `.env`. It must change that password at first sign-in.
Bootstrap does nothing once any `master` user holds `ridm:owner`, so the
variables can stay in `.env`. Adding `BOOTSTRAP_SAMPLE_CLIENT=true` also makes
sure `master` has a public single-page-app client, `sample-spa` (PKCE,
redirect `http://localhost:3000/callback`, post-logout redirect and CORS origin
`http://localhost:3000`); an existing one is left as it is.

Check it is up:

```bash
curl -s http://localhost:8090/readyz
curl -s http://localhost:8090/t/master/.well-known/openid-configuration | jq .issuer
```

The server generates an RSA signing key the first time a tenant needs one.
Debug builds compile the RSA and argon2 crates optimised, so that and password
hashing take milliseconds rather than seconds.

## 5. Start the UI

In a second terminal:

```bash
cd ui
npm install
API_PROXY=http://localhost:8090 npx next dev -p 3110
```

`API_PROXY` makes the dev server forward `/t`, `/admin` and `/.well-known` to the
API, so the pages call it same-origin, as they are when the server embeds the UI,
and session cookies work without CORS. `next dev` reloads pages as you edit them.
To run the pages the way the container image serves them instead, build the export
once (`NEXT_PUBLIC_API_URL= npm run build` in `ui/`), start the API with
`cargo run -p ridm-api --features embedded-ui` and without `UI_URL`, and open
<http://localhost:8090/console/>.

| Page | URL |
|------|-----|
| Admin console | <http://localhost:3110/console/> |
| Account console | <http://localhost:3110/account/?tenant=master> |
| Mailpit | <http://localhost:8025> |
| Swagger UI over the admin API | <http://localhost:8090/docs/> (because `DOCS_ENABLED=true`) |

Open the admin console, sign in through tenant **`master`** as `admin` with the
bootstrap password, and choose a new one when asked. The consoles are described
in [The admin and account consoles](../admin/consoles.md).

## 6. Give the CLI a token

Every `ridm` command except `bootstrap` talks to the admin API with a bearer
token. On a development machine the quickest is to have `ridm bootstrap` mint
one for the administrator, straight through the database:

```bash
cargo build -p ridm-cli
export RIDM_URL=http://localhost:8090
export RIDM_TOKEN=$(target/debug/ridm bootstrap --no-migrate --issue-token local-dev)
```

That token carries every permission the administrator holds and expires in 30
days (`--token-days`). The way that works against any server, including one
whose database you cannot reach, is a personal access token from the account
console:

1. Open the account console at <http://localhost:3110/account/?tenant=master>,
   signed in as `admin`.
2. Under **Security → Personal access tokens**, create a token. Tick the
   permissions the CLI will need; for the demo tenant that is
   `ridm:tenants:read`, `ridm:tenants:write`, `ridm:tenants:create`,
   `ridm:tenants:import`, `ridm:users:read`, `ridm:users:write`,
   `ridm:roles:read`, `ridm:roles:write`, `ridm:clients:read` and
   `ridm:clients:write`. A token can never carry more than its owner holds.
3. Copy the `rpat_…` value; it is shown once.

Then build the CLI and store the token in a profile:

```bash
cargo build -p ridm-cli                  # target/debug/ridm
export PATH="$PWD/target/debug:$PATH"
export RIDM_TOKEN=rpat_...               # the token you just copied
ridm login --url http://localhost:8090
ridm whoami
```

`ridm login` checks the token against `/admin/me` and writes the URL and token to
`~/.config/ridm/config.json` (mode 0600). With `RIDM_TOKEN` exported it uses that
token instead of prompting; `--token-stdin` reads it from a pipe. See
[The ridm command line](../admin/cli.md) for profiles and the other ways to
authenticate.

## 7. Create the demo tenant

```bash
export RIDM_URL=http://localhost:8090
examples/setup.sh
```

`setup.sh` exits unless `RIDM_TOKEN` is exported, even after `ridm login`,
because looking users up and assigning roles call the admin API with `curl`,
which cannot read the token `ridm login` stored. It:

1. creates the tenant `demo` ("Example Orders Co.") if it does not exist;
2. imports [`examples/demo-tenant.json`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/examples/demo-tenant.json)
   with `ridm tenant import`: the resource server `https://orders.example` with
   the permissions `orders:read` and `orders:write`, matching scopes, the roles
   `orders-reader` and `orders-manager`, the public client `orders-spa` and the
   confidential client `orders-web`;
3. creates two users and gives each one role;
4. prints the `orders-web` client secret, the first time only.

**Keep the secret it prints.** It is shown once; the
[web app quickstart](web-app.md) needs it. The script is safe to re-run: the
import is a reconciliation, and each run resets the two users' passwords.

| User | Password | Role | May |
|------|----------|------|-----|
| `dana` | `Demo-Passw0rd!2026` | `orders-manager` | read and place orders |
| `sam` | `Demo-Passw0rd!2026` | `orders-reader` | read orders only |

`DEMO_PASSWORD=… examples/setup.sh` chooses another password, and
`SPA_URL=http://localhost:3101` or `WEB_URL=…` registers the clients for another
origin when port 3100 or 3200 is taken (the script substitutes it into the
document as it imports it).

Confirm the tenant matches its document:

```bash
ridm --tenant demo tenant diff -f examples/demo-tenant.json
```

An empty plan means the tenant is exactly what the file describes. See
[Configuration as code](../concepts/config-as-code.md).

## Where next

- [Protect a Rust API with ridm-auth](protect-an-api.md): the orders API is the
  finished version.
- [Sign in from a single-page app](spa.md) and
  [Sign in from a server-side web app](web-app.md): the two demo clients.
- [Machine-to-machine access](machine-to-machine.md): a token with no user
  behind it.

## Running the API in a container instead

`docker compose --env-file .env -f deploy/docker-compose.yml --profile dev up -d`
also builds and runs the API (`api-dev`, on 8080), runs the migrations with the
one-shot `migrate` service, and seeds `master` with an administrator from
`BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` (compose defaults
`admin@ridm.local` and `ChangeMe-Now-1234`) and the sample client `sample-spa`
described above. The image embeds the UI, so the consoles are at
<http://localhost:8080/console/> and <http://localhost:8080/account/?tenant=master>
with nothing else running. For work on the pages, run the API with `cargo` and the
UI under `next dev` as above. See [docker-compose](../deploy/docker-compose.md).

## Resetting

```bash
docker compose --env-file .env -f deploy/docker-compose.yml --profile dev down -v   # drops the data volumes
```

To reset only the administrator's password, with a token for a user that may:

```bash
printf 'a-new-password-of-12+' |
  ridm --tenant master user reset admin --password-stdin --no-must-change
```
