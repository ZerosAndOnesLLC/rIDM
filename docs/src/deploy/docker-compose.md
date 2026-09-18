# docker-compose

[`deploy/docker-compose.yml`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/deploy/docker-compose.yml)
runs the API with Postgres and Valkey on one machine. It is the fastest way to evaluate
rIDM and the stack CI boots to test the container image. It is not a production
deployment: it has no TLS, no reverse proxy and no UI. A production compose profile and
reverse-proxy examples are plan item 11.3 and are not written yet.

## Services and profiles

| Service | Profile | Image | What it does |
|---------|---------|-------|--------------|
| `postgres` | always | `postgres:18.6-alpine` | The database. On first initialisation it runs `deploy/postgres/init-app-role.sh`, which creates the migrator and app roles |
| `valkey` | always | `valkey/valkey:9.1.2-alpine3.24` | Valkey with append-only persistence, `maxmemory 256mb`, `allkeys-lru` |
| `migrate` | always | the rIDM image | One-shot: runs `ridm-api migrate` as the migrator role, then exits |
| `api` | `prod` | the rIDM image | The API with JSON logs, `Secure` cookies, Swagger UI off, no seeding |
| `mailpit` | `dev` | `axllent/mailpit:v1.31.1` | Catches every outgoing email; web UI on 8025, SMTP on 1025 |
| `api-dev` | `dev` | the rIDM image | The API with pretty logs, `COOKIE_SECURE=false`, Swagger UI at `/docs`, SMTP pointed at Mailpit, and first-run bootstrap |

Choose one profile. `api` and `api-dev` both publish `RIDM_HTTP_PORT`, so the two cannot
run together. Services without a profile start with either.

The rIDM image is `${RIDM_IMAGE:-ghcr.io/zerosandonesllc/ridm:latest}`, and each service
using it also has a `build` section pointing at `api/Dockerfile`. No image is published
yet (release images are plan item 11.4), so build it from the checkout:

```bash
docker compose -f deploy/docker-compose.yml --profile dev build
```

or pass `--build` to `up`. To run an image you built elsewhere, set `RIDM_IMAGE` and use
`up --no-build`, which is what CI does.

## First run

`MASTER_KEY` has no default: compose refuses to start without it. It is 32 bytes, hex
or base64:

```bash
export MASTER_KEY=$(openssl rand -hex 32)
```

Keep it. It encrypts signing keys, MFA secrets and provider credentials in the
database; a database restored without the same key cannot decrypt them. Put it in the
`.env` file compose reads, or your shell profile, rather than retyping it: starting the
stack later with a different key leaves the stored secrets unreadable. See
[Signing keys and the master key](../concepts/keys.md).

### The dev profile

```bash
docker compose -f deploy/docker-compose.yml --profile dev up -d --build
curl http://localhost:8080/readyz
```

Order of events: Postgres initialises its volume (and creates the two roles), `migrate`
applies every migration (the first one seeds the `master` tenant) and exits, then
`api-dev` starts. Because `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` are set,
the first start creates the global administrator in `master` (`admin@ridm.local` /
`ChangeMe-Now-1234` unless overridden), who must change the password at first sign-in.
Bootstrap does nothing once a global owner exists. The service also sets
`BOOTSTRAP_SAMPLE_CLIENT=true`, which creates a public single-page-app client,
`sample-spa`, in `master`: PKCE, redirect URI `http://localhost:3000/callback`,
post-logout redirect `http://localhost:3000/`, CORS origin `http://localhost:3000`.
It is created once and left alone afterwards. For your own applications, see
[Registering clients](../admin/clients.md).

Mail sent by any tenant appears at <http://localhost:8025>.

The dev profile does not start the UI. Build and serve it as described in
[Run rIDM locally](../quickstarts/local.md), and set `UI_URL` on the API if the pages are
not on the API's own origin (`api-dev` does not pass `UI_URL` through; add it to the
service's `environment` or run the API outside compose as the quickstart does).

### The prod profile

```bash
export PUBLIC_URL=https://id.example.com
docker compose -f deploy/docker-compose.yml --profile prod up -d --build
```

The `api` service does not bootstrap. Create the first administrator with the
server's `bootstrap` command, run once against the same database:

```bash
docker compose -f deploy/docker-compose.yml --profile prod run --rm \
  -e DATABASE_URL=postgres://ridm_migrator:ridm_migrator@postgres:5432/ridm \
  api bootstrap --email admin@example.com
```

It prompts for the password (or reads it from stdin with `--password-stdin`) and marks
it for change at first sign-in unless `--no-must-change` is given. It runs as the
service's own DML-only role and does not migrate: the `migrate` service has already
applied every migration, and if any were pending `bootstrap` would exit 1 and tell you to
run `ridm-api migrate` first.

The prod profile sets `COOKIE_SECURE=true`, so browsers only keep the session cookie over
https: put a TLS-terminating proxy in front of port 8080 and set `PUBLIC_URL` to the
https URL clients use (see [TLS and reverse proxies](tls-and-proxies.md)). Its default
`PUBLIC_URL` is `http://localhost:8080`, which is only useful for API-level smoke tests.

## Variables

Compose substitutes these from the environment or from a `.env` file. With
`-f deploy/docker-compose.yml` the default `.env` is `deploy/.env`, next to the compose
file, not one in the directory you run compose from; to use the repository root's
`.env`, pass `--env-file .env`.

| Variable | Default | Used for |
|----------|---------|----------|
| `MASTER_KEY` | none, required | The master key |
| `PUBLIC_URL` | `http://localhost:${RIDM_HTTP_PORT}` | Externally visible base URL; issuers are `{PUBLIC_URL}/t/{slug}` |
| `RIDM_HTTP_PORT` | `8080` | Host port of `api` / `api-dev` |
| `RIDM_PG_PORT` | `5432` | Host port of Postgres |
| `RIDM_VALKEY_PORT` | `6379` | Host port of Valkey |
| `RIDM_MAILPIT_UI_PORT` | `8025` | Host port of the Mailpit web UI |
| `RIDM_MAILPIT_SMTP_PORT` | `1025` | Host port of Mailpit's SMTP listener, for an API run outside compose |
| `RIDM_IMAGE` | `ghcr.io/zerosandonesllc/ridm:latest` | Image for `migrate`, `api`, `api-dev` |
| `POSTGRES_PASSWORD` | `ridm` | Password of the `ridm` superuser |
| `RIDM_MIGRATOR_USER`, `RIDM_MIGRATOR_PASSWORD` | `ridm_migrator` / `ridm_migrator` | The schema-owning role `migrate` connects as |
| `RIDM_APP_USER`, `RIDM_APP_PASSWORD` | `ridm_app` / `ridm_app` | The DML-only role the API connects as |
| `LOG_FORMAT` | `json` (`api`); `pretty` in `api-dev` | Log format |
| `RUST_LOG` | `info` (`api`); `info,ridm_api=debug` in `api-dev` | Log filter |
| `TRUSTED_PROXIES` | empty | Proxies whose forwarding headers are honoured |
| `COOKIE_SECURE` | `true` (`api`); forced `false` in `api-dev` | `Secure` cookies |
| `DOCS_ENABLED` | `false` (`api`); forced `true` in `api-dev` | Swagger UI at `/docs` |
| `BOOTSTRAP_ADMIN_EMAIL`, `BOOTSTRAP_ADMIN_PASSWORD` | `admin@ridm.local` / `ChangeMe-Now-1234` | `api-dev` only: the first global administrator |

The role passwords are read by `init-app-role.sh` only when the Postgres volume is first
initialised. Changing them afterwards changes what the API and `migrate` connect with,
not the roles themselves; alter the roles in Postgres to match.

Other server settings (`SMTP_*` for the `api` service, `UI_URL`, `METRICS_TOKEN`,
`OTEL_EXPORTER_OTLP_ENDPOINT`, `AUDIT_SINK_URL`, pool sizes, rate limits) are not passed
through by the compose file. Add them to the service's `environment` block in a
`docker-compose.override.yml`; the full list is in
[Server configuration](../reference/configuration.md).

Every port, including Postgres and Valkey, is published on all host interfaces. That
suits a laptop. On a shared or internet-facing host, drop the `ports` entries of
`postgres` and `valkey` in an override, because rIDM authenticates to them but cannot
protect them from anyone else who can connect.

## Volumes

| Volume | Mounted at | Holds |
|--------|-----------|-------|
| `pgdata` | `/var/lib/postgresql` | The database |
| `valkeydata` | `/data` | Valkey's append-only file |

`docker compose down` keeps both; `down -v` deletes them, which is a full reset: the next
`up` initialises a fresh database, recreates the roles and bootstraps again. Losing
`valkeydata` alone signs every browser out and drops in-flight sign-ins; see
[Postgres and Valkey](postgres-valkey.md#if-valkey-is-lost).

## Tuning in the file

Postgres runs with `shared_buffers=256MB`, `max_connections=200` and logs statements
slower than 250 ms. Valkey is capped at 256 MB with `allkeys-lru` eviction. Both are
sized for evaluation. Under memory pressure `allkeys-lru` may evict live browser
sessions and access-token denylist entries along with cache entries; for anything
beyond a trial, give Valkey enough memory that it never evicts (see
[Postgres and Valkey](postgres-valkey.md#valkey)).

## Upgrading the stack

Pull or rebuild the image and run `up` again. `migrate` runs on every `up`, applies
whatever migrations the new image carries, and the API starts only after it succeeds.
There is no upgrade guide or tested upgrade path between versions yet (plan items 11.5
and 11.7); take a database backup before upgrading.
