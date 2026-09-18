# Container image

The server ships as one container image built from
[`api/Dockerfile`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/api/Dockerfile).
The same image runs everywhere and is configured entirely through environment variables.
No image is published yet: signed multi-arch images on GHCR, with an SBOM, are plan item
11.4. Until then, build it yourself.

## Building

```bash
docker build -f api/Dockerfile -t ridm .
docker buildx build --platform linux/amd64,linux/arm64 -f api/Dockerfile -t ridm .
```

Run either from the repository root; the build context is the whole workspace. The
build has three stages:

- **ui** (`node:24.21.0-bookworm-slim`, overridable with `--build-arg NODE_VERSION=...`)
  runs `npm ci` and `npm run build` in `ui/` with `NEXT_PUBLIC_API_URL` empty, producing
  the same-origin static export `ui/out`. It runs once on the build platform, since the
  files are the same for every architecture.
- **builder** (`rust:1.98.1-bookworm`, overridable with `--build-arg RUST_VERSION=...`)
  compiles the dependencies first against stub sources, so a source change does not
  rebuild them, then builds `ridm-api` in release mode with `--locked` and
  `--features embedded-ui`, which compiles `ui/out` into the binary, and strips it.
- **runtime** (`gcr.io/distroless/cc-debian12:nonroot`) holds only the binary at
  `/ridm-api`. There is no shell and no package manager, and no dynamic OpenSSL: TLS
  uses rustls with the aws-lc-rs provider.

The image serves the sign-in pages and both consoles itself on `PUBLIC_URL`'s origin
(`/login/`, `/console/`, `/account/`, ...); nothing else needs hosting. Set
`EMBEDDED_UI=false` for a node that should answer the API alone, or `UI_URL` to another
origin when the pages are hosted elsewhere; see
[Deployment overview](overview.md#where-the-ui-is-served-from).

## Runtime properties

| Property | Value |
|----------|-------|
| Entrypoint | `/ridm-api` |
| User | `nonroot:nonroot` (distroless's UID/GID 65532) |
| Port | `8080` (`EXPOSE 8080`, `BIND_ADDR=0.0.0.0:8080` set in the image) |
| Signals | `SIGTERM` or `SIGINT` stops accepting connections and drains in-flight requests for up to 20 seconds |
| Configuration | Environment variables only; a `.env` file in the working directory is read if present |

Because the process runs as non-root it cannot bind ports below 1024 without extra
capabilities; keep 8080 and map it, or let a proxy listen on 443.

The minimum environment is `DATABASE_URL`, `REDIS_URL`, `PUBLIC_URL` and the master key
(`MASTER_KEY`, or `MASTER_KEY_FILE` pointing at a mounted secret file). Every variable
is listed in [Server configuration](../reference/configuration.md). A configuration
error prints `configuration error: ...` and exits with status 2 before anything else
happens.

```bash
docker run --rm -p 8080:8080 \
  -e DATABASE_URL=postgres://ridm_app:secret@db.internal:5432/ridm \
  -e REDIS_URL=redis://valkey.internal:6379 \
  -e PUBLIC_URL=https://id.example.com \
  -e MASTER_KEY_FILE=/run/secrets/ridm_master_key \
  -e TRUSTED_PROXIES=10.0.0.0/8 \
  -v /srv/ridm/master_key:/run/secrets/ridm_master_key:ro \
  ridm
```

`MASTER_KEY_FILE` accepts the raw 32 bytes, or the same hex or base64 text
`MASTER_KEY` takes. When both are set, `MASTER_KEY` wins.

## Commands

The entrypoint is the server; arguments select a one-shot command instead.

| Arguments | What it does | Exit status |
|-----------|--------------|-------------|
| (none) | Runs the server | 1 on a fatal error, 2 on a configuration error |
| `migrate` | Applies pending migrations and exits | 0 applied (or nothing to do), 1 failure, 2 configuration error |
| `bootstrap [--email E] [--username U] [--password-stdin] [--no-must-change]` | Creates the first global administrator in the `master` tenant (and the `sample-spa` client when `BOOTSTRAP_SAMPLE_CLIENT=true` is set with the `BOOTSTRAP_ADMIN_*` variables). Applies pending migrations only when `MIGRATE_ON_START=true`; otherwise pending migrations make it stop | 0 created or already bootstrapped, 1 failure (including pending migrations), 2 bad arguments or configuration |
| `rotate-master-key [--status]` | Re-encrypts secrets at rest under the current `MASTER_KEY_VERSION`; `--status` only reports | 0 done, 1 failure |
| `openapi` | Prints the OpenAPI document of the admin API | 0 |
| `--healthcheck` | Probes the local server's `/healthz` (see below) | 0 healthy, 1 not |

Every command loads the full configuration, so `migrate` and `bootstrap` also need
`REDIS_URL`, `PUBLIC_URL` and the master key set, even though `migrate` only talks to
Postgres.

`bootstrap` runs as `DATABASE_URL`'s role, normally the DML-only app role, so run
`migrate` as the migrator first. With migrations pending and `MIGRATE_ON_START` off it
exits 1 with a message telling you to run `ridm-api migrate`.

Master key rotation is described in [Rotating keys](../admin/key-rotation.md).

## Running migrations

Migrations are embedded in the binary (from `api/migrations`) and applied with sqlx,
which takes a Postgres advisory lock, so two runners at once are safe: one waits for the
other. There are two ways to apply them.

**A separate migrate step (recommended).** Run the image with `migrate` as the role that
owns the schema, then start the servers as the DML-only role:

```bash
docker run --rm \
  -e DATABASE_URL=postgres://ridm_migrator:secret@db.internal:5432/ridm \
  -e REDIS_URL=redis://valkey.internal:6379 \
  -e PUBLIC_URL=https://id.example.com \
  -e MASTER_KEY_FILE=/run/secrets/ridm_master_key \
  -v /srv/ridm/master_key:/run/secrets/ridm_master_key:ro \
  ridm migrate
```

This is what the compose file's `migrate` service does, and what a Kubernetes Job or a
pre-deploy task in your pipeline should do. The API never holds DDL rights, so it cannot
disable the row level security that separates tenants.

**At startup.** `MIGRATE_ON_START=true` makes each server check for pending migrations
before it listens and apply them, if there are any, as its own `DATABASE_URL` role.
Nothing pending means nothing is applied, so a server running as the DML-only app role
starts normally with the flag on once `ridm-api migrate` has run; a pending migration
then fails startup, because that role cannot apply it. For the server to migrate itself,
its role must own the schema, which gives the running server the power to alter tables
and turn row level security off. Simpler, and weaker; keep that for single-node trials.

With `MIGRATE_ON_START` off (the default) the server does not touch the schema; if
migrations are pending it logs a warning (`database migrations are pending`) and starts.

The two roles and why they differ are covered in
[Postgres and Valkey](postgres-valkey.md#two-roles-and-row-level-security). Migrations
are forward-only; there are no down migrations, so a rollback means restoring the
database from before the upgrade.

## Health checks

| Endpoint | Meaning | Use as |
|----------|---------|--------|
| `GET /healthz` | The process is up and serving HTTP. Never touches Postgres or Valkey. `200 {"status":"ok","version":"..."}` | Liveness probe |
| `GET /readyz` | Postgres and Valkey both answer. `200` with `{"status":"ok","checks":{"database":"ok","cache":"ok"}}`, or `503` with `"status":"degraded"` and the failing check as `"fail"` | Readiness probe, load-balancer health check |

Use `/healthz` for liveness so a database outage does not make the orchestrator restart
every node, and `/readyz` for readiness so traffic stops reaching a node that cannot
serve it. More in [Observability](observability.md#health-probes).

The image has no curl, so the binary probes itself: `/ridm-api --healthcheck` requests
`/healthz` at the address in `BIND_ADDR`, with a 2-second timeout. A wildcard bind
address (`0.0.0.0` or `::`) becomes the loopback address of the same family; any other
address is dialled as it is. When `TLS_CERT` is set the probe speaks https and trusts
exactly that certificate: the server must present it and prove it holds its key. The
certificate's names, chain and dates are not checked, because the probe dials an IP
address and only asks whether the process answers.

The Dockerfile declares the probe:

```dockerfile
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/ridm-api", "--healthcheck"]
```

The compose file overrides the timing for local use:

```yaml
healthcheck:
  test: ["CMD", "/ridm-api", "--healthcheck"]
  interval: 10s
  timeout: 3s
  retries: 10
  start_period: 15s
```

Kubernetes ignores Docker's `HEALTHCHECK`; use HTTP probes on `/healthz` and `/readyz`
there, or an exec probe running `/ridm-api --healthcheck`.

The port opens only after startup work finishes: the server connects to Postgres,
applies pending migrations if `MIGRATE_ON_START` is on, pings Valkey, runs bootstrap if
configured, and makes sure every tenant has its console clients. Give the probes a
start period (the image allows 60 seconds, the compose file 15 seconds and then ten
retries) rather than expecting the port at once.

## Kubernetes

There is no Helm chart yet (plan item 11.2). The pieces map directly: a Deployment of
the image with the probes above, a Job running `migrate` as the migrator role before each
rollout, the master key and database passwords from Secrets (`MASTER_KEY_FILE` pointing
at a mounted Secret keeps the key out of the process environment), and a Service behind
your Ingress with `TRUSTED_PROXIES` set to the Ingress controller's pod network. Set
`terminationGracePeriodSeconds` above 20 so the drain can finish.
