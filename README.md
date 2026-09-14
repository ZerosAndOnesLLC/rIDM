# rIDM

A modern, multi-tenant Identity Management server: OpenID Connect provider, JWT issuer,
user/group/role management, MFA, and identity brokering, with a bundled admin UI and
end-user account console.

- **Stack:** Rust (axum, sqlx, Redis) API in `api/`, Next.js static-export UI in `ui/`.
- **Cloud-agnostic:** runs anywhere a container, Postgres, and Redis run.
- **License:** MIT.

## Repository layout

| Path | Purpose |
|------|---------|
| `api/` | `ridm-api` — the identity server |
| `crates/ridm-core/` | shared types, provider traits, event definitions |
| `api/migrations/` | sqlx migrations (forward-only) |
| `ui/` | Next.js 16 static export: admin console, account console, auth pages |
| `deploy/` | docker-compose, Helm chart, reverse-proxy examples |

## Quick start (docker-compose)

```bash
export MASTER_KEY=$(openssl rand -hex 32)      # keep this safe; it encrypts secrets at rest
docker compose -f deploy/docker-compose.yml --profile dev up -d
curl http://localhost:8080/readyz
```

The `dev` profile adds [Mailpit](http://localhost:8025) to catch outbound email and
seeds a `master` tenant, a global admin, and a sample client on first run. Use
`--profile prod` for a stack without those extras. Ports are overridable with
`RIDM_HTTP_PORT`, `RIDM_PG_PORT`, `RIDM_REDIS_PORT`, `RIDM_MAILPIT_UI_PORT`.

## Development

Requirements: Rust 1.98+, Node.js 24 LTS, Postgres 16+, Redis 8+ (or Valkey), `sqlx-cli`.

```bash
cp .env.example .env                           # then set MASTER_KEY and the URLs
sqlx migrate run --source api/migrations       # or set MIGRATE_ON_START=true
cargo run -p ridm-api
```

Configuration is entirely environment-driven; every variable is documented in
`.env.example`. Health probes: `GET /healthz` (liveness) and `GET /readyz`
(database + cache).

### UI

```bash
cd ui
npm install
npm run lint && npm run typecheck
npm run build          # static export to ui/out
```

`NEXT_PUBLIC_API_URL` is empty by default (same origin, for the embedded single-binary
mode). Set it at build time when hosting `ui/out` on a separate static host or CDN.

### CI

Every pull request runs the `ci` workflow: rustfmt, `cargo check`, clippy with warnings
denied, `cargo audit`, `cargo deny`, ESLint, `tsc`, unit tests, integration tests
against Postgres and Redis, the UI static export, and a container image boot test.
Dependencies are updated by Renovate with exact pins.

### Container image

```bash
docker build -f api/Dockerfile -t ridm .
docker buildx build --platform linux/amd64,linux/arm64 -f api/Dockerfile -t ridm .
```

The image is distroless, runs as non-root, and its `HEALTHCHECK` calls
`/ridm-api --healthcheck`.

See `working-plan.md` for the roadmap and current status.
