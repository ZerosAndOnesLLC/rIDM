# rIDM

[![ci](https://github.com/ZerosAndOnesLLC/rIDM/actions/workflows/ci.yml/badge.svg)](https://github.com/ZerosAndOnesLLC/rIDM/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A modern, multi-tenant Identity Management server: OpenID Connect provider, JWT issuer,
user/group/role management, MFA, and identity brokering, with a bundled admin console and
end-user account console.

> **Status:** pre-release, under active development. Nothing here is production ready
> until v0.1.0 is tagged. See [`working-plan.md`](working-plan.md) for the roadmap and
> what is done.

## Why rIDM

- **Cloud-agnostic.** Runs anywhere a container, Postgres, and Redis run: bare metal,
  docker-compose, Kubernetes, any cloud. No provider-specific dependencies in the
  default build.
- **Multi-tenant from the first migration.** Every tenant has its own issuer
  (`{PUBLIC_URL}/t/{slug}`), signing keys, users, clients, policies, branding, and
  admins. Every tenant-scoped table is protected by forced Postgres row level security
  bound per transaction, with composite foreign keys so rows can never cross tenants.
- **Standards, not surprises.** Authorization code + PKCE, client credentials, refresh
  token rotation with reuse detection, device flow, PAR, JAR/JARM, DCR, RP-initiated,
  back-channel and front-channel logout, token exchange, DPoP. No implicit, hybrid, or
  password grants.
- **Single binary.** The API embeds the built UI, so a deployment is one image plus
  Postgres and Redis. The UI can also be hosted on any static host or CDN.
- **Config as code.** Every tenant exports to one JSON document and imports
  idempotently, for GitOps and reproducible environments.
- **Built for scale.** Stateless API nodes, cache-first reads, short-lived JWTs, Redis
  for sessions and flow state, indexes that lead with `tenant_id`.

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

## Configuration

Entirely environment-driven; the same image runs everywhere. Every variable is documented
in [`.env.example`](.env.example). The essentials:

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | Postgres 16+ connection string; use a **non-superuser** role (superusers bypass row level security) |
| `REDIS_URL` | Redis 8+ / Valkey connection string |
| `PUBLIC_URL` | Externally visible base URL; tenant issuers are `{PUBLIC_URL}/t/{slug}` |
| `MASTER_KEY` / `MASTER_KEY_FILE` | 32-byte key (hex or base64) encrypting secrets at rest |
| `BIND_ADDR` | Listen address, default `0.0.0.0:8080` |
| `TRUSTED_PROXIES` | CIDRs whose `X-Forwarded-For` / `Forwarded` headers are honoured |
| `TLS_CERT` / `TLS_KEY` | Native TLS termination; leave unset behind a reverse proxy |
| `MIGRATE_ON_START` | Apply pending migrations at startup |
| `LOG_FORMAT`, `RUST_LOG` | `json` or `pretty`; tracing filter |
| `DOCS_ENABLED` | Serve Swagger UI at `/docs` (off in production) |

Health probes: `GET /healthz` (liveness) and `GET /readyz` (database + cache).
`GET /.well-known/security.txt` serves the vulnerability disclosure policy.

## Development

Requirements: Rust 1.98+ (pinned in `rust-toolchain.toml`), Node.js 24 LTS, Docker,
`sqlx-cli`.

```bash
cp .env.example .env                           # set MASTER_KEY and the URLs
docker compose -f deploy/docker-compose.yml up -d postgres redis
sqlx migrate run --source api/migrations       # or MIGRATE_ON_START=true
cargo run -p ridm-api
```

### UI

```bash
cd ui
npm install
npm run lint && npm run typecheck
npm run build          # static export to ui/out
```

`NEXT_PUBLIC_API_URL` is empty by default (same origin, for the embedded single-binary
mode). Set it at build time when hosting `ui/out` on a separate static host or CDN.

### Container image

```bash
docker build -f api/Dockerfile -t ridm .
docker buildx build --platform linux/amd64,linux/arm64 -f api/Dockerfile -t ridm .
```

The image is distroless, runs as non-root, has no dynamic OpenSSL dependency, and its
`HEALTHCHECK` calls `/ridm-api --healthcheck`.

### CI

Every pull request runs the `ci` workflow: rustfmt, `cargo check`, clippy with warnings
denied, `cargo audit`, `cargo deny`, ESLint, `tsc`, unit tests, integration tests
against Postgres and Redis, the UI static export, and a container image boot test.
`main` is protected; all checks are required. Dependencies are exact-pinned and updated
by Renovate.

## Repository layout

| Path | Purpose |
|------|---------|
| `api/` | `ridm-api`: the identity server (axum, sqlx, Redis) |
| `api/migrations/` | sqlx migrations (forward-only) |
| `crates/ridm-core/` | shared types, provider traits, event definitions |
| `ui/` | Next.js 16 static export: admin console, account console, auth pages |
| `deploy/` | docker-compose, Helm chart, reverse-proxy examples |
| `.github/` | CI workflows, issue and PR templates |

## Roadmap

The full phased plan lives in [`working-plan.md`](working-plan.md). In short: scaffold →
tenants/users/roles → keys and JWTs → OIDC core → browser flows and end-user UI → admin
API → admin UI → MFA and passkeys → account console, brokering, device flow → scale,
security and operability → CLI and developer experience → packaging and v0.1.0. Post-v1:
organizations, adaptive auth, SAML, LDAP, HSM/KMS key custody.

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md): environment setup, conventions, test matrix, PR
  checklist.
- [SECURITY.md](SECURITY.md): how to report vulnerabilities privately.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT. See [LICENSE](LICENSE).
