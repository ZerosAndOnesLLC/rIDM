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

- **Cloud-agnostic.** Runs anywhere a container, Postgres, and Valkey run: bare metal,
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
  Postgres and Valkey. The UI can also be hosted on any static host or CDN.
- **Config as code.** Every tenant exports to one JSON document and imports
  idempotently, for GitOps and reproducible environments.
- **Built for scale.** Stateless API nodes, cache-first reads, short-lived JWTs, Valkey
  for sessions and flow state, indexes that lead with `tenant_id`.

## What works today

Per tenant, under `/t/{slug}`: discovery (`/.well-known/openid-configuration`), JWKS,
`/authorize` (code + PKCE S256 only; query, fragment, form_post and JARM response
modes), `/par`, JWT-secured request objects, `/token` (authorization_code,
refresh_token with rotation and reuse detection, client_credentials with service
accounts; client_secret_basic/post, private_key_jwt, none), `/userinfo`,
`/introspect`, `/revoke`, `/end_session` with back-channel and front-channel logout,
dynamic client registration and management. Globally: WebFinger issuer discovery.

Browser login is a flow API (`/flows/{id}/...`) that the UI drives step by step:
password, magic link, email and SMS one-time codes, self-registration with
schema-driven profiles and email verification, invitations, password reset and
forced password change, profile completion, terms acceptance, consent. Flows are
CSRF-bound, rate-limited per user and per IP, and demand a CAPTCHA (Turnstile or
hCaptcha) after repeated failures. Email and SMS go through per-tenant SMTP or webhook
settings with localized templates and a retrying outbound queue.

Browser sessions honour the tenant session policy: idle and absolute timeouts, a cap
on concurrent sessions per user (oldest revoked first), and "remember this device",
which registers a trusted device only once the whole flow (including any second
factor) has completed. Sessions are mirrored to Postgres for listing, sign-out
everywhere and audit. `/authorize` honours `prompt` (`none`, `login`, `consent`,
`create`, `select_account`), `max_age` and `acr_values`. The end-user pages themselves
land later in Phase 4; MFA in Phase 7.

Locale is negotiated per request: the OIDC `ui_locales` parameter, then the user's
stored locale, then the tenant default, constrained to the tenant's supported list
(exact tag or same language). The flow state carries the result as `locale`, `dir`
(`ltr`/`rtl`) and the selectable `locales`; every email or SMS a flow triggers is
rendered in that locale, and self-registered users are stored with it. The UI ships
English (`ui/src/i18n/en.json`) with key-by-key fallback for added bundles, `Intl`
plural rules, and logical CSS so right-to-left languages mirror the layout.

Users get security notices, in their locale, through the tenant's messaging
settings: a sign-in from a browser they have not used before (email, or SMS when
the account has only a verified phone), a password change (recovery or forced
change, never the initial password), an email address change (sent to the previous
address), and MFA changes once Phase 7 lands. Each notice can be switched off per
tenant under `settings.notifications`.

The admin API (`/admin/...`) is guarded by `ridm:<resource>:<action>` permissions that
every tenant carries on a built-in resource server, `urn:ridm:admin`, with five built-in
roles: `ridm:owner`, `ridm:admin`, `ridm:user-manager`, `ridm:client-manager` and
`ridm:viewer`. Roles held in `master` reach every tenant; roles held in any other
tenant reach that tenant only. Permissions are re-read from the caller's effective
roles on every request, so revoking a role takes effect immediately. See
[Admin API access](#admin-api-access).

## Quick start (docker-compose)

```bash
export MASTER_KEY=$(openssl rand -hex 32)      # keep this safe; it encrypts secrets at rest
docker compose -f deploy/docker-compose.yml --profile dev up -d
curl http://localhost:8080/readyz
```

The `dev` profile adds [Mailpit](http://localhost:8025) to catch outbound email and
seeds a `master` tenant, a global admin, and a sample client on first run. Use
`--profile prod` for a stack without those extras. Ports are overridable with
`RIDM_HTTP_PORT`, `RIDM_PG_PORT`, `RIDM_VALKEY_PORT`, `RIDM_MAILPIT_UI_PORT`.

## Configuration

Entirely environment-driven; the same image runs everywhere. Every variable is documented
in [`.env.example`](.env.example). The essentials:

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | Postgres 16+ connection string; use a **non-superuser, DML-only** role (superusers bypass row level security, owners can disable it) |
| `REDIS_URL` | Redis 8+ / Valkey connection string |
| `PUBLIC_URL` | Externally visible base URL; tenant issuers are `{PUBLIC_URL}/t/{slug}` |
| `MASTER_KEY` / `MASTER_KEY_FILE` | 32-byte key (hex or base64) encrypting secrets at rest |
| `BIND_ADDR` | Listen address, default `0.0.0.0:8080` |
| `TRUSTED_PROXIES` | CIDRs whose `X-Forwarded-For` / `Forwarded` headers are honoured |
| `TLS_CERT` / `TLS_KEY` | Native TLS termination; leave unset behind a reverse proxy |
| `MIGRATE_ON_START` | Apply pending migrations at startup; otherwise run `ridm-api migrate` as the schema-owner role |
| `LOG_FORMAT`, `RUST_LOG` | `json` or `pretty`; tracing filter |
| `DOCS_ENABLED` | Serve Swagger UI at `/docs` (off in production) |

Health probes: `GET /healthz` (liveness) and `GET /readyz` (database + cache).
`GET /.well-known/security.txt` serves the vulnerability disclosure policy.

## Development

Requirements: Rust 1.98+ (pinned in `rust-toolchain.toml`), Node.js 24 LTS, Docker,
`sqlx-cli`.

```bash
cp .env.example .env                           # set MASTER_KEY and the URLs
docker compose -f deploy/docker-compose.yml up -d postgres valkey
DATABASE_URL=postgres://ridm_migrator:ridm_migrator@localhost:5432/ridm \
  sqlx migrate run --source api/migrations     # or: cargo run -p ridm-api -- migrate
cargo run -p ridm-api                          # runs as the DML-only ridm_app role
```

Two database roles are used on purpose: `ridm_migrator` owns the schema and runs
migrations; `ridm_app` (what the API uses) has DML privileges only. Postgres superusers
bypass row level security and table owners can disable it, so neither may be the API's
role. The compose stack creates both and runs migrations in a one-shot `migrate`
service; on Kubernetes use a Job. `MIGRATE_ON_START=true` is a simpler single-role mode
for small installs.

### Master key rotation

Secrets at rest (signing keys, MFA credentials, IdP secrets) are encrypted with
`MASTER_KEY`, and every ciphertext records the key generation that produced it. To
rotate without downtime:

1. Generate a new key and roll it out to every node as `MASTER_KEY` with
   `MASTER_KEY_VERSION` incremented, keeping the old one in `MASTER_KEY_PREVIOUS`
   (`<old version>=<old key>`). New writes use the new generation; old rows still decrypt.
2. Run `ridm-api rotate-master-key` once (any node, same configuration). It re-encrypts
   every row under the current generation in batches. `--status` shows what remains.
3. Remove the old key from `MASTER_KEY_PREVIOUS`.

### First-run bootstrap

The `master` tenant hosts global administrators. Create the first one either from the
environment at startup (the compose `dev` profile does this):

```bash
BOOTSTRAP_ADMIN_EMAIL=admin@example.com BOOTSTRAP_ADMIN_PASSWORD='a-long-passphrase' cargo run -p ridm-api
```

or interactively (prompts for anything not given):

```bash
ridm-api bootstrap --email admin@example.com [--username admin] [--password-stdin] [--no-must-change]
```

Bootstrap is idempotent: once any user in `master` holds the `ridm:owner` role it does
nothing. The password must satisfy the master tenant's policy, and admins created
from the environment must change it at first login.

### Admin API access

Admin endpoints take a bearer access token in the `Authorization` header (never a
query or form parameter). The token may come from any tenant, but it must:

- carry `urn:ridm:admin` in `aud`, which the token endpoint only grants to clients
  that list it in `allowed_audiences` (it is never implied, even for otherwise
  unrestricted clients);
- belong to an active user, or to a machine client's service-account user, whose
  effective roles grant at least one `ridm:*` permission;
- still have a live browser session when it was issued in one, so signing out ends
  admin access before the token expires.

Missing or invalid tokens get `401` with a `WWW-Authenticate: Bearer` challenge; a valid
token without the needed permission gets `403` `application/problem+json`. Tokens from
`master` are global; tokens from any other tenant only reach that tenant.

Every tenant is seeded with the same permission catalogue and built-in roles, which are
immutable (they cannot be renamed or deleted, but can be assigned and used as
composites). Custom roles may be granted any catalogue permission or a wildcard such as
`ridm:users:*` or `ridm:*` on the `urn:ridm:admin` resource server. The catalogue and
the roles are served at `GET /admin/permissions`; `GET /admin/me` reports the caller's
scope, roles and permissions.

| Role | Grants |
|------|--------|
| `ridm:owner` | everything, including creating, deleting and importing tenants |
| `ridm:admin` | everything except `ridm:tenants:create`, `ridm:tenants:delete`, `ridm:tenants:import` |
| `ridm:user-manager` | users, invitations, groups; read roles, tenant settings and audit |
| `ridm:client-manager` | clients, scopes, claim mappers, resource servers; read roles, tenant settings and audit |
| `ridm:viewer` | every `*:read` permission |

### UI

```bash
cd ui
npm install
npm run lint && npm run typecheck
npm run build          # static export to ui/out
```

`NEXT_PUBLIC_API_URL` is empty by default (same origin, for the embedded single-binary
mode). Set it at build time when hosting `ui/out` on a separate static host or CDN.

`npm run e2e` runs the Playwright suite (password, magic-link, registration, recovery,
consent and logout journeys, with axe-core accessibility checks on every page) against
a running API and Mailpit; see [`ui/e2e/README.md`](ui/e2e/README.md).

The end-user pages live under `ui/src/app`: `/login/`, `/register/`, `/invite/`,
`/consent/`, `/mfa/`, `/recover/`, `/verify/`, `/logout/`, `/device/` and `/error/`.
Every page is driven by query parameters (`tenant`, `flow`, `token`, ...), loads the
tenant's public branding document (`GET /t/{slug}/branding`: name, logo, colours,
links, custom CSS, locales, sign-in methods) and applies it as a theme, and speaks the
flow API step by step. Pages redirect each other by flow stage, so the API only ever
sends the browser to `/login/` or `/logout/`.

To work on the pages against a local API, run the dev server with the API proxied
same-origin (session cookies work without CORS) and point the API back at it:

```bash
UI_URL=http://localhost:3110 cargo run -p ridm-api             # API on :8090
cd ui && API_PROXY=http://localhost:8090 npx next dev -p 3110   # UI on :3110
```

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
against Postgres and Valkey, the UI static export, and a container image boot test.
`main` is protected; all checks are required. Dependencies are exact-pinned and updated
by Renovate.

## Repository layout

| Path | Purpose |
|------|---------|
| `api/` | `ridm-api`: the identity server (axum, sqlx, Valkey) |
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
