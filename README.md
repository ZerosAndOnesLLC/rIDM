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

The admin console at `/console/` signs administrators in through their own tenant's
login page (authorization code with PKCE against a built-in `ridm-admin-console`
client), then works the admin API with a tenant switcher for global administrators,
global search (`Ctrl`/`⌘ K`), keyboard shortcuts, light and dark themes and a phone
layout. See [Admin console](#admin-console).

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

Every tenant carries a built-in public client, `ridm-admin-console`, that the bundled
console signs in with: authorization code with PKCE, no consent step, `urn:ridm:admin`
as its only audience, and redirect URIs derived from `UI_URL` (`/console/callback/`,
`/console/`). It is created at startup and with every new tenant, its URIs are
brought back in line whenever `UI_URL` changes, and it cannot be deleted or carried
in a tenant document (exports leave it out, imports refuse it, prune never plans its
deletion). Everything else on it (token lifetimes, CORS origins) is tunable.

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

Admin resources so far (all under `/admin`, RFC 9457 problem+json errors, cursor
pagination with `?cursor=&limit=`):

| Route | Permission | Notes |
|-------|------------|-------|
| `GET /admin/me`, `GET /admin/permissions` | any admin | caller identity; catalogue and built-in roles |
| `GET /admin/tenants` | `ridm:tenants:read` | global admins page through every tenant; tenant-scoped admins get their own |
| `POST /admin/tenants` | `ridm:tenants:create` (global only) | `{slug, display_name, settings?}` |
| `GET /admin/tenants/{slug}` | `ridm:tenants:read` | disabled tenants are still served here |
| `PATCH /admin/tenants/{slug}` | `ridm:tenants:write` | `display_name`, `status`, and `settings` as a JSON merge patch (RFC 7396): send only what changed, `null` clears; unknown settings fields are rejected |
| `DELETE /admin/tenants/{slug}` | `ridm:tenants:delete` (global only) | cascades; `master` cannot be deleted or disabled |
| `GET/PUT/DELETE /admin/tenants/{slug}/captcha` | read / write | provider, site key and secret (stored encrypted; reads return `secret_set` instead of the secret) |
| `GET/PUT /admin/tenants/{slug}/profile-schema` | read / write | the user profile schema (declared attributes with type, validation, editability and exposure); `PUT` replaces it after structural validation |
| `GET /admin/tenants/{slug}/clients` | `ridm:clients:read` | `?search=` prefix-matches `client_id` and name |
| `POST /admin/tenants/{slug}/clients` | `ridm:clients:write` | any field of the client model; missing ones take type-driven defaults (`spa`, `web`, `native`, `machine`, `device`); scopes and audiences must exist; the secret is in the `201` body and nowhere else |
| `GET /admin/tenants/{slug}/clients/{client}` | `ridm:clients:read` | `{client}` is the id or the public `client_id`; `secrets` lists ids and validity, never hashes |
| `PATCH /admin/tenants/{slug}/clients/{client}` | `ridm:clients:write` | merge patch over the metadata plus `status`; `null` clears a field or resets a defaulted one; `client_id` is immutable; switching to a secret-based auth method mints a secret, returned once |
| `DELETE /admin/tenants/{slug}/clients/{client}` | `ridm:clients:write` | cascades to roles scoped to the client, refresh tokens and consents |
| `POST /admin/tenants/{slug}/clients/{client}/secrets` | `ridm:clients:write` | rotate: `{grace_secs?}` keeps the previous secret working (default 24h, `0` retires it, max 30 days); the new secret is shown once |
| `DELETE /admin/tenants/{slug}/clients/{client}/secrets/{id}` | `ridm:clients:write` | revoke one secret early; the last secret of a confidential client cannot be revoked, rotate instead |
| `PUT/DELETE /admin/tenants/{slug}/clients/{client}/service-account` | `ridm:clients:write` | create / remove the user (`svc-<client_id>`) that `client_credentials` tokens are issued for, so the client can hold roles and groups; needs the `client_credentials` grant |
| `POST /admin/tenants/{slug}/clients/{client}/registration-token` | `ridm:clients:write` | issue (replacing) the RFC 7592 registration access token and `registration_client_uri` |
| `GET /admin/tenants/{slug}/users` | `ridm:users:read` | `?search=` (username/email prefix), `status`, `org_id`, `include_deleted` |
| `POST /admin/tenants/{slug}/users` | `ridm:users:write` | user fields plus `password` (policy-checked) or `temporary_password: true` (returned once, change forced at first login) |
| `GET /admin/tenants/{slug}/users/{id}` | `ridm:users:read` | user plus `password` summary, direct and effective `roles`, `groups` |
| `PATCH /admin/tenants/{slug}/users/{id}` | `ridm:users:write` | absent = unchanged, `null` clears; `status` is `active` or `disabled` (disabling ends sessions); unknown fields rejected |
| `DELETE /admin/tenants/{slug}/users/{id}` | `ridm:users:write` | soft delete; sessions and trusted devices end |
| `PUT /admin/tenants/{slug}/users/{id}/password` | `ridm:users:write` | `{password?, must_change?, skip_policy?, notify?, revoke_sessions?}`; without `password` a temporary one is generated and returned once |
| `POST /admin/tenants/{slug}/users/{id}/force-password-change`, `.../unlock` | `ridm:users:write` | flag a change at next login; clear a lockout |
| `GET/DELETE /admin/tenants/{slug}/users/{id}/sessions[/{id}]` | read / write | live SSO sessions; revoke one or all |
| `GET /admin/tenants/{slug}/users/{id}/credentials`, `DELETE .../credentials/{id}` | read / write | password summary plus factor rows (type, label, timestamps; never the material); remove a factor |
| `GET/DELETE /admin/tenants/{slug}/users/{id}/devices[/{id}]` | read / write | trusted devices; revoke one or all |
| `GET /admin/tenants/{slug}/users/{id}/roles`, `PUT/DELETE .../roles/{id}` | read / write | direct and effective roles; granting is refused when the role (composites included) carries admin permissions the caller lacks |
| `GET /admin/tenants/{slug}/users/{id}/groups`, `PUT/DELETE .../groups/{id}` | read / write | direct and effective groups; joining is guarded like a role grant against the group's and its ancestors' roles |
| `GET /admin/tenants/{slug}/users/{id}/consents`, `DELETE .../consents/{client_id}` | read / write | granted scopes per client; revoke |
| `GET/POST /admin/tenants/{slug}/groups`, `GET/PATCH/DELETE .../groups/{id}` | `ridm:groups:read` / `write` | flat list with `parent_id`; detail carries the group's own roles and member count; moving a group under its own descendant is refused |
| `GET .../groups/{id}/members`, `PUT/DELETE .../members/{user_id}` | read / write | joining is refused when the group (or an ancestor) carries admin permissions the caller lacks |
| `GET .../groups/{id}/roles`, `PUT/DELETE .../roles/{role_id}` | read / write | roles every member inherits; granting is guarded like a role grant |
| `GET/POST /admin/tenants/{slug}/roles`, `GET/PATCH/DELETE .../roles/{id}` | `ridm:roles:read` / `write` | `?client_id=` or `?realm_only=true`; detail carries composites and granted permissions; built-in `ridm:*` roles are listed and assignable but immutable |
| `GET .../roles/{id}/composites`, `PUT/DELETE .../composites/{child_id}` | read / write | cycles refused; adding a child is guarded by the child's admin permissions |
| `GET .../roles/{id}/permissions`, `PUT/DELETE .../permissions/{permission_id}` | read / `ridm:resource-servers:write` | admin-catalogue permissions can only be granted by a caller who holds them; built-in roles keep their seeded set; takes effect on the next request |
| `GET .../roles/{id}/holders` | read | users and groups holding the role directly |
| `GET/POST /admin/tenants/{slug}/resource-servers`, `GET/PATCH/DELETE .../{id}` | `ridm:resource-servers:read` / `write` | audience identifier (immutable), name, token TTL, signing alg, offline access; `urn:ridm:admin` is read-only |
| `GET/POST .../resource-servers/{id}/permissions`, `DELETE .../permissions/{id}` | read / write | the built-in catalogue cannot be extended or trimmed |
| `GET/POST /admin/tenants/{slug}/scopes`, `GET/PATCH/DELETE .../scopes/{id}` | `ridm:scopes:read` / `write` | name immutable; description, claims and `is_default` tunable, also for the standard scopes, which cannot be deleted; discovery follows at once |
| `GET/POST /admin/tenants/{slug}/claim-mappers`, `GET/PATCH/DELETE .../{id}` | `ridm:mappers:read` / `write` | `{name, client_id?, config}` with `config` = `{type, ..., include_in}`; `?client_id=` or `?tenant_wide=true`; templates must compile; tokens reflect changes at once |
| `GET /admin/tenants/{slug}/keys`, `GET .../keys/{id}` | `ridm:keys:read` | `?status=pending|active|retiring|revoked`; public JWK only, never private material |
| `POST /admin/tenants/{slug}/keys` | `ridm:keys:write` | `{alg?, rsa_bits?, activate?, not_before?}`; defaults from the tenant key policy; `pending` (published, not signing) unless `activate` |
| `POST /admin/tenants/{slug}/keys/rotate` | `ridm:keys:write` | new active key with the policy's algorithm; the previous active key retires with the policy's overlap |
| `POST .../keys/{id}/activate`, `.../retire`, `.../revoke` | `ridm:keys:write` | activate retires other active keys of the same algorithm; retire keeps the key published until the overlap ends; revoke unpublishes at once |
| `GET /admin/master-key`, `POST /admin/master-key/rotate` | `ridm:keys:read` / `write` (global only) | encrypted rows per master-key generation and how many are pending; re-encrypt them under the current generation |
| `GET/POST /admin/tenants/{slug}/invitations`, `GET/DELETE .../{id}`, `POST .../{id}/resend` | `ridm:invitations:read` / `write` | `?open_only=`; `{email, roles?, groups?, org_id?, expires_days?}`; the token only travels in the email; resend replaces it; inviting into roles or groups is guarded like a grant |
| `POST /admin/tenants/{slug}/users/import?dry_run=` | `ridm:users:write` + `ridm:invitations:write` | `application/json` (array or `{"users": [...]}`) or `text/csv` (`attr.<name>` columns become attributes); per row: `password` (policy-checked) or `password_hash` (argon2, bcrypt, pbkdf2, sha, md5; upgraded at first login), `roles`/`groups` by name; rows fail independently and the report lists each failure; 10 000 rows / 32 MiB per request |
| `GET /admin/tenants/{slug}/users/export?format=json|csv` | `ridm:users:read` | every live user streamed page by page, without credentials |
| `GET/PUT/DELETE /admin/tenants/{slug}/messaging/email`, `POST .../email/test` | `ridm:messaging:read` / `write` | `{type: "smtp", host, port, username?, password?, from, security?}` or `{type: "http", url, auth_header?, from}`; reads report `source` (tenant, server default, none) with `password_set` / `auth_header_set` instead of the secret; an omitted secret keeps the stored one; test sends go straight through the sender and report the backend or its error |
| `GET/PUT/DELETE /admin/tenants/{slug}/messaging/sms`, `POST .../sms/test` | read / write | HTTP gateway `{url, auth_header?, from?}`, same redaction and test-send rules |
| `GET .../messaging/templates`, `GET/PUT/DELETE .../templates/{channel}/{event}/{locale}`, `POST .../templates/preview` | read / write / read | events and channels catalogue plus tenant overrides; a `GET` returns the override or the built-in as a starting point; overrides are validated by rendering; preview renders the stored template or an unsaved `draft` with sample `vars` |
| `GET .../messaging/log?status=&limit=`, `POST .../log/{id}/redeliver` | read / write | outbound queue entries without bodies (links and codes stay private); dead messages can be requeued |
| `GET /admin/tenants/{slug}/audit` | `ridm:audit:read` | newest first; `?from=&to=&name=&actor_id=&subject_id=&user_id=&cursor=&limit=`; `name` matches exactly or as a prefix when it ends in `.` or `*` |
| `GET .../audit/export?format=json|csv`, `GET .../audit/verify` | `ridm:audit:read` | oldest first with `prev_hash`/`hash` for offline checking; verify walks the retained chain and names the first broken position |
| `GET .../users/{id}/audit` | `ridm:audit:read` | rows where the user is actor or subject |
| `GET /admin/audit`, `.../export`, `.../verify` | `ridm:audit:read` (global only) | the global chain: events with no tenant, such as master-key rotation |
| `GET/POST /admin/tenants/{slug}/webhooks`, `GET/PATCH/DELETE .../{id}` | `ridm:webhooks:read` / `write` | `{name, url, events, enabled?, headers?, max_attempts?}`; `events` are exact names, prefixes (`user.*`) or `*`; the signing `secret` is returned once on create |
| `POST .../webhooks/{id}/secret`, `POST .../webhooks/{id}/test` | `ridm:webhooks:write` | rotate the secret (shown once); deliver a `webhook.test` event now and report the attempt |
| `GET .../webhooks/{id}/deliveries?status=&limit=`, `GET .../deliveries/{id}`, `POST .../deliveries/{id}/redeliver` | read / read / write | delivery log with status, attempts, last status code, error and a response snippet; redeliver requeues and attempts at once |
| `GET/POST /admin/tenants/{slug}/ip-rules`, `GET/PATCH/DELETE .../{id}` | `ridm:tenants:read` / `write` | `{cidr, action?: allow|deny, client_id?, description?}`; networks are normalized; `?client_id=` or `?tenant_wide=true`; enforced from Phase 9.2 |
| `GET /admin/tenants/{slug}/export` | `ridm:tenants:export` | the tenant's configuration as one deterministic JSON document (`ridm.tenant/1`): settings, profile schema, resource servers and permissions, scopes, clients, roles (composites, permission grants), groups (by path, with roles), claim mappers, message templates, webhooks and IP rules, keyed by natural identifiers; no secrets, users or provider credentials |
| `GET /openapi.json`, `GET /docs` | none | the admin API's OpenAPI 3 document, derived from the routers; Swagger UI at `/docs` when `DOCS_ENABLED=true` |
| `POST /admin/tenants/{slug}/import?dry_run=&prune=` | `ridm:tenants:import` | `dry_run` returns the plan (creates, updates with field-level diffs, and with `prune` deletes of unmentioned configuration); otherwise applies it and reports what was applied, per-item errors, and the secrets of clients and webhooks it created (shown once); applying the same document twice is a no-op |

### Admin API test coverage

Besides one suite per resource (`api/tests/admin_*.rs`), `admin_matrix.rs` derives every
admin operation and the permission it requires from the route sources and checks all
five built-in roles, the global owner and anonymous callers against each one, then calls
every tenant-scoped operation across tenants; `admin_pagination.rs` walks listings with
inserts in the middle; `openapi.rs` keeps `api/openapi.json` current; and the Playwright
spec `ui/e2e/openapi-contract.spec.ts` compares the live document with the committed one
and drives the generated client against the live API.

### OpenAPI and the TypeScript client

`GET /openapi.json` serves the admin API document; `ridm-api openapi` prints the same
document without a database. It is derived from the routers with utoipa, so every route
is documented or the build fails, and a test keeps the committed `api/openapi.json` equal
to what the binary produces. Operation ids are the handler names prefixed with their tag
(`users_list`, `clients_create`), unique across the document as generated clients
require. The UI's typed client (`ui/lib/api/client.ts`, built on `openapi-fetch`) is
generated from that file:

```bash
cargo run -p ridm-api -- openapi > api/openapi.json
cd ui && npm run gen:api        # writes lib/api/openapi.d.ts
```

Every write through the admin API evicts what it changes: tenant documents (slug, id,
discovery, JWKS, email-domain), clients, client JWKS, scopes, provider settings,
webhooks and the profile schema are evicted by key; roles, groups, memberships,
composites and permission grants bump the tenant's roles version (effective roles and
admin permissions hang off it); claim mappers bump a mappers version; all of it
propagates to every node's in-process cache through Valkey.

Webhook deliveries are queued by an in-process subscriber of the event bus and sent by
the `webhook_delivery` job (every 30 s, one runner per cluster): `POST` with a JSON body
`{delivery_id, attempt, event}`, headers `X-RIDM-Event`, `X-RIDM-Delivery`, `X-RIDM-Webhook`
and `X-RIDM-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>`. A 2xx
counts as delivered; 5xx, 408, 425, 429 and network errors retry with backoff (30 s, 2 m,
10 m, 30 m, 2 h, 6 h) up to `max_attempts`; other 4xx are dead at once. Secrets are stored
encrypted under the master key and take part in master-key rotation.

Every domain event is appended to `audit_events` (monthly partitions, tenant RLS) by an
in-process writer; rows are hash-chained per tenant (`SHA-256(prev_hash || row)`), so a
row changed or removed inside the retained window fails verification. Retention is a
tenant setting (`settings.audit.retention_days`, default 365, `0` keeps forever); a daily
job creates upcoming partitions and drops each tenant's expired chain prefix, so what
remains stays contiguous. The global chain follows the master tenant's policy.

Tenant settings cover the password, session, MFA, registration, locale, branding,
key, discovery, DCR, auth-method, lockout, CAPTCHA, notification and audit-retention policies plus a
free-form `features` flag map. IP rules and webhooks get their own resources later in
Phase 5.

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

### Admin console

The console lives under `/console/` (the `/admin/*` paths are the API). Signed out, every
console page shows a card asking which tenant to sign in through (global administrators
use `master`); the browser then goes through that tenant's normal login page, including
any forced password change or MFA, and comes back to `/console/callback/` with an
authorization code that the page exchanges with PKCE. No consent step is shown for the
console's own client. Tokens live in the tab's `sessionStorage`; the access token is
refreshed ahead of expiry through refresh-token rotation, and because admin tokens are
bound to the browser session, "Sign out" (RP-initiated logout with the ID token as hint)
ends both at once. A 401 the API still returns, for a revoked session or a removed role,
drops the console back to the sign-in card with a notice.

The frame: sidebar navigation filtered by the administrator's permissions (`/admin/me`),
a tenant switcher for global administrators (the chosen tenant travels as `?tenant=` so
links deep-link), global search over pages, users and clients of the current tenant,
theme switch (system, light, dark; kept in `localStorage` and applied before first
paint), and keyboard shortcuts: `Ctrl`/`⌘ K` or `/` search, `t` tenant switcher, `g o`
overview, `?` the shortcut list. Below the `md` breakpoint the navigation is a drawer.
Console code sits in `ui/src/app/console/`, `ui/src/components/console/` and
`ui/src/lib/console/` (`auth.ts` holds the PKCE flow, `session.tsx` the token store the
typed client reads from).

Pages so far: **Tenants** (`/console/tenants/`: every tenant for global administrators,
filter, "New tenant" dialog that lands on the new tenant's settings) and **Settings**
(`/console/settings/`: every tenant setting on one page, grouped as general, sign-in,
passwords and lockout, sessions and tokens, branding, locale and notices, keys, discovery
and audit, plus a delete-tenant zone for global owners). Settings save as you go: each
change is applied to the page at once and joined into one JSON merge patch that is sent
`PATCH /admin/tenants/{slug}` once typing pauses (600 ms, at most 2.5 s into continuous
editing, and with `keepalive` when the tab is hidden or closed); the header shows
"Unsaved changes", "Saving…", "Saved" or the API's reason for refusing, in which case the
stored settings are reloaded. The CAPTCHA provider (site key and secret, stored encrypted
behind its own endpoint) saves as soon as both keys are present and shows "Configured"
without ever reading the secret back. The branding editor frames the real login page
(`/login/?tenant=<slug>&preview=1`): the page renders its sign-in form on a stand-in flow,
tells the editor it is ready, and applies every draft change (name, logo, colours, links,
custom CSS) it receives by `postMessage` from the console's origin.

**Clients** (`/console/clients/`): a searchable table (prefix search on client ID and
name, cursor paging), a four-step creation wizard (kind of client → grants and
authentication → URIs → scopes and audiences, with the API's type-driven defaults
preselected) whose result shows the client ID and any secret exactly once, and a detail
page (`?client=<id>`) saving as you go over `PATCH /admin/tenants/{slug}/clients/{client}`:
basics, grants and authentication (a switch to a secret-based method reveals the minted
secret once), URIs, scopes and audiences, token lifetimes, format, ID token encryption and
JWKS, secrets (rotate with a grace period, revoke a retiring one), service account,
registration access token (RFC 7592, revealed once) and deletion. The **playground**
(`/console/playground/?tenant=&client=`) runs the client's flow for real: authorization
code with PKCE through the tenant's login page with the console as the redirect target
(`/console/playground/` can be added to the client's redirect URIs in one click), or
client credentials for machine clients with a pasted secret kept in the tab only; it then
shows the token response, the decoded access and ID tokens, calls userinfo and refreshes.

**Users** (`/console/users/`): a windowed table (only the rows in view are rendered) with
prefix search, status filter and deleted users on request, loading further pages as you
scroll; "New user" (temporary password revealed once, or a chosen password, or none),
"Invite" (email, roles, groups, expiry; open invitations listed under `?view=invitations`
with resend and revoke), "Import" (paste or pick JSON or CSV, dry run first with a per-row
report, then import) and "Export" (JSON or CSV download). The detail page (`?user=<id>`)
has tabs: Profile (identity fields and the attributes the tenant's profile schema
declares, each rendered by type, saving as you go with the complete attribute set),
Password & credentials (summary, replace with a temporary or chosen password with
notify/sign-out-everywhere/skip-policy options, require a change at next sign-in,
enrolled factors with removal), Sessions & devices (revoke one or all), Roles and Groups
(direct with assign/remove, effective shown), Consents (revoke) and Audit (the user's
events, expandable). Disable, unlock and delete sit in the header. Personal access
tokens and linked identities appear with Phases 8.5 and 8.3.

**Groups, roles, resource servers, scopes and claim mappers** each get a list-and-detail
page (`/console/groups/`, `/console/roles/`, `/console/resource-servers/`,
`/console/scopes/`, `/console/claim-mappers/`; the selected item travels as a query
parameter). Groups are a tree: create at any level, move under another group (never
under a descendant), edit attributes as JSON, attach roles, add members through a user
search and remove them. Roles: realm or per-client, composites, permissions granted from
any resource server (admin-catalogue permissions only by someone who holds them), and who
holds the role; built-in `ridm:*` roles are read-only. Resource servers: name, token
lifetime cap, signing algorithm, offline access, and their permissions; `urn:ridm:admin`
is read-only. Scopes: description, released claims, resource server binding and
"granted by default"; standard scopes can be tuned but not deleted. Claim mappers:
tenant-wide or per client, of kind user attribute, groups, roles, fixed value, Handlebars
template (must compile) or audience, with the tokens they are included in. Detail fields
save as you go; membership-style changes apply at once. Identity providers arrive with
brokering in Phase 8.3.

The profile schema itself is edited under Settings → Profile attributes (name, type,
label, description, who may edit, position, required, multiple values, where the value
surfaces, validation per type), saved whole through the new
`GET/PUT /admin/tenants/{slug}/profile-schema` routes (`ridm:tenants:read`/`write`).

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
