# rIDM — Working Plan

A modern, multi-tenant Identity Management (IDM) server: OpenID Connect provider,
JWT issuer, user/group/role management, MFA, and identity brokering, with a bundled
admin UI and end-user account console.

Stack: Rust (`api/`) + Next.js static export (`ui/`). Postgres + Valkey.

Open source (MIT). Cloud-agnostic: runs anywhere a container, Postgres, and Valkey run
(bare metal, docker-compose, Kubernetes, any cloud). No provider-specific dependencies.

Rules for executing this plan (from global CLAUDE.md): one sub-phase at a time,
mark `[x]` when done, `cargo check` + commit after each sub-phase, keep README current,
no version bumps outside a release.

---

## 1. Architecture decisions

| Area | Decision | Notes |
|------|----------|-------|
| HTTP framework | **axum 0.8** + tower-http | tower middleware composes cleanly for per-tenant extractors, rate limiting, tracing. Alternative: actix-web for parity with tv/api. Decide before Phase 1. |
| DB | Postgres via **sqlx 0.9** (runtime-tokio, tls-rustls-ring) | Migrations via `sqlx migrate`. No `SELECT *`. |
| Cache / sessions | **Valkey** (Redis protocol via deadpool-redis; Redis 7.2+/8 also works) | Cache-first for tenants, clients, keys, sessions, rate limits, auth-flow state. Invalidate on every write. |
| Tenancy model | **Shared DB, `tenant_id` on every tenant-scoped table** | Composite indexes lead with `tenant_id`. Postgres RLS enabled as defence-in-depth (`SET LOCAL app.tenant_id`). |
| Tenant resolution | **Path prefix**: issuer = `https://{host}/t/{tenant_slug}` | Discovery at `/t/{slug}/.well-known/openid-configuration`. Custom domain per tenant in Phase 9 (host → tenant lookup, cached). |
| Master tenant | Tenant `master` hosts global admins | Global admin roles live here; per-tenant admins live in their tenant. |
| Signing | **Per-tenant key sets**, RS256 default, ES256 + EdDSA supported | Keys stored encrypted at rest (chacha20poly1305, master key from env or mounted file). Rotation with overlap; JWKS publishes active + retiring keys. |
| Access token | **JWT**, short-lived (default 5 min), `iss`/`sub`/`aud`/`azp`/`scope`/`tid`/`roles`/`groups` + custom claim mappers | Optional opaque access tokens per client (introspection-only). |
| Refresh token | **Opaque**, rotated on use, stored hashed (SHA-256), reuse detection revokes family | Redis + Postgres. |
| ID token | Per OIDC Core; `at_hash`, `nonce`, `auth_time`, `amr`, `acr` | |
| Grants | authorization_code + PKCE (S256 required for public clients), refresh_token, client_credentials, device_code (Phase 8), token-exchange (RFC 8693, Phase 9) | **No implicit, no hybrid, no ROPC.** |
| Client auth | client_secret_basic, client_secret_post, private_key_jwt, none (public + PKCE) | |
| Password hashing | argon2id | Tunable params per deployment. |
| Browser SSO session | Server-side in Redis, `__Host-ridm_session` cookie, HttpOnly, Secure, SameSite=Lax | One SSO session per tenant per browser. |
| UI ↔ API auth | **UI is itself an OIDC public client (PKCE) of rIDM** | Admin UI = client of `master`; account console = client of each tenant. Dog-fooding the provider. |
| Login pages + static export | **Flow-handoff pattern**: `/authorize` validates, persists a `login_flow` (Redis), redirects browser to static UI `/login/?flow={id}`; UI calls API to complete steps; API returns final redirect URL to the client's `redirect_uri` | Same pattern for consent, MFA, recovery, verification. No dynamic route segments needed. |
| API docs | utoipa + swagger-ui at `/docs` (disabled in prod by config) | |
| Observability | tracing + tracing-subscriber (JSON), `/healthz`, `/readyz`, Prometheus `/metrics` | |
| Errors | `thiserror` app error → RFC 6749/OIDC error JSON for OAuth endpoints, RFC 9457 problem+json for admin API | |
| Config | env vars via `dotenvy` + typed `Config` struct | 12-factor; same image everywhere. |
| Client IP | `X-Forwarded-For` / `Forwarded` honored only when `TRUSTED_PROXIES` matches the peer | Works behind nginx, Caddy, Traefik, any cloud LB, or none. |
| UI hosting | **Two modes**: (a) API embeds the built `ui/out` via `rust-embed` and serves it (single-binary deploy); (b) `ui/out` on any static host/CDN with `NEXT_PUBLIC_API_URL` set at build | Mode (a) is the default for self-hosters. |
| TLS | Terminated by the operator's reverse proxy, or natively via rustls when `TLS_CERT`/`TLS_KEY` are set | |
| Packaging | Multi-arch container image (amd64/arm64) on GHCR, plus release binaries | Helm chart + docker-compose in `deploy/`. |
| Config as code | Every tenant is exportable/importable as a single JSON document, applied idempotently | GitOps-friendly; the CLI and admin API both support it. |
| Extensibility | Trait-based providers: `KeyEncryptor` (env/file key; KMS/HSM later), `EmailSender` (SMTP/HTTP), `SmsSender` (HTTP webhook), `Captcha` (Turnstile/hCaptcha), `PasswordHasher` (argon2id + legacy verify) | Keeps the core cloud-neutral while allowing optional backends. |
| Events | Internal typed event bus → audit, webhooks, user notifications, cache invalidation (Redis pub/sub across nodes) | Single emit point per domain action. |
| Background jobs | In-process scheduler with Redis-held leader lock | Cleanup, retention, key rotation, email retry, session expiry. |
| Localization | `ui_locales` honored; per-tenant default locale; translation bundles for UI and emails, overridable per tenant | English ships; community translations welcome. |
| Multi-node | Stateless API; all shared state in Postgres/Redis; Redis Sentinel and Cluster supported | Scale horizontally behind any load balancer. |

## 2. Stack and versions (verified 2026-09-14)

All versions are the latest **stable** release as of the date above. Verified by a real
`cargo check` of every backend crate together, and a real `npm install` + `eslint` +
`next build` (static export) of every frontend package together. No alpha/beta/rc/dev builds.

### Toolchain and infrastructure

| Component | Version | Notes |
|-----------|---------|-------|
| Rust | 1.98.1, edition 2024 | |
| Node.js | 24.21.0 (LTS) | 26.x is current but not LTS |
| npm | 12.0.2 | |
| PostgreSQL | 18.6 | minimum supported: 16 |
| Valkey | 9.1.2 | image `valkey/valkey:9.1.2-alpine3.24`; Redis 8.x is protocol-compatible |
| Helm | 4.3.0 | |

### Backend crates (`api/Cargo.toml`)

| Crate | Version | Features / notes |
|-------|---------|------------------|
| axum | 0.8.9 | `macros` |
| tower | 0.5.3 | |
| tower-http | 0.7.1 | `cors`, `trace`, `compression-gzip`, `set-header`, `fs` |
| tower_governor | 0.8.0 | rate limiting |
| tokio | 1.53.1 | `full` |
| sqlx | 0.9.0 | `runtime-tokio`, `tls-rustls-ring`, `postgres`, `uuid`, `chrono`, `json`, `migrate` |
| deadpool-redis | 0.23.1 | `rt_tokio_1` |
| redis | 1.7.0 | `tokio-rustls-comp`, `script` |
| jsonwebtoken | 11.0.0 | `aws_lc_rs` — constant-time RSA; avoids RUSTSEC-2023-0071 exposure |
| rsa | 0.9.10 | `pem` — 0.10 is still RC, do not use |
| p256 | 0.14.0 | `ecdsa`, `pem` |
| ed25519-dalek | 3.0.0 | `rand_core`, `pkcs8`, `alloc` |
| argon2 | 0.6.0 | |
| bcrypt / pbkdf2 / md-5 | 0.19.3 / 0.13.0 / 0.11.0 | legacy hash verification only (imported users) |
| regex | 1.13.1 | profile schema patterns |
| rpassword | 7.5.4 | interactive `ridm-api bootstrap` prompt |
| rand_core (0.6, aliased `rand_core_06`) | 0.6.4 | `getrandom` — rsa 0.9 keygen still takes a rand_core 0.6 RNG |
| totp-rs | 6.0.0 | `qr`, `gen_secret` |
| webauthn-rs | 0.5.5 | `danger-allow-state-serialisation` — 0.6 is still dev, do not use. Requires OpenSSL: `openssl-sys 0.9.117` with `vendored` so the distroless image is self-contained |
| chacha20poly1305 | 0.11.0 | |
| sha2 | 0.11.0 | |
| rand | 0.10.2 | |
| rustls | 0.23.45 | `aws-lc-rs` — 0.24 is still dev, do not use |
| reqwest | 0.13.5 | default-features off; `json`, `rustls`, `form` |
| lettre | 0.11.23 | default-features off; `tokio1`, `tokio1-rustls`, `aws-lc-rs`, `rustls-platform-verifier`, `smtp-transport`, `builder` |
| handlebars | 6.4.4 | |
| serde | 1.0.229 | `derive` |
| serde_json | 1.0.151 | |
| uuid | 1.26.1 | `v4`, `v7`, `serde` |
| chrono | 0.4.45 | `serde` |
| thiserror | 2.0.20 | |
| validator | 0.21.0 | `derive` |
| dotenvy | 0.15.7 | |
| tracing | 0.1.44 | |
| tracing-subscriber | 0.3.23 | `env-filter`, `json` |
| metrics-exporter-prometheus | 0.18.3 | |
| utoipa | 5.5.0 | `axum_extras`, `uuid`, `chrono` |
| utoipa-axum | 0.2.0 | |
| utoipa-swagger-ui | 9.0.2 | `axum` |
| rust-embed | 8.12.0 | embedded UI mode |
| testcontainers-modules (dev) | 0.15.0 | `postgres`, `redis` |
| proptest (dev) | 1.11.0 | property tests for token/blob/cursor parsing |
| testcontainers (dev) | 0.27.3 | `reusable-containers` — no Ryuk in testcontainers-rs; named reusable containers instead |
| cargo-llvm-cov / cargo-fuzz / cargo-audit / cargo-deny (tools) | latest stable at Phase 0.9 (verify then) | coverage, fuzzing, supply chain |

### Frontend packages (`ui/package.json`)

| Package | Version | Notes |
|---------|---------|-------|
| next | 16.3.5 | `output: 'export'`, `trailingSlash: true` |
| react / react-dom | 19.3.0 | |
| typescript | **6.0.3** | TS 7.0.2 builds fine but `typescript-eslint` refuses TS 7; revisit when typescript-eslint adds support (tracked upstream in typescript-eslint#10940) |
| eslint | **9.39.5** | ESLint 10.10.0 crashes `eslint-config-next` (bundled eslint-plugin-react 7.37 uses removed `getFilename` API); revisit when eslint-config-next ships a fixed plugin |
| eslint-config-next | 16.3.5 | |
| tailwindcss / @tailwindcss/postcss | 4.3.3 | |
| @radix-ui/react-dialog | 1.1.23 | plus select 2.3.7, and other primitives at their current 1.x/2.x |
| lucide-react | 1.46.0 | |
| @tanstack/react-query | 5.102.8 | |
| @tanstack/react-table | 9.2.4 | |
| ~~@tanstack/react-virtual~~ | — | dropped in 6.4: the React Compiler lint (`react-hooks/incompatible-library`) flags `useVirtualizer` regardless of opt-out directives; the users table windows rows with a small hook of its own (`ui/src/lib/console/virtual.ts`) |
| react-hook-form | 7.88.0 | |
| @hookform/resolvers | 5.9.1 | |
| zod | 4.6.5 | |
| @simplewebauthn/browser | 14.0.0 | |
| recharts | 3.10.1 | |
| qrcode | 1.5.4 | |
| @types/node / @types/react / @types/react-dom / @types/qrcode | 26.1.0 / 19.2.17 / 19.2.3 / 1.5.6 | |
| @playwright/test / @axe-core/playwright | 1.63.0 / 4.13.0 | e2e + accessibility (pinned at 4.12) |

Pin exact versions in both manifests (no `^`) so the lockfiles and the tables above stay truthful; bump deliberately.

## 3. Repository layout

```
rIDM/
├── Cargo.toml              # workspace (resolver 3, edition 2024, shared deps)
├── crates/
│   ├── ridm-core/          # shared types, provider traits, event definitions
│   ├── ridm-auth/          # published: axum JWT validation for RPs (Phase 10)
│   └── ridm-cli/           # `ridm` command-line tool (Phase 10)
├── api/                    # ridm-api crate
│   ├── migrations/
│   ├── src/
│   │   ├── main.rs
│   │   ├── lib.rs
│   │   ├── config.rs
│   │   ├── error.rs
│   │   ├── db/             # pool, RLS helper, tx helpers
│   │   ├── cache/          # redis pool + typed cache helpers
│   │   ├── models/         # one file per entity (mod.rs = declarations only)
│   │   ├── repos/          # sqlx queries, tenant-scoped
│   │   ├── services/       # domain logic (tokens, keys, flows, mfa, ...)
│   │   ├── oidc/           # discovery, authorize, token, userinfo, jwks, introspect, revoke, end_session
│   │   ├── flows/          # login/consent/mfa/recovery flow state machine
│   │   ├── routes/         # axum routers (oidc, flows, admin, account, health)
│   │   ├── middleware/     # tenant resolver, auth (bearer/session), rate limit, security headers, CORS
│   │   └── util/
│   ├── tests/              # integration, isolation, security, contract, migration tests
│   ├── fuzz/               # cargo-fuzz targets
│   └── Dockerfile
├── ui/                     # Next.js 16, output: 'export', trailingSlash: true
│   └── src/
│       ├── app/
│       │   ├── login/ register/ invite/ consent/ mfa/ recover/ verify/ logout/ device/ error/   # end-user flows
│       │   ├── account/    # self-service console
│       │   └── admin/      # admin console
│       ├── api-client/     # generated TypeScript client from OpenAPI
│       └── i18n/           # translation bundles
│   └── e2e/                # Playwright tests
├── examples/               # RP samples: nextjs-spa, axum-api, confidential-client
├── perf/                   # k6 load-test scripts + baseline results
├── docs/                   # docs site source
├── deploy/
│   ├── docker-compose.yml  # full stack: api + postgres + redis (dev and small prod)
│   ├── helm/ridm/          # Kubernetes chart
│   └── examples/           # nginx, Caddy, Traefik reverse-proxy snippets
├── .github/workflows/      # ci (all required checks), nightly (full conformance), weekly (long fuzz), release
├── README.md
└── working-plan.md
```

## 4. Data model (tenant-scoped unless noted)

Core identity
- `tenants` (global): id, slug, display_name, status, settings jsonb (password policy, session policy, MFA policy, registration policy, locale, branding, custom_domain, captcha, ip rules), created/updated.
- `signing_keys`: id, tenant_id, kid, alg, public_jwk jsonb, private_key_enc bytea, key_version (master-key generation), status (active|retiring|revoked), not_before, expires_at.
- `users`: id, tenant_id, org_id nullable (reserved for Organizations), username, email, email_verified, phone, phone_verified, password_hash, password_algo (argon2id|bcrypt|pbkdf2|sha256-legacy…), must_change_password, password_expires_at, status (active|disabled|locked|pending|deleted), attributes jsonb, locale, last_login_at, password_changed_at, failed_attempts, locked_until, deleted_at. Unique (tenant_id, username), (tenant_id, email).
- `user_profile_schema`: tenant_id, attributes jsonb (name, type, validation, required, editable_by user|admin, visible_in id_token|userinfo).
- `password_history`: tenant_id, user_id, hash, created_at.
- `credentials`: id, tenant_id, user_id, type (password|totp|webauthn|recovery_code|email_otp|sms_otp), data enc, label, created_at, last_used_at.
- `trusted_devices`: id, tenant_id, user_id, device_hash, name, ua, ip, last_seen_at, expires_at.
- `pending_contact_changes`: tenant_id, user_id, new_email/new_phone, token_hash, expires_at.
- `invitations`: id, tenant_id, email, roles[], groups[], org_id, token_hash, invited_by, expires_at, accepted_at.
- `groups` (nestable via parent_id, attributes jsonb), `group_members`.
- `roles`: id, tenant_id, client_id nullable, name, description; `role_assignments` (user|group → role, org_id nullable); `role_composites`.
- `resource_servers`: id, tenant_id, identifier (audience), name, token_ttl, signing_alg, allow_offline_access; `permissions`: resource_server_id, name, description; `permission_assignments` (role → permission).
- `personal_access_tokens`: id, tenant_id, user_id, name, token_hash, scopes[], expires_at, last_used_at, revoked_at.
- `identity_providers`: id, tenant_id, alias, type (oidc|oauth2|saml|ldap), config enc, mapper config, auto_link policy, status. `federated_identities`: user_id ↔ (idp_id, external_subject).

Clients and protocol
- `clients`: id, tenant_id, client_id, name, client_type (spa|web|native|machine|device), name, logo, description, tos_uri, policy_uri, secret_hashes[] (two active for rotation, each with created_at/expires_at), jwks/jwks_uri, token_endpoint_auth_method, redirect_uris[], post_logout_redirect_uris[], allowed_grants[], allowed_scopes[], allowed_audiences[], token TTL overrides, access_token_format (jwt|opaque), id_token_encryption (alg/enc, none), subject_type (public|pairwise), sector_identifier_uri, require_pkce, require_consent (first-party skip), cors_origins[], initiate_login_uri, backchannel_logout_uri, frontchannel_logout_uri, service_account_user_id nullable, registration_access_token_hash (DCR), status.
- `scopes`: id, tenant_id, name, description (shown on consent), claims[], resource_server_id nullable.
- `claim_mappers`: id, tenant_id, client_id nullable, type (user_attr|group|role|permission|hardcoded|template), config jsonb, include_in (access|id|userinfo).
- `sso_sessions`: id, tenant_id, user_id, auth_time, amr[], acr, ip, user_agent, device_id, expires_at, idle_expires_at, revoked_at (Redis primary, Postgres mirror for listing/revocation).
- `refresh_tokens`: id, tenant_id, family_id, client_id, user_id, session_id, token_hash, scopes[], audiences[], expires_at, consumed_at, revoked_at.
- `authorization_codes`, `login_flows`, `par_requests`, `device_codes` (pending), `jti_denylist` — Redis with TTL.
- `device_codes` (approved/consumed, Postgres for audit).
- `consents`: tenant_id, user_id, client_id, scopes[], granted_at, revoked_at.

Operations
- `audit_events`: id, tenant_id, actor (user|client|admin|system), type, target, ip, ua, details jsonb, prev_hash, hash, created_at. Partitioned by month; hash chain for tamper evidence.
- `login_attempts`: tenant_id, identifier, ip, success, reason, created_at.
- `email_templates`, `sms_templates` (per tenant, per locale, per event; fallbacks to defaults), `smtp_settings`, `sms_settings`, `captcha_settings` (encrypted).
- `outbound_messages`: queued email/SMS with attempts, next_attempt_at, last_error.
- `webhooks`: id, tenant_id, url, secret_hash, events[], status; `webhook_deliveries`: attempts, response_code, next_attempt_at.
- `ip_rules`: tenant_id, client_id nullable, cidr, action (allow|deny), reason.
- `admin_roles` are ordinary roles in `master`/tenant with `ridm:*` permissions; `feature_flags`: tenant_id, key, enabled.
- `organizations` (post-v1, reserved): id, tenant_id, slug, name, domains[], settings; `organization_members`; `organization_invitations`.
- `risk_signals` (post-v1): user_id, session_id, signal type, score, created_at.

## 5. Phases

### Phase 0 — Scaffold and open-source hygiene
- [x] 0.1 Cargo workspace (`resolver = "3"`, edition 2024) with `api/` crate; exact-pinned deps from §2. `cargo check` clean.
- [x] 0.2 `config.rs` (typed env: DATABASE_URL, REDIS_URL, PUBLIC_URL, MASTER_KEY or MASTER_KEY_FILE, BIND_ADDR, LOG_FORMAT, DOCS_ENABLED, COOKIE_SECURE, TRUSTED_PROXIES, TLS_CERT/TLS_KEY), `error.rs`, health endpoints, tracing setup.
- [x] 0.3 `deploy/docker-compose.yml` (api, postgres, redis, mailpit) with dev profile that seeds a tenant, admin, and sample client; `api/Dockerfile` (multi-stage, distroless, multi-arch); `.env.example`.
- [x] 0.4 Migration 0001: `tenants`; seed `master`. `sqlx migrate run` tested; optional migrate-on-start flag.
- [x] 0.5 `ui/` Next 16 static export scaffold (exact-pinned deps from §2). ESLint clean, `next build` produces `out/`.
- [x] 0.6 GitHub Actions CI: `cargo check`, `clippy -D warnings`, `cargo test`, `cargo audit`, `cargo deny`, `npm run lint`, `npm run build`. Renovate config.
- [x] 0.7 README, CONTRIBUTING.md, SECURITY.md (disclosure policy), CODE_OF_CONDUCT.md, `security.txt`, issue/PR templates.
- [x] 0.8 Provider traits (`KeyEncryptor`, `EmailSender`, `SmsSender`, `Captcha`, `PasswordHasher`) and the internal event bus skeleton.
- [x] 0.9 Tests: `ridm-core` test-support module with mock `KeyEncryptor`/`EmailSender`/`SmsSender`/`Captcha`; testcontainers harness (Postgres + Redis) with a shared fixture that seeds tenant, client, admin, user; cargo-llvm-cov wired into CI with coverage report.
- [x] 0.10 Branch protection on `main`: PRs only, all required status checks in §6 must pass, no bypass; CODEOWNERS.

### Phase 1 — Tenants, users, groups, roles, profile schema
- [x] 1.1 Migrations: users, user_profile_schema, password_history, credentials, groups, group_members, roles, role_assignments, role_composites (indexes lead with tenant_id; RLS policies; `org_id` reserved columns).
- [x] 1.2 Tenant resolver extractor (`/t/{slug}` → cached `Tenant`), RLS `SET LOCAL` per request tx; Redis pub/sub cache invalidation.
- [x] 1.3 Repos + services: tenant CRUD, user CRUD, group CRUD + membership, role CRUD + assignment, effective-roles resolution (user + groups + composites, cached).
- [x] 1.4 Password service: argon2id hash/verify; legacy verifiers (bcrypt, pbkdf2-sha256/512, sha256/sha512 salted, md5 for migration only) with transparent upgrade on successful login; password policy (length, classes, history N, expiry, must_change_password).
- [x] 1.5 Profile schema service: validate attributes on create/update; enforce editable_by; expose schema to UI forms.
- [x] 1.6 Bootstrap: first-run creates master tenant + global admin from env or interactive CLI.
- [x] 1.7 Unit tests (password, policy, role resolution); integration test harness (testcontainers).
- [x] 1.8 Tests: tenant isolation suite v1 (every repo query cross-tenant → empty/404; direct RLS bypass attempt fails); profile schema validation; legacy-hash upgrade-on-login; migration test applying all migrations to seeded snapshot and checking constraints/row counts.

### Phase 2 — Keys, JWT issuance, encryption
- [x] 2.1 Migration: signing_keys. Keygen (RSA-2048/3072, P-256, Ed25519); private keys encrypted via `KeyEncryptor`.
- [x] 2.2 Rotation service: create → activate → retire → revoke with overlap; scheduled rotation job.
- [x] 2.3 JWKS endpoint (cached, ETag). WebFinger endpoint for issuer discovery.
- [x] 2.4 Token service: sign/verify access + ID tokens; claim-mapper pipeline; pairwise `sub` derivation; optional JWE encryption of ID tokens per client.
- [x] 2.5 Refresh token service: opaque, hashed, rotation, family reuse detection; `jti` denylist for instant access-token revocation.
- [x] 2.6 Master key rotation command: re-encrypt all `*_enc` columns under a new key version, zero downtime.
- [x] 2.7 Tests: sign/verify for every alg; rotation overlap (old kid still verifies until retired); revoked kid rejected; JWKS shape and ETag; pairwise `sub` stability; JWE round trip; master-key rotation re-encrypts and verifies; property tests on JWT decoding.

### Phase 3 — OIDC provider core
- [x] 3.1 Migrations: clients (all fields incl. client_type, dual secrets, subject_type, logout URIs), scopes, claim_mappers, consents, refresh_tokens, resource_servers, permissions, permission_assignments. Default scopes seeded per tenant.
- [x] 3.2 Discovery document, complete and accurate for every supported feature.
- [x] 3.3 `/authorize`: full validation (client, exact redirect_uri incl. loopback rules for native, response_type=code, scope, state, nonce, PKCE, prompt incl. `create`, max_age, acr_values, login_hint, ui_locales, `claims` param, `resource` indicators, `response_mode` query|fragment|form_post|jwt); SSO-session check → code or `login_flow` redirect.
- [x] 3.4 `/token`: authorization_code (+PKCE), refresh_token (rotation), client_credentials (service account roles), with client auth basic/post/private_key_jwt; audience-scoped access tokens for resource servers.
- [x] 3.5 `/userinfo`, `/introspect`, `/revoke`, `/end_session` (RP-initiated logout), back-channel logout and front-channel logout.
- [x] 3.6 PAR (RFC 9126), JAR (RFC 9101), JARM.
- [x] 3.7 Dynamic client registration (RFC 7591) and management (RFC 7592) with per-tenant policy (open|initial-access-token|disabled).
- [x] 3.8 Client secret rotation (two active secrets, grace window) and `jwks_uri` refresh.
- [x] 3.9 Integration tests: code+PKCE round trip, refresh rotation + reuse detection, client_credentials, DCR, logout propagation, negative cases.
- [x] 3.10 Security tests: code replay, PKCE missing/mismatched/plain-downgrade, redirect_uri substring/suffix/scheme attacks, loopback port rules, state/nonce mismatch, `id_token_hint` from another tenant, client secret grace expiry, DCR abuse (open policy off), discovery-vs-routes contract test. Fuzz targets: authorize params, redirect_uri matcher.

### Phase 4 — Browser flows (API) and end-user UI
- [x] 4.1 Flow state machine (Redis): identify → authenticate (password | passkey | magic-link | email-otp | sms-otp | upstream IdP) → mfa → step-up check (acr) → profile-completion → terms → consent → done; CSRF bound to flow; retry counters.
- [x] 4.2 Flow API: `GET /flows/{id}` (public state, branding, locale, available methods), `POST /flows/{id}/{step}`, `/cancel`; completion returns `{ redirect_to }`.
- [x] 4.3 Brute-force protection (per-user + per-IP), CAPTCHA challenge via `Captcha` trait after threshold or on registration.
- [x] 4.4 Messaging: `EmailSender` (SMTP via lettre, generic HTTP), `SmsSender` (HTTP webhook), per-tenant settings (encrypted), per-locale templates (handlebars), outbound queue with retry and dead-letter.
- [x] 4.5 Magic link and email OTP login; SMS OTP login; passwordless-only tenant policy.
- [x] 4.6 Self-registration (per-tenant toggle, profile schema driven, email verification, terms acceptance) and invitation acceptance flow.
- [x] 4.7 Recovery/verification: password reset, email verify, resend, temporary password + forced change.
- [x] 4.8 Session policy enforcement: idle/absolute timeouts, max concurrent sessions, trusted-device "remember me" skipping MFA, `prompt`/`max_age`/`acr_values` honored.
- [x] 4.9 i18n: locale negotiation (`ui_locales` → user locale → tenant default), translation bundles, RTL-safe layout.
- [x] 4.10 UI pages: `/login/`, `/register/`, `/invite/`, `/consent/`, `/mfa/`, `/recover/`, `/verify/`, `/logout/`, `/device/`, `/error/`. Query-param driven; tenant theme (logo, colors, custom links, optional custom CSS); mobile-first.
- [x] 4.11 Security notifications to users: new device login, password changed, MFA changed, email changed.
- [x] 4.12 Tests (trusted-device MFA skip is covered with 7.7 once a second factor exists): flow state machine transitions (every step, every error), CSRF on each step, brute-force lockout timing, CAPTCHA gate, magic-link/OTP single-use + expiry, registration with schema validation, invitation acceptance, recovery token single-use, session idle/absolute/concurrent limits, trusted-device skip, locale negotiation, message queue retry/dead-letter with mock senders. Playwright e2e: password login, magic link (via Mailpit), registration, recovery, consent, logout; extended after 5.1 with email OTP, invitation acceptance, forced password change, profile completion, terms re-acceptance and lockout.

### Phase 5 — Admin API
- [x] 5.1 Admin auth middleware + admin permission model (`ridm:tenants:*`, `ridm:users:read|write`, `ridm:clients:*`, `ridm:keys:*`, `ridm:audit:read`, …) with built-in admin roles: owner, admin, user-manager, client-manager, viewer. Built as: per-tenant built-in resource server `urn:ridm:admin` + permission catalogue + `ridm:*` roles seeded by migration (Rust mirror in `services/admin_access.rs`, contract-tested); `AdminCtx` bearer extractor (audience-bound, session-bound, permissions re-resolved per request, master = global scope); `GET /admin/me`, `GET /admin/permissions`.
- [x] 5.2 Tenants: CRUD, settings (password, session, MFA, registration, locale, branding, captcha, ip rules, feature flags). Built as: `/admin/tenants` list (global: all, paginated; tenant-scoped: own), create/delete global-only, get/patch per scope; settings via JSON merge patch with unknown-field rejection; `features` flag map in settings; captcha provider config (encrypted, secret redacted on read); `AdminTenantPath` extractor admits disabled tenants; problem+json `Json` extractor. IP rules are their own resource in 5.10.
- [x] 5.3 Clients: CRUD, type-driven defaults, secret generate/rotate (reveal-once), URIs, grants, scopes, audiences, token settings, encryption, logout URIs, CORS, service account. Built as: `/admin/tenants/{slug}/clients` (id or public `client_id` in the path); merge-patch updates plus `status`; scopes/audiences validated against the tenant; `secrets` metadata on reads; rotate with grace and revoke by secret id; switching auth method to/from secrets drops or mints one (also on RFC 7592 PUT); service account = a `svc-<client_id>` user linked to the client; registration-token issue for RFC 7592 management.
- [x] 5.4 Users: cursor-paginated list/search, CRUD, set/temp password, force reset, enable/disable/unlock, sessions + revoke, credentials, trusted devices, role/group assignment, consents. Built as: `/admin/tenants/{slug}/users` and sub-resources; create accepts `password` or `temporary_password` (returned once); `PATCH` with `null` clears, `status` limited to active/disabled (disable revokes sessions); password route with policy override, notify and session revocation; credentials = password summary plus `credentials` rows (metadata only, `repos::credentials`); role and group grants pass `require_can_grant` over the composites-expanded (and ancestor-group) permissions via `admin_access::permissions_of_grant`. Deferred to where their storage arrives: PATs (8.5), federated identities (8.3), per-user audit (5.9).
- [x] 5.5 Groups, roles, resource servers + permissions, scopes, claim mappers CRUD. Built as: `/admin/tenants/{slug}/{groups,roles,resource-servers,scopes,claim-mappers}`; `built_in` resource servers, their catalogue and built-in roles are immutable (403); every grant path (role to user/group, group membership, composite child, admin-catalogue permission to role) passes `require_can_grant` over `admin_access::permissions_of_grant`; permission grant/revoke and resource-server/permission deletion bump the roles version; claim mappers are cached per client under a tenant-wide mappers version (`claim_mappers::bump_mappers_version`) so tenant-wide changes reach every client at once; new `scope.*`, `claim_mapper.*`, `resource_server.*`, `permission.*` events. Identity provider CRUD moves to 8.3 with its table and brokering semantics.
- [x] 5.6 Keys: list, rotate, revoke. Master-key rotation status. Built as: `/admin/tenants/{slug}/keys` list (status filter), create (pending or activated), rotate, get, activate, retire, revoke; `/admin/master-key` status with pending row count and `/rotate` re-encryption, both global-only.
- [x] 5.7 Invitations: create/list/revoke/resend. Bulk user import (CSV/JSON, legacy hashes) and export. Built as: `/admin/tenants/{slug}/invitations` (token only by email, resend rotates it, role/group invitations guarded by `require_can_grant`); `POST .../users/import` (JSON or CSV, `dry_run`, per-row report, legacy hashes via `password::import_hash`, roles/groups by name; `services/bulk_users.rs`) and streaming `GET .../users/export` in JSON or CSV.
- [x] 5.8 Messaging admin: SMTP/SMS settings with test-send, template CRUD per locale with preview. Built as: `/admin/tenants/{slug}/messaging/{email,sms}` (encrypted provider settings, secrets redacted as `*_set`, omitted secret kept, validation of security/URLs), `/{email,sms}/test` straight through the configured sender, `/templates` catalogue + `/{channel}/{event}/{locale}` override GET/PUT/DELETE (built-in shown as starting point, rendering validated) + `/preview` (stored or draft, sample vars), `/log` without bodies and `/log/{id}/redeliver`; `services/messaging.rs`.
- [x] 5.9 Audit: list/filter/export; retention policy per tenant. Migration for partitioned `audit_events` with hash chain. Includes the per-user audit route under `/admin/tenants/{slug}/users/{id}/audit` deferred from 5.4. Built as: migration `20260915144648_audit_events` (range-partitioned by month with a default partition, `audit_ensure_partitions()`, tenant RLS, per-chain `seq`), `services/audit.rs` writer subscribed to the event bus (per-chain advisory lock, `SHA-256(prev_hash || canonical row)`), list/export/verify per tenant and for the global chain, `settings.audit.retention_days`, daily `audit_retention` job purging an expired chain prefix and creating partitions.
- [x] 5.10 Webhooks CRUD, delivery log, redeliver. IP rules CRUD. Built as: migration `20260915150001_webhooks_ip_rules` (`webhooks` with encrypted HMAC secret + `key_version`, `webhook_deliveries` queue, `ip_rules`, all under tenant RLS); `services/webhooks.rs` (event patterns, reveal-once secret on create/rotate, bus dispatcher → queued deliveries, `deliver_due` with HMAC `X-RIDM-Signature`, retry/backoff/dead-letter, redeliver, test ping) + `webhook_delivery` job every 30 s; `services/ip_rules.rs` with CIDR normalization (enforcement stays in 9.2); webhook secrets registered for master-key rotation; dispatcher started in main and the test harness.
- [x] 5.11 Tenant export/import (config as code): deterministic JSON, secrets excluded or encrypted, idempotent apply with diff preview. Built as: `services/tenant_config.rs` with the `ridm.tenant/1` document (sorted collections, natural keys: client `client_id`, role `name` or `client_id/name`, permission `identifier#name`, group `path[]`, template `channel/event/locale`), `export`, `plan` (normalizes the desired document, compares against a fresh export, field-level diffs, deletes only with `prune`, built-in roles/servers and standard scopes never deleted) and `apply` (dependency-ordered, per-item errors, secrets of created clients and webhooks reported once); `GET .../export`, `POST .../import`. Secrets are excluded (not encrypted): provider credentials are configured per environment.
- [x] 5.12 Cache invalidation on every write; utoipa docs complete; generated TypeScript admin client published from OpenAPI. Built as: invalidation audit (every cached key has an eviction on its write path; roles/mappers versions cover derived caches); `#[utoipa::path]` on every admin handler with `ToSchema`/`IntoParams` on all models, routers as `utoipa_axum::OpenApiRouter` merged in `openapi.rs` (`/openapi.json`, Swagger UI at `/docs` with `DOCS_ENABLED`, `ridm-api openapi` CLI); committed `api/openapi.json` kept current by a test; `ui/lib/api/openapi.d.ts` generated by `npm run gen:api` (openapi-typescript via npx with TypeScript 5) and `ui/lib/api/client.ts` on `openapi-fetch` with bearer and 401 middleware.
- [x] 5.13 Tests: admin permission matrix (each built-in role × each endpoint), tenant isolation suite v2 (every admin endpoint cross-tenant), cursor pagination stability, bulk import (legacy hashes, bad rows reported), export/import round trip is idempotent and diff is empty, audit hash chain verifies, TypeScript client contract test against live OpenAPI. Built as: `admin_matrix.rs` derives every operation and its required permission from the route sources (`#[utoipa::path]` + first `admin.require*`) and checks all five built-in roles, the global owner and anonymous callers, then calls every tenant-scoped operation across tenants; `admin_pagination.rs` walks user and client listings with mid-walk inserts; bulk import (`admin_bulk_users.rs`), export/import (`admin_tenant_config.rs`) and audit chain (`admin_audit.rs`) suites from their sub-phases; `ui/e2e/openapi-contract.spec.ts` compares the live document with the committed one and drives the typed client against the live API.

### Phase 6 — Admin UI
- [x] 6.1 Shell: OIDC PKCE login, refresh, tenant switcher, global search, sidebar, dark/light, keyboard shortcuts. Built as: the console is served at `/console/` (`/admin/*` is the API); API side, a built-in public client `ridm-admin-console` per tenant (`services/admin_console.rs`: PKCE, no consent, `urn:ridm:admin` audience, redirect URIs from `UI_URL`, ensured at startup and on tenant create, undeletable, excluded from export/import/prune) and tag-prefixed unique OpenAPI operation ids (the generated client had been collapsing same-named handlers); UI side, `lib/console/auth.ts` (PKCE start/callback/refresh/logout, tokens in `sessionStorage`), `lib/console/session.tsx` (external session store read through `useSyncExternalStore`, typed client with shared proactive refresh and 401 fallback, `/admin/me` identity), `components/console/shell.tsx` (sign-in gate, sidebar filtered by permissions, top bar, phone drawer, theme switch, shortcut help), `palette.tsx` (⌘K search over pages/users/clients, tenant switcher for global admins; tenant travels as `?tenant=`), `theme.tsx` (system/light/dark with pre-paint restore), `shortcuts.tsx`; `/console/` overview page; `admin_console.rs` test suite and `e2e/console.spec.ts` (global setup promotes the e2e user to global owner). Navigation entries are added as their pages land.
- [x] 6.2 Tenants: list/create; settings pages (auto-save, all fields), branding editor with live login-page preview. Built as: `/console/tenants/` (all tenants for global admins, client-side filter, create dialog with slug validation → new tenant's settings) and `/console/settings/` (`components/console/settings/*`: general incl. feature flags, sign-in methods/MFA policy/registration, password policy/lockout/CAPTCHA policy + provider sub-form, sessions & tokens, branding, locale & notices, keys/discovery/DCR/audit, danger zone); `lib/console/autosave.ts` (`useAutoSave`: coalesced merge patches, 600 ms debounce capped at 2.5 s, keepalive flush on hide/unload, error → reload stored state) with `SaveIndicator`; console form controls in `components/console/form.tsx` (`Field`, `TextInput`, `NumberInput`, `Toggle`, `SelectInput`, `TagsInput`, `ColorInput`, `TextArea`); branding editor frames the real login page in preview mode (`/login/?tenant=&preview=1` renders `Authenticate` on a stand-in flow, `TenantProvider preview` takes `ridm:preview` postMessage overrides after posting `ridm:preview:ready`); `e2e/console-tenants.spec.ts`.
- [x] 6.3 Clients: table, create wizard (type → grants → URIs → scopes/audiences), detail with auto-save sections, secret reveal-once + rotate, "playground" to run the client's flow end to end. Built as: `/console/clients/` (`components/console/clients/`: `table.tsx` with server prefix search and cursor paging via `useInfiniteQuery`, `wizard.tsx` four steps with `typeDefaults` mirroring the API, `detail.tsx` sections on `useAutoSave` over the metadata merge patch plus secrets/service-account/registration-token/delete mutations, `pickers.tsx` scope and audience check lists, `reveal.tsx` reveal-once modal + copy button); `/console/playground/` with `lib/console/playground.ts` (PKCE run state in sessionStorage across the redirect, token/userinfo requests with the client's auth method, JWT decoding); `lib/console/hooks.ts` (`useDebounced`, `useScopes`, `useResourceServers`); Clients joins the navigation (`g c`); `e2e/console-clients.spec.ts`.
- [x] 6.4 Users: virtualized table with search/filters, user detail (profile per schema, credentials, devices, sessions, PATs, roles, groups, identities, consents, audit), invite dialog, bulk import/export. Built as: `/console/users/` (`components/console/users/`: `table.tsx` windowed rows via `lib/console/virtual.ts` with server prefix search, status filter, include-deleted and scroll-driven paging; `create.tsx` with reveal-once temporary password; `invite.tsx` invite dialog + open-invitations list with resend/revoke; `import.tsx` JSON/CSV paste-or-file with dry run report and export download through the console token; `detail.tsx` tabs — profile (identity fields + `attributes.tsx` schema-driven fields, full attribute set on every save), password & credentials, sessions & devices, roles, groups, consents, audit); API: new `GET/PUT /admin/tenants/{slug}/profile-schema` routes (test in `admin_tenants.rs`) and a Profile attributes editor in Settings (`settings/profile.tsx`, whole-schema PUT on auto-save); PATs and identities are placeholders until 8.5/8.3; Users joins the navigation (`g u`); `e2e/console-users.spec.ts`.
- [x] 6.5 Groups (tree), roles, resource servers + permissions, scopes, claim mappers, identity providers (with test-connection). Built as: `components/console/access/` — `groups.tsx` (tree with `role=tree`, create at any level, parent select excluding descendants, JSON attributes, group roles, members via user-search `Picker`), `roles.tsx` (realm/client roles, composites, permission grants from a catalogue built over every resource server, holders resolved to users/groups, built-in read-only), `resource-servers.tsx` (fields + permissions, `urn:ridm:admin` read-only), `scopes.tsx` (description, claims, resource server binding, default flag; standard scopes undeletable), `mappers.tsx` (kind-specific fields via `MapperFields`, include-in targets, whole-config PATCH on auto-save); shared `common.tsx` (`CreateDialog`, `DeleteButton`, `Split`); `lib/console/access.ts`; five route pages; navigation entries (`g g`, `g r`, `g a`, `g p`, `g m`); `e2e/console-access.spec.ts`. Identity providers (with test-connection) move with their CRUD to 8.3.
- [x] 6.6 Keys page (timeline, rotate), audit viewer (filters, export), webhooks (deliveries, redeliver), IP rules, messaging (settings, templates with preview, test-send). Built as: `components/console/ops/` — `keys.tsx` (timeline bars per key, rotate, create pending/activated, activate/retire/revoke, JWK viewer, master-key status + re-encrypt for global admins), `audit.tsx` (tenant or global chain, filters with `datetime-local` → RFC 3339 `Z`, cursor stack for newer/older, expandable rows, JSON/CSV export through the console token, verify), `ip-rules.tsx` (inline add/edit/delete; uses `ridm:tenants:*` like the API), `webhooks.tsx` (list/detail with auto-save, reveal-once secret on create/rotate, test ping, deliveries with status filter, 10 s refresh and redeliver), `messaging.tsx` (email/SMS provider forms with write-only secrets and test send, template picker + editor with debounced draft preview and opt-in HTML rendering, override/reset, outbound log with redeliver); `lib/console/ops.ts` (event-name catalogue, `downloadWithToken`); navigation groups Security and Integrations; `e2e/console-ops.spec.ts` (with an afterAll that removes any template override left by a failed run, since the registration emails of other specs depend on the built-in).
- [x] 6.7 Dashboard: logins/day, active sessions, failed logins, MFA adoption, top clients (recharts). Built as: new `services/stats.rs` + `routes/admin/stats.rs` (`GET /admin/tenants/{slug}/stats?days=`, `ridm:tenants:read`; per-day sign-ins/failures from `login_attempts`, live sessions from `sso_sessions`, user counts and TOTP/passkey enrolment from `credentials`, top clients from `authorization.granted` audit rows; `admin_stats.rs` test); `components/console/dashboard.tsx` on the overview page (stat tiles, recharts line chart with legend, tooltip and table view, horizontal bar chart of top clients with direct labels, users card with an adoption progress bar; series colours `--series-1/2` validated with the dataviz palette script in light and dark).
- [x] 6.8 Tenant export/import UI with diff preview. Built as: `components/console/config.tsx` at `/console/config/` — export download and load-into-editor, file or paste import, prune toggle, `dry_run` plan grouped by resource with op badges and field diffs (long values collapse), apply with per-item errors and reveal-once secrets of created clients/webhooks; navigation entry (`g x`); `e2e/console-config.spec.ts`.
- [x] 6.9 Playwright e2e: admin login, tenant create + settings auto-save, client wizard + secret reveal, user CRUD + invite, role/group assignment, key rotate, audit filter, export/import with diff. Axe accessibility checks on every admin page. Built as: the journeys landed with their sub-phases (`console`, `console-tenants`, `console-clients`, `console-users`, `console-access`, `console-ops`, `console-config` specs, every one with axe checks on the pages it touches); `console-a11y.spec.ts` sweeps every console page in its landing state (light, dark, phone width with an overflow check); findings fixed along the way: header search button name, link colour derived from the tenant accent (`--link` = accent mixed toward black/white per theme, used by the end-user pages too), cards clipped to their grid cell, users table scrolling sideways on phones. Full suite: 84 Playwright tests and 61 Rust test binaries green. Phase 6 complete.

### Phase 7 — MFA and credential hardening
- [x] 7.1 TOTP: enroll (QR), verify, recovery codes (hashed). Built as: `services/totp.rs` (RFC 6238 SHA-1/6/30 with one step of skew via `totp-rs`; secret encrypted in a `totp` credential row under AAD `credentials:{tenant}:{id}`; ten `xxxxx-xxxxx` recovery codes SHA-256 hashed inside one encrypted `recovery_code` row, single-use; per-step replay guard in Redis; pending enrolment in Redis bound to the flow; `MfaChanged` events and `mfa_changed` notices); flow steps `POST /flows/{id}/mfa/totp/enroll` (secret + otpauth URI), `/mfa/totp/confirm` (proof code → `{recovery_codes, flow}`), `/mfa/verify` (app code or recovery code, `remember_device`), five wrong codes discard the flow; `PublicFlow.mfa` (`factors`, `enroll`, `recovery_codes`); `flows::mfa_required` now evaluates the tenant policy (`required` enrols on first sign-in, `optional` asks enrolled users, trusted device skips, `acr_values` step-up always asks; role modes behave as `optional` until 7.4) and a passed factor refreshes the session with `amr` + `acr` (`ACR_MFA` or the requested class); `/mfa/` page: enrol (QR rendered client-side with `qrcode`, manual key, device label), verify, recovery-code mode, recovery codes shown once with copy/download; `api/tests/mfa_totp.rs`, matrix steps, `ui/e2e/mfa.spec.ts` (step-up driven so other specs stay untouched).
- [ ] 7.2 WebAuthn/passkeys: register, authenticate, passwordless + discoverable credentials, multiple authenticators with labels.
- [ ] 7.3 Email OTP and SMS OTP as second factors (reusing 4.5 senders).
- [ ] 7.4 Tenant MFA policy: off | optional | required | required-for-roles | required-for-admins; step-up by `acr_values`; `amr`/`acr` claims accurate.
- [ ] 7.5 Breached-password check via k-anonymity (HIBP-compatible, pluggable, off by default for air-gapped installs).
- [ ] 7.6 UI: `/mfa/` flow page, account console MFA + passkeys + trusted devices management.
- [ ] 7.7 Tests: TOTP drift window, recovery code single-use, WebAuthn register/authenticate with virtual authenticator (Playwright CDP), OTP factors, MFA policy matrix (off/optional/required/for-roles/for-admins), step-up `acr` enforcement, `amr` accuracy, HIBP check with mock. Playwright e2e: TOTP enroll + login, passkey enroll + passwordless login.

### Phase 8 — Account console, identity brokering, device flow, PATs
- [ ] 8.1 Account console UI (`/account/`): profile per schema (auto-save), password change, email/phone change with verification, MFA, passkeys, trusted devices, sessions (revoke, sign out everywhere), linked identities, consented apps, personal access tokens, data export, account deletion.
- [ ] 8.2 Account API (self-scoped): all of the above; GDPR export (JSON) and deletion (soft-delete → purge job).
- [ ] 8.3 (also adds the admin identity-provider CRUD deferred from 5.5 and the `users/{id}/identities` list/unlink routes deferred from 5.4) Upstream OIDC/OAuth2 providers: per-tenant config, `/broker/{alias}/start|callback`, discovery + JWKS cache, attribute mappers, account linking (auto by verified email | explicit | always-new), first-login profile completion. Presets: Google, Microsoft, GitHub, Apple, GitLab.
- [ ] 8.4 Device authorization grant (RFC 8628): `/device_authorization`, `/device/` UI, polling on `/token`.
- [ ] 8.5 Personal access tokens: create/list/revoke, usable as bearer with scoped permissions. Includes the admin `users/{id}/pats` list/revoke routes deferred from 5.4.
- [ ] 8.6 Tests: account endpoints self-scoped only (cannot read another user), email/phone change verification, GDPR export completeness, deletion → purge job, upstream IdP brokering against a mock OIDC provider (state/nonce checks, linking policies, first-login completion), device flow polling states (pending/slow_down/denied/expired), PAT scope enforcement. Playwright e2e: account console profile, sessions revoke, linked identity.

### Phase 9 — Scale, security, operability
- [ ] 9.1 Rate limiting (per IP / client / tenant) on `/token`, `/authorize`, flow endpoints; security headers + CSP for UI; strict CORS from client config.
- [ ] 9.2 IP allow/deny rules enforcement per tenant/client.
- [ ] 9.3 Custom domains per tenant (host → tenant map, issuer override).
- [ ] 9.4 Token exchange (RFC 8693), DPoP (RFC 9449).
- [ ] 9.5 Webhooks delivery engine (signed payloads, retry with backoff, dead-letter) driven by the event bus.
- [ ] 9.6 SCIM 2.0 server (users/groups) for tenant provisioning, with bearer auth per SCIM client.
- [ ] 9.7 Background jobs: expired tokens/sessions/flows cleanup, audit retention, soft-delete purge, message retry, key rotation; leader lock in Redis.
- [ ] 9.8 OpenTelemetry OTLP trace export; Prometheus metrics complete (logins, tokens, latencies, queue depths); audit export sink (syslog/HTTP).
- [ ] 9.9 Redis Sentinel/Cluster support; Postgres read-replica routing for read-heavy admin queries.
- [ ] 9.10 Perf: `EXPLAIN` review, indexes, k6 load test targeting 5k token req/s per node; JWKS/discovery cached with ETag; pool tuning.
- [ ] 9.11 OIDC conformance suite (basic OP, config, PKCE, RP-initiated logout, back-channel logout, DCR profiles); fix findings.
- [ ] 9.12 Security review pass (`/security-review`), `cargo audit`/`cargo deny` in CI, threat model document.
- [ ] 9.13 Tests: rate-limit thresholds and headers, IP rules, custom-domain issuer resolution, token exchange + DPoP proofs (replay, wrong htm/htu), webhook signing/retry/dead-letter, SCIM filter/patch semantics, cleanup jobs with leader lock (two nodes, one runs). Conformance suite as a required PR check. k6 smoke with thresholds as a required PR check; full baseline on release. cargo-fuzz bounded run per PR, long run weekly.

### Phase 10 — Developer experience and CLI
- [ ] 10.1 `ridm` CLI: bootstrap, tenant export/import/diff, key rotate, master-key rotate, user create/reset, client create; talks to admin API (or DB for bootstrap).
- [ ] 10.2 `ridm-auth` crate: axum extractor/middleware that validates rIDM JWTs (JWKS cache, audience/permission checks). Published to crates.io.
- [ ] 10.3 Example RP apps: Next.js SPA (PKCE), Rust axum API using `ridm-auth`, generic confidential client.
- [ ] 10.4 Docs site (mdBook or Docusaurus): concepts, quickstarts, admin guide, API reference (OpenAPI), deployment guide, migration guide from Keycloak/Auth0 (import mapping).
- [ ] 10.5 Dev mode polish: seeded data, Mailpit, hot reload notes, `make`/`just` targets.
- [ ] 10.6 Tests: `ridm` CLI integration tests against the harness; `ridm-auth` crate tests (JWKS cache refresh on unknown kid, audience/permission checks, clock skew); example apps smoke-tested in CI against docker-compose.

### Phase 11 — Packaging and release
- [ ] 11.1 Embedded UI mode: `rust-embed` serves `ui/out` with trailing-slash fallback; image build runs `npm run build`.
- [ ] 11.2 Helm chart (`deploy/helm/ridm`): Deployment, Service, Ingress, HPA, external Postgres/Redis values, existing-Secret refs, PodDisruptionBudget.
- [ ] 11.3 Reverse-proxy examples (nginx, Caddy, Traefik); production docker-compose profile.
- [ ] 11.4 Release workflow: tag → multi-arch image to GHCR (cosign-signed, SBOM attached), static musl binaries (linux amd64/arm64), Helm chart package, changelog.
- [ ] 11.5 Backup/restore guide (DB + master key), upgrade guide, `security.txt`.
- [ ] 11.6 Cut v0.1.0: bump Cargo.toml + package.json, changelog, README final.
- [ ] 11.7 Tests: embedded-UI mode serves every route with trailing slash; Helm chart lint + kind smoke deploy as a required PR check; image starts, migrates, and passes `/readyz`; upgrade test from previous release tag.

### Phase 12 — Post-v1: Organizations and adaptive auth
- [ ] 12.1 Organizations within a tenant: CRUD, members, org-scoped roles, invitations, verified domains with auto-join, org picker in login flow, `org_id` claim.
- [ ] 12.2 Org-scoped admin roles and admin UI (org admins manage their own members).
- [ ] 12.3 Risk-based adaptive auth: signals (new device, new country, impossible travel, velocity), per-tenant policy raising MFA requirement or blocking; risk events in audit.
- [ ] 12.4 User impersonation by admins: explicit permission, banner in session, `act` claim, full audit.
- [ ] 12.5 Audit hash-chain verification tool and export sinks hardened; feature flags UI.
- [ ] 12.6 CIBA (backchannel authentication) and FAPI 2.0 security profile (PAR + DPoP/mTLS + JARM already present).
- [ ] 12.7 Tests: org isolation (org admin cannot escape org), domain auto-join, risk policy matrix, impersonation audit trail and `act` claim, CIBA flow states.

### Phase 13 — Post-v1: Enterprise federation and key custody
- [ ] 13.1 SAML 2.0 identity provider (rIDM as IdP): metadata, SP registration, SSO/SLO, attribute statements, signing/encryption.
- [ ] 13.2 SAML 2.0 upstream (rIDM as SP) as an `identity_providers` type.
- [ ] 13.3 LDAP / Active Directory upstream: bind auth, user/group sync job, mappers, write-back optional.
- [ ] 13.4 Kerberos/SPNEGO desktop SSO (optional feature flag).
- [ ] 13.5 mTLS client authentication (RFC 8705) and certificate-bound tokens.
- [ ] 13.6 `KeyEncryptor` backends: PKCS#11/HSM and cloud KMS as optional cargo features (kept out of the default build to stay provider-neutral).
- [ ] 13.7 Data residency: per-tenant database routing for regulated customers.
- [ ] 13.8 Tests: SAML IdP against a reference SP (SSO/SLO, signature validation, replay), SAML/LDAP upstream against containers (samltest-compatible SP, OpenLDAP), mTLS client auth, HSM backend against SoftHSM.

## 6. Testing strategy

Tests are a deliverable of every sub-phase, not a phase of their own. Each phase ends with a test bullet.

**Merge policy: `main` is protected. Every suite below is a required status check on every PR; a PR cannot merge until all of them pass. No admin bypass.** Suites that are too slow for full depth on every PR run a bounded version on the PR (still required) and the full version on a schedule; both are listed.

| Layer | Tooling | Where | Runs |
|-------|---------|-------|------|
| Unit | `cargo test`, mock provider traits from `ridm-core::test_support` | every crate | every PR (required) |
| Integration (HTTP) | testcontainers (Postgres 18, Redis 8), real axum router, shared seeded fixture | `api/tests/` | every PR (required) |
| Tenant isolation | every admin/account/OIDC endpoint invoked cross-tenant; direct RLS bypass attempts | `api/tests/isolation/` | every PR (required) |
| Security suite | named negative cases (see phase bullets); grows with every finding | `api/tests/security/` | every PR (required) |
| Contract | discovery document vs registered routes; generated TS client vs live OpenAPI; SCIM schema | `api/tests/contract/`, `ui/` | every PR (required) |
| Migration | apply all migrations to seeded snapshot; constraints, indexes, row counts; downgrade not supported (documented) | `api/tests/migrations/` | every PR (required) |
| UI e2e | Playwright against docker-compose stack (Mailpit for email, CDP virtual authenticator for passkeys); axe-core a11y on every page | `ui/e2e/` | every PR (required) |
| Conformance | OpenID Foundation conformance suite (Docker): basic OP, config, PKCE, RP-initiated logout, back-channel logout, DCR, FAPI2 (post-v1) | `.github/workflows/conformance.yml` | **every PR (required)**; full profile matrix nightly |
| Fuzz | cargo-fuzz: authorize params, JWT decode, redirect_uri matcher, PKCE, SCIM filter parser | `api/fuzz/` | **every PR, 60 s per target (required)**; 4 h per target weekly |
| Load | k6 scripts with documented baseline (target 5k token req/s per node, p99 < 50 ms `/token`) | `perf/` | **every PR smoke with thresholds (required)**; full baseline on release |
| Packaging | Helm lint + kind smoke deploy; image boots, migrates, `/readyz`; upgrade from previous tag | `.github/workflows/ci.yml` | **every PR (required)**; upgrade-from-tag on release |
| Coverage | cargo-llvm-cov; floor 80% on `services/`, `oidc/`, `flows/`, `middleware/`; PR fails if below floor | CI | every PR (required) |
| Static | clippy `-D warnings`, `cargo audit`, `cargo deny`, ESLint, `tsc --noEmit` | CI | every PR (required) |

Required status checks on `main` (branch protection): `unit`, `integration`, `isolation`, `security`, `contract`, `migration`, `ui-e2e`, `conformance`, `fuzz-smoke`, `load-smoke`, `packaging`, `coverage`, `static`. Adding a suite means adding it to this list and to branch protection in the same PR.

Conventions
- Integration tests use one shared Postgres/Redis container per test binary; each test creates its own tenant slug so tests run in parallel without interference.
- Every security finding (review, fuzz, conformance, external report) gets a regression test in `api/tests/security/` before the fix is merged.
- Playwright runs against the embedded-UI build so e2e covers the same artifact that ships.
- Mock senders capture messages in memory; tests assert on captured content (links, codes) rather than sleeping or polling.

## 7. Public API surface (v1)

OIDC (per tenant, prefix `/t/{slug}`):
`/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/authorize`, `/par`, `/token`, `/userinfo`, `/introspect`, `/revoke`, `/end_session`, `/device_authorization`, `/register` (DCR) + `/register/{client_id}`, `/broker/{alias}/start|callback`, `/backchannel_logout` (RP side handled by clients).
Global: `/.well-known/webfinger`.

Flows (per tenant): `/flows/{id}`, `/flows/{id}/{step}` (password, passkey, magic-link, email-otp, sms-otp, mfa/{type}, profile, terms, consent, org), `/flows/{id}/cancel`, `/register/*`, `/invitations/{token}`, `/recovery/*`, `/verification/*`, `/device/*`.

Account (per tenant, bearer): `/account/me`, `/account/password`, `/account/email`, `/account/phone`, `/account/credentials/*`, `/account/devices/*`, `/account/sessions/*`, `/account/consents/*`, `/account/identities/*`, `/account/tokens/*` (PATs), `/account/export`, `/account/delete`.

Admin (global, bearer): `/admin/tenants/*` and per tenant: `clients`, `users`, `invitations`, `groups`, `roles`, `resource-servers`, `scopes`, `mappers`, `keys`, `idps`, `sessions`, `audit`, `webhooks`, `ip-rules`, `messaging`, `templates`, `settings`, `export`, `import`, `flags`. SCIM: `/scim/v2/{tenant}/Users|Groups`.

Ops: `/healthz`, `/readyz`, `/metrics`, `/docs` (non-prod).

## 8. Non-goals
Anything cloud-provider-specific in the default build (KMS, managed secrets, proprietary queues). Everything else from the earlier non-goals list has been moved into Phases 12–13 with schema room reserved now (`org_id` columns, `identity_providers.type`, `credentials.type`, `KeyEncryptor` trait).

## 9. Open decisions (confirm before Phase 1)
1. axum (recommended) vs actix-web for consistency with tv/api.
2. Tenant in path (`/t/{slug}`, recommended) vs subdomain-only.
3. Per-tenant signing keys (recommended) vs one global key set.
4. v1 cut line: Phases 0–11 are v1 (large). If you want a faster first release, ship v0.1 after Phase 8 and label 9–11 as v0.2.
