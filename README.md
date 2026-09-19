# rIDM

[![ci](https://github.com/ZerosAndOnesLLC/rIDM/actions/workflows/ci.yml/badge.svg)](https://github.com/ZerosAndOnesLLC/rIDM/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A modern, multi-tenant Identity Management server: OpenID Connect provider, JWT issuer,
user/group/role management, MFA, and identity brokering, with a bundled admin console and
end-user account console.

> **Status:** pre-release, under active development. Nothing here is production ready
> until v0.1.0 is tagged. See [`working-plan.md`](working-plan.md) for the roadmap and
> what is done.

**Documentation:** <https://zerosandonesllc.github.io/rIDM/> — concepts, quickstarts,
the admin guide, the API reference, deployment and migration from Keycloak or Auth0.
The source is in [`docs/`](docs/); this README stays the developer's overview.

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
- **One image.** A deployment is the API image plus Postgres and Valkey. The image
  compiles the UI's static export into the server, which serves the sign-in pages and
  both consoles on its own origin; the same export can also go on any static host or
  CDN.
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
dynamic client registration and management (`settings.dcr`: `mode` — including
`initial_access_token`, which demands a token an administrator issued (see the admin
API) — `allowed_grants`, and `require_pkce`, on by default, which decides whether a dynamically registered
confidential client must send a code challenge; public clients always must). Globally:
WebFinger issuer discovery.

Browser login is a flow API (`/flows/{id}/...`) that the UI drives step by step:
password, magic link, email and SMS one-time codes, self-registration with
schema-driven profiles and email verification, invitations, password reset and
forced password change, a second factor, profile completion, terms acceptance,
consent. Flows are CSRF-bound, rate-limited per user and per IP, and demand a CAPTCHA (Turnstile or
hCaptcha) after repeated failures. Email and SMS go through per-tenant SMTP or webhook
settings with localized templates and a retrying outbound queue.

Browser sessions honour the tenant session policy: idle and absolute timeouts, a cap
on concurrent sessions per user (oldest revoked first), and "remember this device",
which registers a trusted device only once the whole flow (including any second
factor) has completed. Sessions are mirrored to Postgres for listing, sign-out
everywhere and audit. `/authorize` honours `prompt` (`none`, `login`, `consent`,
`create`, `select_account`), `max_age` and `acr_values`.

The session and trusted-device cookies are named per tenant and always carry
`Path=/`: `__Host-ridm_session_{slug}` and `__Host-ridm_device_{slug}` when cookies are
`Secure`, `ridm_session_{slug}` and `ridm_device_{slug}` over plain http (local
development, `COOKIE_SECURE=false`). Both are `HttpOnly` and `SameSite=Lax`, and
sessions work the same on a tenant's custom domain. Upgrading from a build that used
the older path-scoped names signs everyone out once and forgets remembered devices
once.

A live session is re-checked at `/authorize` (and when a device code is approved)
against the tenant's MFA policy as it stands now and against a pending forced password
change: a session that no longer satisfies either is sent back to that stage of the
flow (`prompt=none` answers `login_required`), and the session of a disabled or
deleted user gets no code. Ending a session revokes its refresh tokens (offline ones
included), and a code whose session was signed out before it was exchanged is refused.
Every way a session ends — the user signing out one or all sessions, an administrator
revoking one or all, a password change with "sign out other sessions", an admin
password reset with `revoke_sessions`, a recovery password reset (which signs out
everywhere), disabling or deleting the user (SCIM included) and eviction by the
concurrent-session cap — sends back-channel logout to the clients that registered for
it, and front-channel logout where a browser is present.

Two-step verification (`/flows/{id}/mfa/...`) uses an authenticator app (TOTP, RFC
6238: SHA-1, six digits, 30-second steps, one step of drift either side, every code
accepted once). The tenant `mfa` policy decides who is asked: `required` asks
everyone and enrols a second step on the first sign-in, `optional` asks users who
enrolled one, `required_for_roles` asks holders of any listed role (directly, through
a group or a composite) and `required_for_admins` asks anyone holding an admin-console
permission, both treating everyone else as `optional`; `off` never asks. A trusted
device skips the policy-driven check. A client step-up is a requested `acr_values`
class ending in `:mfa` (rIDM's own is `urn:ridm:acr:mfa`): it is always honoured, even
on a trusted device, and a live session that only lacks that class is sent straight to
the second factor (no password again; `prompt=none` answers `login_required`). Other
requested classes are voluntary, so the token carries the class the session actually
holds. Sessions and tokens say how the user signed in: `amr` lists the methods (`pwd`,
`otp`, `sms`, `hwk`, `user`, plus `mfa` once a second factor passed) and `acr` is
`urn:ridm:acr:single` for a single-factor session and, once a second factor passed,
the `:mfa` class the client asked for or `urn:ridm:acr:mfa`. Enrolment
returns a set of ten single-use recovery codes, shown once; any of them replaces the
app for one sign-in and the user is told how many remain. Secrets are encrypted per
row under the master key, recovery codes are hashed then encrypted, and the session
records `amr` (`otp`, `mfa`) and `acr` (`urn:ridm:acr:mfa`, or the class the client
asked for) so tokens say how the user signed in.

Passkeys (WebAuthn) serve both as a passwordless sign-in and as a second step. With
the tenant's `auth.passkey` option on, the login page offers "Sign in with a passkey":
`POST /flows/{id}/passkey/start` issues a discoverable-credential challenge and
`/passkey/finish` verifies the assertion, finds the credential by the id the
authenticator presented, checks that the user handle names its owner, and opens the
session. User verification is required, so a passkey sign-in is two factors already
(`amr` `hwk`, `user`, `mfa`) and no second step follows. At the `mfa` stage a user
enrols a passkey (`/mfa/passkey/register` then `/register/finish`, with a label,
existing keys excluded; the first second factor also issues the recovery codes) or
verifies with one (`/mfa/passkey/start` then `/finish`). The relying party id is the
UI's host (or the tenant's custom domain); the API's own origin is accepted when it
shares that host. Each passkey is one encrypted `webauthn` credential row (public key,
sign counter and backup flags, the counter checked on every assertion), and
challenges live in Valkey for five minutes, bound to the flow and spent by the first
answer.

Codes by email and by text message are second factors too. The tenant's
`settings.mfa_methods` (`totp`, `email_otp`, `sms_otp`; passkeys follow `auth.passkey`)
decides which methods the `mfa` stage offers, and the flow state lists them under
`mfa.methods`. Enrolment proves the channel: `POST /flows/{id}/mfa/email/enroll` sends a
code to the account's address and `/mfa/email/confirm` checks it (the address is then
verified); `/mfa/sms/enroll` takes a `phone` in E.164 when the account has none (or to
change it) and `/mfa/sms/confirm` saves the number verified. Each enrolled channel is one
`email_otp` or `sms_otp` credential row, and the first second factor issues the recovery
codes. Later sign-ins call `/mfa/{email|sms}/send` (a code to the account's current,
verified address or number; a repeat within twenty seconds reuses the pending code
instead of sending twice, and sends are limited to three per ten minutes per user) and
`/mfa/{email|sms}/verify`. Codes are six digits, hashed in Valkey, bound to the flow,
single-use, good for ten minutes and five attempts; a passed code records `amr` `otp`
(plus `sms` for a text message). Removing a user's last second factor, by the user or
an administrator, also removes their recovery codes.

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
address), and MFA changes (an authenticator added, a recovery code used). Each notice can be switched off per
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

The same admin API is driven from a terminal by `ridm`, a second binary in this
repository: profiles and a login of its own, tenant configuration as code (export,
diff, import), key and master-key rotation, and user and client creation. See
[Command-line administration](#command-line-administration-ridm).

## Quick start (docker-compose)

```bash
export MASTER_KEY=$(openssl rand -hex 32)      # keep this safe; it encrypts secrets at rest
docker compose -f deploy/docker-compose.yml --profile dev up -d
curl http://localhost:8080/readyz
```

The `dev` profile adds [Mailpit](http://localhost:8025) to catch outbound email and, on
first run, seeds a global administrator in the `master` tenant (`admin@ridm.local` /
`ChangeMe-Now-1234` unless `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` say
otherwise; the password must be changed at first sign-in; the image serves the admin
console at <http://localhost:8080/console/>) and the public SPA client
`sample-spa` in `master` (PKCE, redirect `http://localhost:3000/callback`, post-logout
`http://localhost:3000/`, CORS origin `http://localhost:3000`). Use `--profile prod`
for a stack without those extras. With `-f deploy/docker-compose.yml`, compose reads
its `.env` from `deploy/`; to use the repository's `.env` pass `--env-file .env`. Ports are overridable with
`RIDM_HTTP_PORT`, `RIDM_PG_PORT`, `RIDM_VALKEY_PORT`, `RIDM_MAILPIT_UI_PORT`.

## Configuration

Entirely environment-driven; the same image runs everywhere. Every variable is documented
in [`.env.example`](.env.example). The essentials:

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | Postgres 16+ connection string; use a **non-superuser, DML-only** role (superusers bypass row level security, owners can disable it) |
| `REDIS_URL` | Valkey 9+ or Redis 8+: `redis://`, `redis+cluster://h1,h2`, or `redis+sentinel://s1,s2/<master>` (see [topologies](#valkey-topologies-and-postgres-read-replicas)) |
| `DATABASE_READ_URL` | Optional read replica for listings and statistics |
| `DB_POOL_MIN`, `DB_POOL_MAX`, `REDIS_POOL_MAX` | Connection pool sizes per node (2, 20, 32) |
| `PUBLIC_URL` | Externally visible base URL; tenant issuers are `{PUBLIC_URL}/t/{slug}` |
| `MASTER_KEY` / `MASTER_KEY_FILE` | 32-byte key (hex or base64) encrypting secrets at rest |
| `BIND_ADDR` | Listen address, default `0.0.0.0:8080` |
| `TRUSTED_PROXIES` | CIDRs whose `X-Forwarded-For` / `Forwarded` headers are honoured |
| `OUTBOUND_ALLOW_NETWORKS` | private CIDRs that requests to tenant-chosen URLs may reach anyway (internal applications); empty = public addresses only |
| `TLS_CERT` / `TLS_KEY` | Native TLS termination; leave unset behind a reverse proxy |
| `MIGRATE_ON_START` | `true`: apply pending migrations at startup (and in `ridm-api bootstrap`) as `DATABASE_URL`'s role, which must then own the schema; an up-to-date database needs nothing. Off (default): startup only warns when migrations are pending; run `ridm-api migrate` as the schema-owner role |
| `LOG_FORMAT`, `RUST_LOG` | `json` or `pretty`; tracing filter |
| `DOCS_ENABLED` | Serve Swagger UI at `/docs` (off in production) |
| `BREACH_CHECK_URL` | Have I Been Pwned compatible range endpoint for the breached-password check (default `https://api.pwnedpasswords.com/range/`; `off` for air-gapped installs) |
| `RATE_LIMITS` | Master switch for request ceilings (default `true`; off only for tests and local experiments) |
| `RATE_LIMIT_IP_PER_MINUTE` | Requests per minute one client address may make to every limited endpoint of every tenant together (default 6000; 0 = off). Per-tenant ceilings are in tenant settings |
| `HSTS_MAX_AGE` | `Strict-Transport-Security` max-age in seconds, sent when `PUBLIC_URL` is https (default two years; 0 = off) |
| `RETENTION_DAYS` | Days the hourly cleanup keeps spent rows (expired tokens and sessions, login attempts, sent messages, finished deliveries; default 30) |
| `METRICS_TOKEN` | Bearer token `GET /metrics` demands; open when unset |
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME` | Export traces (one span per request, see [Observability](#observability)) over OTLP/HTTP to this collector base URL under this service name (`ridm`) |
| `AUDIT_SINK_URL`, `AUDIT_SINK_TOKEN` | Ship every audit row to an HTTP endpoint (JSON batches, optional bearer) or a syslog receiver (`syslog://`, `syslog+tcp://`) |

Health probes: `GET /healthz` (liveness) and `GET /readyz` (database + cache); `GET /metrics` for Prometheus (see [Observability](#observability)).
`ridm-api --healthcheck` probes `/healthz` itself for images without curl: it dials
`BIND_ADDR` (an unspecified `0.0.0.0` or `::` becomes loopback) and, when `TLS_CERT` is
set, speaks HTTPS trusting exactly that certificate.
`GET /.well-known/security.txt` serves the vulnerability disclosure policy.

### SCIM provisioning

Each tenant exposes a SCIM 2.0 server (RFC 7643/7644) at `{PUBLIC_URL}/scim/v2/{slug}`:
`ServiceProviderConfig`, `ResourceTypes`, `Schemas`, and `Users` and `Groups` with
GET (filter, `startIndex`, `count`), POST, PUT, PATCH and DELETE, all as
`application/scim+json` with SCIM error documents (`scimType`: `invalidFilter`,
`invalidSyntax`, `invalidPath`, `invalidValue`, `noTarget`, `uniqueness`, `tooMany`). A provisioning
system authenticates with a bearer token minted for the tenant (console: Provisioning;
API: `/admin/tenants/{slug}/scim/tokens` under `ridm:scim:read`/`write`, which user
managers hold): `rscim_` tokens are shown once, stored hashed, optionally expiring,
revocable, and confined to their tenant. Changes are attributed to the token in the
audit log.

A SCIM User maps onto a user: `userName` ↔ username, `externalId` ↔ the new
`external_id` column (unique per tenant), the primary `emails` entry ↔ email, the first
`phoneNumbers` entry ↔ phone, `active` ↔ active/disabled, `locale` ↔ locale, and
`name.givenName`, `name.familyName` and `displayName` ↔ the profile attributes
`given_name`, `family_name` and `display_name` when the profile schema declares them
(or allows undeclared attributes); `groups` is read-only. A SCIM Group maps onto a
group: `displayName` ↔ name, `externalId` ↔ `attributes.externalId`, `members` ↔
memberships (users). Deleting a user through SCIM soft-deletes it like the admin API,
and deactivating or deleting one ends their sessions with back-channel logout. A
provisioning token cannot grant administration: adding members to a group that carries
admin (`ridm:*`) permissions is refused with `403`. Provisioning may set profile
attributes declared `editable_by: none`, as bulk import may; interactive admin edits
still cannot.

Filters follow the RFC grammar (`eq ne co sw ew gt ge lt le pr`, `and`/`or`/`not`,
parentheses, dotted and `attr[filter].sub` paths, schema-URN prefixes, case-insensitive
attribute names and string comparisons). A user filter that is one equality on
`userName`, `externalId`, `emails`/`emails.value` or `id` (possibly `and`-ed with more
conditions) is answered from the index; any other user filter is evaluated over the
tenant's users up to 2,000 rows and refused beyond that with `tooMany`, so provisioning
systems should look users up by those attributes (they do). Group filters run over all
groups. `count` is clamped to 200 and `startIndex` beyond 2,000 is refused.

PATCH applies RFC 7644 `add`, `replace` and `remove` operations to the resource's SCIM
document — with or without `path`, simple and dotted paths, filtered multi-valued paths
such as `emails[type eq "work"].value` and `members[value eq "<id>"]`, `"True"`/`"False"`
strings for booleans — and stores the result as a full replace, so PATCH and PUT share
one path.

### Token exchange and DPoP

**Token exchange (RFC 8693)**, `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
at `/token`, lets a client allowed that grant trade an access token of the tenant
(`subject_token`, type `access_token` — a JWT or an opaque `at_…` token — or `jwt`)
for one aimed at other audiences
(`audience` and `resource`, resolved like every other audience request) and optionally
narrowed in `scope` (never widened, never beyond the client's own scopes). The new token
keeps the subject, session, `amr` and `acr`, never outlives the subject token, comes
without a refresh token and reports `issued_token_type`. With an `actor_token` the
result is a delegation: `act` names the acting party (`sub`, `client_id`) and nests
the previous `act` on re-exchange. Revoked, expired or foreign subject tokens are
`invalid_grant`; unsupported token types `invalid_request`.

**DPoP (RFC 9449)** sender-constrains tokens to a client-held key. A `DPoP` header on a
token request — a `dpop+jwt` signed with the embedded public key, naming the method,
the URL, a fresh `jti` and `iat` — binds every token of the response to the key's
thumbprint: the access token carries `cnf.jkt`, `token_type` is `DPoP`, introspection
reports both, and a public client's refresh token is bound too (a later refresh needs
a proof from the same key, and a wrong key leaves the token unspent). Proofs are
one-time within a five-minute window (replays are refused), may be no more than five
minutes old or thirty seconds in the future, must match the request method and URL
(query ignored; the custom domain and the `/t/{slug}` form both count), and at
resources must carry `ath`, the hash of the very token. A bound token presented as a
plain bearer token, without a proof or with another key's proof is refused with a
`DPoP` challenge (`WWW-Authenticate: DPoP algs=...`) by `/userinfo`, the account API
and the admin API. Clients registered with `dpop_bound_access_tokens` (console: client
detail, or the DCR metadata field) must always present a proof. Server-provided nonces
and `dpop_jkt` at `/authorize` are not implemented.

### Performance

The token path touches the database as little as possible: clients, tenants, signing
keys, scopes and claim mappers are read through the two-level cache (in-process plus
Valkey, evicted on every write); a user's effective roles and groups and the permissions
a role set holds on a resource server are cached under the tenant's roles version
(any role, group, membership, grant or permission change moves it); resource servers are
cached by identifier and evicted when written. Discovery and JWKS documents are cached
whole with an `ETag` and `Cache-Control: max-age=300`, and answer `304` to
`If-None-Match`. The JWKS document hangs off a per-tenant keys version that every key
change moves, so a document read before a key was written is never served after it, and
a tenant's first key is generated by one node while the others wait for it (one active
key per tenant and algorithm, enforced by a partial unique index): what a token is
signed with is always in the set the server publishes. Every hot query runs on an index
(reviewed with `EXPLAIN ANALYZE` in Phase 9.10). Pool sizes: `DB_POOL_MAX` (default 20; roughly twice the CPU count of the
database server divided by the number of API nodes) and `REDIS_POOL_MAX` (default 32).

Load tests live in [`perf/`](perf/README.md): a k6 script for `/token` and the
discovery documents with a PR smoke (thresholds on a debug build, the `load-smoke`
check) and a release baseline targeting 5,000 token requests per second per node.

### Token claims

An ID token carries the authentication context (`auth_time`, `amr`, and an `acr` that is
`urn:ridm:acr:single` or `urn:ridm:acr:mfa`, both named in
`acr_values_supported`) and the tenant's id as `tid`, which a relying party serving
several tenants of one deployment keys on. What a scope releases is its `claims` list,
standard scopes included (the `profile`, `email`, `address` and `phone` scopes are
seeded with the OIDC Core §5.4 claims, and an administrator may change them); the
released claims are read from `/userinfo`, since an access token is always issued
alongside, and a client that would rather have them in the ID token too sets
`id_token_scope_claims`. Profile attributes whose schema entry lists `visible_in`
(`id_token`, `userinfo`, `access_token`) appear there under the attribute's name; they
never overwrite a scope-released or protected claim, and a claim mapper may override
them. An ID token minted from a refresh token repeats the
original `auth_time`, `amr` and `acr` (OIDC Core §12.2), which the token family stores.
Replaying an authorization code revokes everything the first exchange produced: the
refresh family and the access token, which is a JWT and stops through the `jti` denylist
(RFC 6749 §4.1.2).

A request that names no `scope` gets the tenant's default scopes (`is_default`) that
the client may hold, at `/authorize`, at device authorization and on
`client_credentials` (there without `openid` and `offline_access`). A scope bound to a
resource server (`resource_server_id`) adds that server to the token's audiences; a
client that may not target the server gets `invalid_scope`, and a bound scope is left
out of any token that lacks its audience.

**Access token format.** Access tokens are JWTs (`typ` `at+jwt`) unless the client is
registered with `access_token_format: opaque`: it then receives an `at_…` reference
whose claims are kept in Valkey until it expires (a Valkey loss ends them early, as it
ends SSO sessions). Opaque tokens are accepted by `/userinfo`, `/introspect`, `/revoke`,
token exchange (as type `access_token`), and the account and admin APIs; a resource
server has to call `/introspect` for them, since `ridm-auth` and any other JWT validator
cannot read them. The built-in console clients refuse the opaque format, and
introspection refuses ID tokens.

**Signing algorithm.** A resource server may name the algorithm its tokens are signed
with (`signing_alg`: `RS256`, `RS384`, `RS512`, `ES256` or `EdDSA`); saving it makes sure
the tenant holds an active key of that algorithm, the scheduled rotation rotates every
algorithm in use, and a request for several audiences that disagree on the algorithm is
`invalid_target` (request them separately). Otherwise the tenant key policy decides.

**Refresh tokens.** Without `offline_access` a refresh token is bound to the SSO session
it came from: it stops working when that session ends (sign-out, idle or absolute
timeout), and each refresh counts as activity that extends the idle window. With
`offline_access` it outlives the session's timeouts, though an explicit sign-out or a
revoked session still revokes it. `offline_access` is granted only when every resource
server among the audiences has `allow_offline_access`, and silently dropped otherwise;
device-flow clients that need long-lived tokens should request it. On a refresh (and on
code exchange) `resource` may only narrow to audiences of the original grant
(`invalid_target` otherwise), and a `scope` the grant did not include is
`invalid_scope`, answered before the refresh token is spent, so it stays usable.

`acr_values` is a preference list: rIDM honours the first class it recognises, so a
request naming `urn:ridm:acr:mfa` first demands a second factor while one that accepts
`urn:ridm:acr:single` first does not. The `claims` request parameter is not implemented,
which discovery states.

Token exchange needs an explicit entitlement. On every other grant an empty
`allowed_audiences` means "no restriction" (a request with no `resource` then gets the
client's `allowed_audiences`, plus the servers of any bound scopes, and the client
itself as audience only when there are none), because the client acts for a user who
authorized it; a subject token presented for exchange may have been minted for someone
else, so a client may only exchange for audiences it lists. A subject token carrying
`cnf.jkt` can only be exchanged by a request that proves the same key, so exchange
cannot strip a sender-constrained binding.

### OpenID conformance

The OpenID Foundation conformance suite runs against rIDM from
[`conformance/`](conformance/README.md): the suite's released images behind its own
nginx, rIDM behind a Caddy TLS front as `https://ridm.local` (a private CA the suite
trusts), and a headless Chromium driver that signs in, approves consent and confirms
logout for every browser step the tests leave pending. The `conformance` workflow runs
the configuration, basic (discovery + dynamic registration), RP-initiated, back-channel
and front-channel logout certification plans on every pull request and weekly, fails on
any finding not listed in `conformance/expected-failures.json`, and uploads the suite's
exported logs as an artifact.

### Valkey topologies and Postgres read replicas

`REDIS_URL` picks the cache topology: `redis://host:6379` (one server, also
`rediss://`), `redis+cluster://host1:7000,host2:7001` (a cluster: keys need no hash
tags, because writes and scripts touch one key at a time and the one multi-key read,
the `MGET` behind a user's session list, is split by slot in the cluster client), or
`redis+sentinel://sentinel1:26379,sentinel2:26379/mymaster` (Sentinel-managed
replication; the pool follows the current master and the cache-invalidation subscriber
re-resolves it on reconnect). Credentials go before an `@` and apply to every host.

`DATABASE_READ_URL` names a Postgres read replica. When set, listings and statistics
(users, clients, groups, roles, invitations, webhook deliveries, the audit log, the
overview) run there inside read-only transactions (a write routed by mistake fails);
everything else, and every read that feeds a decision, stays on the primary. A listing
may trail a change by the replica's lag. Unset, the same pool serves both.

### Observability

`GET /metrics` exposes Prometheus metrics (`text/plain; version=0.0.4`), open by default
and behind `Authorization: Bearer <METRICS_TOKEN>` when that variable is set:

| Metric | Labels | Meaning |
|--------|--------|---------|
| `ridm_http_requests_total`, `ridm_http_request_duration_seconds` | `method`, `route` (the matched pattern), `status` | every request, by route |
| `ridm_token_requests_total` | `grant`, `outcome` (`issued` or the OAuth error) | `/token` grants |
| `ridm_logins_total` | `method` (`password`, `webauthn`, `mfa`, ...), `outcome` (`success`, `invalid_credentials`, `locked`, `disabled`) | first-factor sign-ins |
| `ridm_sessions_created_total` | | browser sessions opened |
| `ridm_rate_limit_rejections_total`, `ridm_ip_rule_rejections_total{scope}` | | requests refused by the guard |
| `ridm_webhook_deliveries_total{outcome}`, `ridm_webhook_deliveries_pending`, `ridm_messages_queued` | | delivery outcomes and queue depths (gauges refreshed by the delivery jobs) |
| `ridm_job_runs_total{job,outcome}`, `ridm_job_duration_seconds{job}`, `ridm_cleanup_rows_total{table}` | | background jobs |
| `ridm_audit_events_total`, `ridm_audit_sink_rows_total`, `ridm_audit_sink_failures_total`, `ridm_audit_sink_dropped_total` | | the audit writer and its export sink |

Traces: set `OTEL_EXPORTER_OTLP_ENDPOINT` (the collector's base URL, e.g.
`http://otel-collector:4318`) and every request is exported over OTLP/HTTP (protobuf)
under `OTEL_SERVICE_NAME` (default `ridm`) as one INFO server span named
`METHOD /route/{template}` (the matched route, never the concrete path or query, which
can carry codes and invitation tokens) with `http.request.method`, `http.route` and
`http.response.status_code`, plus whatever spans inside it `RUST_LOG` enables; unset, no
exporter runs. Logs are JSON (`LOG_FORMAT=json`) with the current span's fields; at the
default `info` level log lines do not repeat the request span (it shows from `debug`).

Audit export: set `AUDIT_SINK_URL` and every audit row (as stored, with its chain
sequence and hash) is also shipped: to `https://…` as JSON arrays of up to 100 rows
(within a second of the first), with `Authorization: Bearer <AUDIT_SINK_TOKEN>` when
set, in up to three attempts with backoff; or to `syslog://host:514` (UDP) /
`syslog+tcp://host:514` as one RFC 5424 message per row (`<134>1 <time> <host> ridm -
<event name> - <json>`). The sink never slows the writer: a bounded queue drops rows
when the destination falls behind and counts them.

### Background jobs

An in-process scheduler runs every job on its interval with jitter, and each pass takes
a Valkey leader lock (`ridm:lock:<job>`, compare-and-delete release), so a job runs on
one node at a time however many nodes there are; a node that does not get the lock
skips the pass. Every pass is counted and timed (`ridm_job_runs_total`,
`ridm_job_duration_seconds`) and its outcome stored as the job's last run in Valkey
(`ridm:jobs:last_run`, read by `jobs::status::all`).

| Job | Every | What it does |
|-----|-------|--------------|
| `key_rotation` | 1 h | rotates and retires signing keys per the tenant key policy |
| `audit_retention` | 24 h | creates upcoming audit partitions (through `audit_ensure_partitions`, see below), drops expired chain prefixes; a failure to create partitions does not stop the purge |
| `user_purge` | 24 h | hard-deletes soft-deleted users past the tenant's retention |
| `webhook_delivery` | 30 s | retries webhook deliveries whose backoff elapsed (prompt delivery happens on the event) |
| `message_delivery` | 30 s | sends queued and retrying email/SMS |
| `cleanup` | 1 h | deletes spent rows older than `RETENTION_DAYS` (default 30): expired, revoked or consumed refresh tokens; ended sessions (kept a week at most); login attempts; sent or dead messages; delivered or dead webhook deliveries; device-code audit rows; expired, accepted or revoked invitations; expired or revoked trusted devices, personal access tokens and provisioning tokens — in batches of 5,000 rows |

The two delivery jobs find the tenants with due work in one cross-tenant query and visit
only those, so their cost follows the backlog rather than the number of tenants.

### Custom domains

A tenant can be served on its own host: set `settings.custom_domain` (console: Settings →
General → Custom domain) to a hostname such as `login.example.com` (a port is allowed for
development), point the name at rIDM and terminate TLS for it. The tenant's issuer
becomes `https://<host>`, and discovery, JWKS, `/authorize`, `/token`, the flow API and
every other tenant endpoint answer on that host without the `/t/<slug>` prefix (the
prefixed paths keep working and report the same issuer). Requests are matched by the
`Host` header, or `X-Forwarded-Host` from a `TRUSTED_PROXIES` peer; the host is looked up
through the tenant cache and takes effect the moment the setting changes. Domains are
validated, lower-cased, unique across tenants and may not be the deployment's own hosts.
When the server serves the embedded UI, the tenant's sign-in pages and account console
are served on that host too, and every redirect and emailed link for the tenant's users
(`/authorize` to `/login/`, logout, device, recovery, invitation, verification and
magic links) points there, so the session the pages set belongs to the host `/authorize`
answers on; the built-in account console client accepts the host's callback. With the UI
hosted separately, the pages stay at `UI_URL`.

A custom domain serves its tenant and nothing else. Only `/healthz`, `/readyz`,
`/.well-known/webfinger`, `/.well-known/security.txt`, the tenant's own `/t/{slug}/…`
and `/scim/v2/{slug}/…` paths and, with the embedded UI, a GET of a file of the export
(`/login/`, `/account/`, `/_next/static/…`, but not the admin console or `/`) pass
through as they are; every other path is rewritten
under `/t/{slug}`, so the admin API, `/metrics`, `/docs`, `/openapi.json` and other
tenants' paths answer `404` there. Session cookies are `Path=/` and named per tenant, so
sign-in works on the custom domain as on the primary host.

### Outbound requests

URLs that tenant administrators or client registrations choose — webhook targets,
back-channel logout URIs, client `jwks_uri`s, identity provider endpoints, a tenant's
HTTP email and SMS gateways, the CAPTCHA `verify_url` and a tenant's SMTP host — are
reached only on public addresses. Names are resolved through a resolver that drops
private, loopback, link-local, carrier-grade NAT, unique-local, documentation and
other reserved addresses (IPv4-mapped and similar IPv6 forms included) and fails when
none is left, so a name that later resolves inward (DNS rebinding) is refused at
connection time; IP literals are checked before the request is sent. These clients
follow no redirects and ignore `HTTP_PROXY`/`HTTPS_PROXY`. For development, loopback
named as such (`localhost`, `127.0.0.0/8`, `::1`) is allowed, and the operator can open
private networks for internal applications with `OUTBOUND_ALLOW_NETWORKS` (addresses
inside them count as public). A tenant SMTP host that is
a private IP literal is refused when saved; a named one is resolved the same way, the
connection goes to the vetted address (the first allowed one only) and TLS verifies the
configured host name. URLs the operator sets in the environment (`AUDIT_SINK_URL`,
`BREACH_CHECK_URL`, the server-wide SMTP settings) are not filtered.

### Rate limits, browser hardening and cross-origin policy

Every OAuth and sign-in endpoint sits behind a request ceiling counted in fixed
windows in Valkey, so all nodes share one view. Three endpoint families each have a
per-address limit under `settings.rate_limits` (`token_per_ip` for `/token`,
`/introspect`, `/revoke`, `/userinfo` and `/device_authorization`; `authorize_per_ip`
for `/authorize`, `/par` and dynamic registration; `flows_per_ip` for the flow API,
recovery, verification, invitations, device verification and brokering), the token
family also has `token_per_client` (counted once the client is known and before its
secret is checked, so guessing a secret is bounded), `tenant_total` caps everything
together, and the deployment-wide `RATE_LIMIT_IP_PER_MINUTE` applies on top across
tenants. Every limited response carries `RateLimit-Limit`, `RateLimit-Remaining` and
`RateLimit-Reset` for the tightest bucket; a refused request is `429` with
`Retry-After`, as `{"error": "slow_down"}` on OAuth endpoints, `application/problem+json`
on the flow API, and a plain HTML page on browser navigations (`/authorize`,
brokering). The client address is the TCP peer, or, when the peer is in
`TRUSTED_PROXIES`, the forwarded chain read from the right: entries that are themselves
trusted proxies are skipped and the first one that is not is the client
(`X-Forwarded-For`, else the `for=` elements of `Forwarded`), so a caller cannot choose
its own address through an appending proxy. Valkey being unreachable
fails open with a warning. The admin console edits the policy under Settings → Rate
limits; the defaults (per minute: 600 token, 1200 per client, 300 authorize, 600 flow,
no tenant total) are meant for a busy office behind one NAT address.

#### IP rules

IP rules (`/admin/tenants/{slug}/ip-rules`, console `/console/ip-rules/`) form two scopes:
tenant-wide and per client. Within a scope the most specific matching network decides;
an address matching no rule passes unless the scope holds any `allow` rule, in which
case the scope is an allow list and everything else is refused. Both scopes must pass.
The tenant scope is checked by the request guard on the same endpoint families the
rate limits cover, before anything else runs; the client scope once the client is known,
at `/authorize` (a page, never a redirect to the client) and at every
client-authenticated endpoint (`access_denied`, before the secret is examined). The flow
API answers `403` as `application/problem+json`. Rules are cached per tenant and take
effect the moment they change; if the rules cannot be read the request is refused, not
waved through. The address is resolved like the rate limiter's, so behind a proxy set
`TRUSTED_PROXIES` or every client appears as the proxy.

Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer` and a `Content-Security-Policy` that lets nothing load
from or frame an API response (`frame-ancestors 'none'` alone under `/docs`, which
needs its scripts), plus `Strict-Transport-Security` when `PUBLIC_URL` is https. The
UI's static export carries its own hash-based policy (see [UI](#ui)).

Cross-origin requests are admitted by one rule set: the UI's and the API's own origins
may call everything (the consoles and the sign-in pages run there, with cookies);
discovery, JWKS, WebFinger and branding answer any origin; under `/t/{slug}/` the
tenant's custom domain and any origin registered in `cors_origins` on one of the
tenant's active clients are admitted (the
union is cached per tenant and evicted on every client change); everything else gets no
CORS headers. Because a preflight cannot say which client a `/token` call is for, the
client-authenticated endpoints check again once the client is known: a browser `Origin`
that is neither the UI's, the API's nor registered on that very client is refused with
`invalid_request` even though the tenant admits it. Server-side clients send no
`Origin` and are never checked.

## Development

[`GETTING-STARTED.md`](GETTING-STARTED.md) is the short path from nothing to a running
server, an admin console, a demo tenant and the three example applications, with every
local URL and credential in one place. What follows is the reference.

Requirements: Rust 1.98+ (pinned in `rust-toolchain.toml`), Node.js 24 LTS, Docker,
`sqlx-cli`.

```bash
cp .env.example .env                           # set MASTER_KEY and the URLs
docker compose --env-file .env -f deploy/docker-compose.yml up -d postgres valkey
DATABASE_URL=postgres://ridm_migrator:ridm_migrator@localhost:5432/ridm \
  sqlx migrate run --source api/migrations     # or: cargo run -p ridm-api -- migrate
cargo run -p ridm-api                          # runs as the DML-only ridm_app role
```

`--env-file .env` is needed because compose otherwise looks for `deploy/.env`, and the
compose file refuses to start without `MASTER_KEY`.

**`make` shortcuts.** The `Makefile` wraps the commands above and the ones that follow;
`make` alone lists them. It reads ports and URLs from `.env` and needs nothing beyond
Docker, cargo and npm (`make watch` also wants `watchexec`).

```bash
make setup        # Postgres, Valkey and Mailpit; migrations; first admin; a token
make api          # the API from source           (or: make watch, restarting on change)
make ui           # the UI with hot reload, :3110 (API_PROXY to the API)
make seed         # the demo and acme tenants, below
make lint test    # rustfmt, clippy, UI lint and types; unit tests
```

`make token` runs `ridm bootstrap --issue-token`: it creates the first global
administrator if there is none and mints a 30-day personal access token for it straight
through the database into `target/dev/token` (mode 0600), so a fresh stack can be
scripted without a browser (`make token ADMIN=<username>` when the owner is not
`admin`). `make seed` then loads two tenants through the admin API: **`demo`**, the one
the [example applications](#example-relying-parties) use, and **`acme`**
([`dev/acme-tenant.json`](dev/acme-tenant.json)), a tenant for working on the consoles —
a profile schema, a group tree whose groups carry roles, one client of each type and
120 users spread across the groups, some disabled or unverified (`ACME_USERS=500 make
seed` for more). Both are re-runnable.

**Hot reload.** `make ui` runs `next dev`, which reloads pages as they are edited. The
API is a compiled binary: `make watch` restarts it when Rust, SQL or TOML under `api/`
or `crates/` changes. A restart does not apply a new migration (`make migrate` does, as
the schema owner), and it drops every in-memory cache, which is harmless because each
reads through Valkey. Debug builds compile RSA key generation and argon2 hashing with
optimisations (`[profile.dev.package.*]` in `Cargo.toml`), so creating a tenant or
signing in is not the slow part of a dev loop. All outgoing mail lands in Mailpit
(`make mail` prints its address); the API sends there when `.env` has
`SMTP_HOST=localhost`, `SMTP_PORT=1025` and `SMTP_SECURITY=none`.

Two database roles are used on purpose: `ridm_migrator` owns the schema and runs
migrations; `ridm_app` (what the API uses) has DML privileges only. Postgres superusers
bypass row level security and table owners can disable it, so neither may be the API's
role. The compose stack creates both and runs migrations in a one-shot `migrate`
service; on Kubernetes use a Job. With `MIGRATE_ON_START` off (the default) the API
only warns at startup when migrations are pending. `MIGRATE_ON_START=true` is a
simpler single-role mode for small installs: pending migrations are applied at startup
as `DATABASE_URL`'s role, and an up-to-date database needs no schema rights.

### Self-service account API

The account console at `/account/` is an OIDC public client of the user's own tenant,
`ridm-account-console` (PKCE, built in like the admin console's client, following
`UI_URL`, undeletable and left out of exports), whose tokens carry the built-in
`urn:ridm:account` audience and reach only the self-service API under
`/t/{slug}/account/`. A token may only act on its own subject and only in the tenant
that issued it, and its SSO session must still be alive. The routes:

| Route | What it does |
|-------|--------------|
| `GET me` | identity plus the session's `auth_time`, `acr` and `amr` |
| `GET/PATCH profile` | the profile by the tenant's schema: declared attributes with their values, which of them the user may edit (`editable_by: user`; the rest are kept as they are), the locale (one the tenant supports), pending contact changes |
| `GET/PUT password` | the password's state and policy; a change needs the current password while one is set and can end every other session (`sign_out_others`, with back-channel logout) |
| `POST email/change`, `POST email/confirm`, `DELETE email/change` | a six-digit code goes to the new address and the right code moves the account over, verified; the previous address is told; an address another account uses is a `409` |
| `POST phone/change`, `POST phone/confirm`, `DELETE phone/change`, `DELETE phone` | the same by text message; the number cannot be removed while it backs an SMS second step |
| `GET mfa`, `POST mfa/totp/enroll\|confirm`, `mfa/passkey/register[/finish]`, `mfa/{email\|sms}/enroll\|confirm`, `DELETE mfa/credentials/{id}`, `POST mfa/recovery-codes` | second factors and recovery codes (the same services as the login-flow steps, scoped to the SSO session; the recovery codes go with the last factor) |
| `GET devices`, `DELETE devices[/{id}]` | trusted browsers |
| `GET sessions`, `DELETE sessions[/{id}]` | live sessions (the current one first) and ending one or all of them, with their refresh tokens and back-channel logout; `?keep_current=true` keeps this one |
| `GET apps`, `DELETE apps/{client_id}` | applications the user consented to, and withdrawing that consent along with the application's refresh tokens |
| `GET identities`, `POST identities/link`, `DELETE identities/{idp_id}` | the upstream accounts linked to this one and the providers still available; linking hands back a one-time URL the browser takes to the broker and returns from with `?linked=1` or `?link_error=<code>`; unlinking |
| `GET tokens`, `POST tokens`, `DELETE tokens/{token_id}` | personal access tokens: the user's tokens (metadata), the scopes a new one may carry (`account`, plus the admin permissions the user holds), the tenant's maximum lifetime; minting answers with the token once; revoking |
| `GET export` | everything held about the user as one JSON download: the record, credential metadata, devices, sessions, consents, roles, groups and the audit trail; never any secret material |
| `DELETE me` | delete the account (the username typed again as confirmation): every session, token and device ends now and the row is soft-deleted, so the username and email free up at once; a daily job purges it after `settings.account.deletion_retention_days` (default 30, admin deletions too). `settings.account.self_deletion` switches it off per tenant, and administrators must be removed by another administrator |

Every security change (a factor, a device, a session, the password, a contact
detail, the export, deletion) needs a sign-in from the last fifteen minutes, and one
that passed the second step once the account has one; otherwise the API answers `403`
with the problem type `urn:ridm:error:reauthentication-required` and the page sends
the user back through sign-in (`max_age=0`, plus `acr_values` for the second step) and
returns. Contact-change codes follow the passwordless rules: hashed, single-use, ten
minutes, five attempts, three sends per ten minutes, and a repeat inside twenty seconds
reuses the pending code.

### Personal access tokens

Users mint long-lived bearer tokens (`rpat_…`, shown once, stored as a SHA-256) from the
account console for scripts and integrations. A token carries scopes: `account` admits
it to the self-service account API as the user (without a session, so nothing that
needs a recent sign-in, and a token can never mint another), and admin permission names
admit it to the admin API with exactly those permissions. Scopes must be held by the
user when the token is made and are narrowed at every use to what the user still holds,
so a removed role narrows every token at once; a disabled or locked user's tokens stop
working. `settings.account.personal_tokens` switches minting off per tenant and
`settings.account.personal_token_max_days` (default 365, `0` for no limit) caps and
defaults the lifetime. `last_used_at` is recorded at most once a minute; introspection
answers `token_type: personal_access_token` with the subject, username, scope and
expiry; account deletion revokes what is left. Administrators list and revoke a user's
tokens from the user detail; the tokens themselves are never readable again. Events:
`personal_token.created`, `personal_token.revoked`.

### Device authorization grant

Input-constrained devices (TVs, CLIs, kiosks) sign users in with the device
authorization grant (RFC 8628). A client of type `device` (or any client allowed the
`urn:ietf:params:oauth:grant-type:device_code` grant) posts `client_id` and `scope`
(plus `resource` indicators) to `/t/{slug}/device_authorization` and receives a
`device_code`, a `user_code` (`XXXX-XXXX`, letters that are hard to confuse), the
`verification_uri` (the `/device/` page), `verification_uri_complete`, `expires_in`
(ten minutes) and `interval` (five seconds). The user enters the code on `/device/`;
the API turns it into a login flow for the device's client, so sign-in, second step,
profile completion, terms and consent apply as for any application, and the flow's
finish approves the device code and returns the browser to the device page (`done=1`;
a denial or cancellation returns with `error=access_denied`). The device polls `/token`
with the grant and its `device_code`: `authorization_pending` until the user decides,
`slow_down` when it polls faster than the interval (which then grows by five seconds),
`access_denied`, `expired_token`, then the tokens (an ID token with the session's
`amr`, `acr` and `auth_time`, a refresh token when the client may) exactly once. Wrong
user codes are limited to ten per address per ten minutes. Pending codes live in Valkey;
every code leaves a `device_codes` audit row (pending, approved, denied, consumed).

### Identity brokering

Users may sign in through an upstream OpenID Connect or OAuth 2.0 provider configured per
tenant (`identity_providers`, above). The login page offers every enabled, non-hidden
provider as a "Continue with ..." button that sends the browser to
`GET /t/{slug}/broker/{alias}/start?flow={id}`; rIDM redirects to the provider's
authorization endpoint with a fresh `state` (its record in Valkey remembers the flow),
a `nonce` and a PKCE challenge, and receives the browser back on
`/t/{slug}/broker/{alias}/callback` (GET, or POST for Apple's `form_post`). The code is
redeemed at the token endpoint (`client_secret_basic`, `client_secret_post` or PKCE
alone); an OIDC ID token is verified against the provider's JWK set (cached an hour,
re-fetched once for an unknown `kid`), its issuer (Microsoft's `common` accepts any
directory), audience, expiry and nonce; plain OAuth 2.0 providers are read through
`userinfo` (GitHub's primary verified address through `/user/emails`). The identity is
then resolved: the account linked to that provider and subject signs in (`amr: ["fed"]`);
otherwise the `link_policy` decides — `verified_email` links an existing account whose
address both sides verified, `explicit` never links by email (the user signs in the usual
way and links from the account console), `always_new` always creates an account. When
the address belongs to another account, `verified_email` (unless both sides verified
it) and `explicit` refuse with `broker_error=email_in_use` on the login page, while
`always_new` creates the new account without an email address. A new account takes its username from the mapped claim, else the email, else
`{alias}-{subject}`; mapped attributes are written on every sign-in, and the login flow
then continues like any other first factor (second step, profile completion for required
attributes, terms, consent). Events: `identity_provider.*`, `identity.linked`,
`identity.unlinked`, `login.brokered`. Upstream endpoints must use https (plain http is
accepted for loopback hosts, for development and tests); providers export and import
with the tenant configuration without their secrets.

### Breached-password check

Breached-password check: with `password.check_breached` on, every password a user
or administrator sets (registration, recovery, forced change, admin reset, imports
with a plaintext `password`) is looked up in a Have I Been Pwned compatible range API
by k-anonymity: only the first five hex digits of its SHA-1 leave the server, and the
match happens locally on the padded answer. `BREACH_CHECK_URL` names the endpoint
(default `https://api.pwnedpasswords.com/range/`; `off` disables it deployment-wide
for air-gapped installs, and the tenant toggle is then inert). A refused password is
a validation error on the `password` field; a lookup failure is logged and lets the
password through, so an outage never blocks sign-ups or resets. The checker is a
`BreachChecker` provider, so another corpus can be plugged in.

### Master key rotation

Secrets at rest (signing keys, MFA credentials, identity provider client secrets,
tenant provider settings — SMTP, SMS gateway and CAPTCHA configuration — and webhook
signing secrets) are encrypted with
`MASTER_KEY`, and every ciphertext records the key generation that produced it. To
rotate without downtime:

1. Generate a new key and roll it out to every node as `MASTER_KEY` with
   `MASTER_KEY_VERSION` incremented, keeping the old one in `MASTER_KEY_PREVIOUS`
   (`<old version>=<old key>`). New writes use the new generation; old rows still decrypt.
2. Run `ridm-api rotate-master-key` once (any node, same configuration). It re-encrypts
   every row under the current generation in batches. `--status` shows what remains.
   `ridm master-key status` and `ridm master-key rotate` do the same over the admin API,
   from anywhere that can reach the server.
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
nothing. The username defaults to `admin` (`BOOTSTRAP_ADMIN_USERNAME` from the
environment). The password must satisfy the master tenant's policy, and admins created
from the environment must change it at first login. With `BOOTSTRAP_SAMPLE_CLIENT=true`
(and the admin variables set) startup and `ridm-api bootstrap` also make sure `master`
has the public SPA client `sample-spa` (PKCE, redirect `http://localhost:3000/callback`,
post-logout `http://localhost:3000/`, CORS `http://localhost:3000`); an existing one is
left as it is. `ridm-api bootstrap` migrates only when `MIGRATE_ON_START=true`;
otherwise, with migrations pending, it exits `1` and asks for `ridm-api migrate` first.
`ridm bootstrap` takes the same flags and runs the same code, for operators who have
the CLI rather than the server binary at hand; its `--issue-token NAME [--token-days N]`
also mints a personal access token for the administrator and prints it alone on stdout
(what `make token` uses).

### Validating tokens in your own API (`ridm-auth`)

[`crates/ridm-auth`](crates/ridm-auth/README.md) is the relying-party half, so a Rust
service that accepts rIDM tokens does not have to write JWKS handling of its own. It is
packaged for crates.io but will be published at the first release; until then depend on
it from this repository (`ridm-auth = { git = "https://github.com/ZerosAndOnesLLC/rIDM" }`). It verifies the signature against the tenant's published keys, checks that the
token was meant for *that* API and not another of the same tenant, and answers the
permission question.

```rust
let validator = ridm_auth::Validator::builder("https://idm.example.com/t/acme")
    .audience("https://orders.example")   // the resource server identifier
    .discover()                           // jwks_uri from the discovery document
    .await?
    .shared();

let claims = validator.validate(token).await?;
claims.require_permission("orders:read")?;
```

With the default `axum` feature, `Guard` is a route layer and `RidmClaims` an extractor;
every refusal answers as RFC 6750 says it should — 401 `invalid_token`, 403
`insufficient_scope`, 503 with `Retry-After` when the key set is out of reach, each with a
`WWW-Authenticate` challenge.

```rust
Router::new()
    .route("/orders", get(list_orders))
    .route_layer(from_fn_with_state(
        Guard::new(validator.clone()).permission("orders:read"),
        guard,
    ))
    .with_state(validator);
```

The key set is cached and refreshed when a token names a key it has not seen, so a
`ridm key rotate` is picked up without a restart; while the issuer is unreachable the last
good set keeps answering. `typ` must be `at+jwt`, which is what stops an ID token being
spent as an access token, and a sender-constrained token (`cnf.jkt`) is refused rather
than silently downgraded to a bearer one, because this crate verifies no DPoP proof. It
validates JWTs only: a client registered for opaque access tokens (`at_…`) sends tokens
that only `/introspect` can read. It does not do revocation — rIDM's access tokens are
short-lived, and an API that must react sooner should call `/introspect` instead. `api/tests/ridm_auth.rs` runs it against tokens
this server really issues.

### Example relying parties

[`examples/`](examples/README.md) holds three applications against one demo tenant,
each showing a different half of the protocol:

| Example | What it is | Runs on |
|---------|------------|---------|
| `examples/axum-api/` | a **resource server** — a Rust API that accepts rIDM tokens through `ridm-auth`, with no session and no user table of its own | `:8081` |
| `examples/nextjs-spa/` | a **public client** — authorization code with PKCE, no secret, tokens in memory, silent re-authentication with `prompt=none` | `:3100` |
| `examples/confidential-client/` | a **confidential client** — a server-side web app with a secret, a session cookie, refresh token rotation, RP-initiated *and* back-channel logout | `:3200` |

Both clients call the same API, so one token can be watched all the way: minted
for `https://orders.example`, verified by a service that has never heard of the
user. `examples/setup.sh` builds the tenant from
[`examples/demo-tenant.json`](examples/demo-tenant.json) — the resource server and
its permissions, the scopes, two roles and the two clients — with
`ridm tenant import`, then creates a user for each role.

### Command-line administration (`ridm`)

`crates/ridm-cli` builds a second binary, `ridm`, that works the admin API from a
terminal — `cargo build -p ridm-cli`, or `cargo run -p ridm-cli -- <args>` while
developing. It needs nothing but network access to the server and a token.

```bash
ridm login --url https://idm.example.com             # paste a personal access token
ridm whoami

ridm --tenant acme tenant export -o acme.json        # configuration as code
ridm --tenant acme tenant diff   -f acme.json        # what an import would change
ridm --tenant acme tenant import -f acme.json        # plan, confirm, apply

ridm --tenant acme key rotate
ridm --tenant acme user create alice --email alice@example.com --temporary-password
ridm --tenant acme user reset alice --revoke-sessions
ridm --tenant acme client create --name "Acme SPA" --type spa \
     --redirect-uri https://acme.example/callback
ridm --tenant acme client iat create --description "partner onboarding" --max-uses 5
ridm master-key status
```

| Command | Does |
|---------|------|
| `login`, `logout`, `whoami`, `profile list\|use\|show` | credentials and which server they are for |
| `bootstrap` | create the first global administrator (the database, not the API) |
| `tenant list\|show\|create\|export\|import\|diff` | tenants and their configuration document |
| `key list\|rotate` | a tenant's token signing keys |
| `master-key status\|rotate` | the key that encrypts secrets at rest, deployment-wide |
| `user create\|reset` | create a user; set or reset a password |
| `client create` | register an OAuth client; its secret is printed once |
| `client iat create\|list\|revoke` | initial access tokens for dynamic client registration: `create [--description TEXT] [--expires-in SECS] [--max-uses N]` prints the token once, `list` shows metadata, `revoke ID` |

**Authenticating.** An admin token must carry `urn:ridm:admin` in `aud` and belong to
a user with `ridm:*` permissions (see [Admin API access](#admin-api-access)), so the
CLI asks for that resource whatever the grant. `ridm login` takes three routes:

- a **personal access token** (`rpat_…`) minted in the account console — the default,
  needs no client registration, and is what CI should put in `RIDM_TOKEN`;
- `--client-id X --client-secret-stdin`, **client credentials** of a machine client
  whose service-account user holds admin roles;
- `--client-id X --device`, the **device authorization grant**: the CLI prints a code,
  the operator approves it in a browser, and the refresh token keeps the session alive.
  The client must allow `urn:ietf:params:oauth:grant-type:device_code` and list
  `urn:ridm:admin` in its audiences; the built-in console clients deliberately do not.

**Profiles.** `ridm login` writes the server URL, the tenant and the credential to
`~/.config/ridm/config.json` (`$XDG_CONFIG_HOME` or `$RIDM_CONFIG` if set), mode `0600`
because a refresh token or a client secret may be in it. `--profile` picks one,
`ridm profile use` changes the default, and `--url`/`--tenant`/`--token` (or `RIDM_URL`,
`RIDM_TENANT`, `RIDM_TOKEN`) override a profile without writing anything — enough on
their own for a pipeline that stores no file at all. An expiring OAuth credential is
refreshed in place before the request that needs it.

**Output and exit codes.** `--output json` prints the API response verbatim for `jq`;
without it, results are tables and sentences. `0` succeeded, `1` the command ran and
failed, `2` the command line or the configuration was wrong, and `3` from
`tenant diff --exit-code` when the plan is not empty. Commands that destroy or rewrite
(`tenant import`, `master-key rotate`) show what they are about to do and ask; `--yes`
skips the question and is required when stdin is not a terminal.

**Building without the database.** `bootstrap` is the one command that cannot use the
admin API — no token can exist yet — so it links the server library and reads the
server's own environment (`DATABASE_URL`, `REDIS_URL`, `MASTER_KEY`). Build with
`--no-default-features` for a slim, HTTP-only `ridm` that leaves bootstrapping to
`ridm-api bootstrap` in the container.

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
| `GET /admin/tenants/{slug}/stats` | `ridm:tenants:read` | `?days=` (1–365, default 30): sign-ins and failures per day, live sessions, user counts and second-factor adoption, most authorized clients |
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
| `GET/POST /admin/tenants/{slug}/dcr/initial-access-tokens`, `DELETE .../{token}` | `ridm:clients:read` / `write` | initial access tokens that `POST /t/{slug}/register` demands when `settings.dcr.mode` is `initial_access_token`: `{description?, expires_in_secs?, max_uses?}`, the token returned once and stored in Postgres; revoke by id; events `dcr_token.created`, `dcr_token.revoked` |
| `GET /admin/tenants/{slug}/users` | `ridm:users:read` | `?search=` (username/email prefix), `status`, `org_id`, `include_deleted` |
| `POST /admin/tenants/{slug}/users` | `ridm:users:write` | user fields plus `password` (policy-checked) or `temporary_password: true` (returned once, change forced at first login); `status` may not be `locked` or `deleted` |
| `GET /admin/tenants/{slug}/users/{id}` | `ridm:users:read` | user plus `password` summary, direct and effective `roles`, `groups` |
| `PATCH /admin/tenants/{slug}/users/{id}` | `ridm:users:write` | absent = unchanged, `null` clears; `status` is `active` or `disabled` (disabling ends sessions); unknown fields rejected |
| `DELETE /admin/tenants/{slug}/users/{id}` | `ridm:users:write` | soft delete; sessions (with back-channel logout) and trusted devices end |
| `PUT /admin/tenants/{slug}/users/{id}/password` | `ridm:users:write` | `{password?, must_change?, skip_policy?, notify?, revoke_sessions?}`; without `password` a temporary one is generated and returned once; `revoke_sessions` ends every session with back-channel logout |
| `POST /admin/tenants/{slug}/users/{id}/force-password-change`, `.../unlock` | `ridm:users:write` | flag a change at next login; clear a lockout |
| `GET/DELETE /admin/tenants/{slug}/users/{id}/sessions[/{id}]` | read / write | live SSO sessions; revoke one or all, with their refresh tokens (offline ones included) and back-channel logout |
| `GET /admin/tenants/{slug}/users/{id}/credentials`, `DELETE .../credentials/{id}` | read / write | password summary plus factor rows (type, label, timestamps; never the material); remove a factor (removing the last second factor also removes the recovery codes) |
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
| `GET/POST /admin/tenants/{slug}/resource-servers`, `GET/PATCH/DELETE .../{id}` | `ridm:resource-servers:read` / `write` | audience identifier (immutable), name, token TTL, `signing_alg` (`RS256`, `RS384`, `RS512`, `ES256`, `EdDSA`; a key of that algorithm is ensured on save), `allow_offline_access` (whether tokens for it may carry `offline_access`); `urn:ridm:admin` is read-only |
| `GET/POST .../resource-servers/{id}/permissions`, `DELETE .../permissions/{id}` | read / write | the built-in catalogue cannot be extended or trimmed |
| `GET/POST /admin/tenants/{slug}/scopes`, `GET/PATCH/DELETE .../scopes/{id}` | `ridm:scopes:read` / `write` | name immutable; description, `claims` (what the scope releases at userinfo and, for clients with `id_token_scope_claims`, in the ID token), `is_default` (granted when a request names no scope) and `resource_server_id` (the scope adds that audience) tunable, also for the standard scopes, which cannot be deleted; discovery follows at once |
| `GET/POST /admin/tenants/{slug}/claim-mappers`, `GET/PATCH/DELETE .../{id}` | `ridm:mappers:read` / `write` | `{name, client_id?, config}` with `config` = `{type, ..., include_in}`; `?client_id=` or `?tenant_wide=true`; templates must compile; protected claims (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `azp`, `at_hash`, `c_hash`, `nonce`, `auth_time`, `amr`, `acr`, `sid`, `tid`, `client_id`, `scope`, `typ`, `cnf`, `act`) and `permissions` cannot be targeted, and only a `roles` mapper may write `roles` and only a `groups` mapper `groups` (replacing the built-in claim); a `user_attribute` mapper reads `attributes.<name>`, or a top-level user field, then an attribute of that bare name; a `roles` mapper naming a client emits only that client's roles; tokens reflect changes at once |
| `GET /admin/tenants/{slug}/keys`, `GET .../keys/{id}` | `ridm:keys:read` | `?status=pending|active|retiring|revoked`; public JWK only, never private material |
| `POST /admin/tenants/{slug}/keys` | `ridm:keys:write` | `{alg?, rsa_bits?, activate?, not_before?}`; defaults from the tenant key policy; `pending` (published, not signing) unless `activate` |
| `POST /admin/tenants/{slug}/keys/rotate` | `ridm:keys:write` | new active key with the policy's algorithm; the previous active key retires with the policy's overlap |
| `POST .../keys/{id}/activate`, `.../retire`, `.../revoke` | `ridm:keys:write` | activate retires other active keys of the same algorithm; retire keeps the key published until the overlap ends; revoke unpublishes at once |
| `GET /admin/master-key`, `POST /admin/master-key/rotate` | `ridm:keys:read` / `write` (global only) | encrypted rows per master-key generation and how many are pending; re-encrypt them under the current generation |
| `GET/POST /admin/tenants/{slug}/invitations`, `GET/DELETE .../{id}`, `POST .../{id}/resend` | `ridm:invitations:read` / `write` | `?open_only=`; `{email, roles?, groups?, org_id?, expires_days?}`; the token only travels in the email; resend replaces it; inviting into roles or groups is guarded like a grant |
| `POST /admin/tenants/{slug}/users/import?dry_run=` | `ridm:users:write` + `ridm:invitations:write` | `application/json` (array or `{"users": [...]}`) or `text/csv` (`attr.<name>` columns become attributes); per row: `password` (policy-checked) or `password_hash` (argon2id/argon2i/argon2d, bcrypt, pbkdf2, sha, md5; upgraded at first login), `roles`/`groups` by name; attributes declared `editable_by: none` may be set; a row granting a role or group whose admin permissions the importer does not hold fails ("cannot grant permissions you do not hold"), in a dry run too; rows fail independently and the report lists each failure; 10 000 rows / 32 MiB per request |
| `GET /admin/tenants/{slug}/users/export?format=json|csv` | `ridm:users:read` | every live user streamed page by page, without credentials |
| `GET/PUT/DELETE /admin/tenants/{slug}/messaging/email`, `POST .../email/test` | `ridm:messaging:read` / `write` | `{type: "smtp", host, port, username?, password?, from, security?}` or `{type: "http", url, auth_header?, from}`; reads report `source` (tenant, server default, none) with `password_set` / `auth_header_set` instead of the secret; an omitted secret keeps the stored one; test sends go straight through the sender and report the backend or its error |
| `GET/PUT/DELETE /admin/tenants/{slug}/messaging/sms`, `POST .../sms/test` | read / write | HTTP gateway `{url, auth_header?, from?}`, same redaction and test-send rules |
| `GET .../messaging/templates`, `GET/PUT/DELETE .../templates/{channel}/{event}/{locale}`, `POST .../templates/preview` | read / write / read | events and channels catalogue plus tenant overrides; a `GET` returns the override or the built-in as a starting point; overrides are validated by rendering; preview renders the stored template or an unsaved `draft` with sample `vars` named as a real send of that event names them (`inviter`, `user_agent`, `ip`, `when`, …) |
| `GET .../messaging/log?status=&limit=`, `POST .../log/{id}/redeliver` | read / write | outbound queue entries without bodies (links and codes stay private); dead messages can be requeued |
| `GET /admin/tenants/{slug}/audit` | `ridm:audit:read` | newest first; `?from=&to=&name=&actor_id=&subject_id=&user_id=&cursor=&limit=`; `name` matches exactly or as a prefix when it ends in `.` or `*` |
| `GET .../audit/export?format=json|csv`, `GET .../audit/verify` | `ridm:audit:read` | oldest first with `prev_hash`/`hash` for offline checking; verify walks the retained chain and names the first broken position |
| `GET .../users/{id}/audit` | `ridm:audit:read` | rows where the user is actor or subject |
| `GET /admin/audit`, `.../export`, `.../verify` | `ridm:audit:read` (global only) | the global chain: events with no tenant, such as master-key rotation |
| `GET/POST /admin/tenants/{slug}/webhooks`, `GET/PATCH/DELETE .../{id}` | `ridm:webhooks:read` / `write` | `{name, url, events, enabled?, headers?, max_attempts?}`; `events` are exact names, prefixes (`user.*`) or `*`; the signing `secret` is returned once on create |
| `POST .../webhooks/{id}/secret`, `POST .../webhooks/{id}/test` | `ridm:webhooks:write` | rotate the secret (shown once); deliver a `webhook.test` event now and report the attempt |
| `GET .../webhooks/{id}/deliveries?status=&limit=`, `GET .../deliveries/{id}`, `POST .../deliveries/{id}/redeliver`, `POST .../deliveries/redeliver-dead` | read / read / write / write | delivery log with status, attempts, last status code, error and a response snippet; redeliver requeues and attempts at once; redeliver-dead does so for every dead delivery of the webhook and reports the count |
| `GET/POST /admin/tenants/{slug}/scim/tokens`, `DELETE .../{id}` | `ridm:scim:read` / `write` | the tenant's SCIM base URL and provisioning tokens; `{name, expires_in_days?}` returns the `rscim_` token once; revoke stops it at once |
| `GET/POST /admin/tenants/{slug}/ip-rules`, `GET/PATCH/DELETE .../{id}` | `ridm:tenants:read` / `write` | `{cidr, action?: allow|deny, client_id?, description?}`; networks are normalized; `?client_id=` or `?tenant_wide=true`; in force at once (see [IP rules](#ip-rules)) |
| `GET/POST /admin/tenants/{slug}/identity-providers`, `GET/PATCH/DELETE .../{idp}` (id or alias), `GET .../presets`, `POST .../discover` | `ridm:idps:read` / `write` | upstream OpenID Connect and OAuth 2.0 providers: a `preset` (`google`, `microsoft`, `github`, `apple`, `gitlab`) fills in protocol, endpoints, scopes and mappers; an OIDC provider's endpoints are discovered from its `issuer` when left out; the `client_secret` is stored encrypted and never returned (`client_secret_set`), `null` clears it; `link_policy` (`verified_email`, `explicit`, `always_new`), `trust_email`, `mappers` (`subject`, `username`, `email`, `email_verified` claim names and `attributes` → claim), `hidden`, `sort_order`; every answer carries the `callback_url` to register upstream |
| `GET /admin/tenants/{slug}/users/{user}/identities`, `DELETE .../identities/{idp_id}` | `ridm:users:read` / `write` | the upstream identities linked to a user, and unlinking one |
| `GET /admin/tenants/{slug}/users/{user}/pats`, `DELETE .../pats/{token_id}` | `ridm:users:read` / `write` | a user's personal access tokens (metadata) and revoking one |
| `GET /admin/tenants/{slug}/export` | `ridm:tenants:export` | the tenant's configuration as one deterministic JSON document (`ridm.tenant/1`): settings, profile schema, resource servers and permissions, scopes, clients, roles (composites, permission grants), groups (by path, with roles), claim mappers, message templates, webhooks, IP rules and identity providers, keyed by natural identifiers; no secrets, users or provider credentials |
| `GET /openapi.json`, `GET /docs` | none | the admin API's OpenAPI 3 document, derived from the routers; Swagger UI at `/docs` when `DOCS_ENABLED=true` |
| `POST /admin/tenants/{slug}/import?dry_run=&prune=` | `ridm:tenants:import` | `dry_run` returns the plan (creates, updates with field-level diffs, and with `prune` deletes of unmentioned configuration); otherwise applies it and reports what was applied, per-item errors, and the secrets of clients and webhooks it created (shown once); an item that would grant admin permissions the importer does not hold is a per-item error (listed under `errors` in the dry-run plan; `ridm tenant diff` fails on it, `ridm tenant import` shows it); applying the same document twice is a no-op |

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

Webhook deliveries are queued by an in-process subscriber of the event bus and sent at
once (one prompt pass per tenant at a time, under a short Valkey lock; on every node,
since the queue hands each row to one sender only); retries are picked up by the
`webhook_delivery` job (every 30 s, one runner per cluster, visiting only the tenants
that have a delivery due, found with one query, so its cost follows the backlog rather
than the number of tenants). A pass attempts up to eight
deliveries at a time through one shared connection pool, so a slow endpoint does not
hold up the others. Each delivery is a `POST` with a JSON body
`{delivery_id, attempt, event}` and headers `X-RIDM-Event`, `X-RIDM-Delivery`,
`X-RIDM-Webhook`, `X-RIDM-Timestamp` and
`X-RIDM-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>` (verify the
signature, then refuse stale `t` values and repeated `X-RIDM-Delivery` ids). A 2xx counts
as delivered; 5xx, 408, 425, 429 and network errors retry with backoff (30 s, 2 m, 10 m,
30 m, 2 h, 6 h) up to `max_attempts`; other 4xx are dead at once. A delivery that dies
raises `webhook.delivery_dead` (audited, never itself delivered to a webhook), stays in
the log with its last status and response snippet, and can be sent again one at a time
or all at once (`POST .../deliveries/redeliver-dead`, the console's "Redeliver dead").
Targets must be https (plain http only to loopback, for development) and are reached
only on public addresses, checked when the connection is made (see
[Outbound requests](#outbound-requests)). Secrets are stored encrypted under the
master key and take part in master-key rotation.

Every domain event is appended to `audit_events` (monthly partitions, tenant RLS) by an
in-process writer; rows are hash-chained per tenant (`SHA-256(prev_hash || row)`), so a
row changed or removed inside the retained window fails verification. Retention is a
tenant setting (`settings.audit.retention_days`, default 365, `0` keeps forever); a daily
job creates upcoming partitions and drops each tenant's expired chain prefix, so what
remains stays contiguous. The global chain follows the master tenant's policy.
Partitions are created by `audit_ensure_partitions(integer)`, a `SECURITY DEFINER`
function the migration grants to every role holding `INSERT` on `audit_events`, so the
DML-only application role can run it; an application role created after that migration
needs `GRANT EXECUTE ON FUNCTION audit_ensure_partitions(integer) TO <role>`.

Tenant settings cover the password, session, MFA, registration, locale, branding,
key, discovery, DCR, auth-method, lockout, CAPTCHA, notification, audit-retention and
account (self-deletion, deletion retention) policies plus a free-form `features` flag map;
IP rules, webhooks, identity providers and messaging have their own resources. The
CAPTCHA policy lives under `settings.captcha` (`on_registration` among it); the former
`settings.registration.captcha` is gone, and a `PATCH` naming it is a `400` (an import
ignores it). The MFA policy switches between modes with `{"mfa": {"mode": …}}` alone,
also away from `required_for_roles`.

### UI

```bash
cd ui
npm install
npm run lint && npm run typecheck
npm run build          # static export to ui/out
```

`NEXT_PUBLIC_API_URL` is empty by default (same origin: the pages call the host they
were loaded from). Set it at build time when hosting `ui/out` on a separate static host
or CDN.

**Embedded UI mode.** `cargo build -p ridm-api --features embedded-ui` compiles `ui/out`
into the binary (`api/src/routes/ui.rs`, `rust-embed`; a debug build reads the files
from `ui/out` at run time instead), and the server then serves the pages itself as the
router's fallback when `UI_URL` is its own origin (the default) and `EMBEDDED_UI` is not
`false`. API routes always win; a miss under an API prefix (`/t/`, `/admin`, `/scim/`,
`/.well-known/`, the probes, `/metrics`, `/docs`, `/openapi.json`) stays the API's bare
`404`; `/login` redirects to `/login/` (`308`, query kept); unknown paths get the
export's `404.html`; `/_next/static/` is cached for a year as immutable and everything
else revalidates against a weak `ETag`; text is gzip-compressed on request. The
container image builds the export in a Node stage and always enables the feature. The
feature is off by default so a Rust-only checkout builds without Node, and CI's `ui-e2e`
job runs the Playwright suite against an API built with it.

The build's `postbuild` step (`scripts/csp.mjs`, unit-tested with `npm run test:scripts`)
gives every exported page a `Content-Security-Policy` `<meta>` tag: scripts may come
from the page's origin, the CAPTCHA vendors, or be one of the page's own inline
scripts (each allowed by its SHA-256 hash, since a static export has no nonces);
connections and form posts may go to the page's origin and `NEXT_PUBLIC_API_URL`;
styles stay inline (React style props and tenant custom CSS); images and fonts may
come from anywhere over https (tenant logos), and objects are forbidden. A meta tag
cannot restrict framing, so the embedded server sends `X-Frame-Options: DENY` and
`frame-ancestors 'none'` with every page but `/login/`, which the console's branding
preview frames and which therefore gets `SAMEORIGIN` and `frame-ancestors 'self'`; the
console pages' meta policy is the only one with `frame-src 'self'`. A reverse proxy or
static host serving `ui/out` itself must send the same headers, and
`Strict-Transport-Security`.

`npm run e2e` runs the Playwright suite (the end-user journeys — password, magic link,
registration, recovery, two-step verification, passkeys through a virtual
authenticator, consent, logout — and the admin console journeys for every
page, with axe-core accessibility checks on every page in light, dark and phone width)
against a running API and Mailpit; see [`ui/e2e/README.md`](ui/e2e/README.md).

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

Port 8090 assumes `BIND_ADDR=127.0.0.1:8090` and `PUBLIC_URL=http://localhost:8090` in
`.env` (the built-in default is 8080), which is what
[`GETTING-STARTED.md`](GETTING-STARTED.md) sets up and the examples expect.

**Identity providers** (`/console/identity-providers/`): the tenant's upstream providers
with a create dialog (preset or OpenID Connect issuer, client credentials) and a detail
editor (callback URL to register upstream, endpoints, client and secret, scopes, PKCE,
link policy, trusted email, claim mappers); the user detail's credentials tab lists a
user's linked identities with unlinking.

### Account console

The account console lives under `/account/` and is the self-service API's own client
(see above). Signed out, every page shows a card asking which organisation to sign in
through (`?tenant=` fills it in, the last one is remembered) and returns to the page
afterwards. Four pages: **Profile** (the fields the tenant's profile schema declares,
saved as they are edited, admin-only fields shown read-only; the language; the email
address and phone number with a change proven by a code sent to the new destination,
pending changes shown with a cancel, the number removable), **Security** (the password,
with a change that asks for the current one and can sign out everywhere else; the second
step and recovery codes; the upstream accounts linked to this one, with linking through
the provider and unlinking; trusted devices; every live session with this browser marked,
each one ending on its own or all but this one at once; personal access tokens, minted
with a name, scopes and lifetime and shown once), **Applications** (the
applications the user let in, with their scopes, privacy and terms links, and a "remove
access" that also cancels their refresh tokens) and **Your data** (the export as a JSON
download, and account deletion behind a dialog that asks for the username). A change the
API refuses until the user signs in again sends them through sign-in and back.

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
passwords and lockout, rate limits, sessions and tokens, branding, locale and notices,
keys, discovery and audit, plus a delete-tenant zone for global owners; the CAPTCHA
toggles sit under passwords and lockout, and when dynamic registration is set to
`initial_access_token` the keys, discovery and audit group lists, issues and revokes the
initial access tokens). Settings save as you go: each
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
secret once), URIs, scopes and audiences, token lifetimes, access token format (JWT or
opaque; not for the built-in console clients), ID token encryption and
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
tokens (revocable) and linked identities (unlinkable) are listed on the Password &
credentials tab.

**Groups, roles, resource servers, scopes and claim mappers** each get a list-and-detail
page (`/console/groups/`, `/console/roles/`, `/console/resource-servers/`,
`/console/scopes/`, `/console/claim-mappers/`; the selected item travels as a query
parameter). Groups are a tree: create at any level, move under another group (never
under a descendant), edit attributes as JSON, attach roles, add members through a user
search and remove them. Roles: realm or per-client, composites, permissions granted from
any resource server (admin-catalogue permissions only by someone who holds them), and who
holds the role; built-in `ridm:*` roles are read-only. Resource servers: name, token
lifetime cap, the algorithm their tokens are signed with, whether tokens for them may
carry `offline_access`, and their permissions; `urn:ridm:admin`
is read-only. Scopes: description, released claims (what userinfo, and the ID token
for clients that ask, carries for the scope), resource server binding (requesting the
scope adds that audience) and "granted by default" (given to a request that names no
scope); standard scopes can be tuned but not deleted. Claim mappers:
tenant-wide or per client, of kind user attribute, groups, roles, fixed value, Handlebars
template (must compile) or audience, with the tokens they are included in. Detail fields
save as you go; membership-style changes apply at once. Identity providers have their
own page (see above).

**Overview** (`/console/`): the dashboard — sign-ins, failed sign-ins and live sessions
for the chosen window (7, 30 or 90 days), two-step adoption, a sign-ins-per-day line
chart with a table view, the most authorized clients, and user counts — fed by the new
`GET /admin/tenants/{slug}/stats?days=` route (`ridm:tenants:read`), which derives
everything from login attempts, sessions, credentials and audit events.

**Export & import** (`/console/config/`): download the tenant's `ridm.tenant/1` document
or load it into an editor, paste or pick a document, preview the plan (creates, field-level
updates with old and new values, deletes when prune is on, errors) and apply it; secrets
of clients and webhooks the import created are shown once.

**Signing keys** (`/console/keys/`): every key on a timeline (created → signs from →
published until) with status, algorithm and public JWK; rotate now, create a pending key
(algorithm, RSA size, activate at once) and activate, retire or revoke each key. Global
administrators also see the master-key status (current generation, rows still under
older ones) and can re-encrypt pending rows. **Audit log** (`/console/audit/`): the
tenant's chain or, for global administrators, the global one; filters by event, time
window, actor, subject and user; newer/older paging; expandable rows with the payload
and hashes; JSON and CSV export; chain verification. **IP rules** (`/console/ip-rules/`):
allow and deny networks per tenant or client, edited in place and in force at once. **Webhooks** (`/console/webhooks/`): create (signing secret shown once),
events as exact names, prefixes or `*`, static headers, attempt limit, enable/disable,
rotate the secret, send a test ping, and the delivery log with status filter, details
and redelivery. **Messaging** (`/console/messaging/`): email provider (SMTP or HTTP
webhook; secrets kept, never shown), SMS gateway, a test send for each, templates per
channel, event and locale with a live preview of the draft (text, optional HTML
rendering, sample variables), save as a tenant override or reset to the built-in, and the
outbound log with redelivery of dead messages.

The profile schema itself is edited under Settings → Profile attributes (name, type,
label, description, who may edit, position, required, multiple values, where the value
surfaces, validation per type), saved whole through the new
`GET/PUT /admin/tenants/{slug}/profile-schema` routes (`ridm:tenants:read`/`write`).

### Container image

```bash
docker build -f api/Dockerfile -t ridm .
docker buildx build --platform linux/amd64,linux/arm64 -f api/Dockerfile -t ridm .
```

The build compiles the UI's static export (built in a Node stage) into the binary, so
the image serves the sign-in pages and consoles itself. The image is distroless, runs
as non-root, has no dynamic OpenSSL dependency, and its
`HEALTHCHECK` runs `/ridm-api --healthcheck`, which asks `/healthz` on `BIND_ADDR`
(loopback when bound to all interfaces), over HTTPS trusting exactly `TLS_CERT` when
native TLS is on.

### CI

Every pull request runs the `ci` workflow: rustfmt, `cargo check`, clippy with warnings
denied, `cargo audit`, `cargo deny`, `cargo package` for `ridm-auth` (published at release),
ESLint, `tsc`, `npm audit`, unit tests, integration
tests against Postgres and Valkey, coverage, the UI static export, the Playwright e2e
suite, a k6 smoke with thresholds (`load-smoke`), a minute of fuzzing per target
(`fuzz-smoke`), a container image boot test, and the example applications signed into
in headless Chromium against that image under docker-compose (`examples-smoke`). The `conformance` workflow runs the
OpenID Foundation suite on the same pull request. `main` is protected; all of those are
required checks and no one can bypass them. Dependencies are exact-pinned and updated by
Renovate.

Two workflows run longer versions of the same suites off the pull-request path: `weekly`
fuzzes each target for four hours (and the conformance plans run weekly too), and
`release` runs the full 200-VU k6 baseline against a release build when a `v*` tag is
pushed, uploading the summary for the release notes. The fuzz targets, their seeds and
how to reproduce a crash are described in [`api/fuzz/README.md`](api/fuzz/README.md);
the load tests in [`perf/README.md`](perf/README.md).

The `docs` workflow builds the documentation site on every pull request and checks every
link and anchor inside it offline (lychee), plus the OpenAPI document the API reference
loads; on `main` it deploys the site to GitHub Pages. To work on the docs locally:

```bash
cargo install mdbook --version 0.5.4 --locked
cd docs && mdbook serve --open     # live reload; the API reference page needs ./build.sh
```

## Repository layout

| Path | Purpose |
|------|---------|
| `api/` | `ridm-api`: the identity server (axum, sqlx, Valkey) |
| `api/migrations/` | sqlx migrations (forward-only) |
| `crates/ridm-core/` | shared types, provider traits, event definitions |
| `crates/ridm-auth/` | `ridm-auth`: validates rIDM tokens in someone else's Rust API (crates.io from the first release) |
| `crates/ridm-cli/` | `ridm`: command-line administration over the admin API |
| `ui/` | Next.js 16 static export: admin console, account console, auth pages |
| `examples/` | three relying parties: an axum resource server, a Next.js SPA, a confidential web app |
| `dev/` | development seed data (`make seed`) |
| `Makefile` | development shortcuts (`make` lists them) |
| `deploy/` | docker-compose (a Helm chart and reverse-proxy examples come in Phase 11) |
| `docs/` | the documentation site (mdBook): concepts, quickstarts, admin guide, reference, deployment, migration |
| `api/fuzz/` | cargo-fuzz targets and their seed corpora |
| `perf/` | k6 load tests: the PR smoke and the release baseline |
| `conformance/` | the OpenID Foundation conformance rig |
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
- [THREAT_MODEL.md](THREAT_MODEL.md): what rIDM protects, from whom, what stops each
  attack today, and what it leaves to the deployment.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT. See [LICENSE](LICENSE).
