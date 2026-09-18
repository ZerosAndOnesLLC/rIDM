# Server configuration

The server is configured entirely through environment variables, so the same binary and image run everywhere. Every variable is read once at start-up by [`api/src/config.rs`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/api/src/config.rs); [`.env.example`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/.env.example) is an annotated template. A `.env` file in the working directory is loaded first when present, and real environment variables win over it.

Everything that is per tenant (password policy, token lifetimes, MFA, branding, rate-limit ceilings and so on) is not here but in the tenant's settings; see [Tenants and tenant settings](../admin/tenants.md) and the [tenant configuration document](tenant-document.md).

Conventions used below:

- An empty or whitespace-only value counts as unset.
- **Booleans** accept `1`, `true`, `yes`, `on` and `0`, `false`, `no`, `off` (any case).
- **Integers** are unsigned 32-bit.
- An invalid or missing required value stops the server with `configuration error: ...` on standard error and exit code `2`.

## Required

| Variable | Type | Meaning |
|----------|------|---------|
| `DATABASE_URL` | Postgres URL | Postgres 16+ connection string. Use a non-superuser role with DML privileges only: superusers bypass row level security, which backs tenant isolation, and a table owner can switch it off. See [Postgres and Valkey](../deploy/postgres-valkey.md). |
| `REDIS_URL` | URL | Valkey (or Redis) connection: `redis://host:6379`, `rediss://` for TLS, `redis+cluster://h1:7000,h2:7001`, or `redis+sentinel://s1:26379,s2:26379/<master name>`. Credentials go before an `@` and apply to every host. |
| `PUBLIC_URL` | `http`/`https` URL | The externally visible base URL, e.g. `https://id.example.com`. Every tenant's issuer is `{PUBLIC_URL}/t/{slug}` (a tenant with a custom domain uses `https://{domain}` instead). Changing it changes every issuer. |
| `MASTER_KEY` or `MASTER_KEY_FILE` | 32 bytes | The master key that encrypts secrets at rest (signing keys, identity providers' client secrets, SMTP and SMS credentials, webhook secrets, second-factor secrets). `MASTER_KEY` is hex or base64 (standard or URL-safe); `MASTER_KEY_FILE` names a file holding the raw 32 bytes or the same text encodings. `MASTER_KEY` wins when both are set. Generate with `openssl rand -hex 32`. See [Signing keys and the master key](../concepts/keys.md). |

## Server

| Variable | Type | Default | Meaning |
|----------|------|---------|---------|
| `BIND_ADDR` | socket address | `0.0.0.0:8080` | Address the HTTP (or HTTPS) listener binds to. `ridm-api --healthcheck` probes `/healthz` at this address (a wildcard `0.0.0.0` or `::` becomes the loopback address of the same family). |
| `UI_URL` | URL | `PUBLIC_URL` | Base URL of the sign-in, consent and console pages. The server redirects browsers to pages under it (`/login/`, `/consent/`, `/console/`, ...) and derives the built-in console clients' redirect URIs from it, updating them at start-up when it changes. Set it to wherever the UI is served; the UI is not embedded in the server binary in this build (planned, Phase 11.1). |
| `DOCS_ENABLED` | boolean | `false` | Serve Swagger UI at `/docs`. `/openapi.json` is served either way. Keep it off in production. |
| `MIGRATE_ON_START` | boolean | `false` | At start-up, apply migrations if any are pending, as `DATABASE_URL`'s role; with none pending nothing is applied, so the DML-only app role can run with it on once `ridm-api migrate` has brought the schema up to date. A pending migration then fails start-up unless the role owns the schema. Off, the server only logs a warning when migrations are pending. `ridm-api bootstrap` follows the same setting. See [Container image](../deploy/container.md#running-migrations). |

## Database and cache

| Variable | Type | Default | Meaning |
|----------|------|---------|---------|
| `DATABASE_READ_URL` | Postgres URL | unset | A read replica for listings and statistics, run in read-only transactions. Anything that feeds a decision stays on the primary. Unset, the primary serves both. |
| `DB_POOL_MIN` | integer | `2` | Minimum Postgres connections per node. Must not exceed `DB_POOL_MAX`. |
| `DB_POOL_MAX` | integer | `20` | Maximum Postgres connections per node. Roughly twice the database server's CPU count divided by the number of API nodes. |
| `REDIS_POOL_MAX` | integer | `32` | Valkey connections per node (at least 1). |

## Security and keys

| Variable | Type | Default | Meaning |
|----------|------|---------|---------|
| `MASTER_KEY_VERSION` | integer ≥ 1 | `1` | Generation number of the current master key, stored with every ciphertext. Bump it when rotating the master key. |
| `MASTER_KEY_PREVIOUS` | `version=key` list | unset | Older generations still needed to decrypt rows not yet re-encrypted: `1=<hex>,2=<hex>`. Every version must be lower than `MASTER_KEY_VERSION`. Remove an entry once `ridm-api rotate-master-key --status` (or `GET /admin/master-key`) shows nothing left under it. |
| `COOKIE_SECURE` | boolean | `true` | Set the `Secure` attribute on the session and trusted-device cookies and give them the `__Host-` prefix (`__Host-ridm_session_{slug}`, `__Host-ridm_device_{slug}`; without it `ridm_session_{slug}`, `ridm_device_{slug}`). Only turn off for plain-HTTP local development. See [TLS and reverse proxies](../deploy/tls-and-proxies.md#cookies). |
| `TRUSTED_PROXIES` | CIDR/IP list | empty | Comma-separated networks whose `X-Forwarded-For`, `Forwarded` and `X-Forwarded-Host` headers are believed. The client address is the TCP peer unless the peer is in this list. Empty means headers are never trusted. See [TLS and reverse proxies](../deploy/tls-and-proxies.md). |
| `HSTS_MAX_AGE` | integer (seconds) | `63072000` (two years) | `Strict-Transport-Security` max-age, sent only when `PUBLIC_URL` is https. `0` disables the header. |
| `ARGON2_M_COST_KIB` | integer | `19456` (19 MiB) | argon2id memory cost for password hashes. |
| `ARGON2_T_COST` | integer | `2` | argon2id iterations. |
| `ARGON2_P_COST` | integer | `1` | argon2id lanes. |
| `BREACH_CHECK_URL` | URL, or `off`/`none`/`false` | `https://api.pwnedpasswords.com/range/` | Have I Been Pwned compatible range endpoint used by tenants with `password.check_breached` on (k-anonymity: only a five-character hash prefix leaves the server). A trailing `/` is added when missing. `off`, `none` or `false` disables the check for the whole deployment (air-gapped installs). |

The argon2 parameters may not go below 8 MiB, 1 iteration and 1 lane. Hashes made with weaker parameters are upgraded on the user's next successful sign-in, so raising them is safe.

## Native TLS

| Variable | Type | Default | Meaning |
|----------|------|---------|---------|
| `TLS_CERT` | file path | unset | PEM certificate chain. |
| `TLS_KEY` | file path | unset | PEM private key. |

Both or neither: setting one alone is a configuration error. With both, the listener speaks HTTPS (rustls); leave them unset when a reverse proxy or load balancer terminates TLS. `ridm-api --healthcheck` then probes over HTTPS, trusting exactly the first certificate in `TLS_CERT`.

## Email

Deployment-wide SMTP defaults, used by tenants that have not configured their own email backend (`PUT /admin/tenants/{slug}/messaging/email`). There is no deployment-wide SMS gateway; SMS is configured per tenant. See [Email, SMS and templates](../admin/messaging.md).

| Variable | Type | Default | Meaning |
|----------|------|---------|---------|
| `SMTP_HOST` | host name | unset | Setting it turns the defaults on. Chosen by the operator, so it may be a private relay; tenant SMTP hosts are held to the [outbound request policy](../admin/security-controls.md#outbound-request-policy) instead. |
| `SMTP_PORT` | integer | `587` | |
| `SMTP_USERNAME` | string | unset | |
| `SMTP_PASSWORD` | string | unset | |
| `SMTP_FROM` | mailbox | required when `SMTP_HOST` is set | `From` header, e.g. `"rIDM <no-reply@example.com>"`. |
| `SMTP_SECURITY` | `starttls`, `tls`, `none` | `starttls` | `tls` is implicit TLS (usually port 465); `none` is plain SMTP, for a local catcher such as Mailpit. |

## Rate limits

Per-tenant ceilings live in `settings.rate_limits` (see [Rate limits, IP rules and CAPTCHA](../admin/security-controls.md)). These two belong to the deployment:

| Variable | Type | Default | Meaning |
|----------|------|---------|---------|
| `RATE_LIMITS` | boolean | `true` | Master switch for every request ceiling. Off only for tests and local experiments. Tenant IP rules are enforced either way. |
| `RATE_LIMIT_IP_PER_MINUTE` | integer | `6000` | Requests per minute one client address may make to every limited endpoint of every tenant together. `0` turns this bucket off. |

## Logging, metrics, tracing and audit export

| Variable | Type | Default | Meaning |
|----------|------|---------|---------|
| `LOG_FORMAT` | `json`, `pretty` (or `text`) | `json` | Log line format. JSON lines carry the current span's fields. |
| `RUST_LOG` | tracing filter | `info` | Log filter, e.g. `info,ridm_api=debug,sqlx=warn`. |
| `METRICS_TOKEN` | string | unset | When set, `GET /metrics` demands `Authorization: Bearer <token>`; unset, it is open. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | URL | unset | OTLP/HTTP collector base URL (e.g. `http://otel-collector:4318`); traces are posted to `<url>/v1/traces` as protobuf: one `info` span per request, named `METHOD /route/{template}`, plus whatever else `RUST_LOG` enables. Unset, no exporter runs. |
| `OTEL_SERVICE_NAME` | string | `ridm` | `service.name` on exported traces. |
| `AUDIT_SINK_URL` | URL | unset | Also ship every audit row: `https://...` (JSON arrays of up to 100 rows), or `syslog://host:514` / `syslog+udp://host:514` (UDP) and `syslog+tcp://host:514` (RFC 5424, one message per row). |
| `AUDIT_SINK_TOKEN` | string | unset | Sent as `Authorization: Bearer <token>` to an HTTP(S) audit sink. |
| `HOSTNAME` | string | `-` | The host field of syslog audit lines. Usually set by the container runtime. |

See [Observability](../deploy/observability.md) for the metric names and the audit sink's delivery behaviour.

## Background jobs

| Variable | Type | Default | Meaning |
|----------|------|---------|---------|
| `RETENTION_DAYS` | integer ≥ 1 | `30` | Days the hourly `cleanup` job keeps spent rows: expired, revoked or consumed refresh tokens, ended sessions (at most a week), login attempts, sent or dead messages, delivered or dead webhook deliveries, expired or used invitations, expired or revoked trusted devices, personal access tokens and provisioning tokens. |

Audit retention is per tenant (`settings.audit.retention_days`), not governed by this variable.

## First-run bootstrap

A development convenience: at start-up, create the `master` tenant's first global owner from the environment. It is a no-op once a user in `master` holds the owner role. Production installs usually run `ridm bootstrap` or `ridm-api bootstrap` once instead; both fall back to these variables for values not given as flags.

| Variable | Type | Default | Meaning |
|----------|------|---------|---------|
| `BOOTSTRAP_ADMIN_EMAIL` | email | unset | Email of the first owner. |
| `BOOTSTRAP_ADMIN_PASSWORD` | string | unset | Initial password; the account must change it at first sign-in. |
| `BOOTSTRAP_ADMIN_USERNAME` | string | `admin` | Username of the first owner. |
| `BOOTSTRAP_SAMPLE_CLIENT` | boolean | `false` | Also make sure `master` has the public single-page-app client `sample-spa`: PKCE, redirect URI `http://localhost:3000/callback`, post-logout redirect `http://localhost:3000/`, CORS origin `http://localhost:3000`. Created once; an existing one is left alone. Read only when the two variables above are set, at start-up and by `ridm-api bootstrap`. |

`BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` must be set together or not at all.

## Server subcommands

The `ridm-api` binary runs the server by default and has these subcommands. All except `openapi` and `--healthcheck` load the full configuration above.

| Command | Purpose |
|---------|---------|
| `ridm-api migrate` | Apply pending migrations, then exit. Run it as the schema-owner role. |
| `ridm-api bootstrap [--email E] [--username U] [--password-stdin] [--no-must-change]` | Create the first global administrator. Applies pending migrations only with `MIGRATE_ON_START=true`; otherwise pending migrations make it exit `1` and name `ridm-api migrate`. |
| `ridm-api rotate-master-key [--status]` | Re-encrypt secrets at rest under the current `MASTER_KEY_VERSION`, or report what is left. |
| `ridm-api openapi` | Print the admin API's OpenAPI document; needs no database. |
| `ridm-api --healthcheck` | Exit `0` when `/healthz` answers at `BIND_ADDR` (over HTTPS when `TLS_CERT` is set), `1` otherwise; the image's `HEALTHCHECK` runs it. |

## Command-line tool (`ridm`)

The [`ridm` CLI](../admin/cli.md) reads these variables; each overrides the stored profile, and the matching flag overrides the variable. It also loads a `.env` file from the working directory.

| Variable | Flag | Meaning |
|----------|------|---------|
| `RIDM_URL` | `--url` | Server origin, e.g. `https://id.example.com`. |
| `RIDM_TOKEN` | `--token` | Bearer token to present (an access token or a personal access token). Never written to disk. |
| `RIDM_TENANT` | `--tenant` | Tenant slug to act on (`master` by default). |
| `RIDM_PROFILE` | `--profile` | Stored profile to use. |
| `RIDM_CONFIG` | | Path of the profile file. Default `$XDG_CONFIG_HOME/ridm/config.json`, else `~/.config/ridm/config.json` (created with mode `0600`). |

`ridm bootstrap` talks to the database directly and so reads the server's own `DATABASE_URL`, `REDIS_URL` and `MASTER_KEY` (and the `BOOTSTRAP_*` variables).

## UI build and development

The Next.js UI in [`ui/`](https://github.com/ZerosAndOnesLLC/rIDM/tree/main/ui) is a static export; these are read when it is built or run with `next dev`, not by the server.

| Variable | When | Meaning |
|----------|------|---------|
| `NEXT_PUBLIC_API_URL` | build time | Base URL of the API when the UI is hosted on another origin. Empty (the default) means same origin. |
| `API_PROXY` | `next dev` only | Proxy `/t`, `/admin`, `/healthz`, `/readyz`, `/.well-known` and `/openapi.json` to this API origin, so the pages call it same-origin, e.g. `API_PROXY=http://localhost:8080 npm run dev`. |
