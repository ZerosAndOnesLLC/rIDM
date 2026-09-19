# Production checklist

Go through this before a deployment carries real users. Each item links to the page that
explains it. rIDM is pre-release (`0.1.0-dev`) with no tagged version yet, so build from
a commit you have reviewed and record which one you run.

## Secrets and keys

- [ ] **The master key is generated once, stored in a secret manager, and backed up
  apart from the database.** `openssl rand -hex 32`; supply it as `MASTER_KEY_FILE`
  (a mounted secret) rather than an environment variable where you can. Every node gets
  the same key. A database backup without its key cannot decrypt signing keys, MFA
  secrets or provider credentials, and anyone holding both has everything, so the key
  and the backups never sit in the same place.
  [Signing keys and the master key](../concepts/keys.md),
  [Container image](container.md#runtime-properties)
- [ ] **You know how to rotate the master key** (`MASTER_KEY_VERSION`,
  `MASTER_KEY_PREVIOUS`, `ridm-api rotate-master-key`) and have done it once in a test
  environment. [Rotating keys](../admin/key-rotation.md)
- [ ] **Signing key rotation is set per tenant** to the interval your relying parties
  can follow; the `key_rotation` job applies it hourly.
  [Rotating keys](../admin/key-rotation.md)
- [ ] **Database and Valkey passwords are not the compose defaults**
  (`ridm`, `ridm_migrator`, `ridm_app`). [docker-compose](docker-compose.md#variables)

## URLs, TLS and proxies

- [ ] **`PUBLIC_URL` is the final https URL.** Every issuer derives from it; changing it
  later breaks every relying party. [TLS and reverse proxies](tls-and-proxies.md#public_url-and-ui_url)
- [ ] **TLS terminates at your proxy, or natively with `TLS_CERT` and `TLS_KEY`**, and
  plain http redirects to https. [TLS and reverse proxies](tls-and-proxies.md)
- [ ] **`COOKIE_SECURE` is `true`** (the default). Sign-in then works only over https,
  which is the point. [TLS and reverse proxies](tls-and-proxies.md#cookies)
- [ ] **`TRUSTED_PROXIES` lists exactly your proxy tier**: empty behind a proxy makes
  every user one address; too wide lets callers forge theirs.
  [TLS and reverse proxies](tls-and-proxies.md#trusted_proxies-and-the-client-address)
- [ ] **The UI is served from the same origin as the API**: the image's embedded UI
  (`UI_URL` unset), or `ui/out` on the same host with the framing headers and HSTS added
  by the static server.
  [Deployment overview](overview.md#where-the-ui-is-served-from),
  [TLS and reverse proxies](tls-and-proxies.md#a-starting-point-for-nginx)
- [ ] **Custom domains have DNS, a certificate and a proxy route** before a tenant turns
  one on. [Custom domains](../admin/custom-domains.md)

## Exposure

- [ ] **`DOCS_ENABLED` is off** (the default), so Swagger UI is not served at `/docs`.
  `/openapi.json` is served either way; it describes the API and holds no data.
  [Server configuration](../reference/configuration.md)
- [ ] **`/metrics` is protected**: `METRICS_TOKEN` is set, or the path is not routed from
  the internet, or both. [Observability](observability.md#metrics)
- [ ] **Postgres and Valkey are not reachable from the internet**, and the compose file's
  published ports are removed on any shared host.
  [Postgres and Valkey](postgres-valkey.md), [docker-compose](docker-compose.md#variables)
- [ ] **Outbound traffic is allowed only where needed**: mail, SMS webhook, webhook
  receivers, upstream identity providers, the breached-password API (or
  `BREACH_CHECK_URL=off`), audit sink, collector. rIDM refuses private and loopback
  destinations for the URLs tenant administrators choose, but an egress firewall is
  still the boundary. [Deployment overview](overview.md#outbound-connections)

## Database

- [ ] **The API connects as the DML-only app role** and migrations run separately as
  the migrator. `MIGRATE_ON_START=true` is harmless under that role once the schema is
  current, but never give the server the migrator's credentials so that it can migrate
  itself.
  [Postgres and Valkey](postgres-valkey.md#two-roles-and-row-level-security),
  [Container image](container.md#running-migrations)
- [ ] **The app role can execute `audit_ensure_partitions`.** The migration grants it to
  roles that already had `INSERT` on the audit log; an app role created later needs the
  grant by hand. [Postgres and Valkey](postgres-valkey.md#audit-partitions-under-the-two-role-setup)
- [ ] **Pool sizes fit `max_connections`** across all nodes (and the replica pool, if
  any). [Postgres and Valkey](postgres-valkey.md#connection-pools)
- [ ] **Valkey has enough memory never to evict, and append-only persistence on.**
  Eviction signs users out and forgets revoked access tokens.
  [Postgres and Valkey](postgres-valkey.md#memory-and-eviction)

## First administrator and tenants

- [ ] **The first global administrator is bootstrapped and has changed the initial
  password** (forced at first sign-in unless `--no-must-change` was used). Remove
  `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` from the environment afterwards.
  [docker-compose](docker-compose.md#the-prod-profile),
  [Administrator access](../admin/access.md)
- [ ] **Administrators use a second factor.** [MFA policy](../admin/mfa-policy.md)
- [ ] **Email works**: `SMTP_HOST`, `SMTP_FROM` (required once `SMTP_HOST` is set),
  `SMTP_SECURITY` (`starttls` by default), or per-tenant settings. Send a test invitation
  or password reset. [Email, SMS and templates](../admin/messaging.md)

## Abuse controls

- [ ] **Rate limits are on** (`RATE_LIMITS=true`, the default) and
  `RATE_LIMIT_IP_PER_MINUTE` suits your traffic; tenant ceilings are reviewed. Never
  carry `RATE_LIMITS=false` over from a load test.
  [Rate limits, IP rules and CAPTCHA](../admin/security-controls.md)
- [ ] **Volume attacks are absorbed in front of rIDM**, by a CDN, WAF or edge proxy.
  rIDM limits what one caller can do; it cannot absorb a flood.
- [ ] **Clocks are synchronised** (NTP) on every node. Token expiry, TOTP and DPoP proofs
  depend on it.

## Operations

- [ ] **Liveness probes `/healthz`, readiness and load-balancer checks probe `/readyz`.**
  [Container image](container.md#health-checks)
- [ ] **Logs are JSON (`LOG_FORMAT=json`) and collected**, with alerts on the lines
  listed in [Observability](observability.md#logs).
- [ ] **Metrics are scraped from every node**, with alerts on job errors, audit sink
  drops and failures, dead-lettered webhooks and readiness.
  [Observability](observability.md#metrics)
- [ ] **Audit rows are shipped off the host** with `AUDIT_SINK_URL`, if your policy
  requires a copy an intruder on the host cannot alter.
  [Observability](observability.md#audit-log-and-export)
- [ ] **`RETENTION_DAYS` and each tenant's audit retention match your policy.**
  [Scaling and performance](scaling.md#background-jobs-on-many-nodes)
- [ ] **Postgres is backed up, encrypted and access-controlled, and a restore has been
  tested with the master key.** A backup and restore guide, and an upgrade guide, are
  planned (plan item 11.5) and not written yet; until then follow your usual Postgres
  practice. [Postgres and Valkey](postgres-valkey.md#backups)
- [ ] **Load has been tested on your hardware** with `perf/token.js` if you expect high
  volume. [Scaling and performance](scaling.md#load-testing)
