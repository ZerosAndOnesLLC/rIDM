# Deployment overview

rIDM is one stateless server binary (`ridm-api`) in front of two stateful services it
does not run itself: Postgres and Valkey. The browser pages (sign-in, consent, the admin
and account consoles) are a static export that the container image compiles into the
server and serves on its own origin; they can also be hosted on any static web server.
This page describes the moving parts and what each one needs; the rest of this section
covers each part in detail.

rIDM is pre-release (`0.1.0-dev`). Several packaging pieces an operator would expect are
planned and not yet present: a
Helm chart (11.2), reverse-proxy example files and a production docker-compose profile
(11.3), published release binaries and signed images (11.4), and backup/restore and
upgrade guides (11.5). Where one of these would naturally appear, these pages say so.

## The parts

```text
                      browsers, relying parties, SCIM clients
                                     |
                                     | https
                                     v
                  +-------------------------------------+
                  |  reverse proxy / load balancer      |   TLS
                  |  (nginx, Caddy, a cloud LB, ...)    |
                  +-------------------------------------+
                                     |
                       API paths and the UI's pages
                                     |
          +-------------+-------------+
          |             |             |
     +---------+   +---------+   +---------+
     | ridm-api|   | ridm-api|   | ridm-api|   stateless nodes, any number,
     +---------+   +---------+   +---------+   each serving the embedded UI
          |  \          |          /  |
          |   +---------+---------+   |
          v             v             v
     +-----------+           +-----------------+
     | Postgres  |           | Valkey          |
     | primary   |           | standalone,     |
     | (+ read   |           | Sentinel or     |
     |  replica) |           | Cluster         |
     +-----------+           +-----------------+

   outbound from the nodes: SMTP or an HTTP mail API, an SMS webhook, webhook
   receivers, upstream identity providers, the breached-password range API,
   an audit sink, an OTLP collector
```

| Part | What it is | Required |
|------|------------|----------|
| `ridm-api` | The HTTP server: OIDC and OAuth endpoints, the flow API the sign-in pages drive, the admin, account and SCIM APIs, background jobs | yes |
| Postgres | The system of record: tenants, users, credentials, clients, keys, refresh tokens, audit log, queues. Version 16 or later; CI and the compose file run 18.6 | yes |
| Valkey | Shared short-lived state and the cache: browser sessions, authorization codes, login flows, one-time codes, rate-limit counters, the access-token denylist, job leader locks, cache invalidation. CI and the compose file run Valkey 9.1 | yes |
| UI | `ui/out`, the Next.js static export of the sign-in pages and the consoles; compiled into the image's binary and served by every node, or hosted separately | yes, for any browser sign-in |
| Mail | The deployment's SMTP defaults (`SMTP_*`), which tenants may override with their own SMTP server or an HTTP mail API | for verification, recovery, invitations, email one-time codes |
| SMS | A per-tenant HTTP webhook configured in the admin console; there is no deployment-wide SMS default | only for SMS one-time codes |

The details of what lives where are in [Postgres and Valkey](postgres-valkey.md).

## Stateless nodes

A node keeps nothing that another node needs. Everything a second request might depend
on (a browser session, a login flow half-way through, an authorization code, a
rate-limit count) is in Valkey or Postgres, so any node can serve any request and no
sticky sessions are needed. Each node does keep an in-process cache of the hottest
read-mostly objects (tenants, clients, signing keys) for about 15 seconds; writes evict
it on every node through a Valkey pub/sub channel. See
[Scaling and performance](scaling.md).

Nodes do share three things, and they must match across the fleet:

- **the same Postgres database and the same Valkey deployment** (one logical Valkey:
  a standalone server, a Sentinel group or a cluster);
- **the same configuration** for the settings that shape what a client sees, above all
  `PUBLIC_URL` (every tenant's issuer is `{PUBLIC_URL}/t/{slug}`), `UI_URL`,
  `TRUSTED_PROXIES` and `COOKIE_SECURE`;
- **the same master key** (`MASTER_KEY` or `MASTER_KEY_FILE`, with `MASTER_KEY_VERSION`
  and `MASTER_KEY_PREVIOUS` during a rotation). It encrypts signing keys, MFA
  credentials, identity-provider secrets and messaging settings at rest; a node with a
  different key cannot read them. See [Signing keys and the master key](../concepts/keys.md).

Background jobs (key rotation, cleanup, delivery retries) run in every node's process
and take a Valkey lock per pass, so each job runs on one node at a time without any
node being special.

## Where the UI is served from

**Embedded (the default).** The container image builds the UI's static export and
compiles it into the server (the `embedded-ui` cargo feature), so every node serves the
sign-in pages and both consoles itself, on `PUBLIC_URL`'s origin: `/login/`,
`/consent/`, `/console/`, `/account/` and the rest. Leave `UI_URL` unset (it defaults to
`PUBLIC_URL`) and there is nothing else to host; the proxy sends every path to rIDM.
API routes always win over pages, and a miss under an API prefix (`/t/`, `/admin/`,
`/scim/`, `/.well-known/`) stays the API's `404` rather than a page. Pages are served
with `trailingSlash` semantics (`/login` redirects to `/login/`), hashed build assets
under `/_next/static/` are cached for a year as immutable, pages revalidate against an
`ETag`, and text is gzip-compressed for clients that accept it. `EMBEDDED_UI=false`
turns the pages off on a node that should serve the API alone.

**Hosted separately.** A binary built without the feature (a plain
`cargo build -p ridm-api`) serves the API only, and a node with `UI_URL` on another
origin does not serve its embedded pages. Build the UI yourself:

```bash
cd ui
npm install
npm run build          # static export to ui/out
```

and serve `ui/out` from any static web server. Two layouts work:

- **Same origin.** One host name; the proxy sends API paths (`/t/`, `/admin/`, `/scim/`,
  `/.well-known/`, `/openapi.json`, `/healthz`, `/readyz`) to rIDM and everything else
  to `ui/out`. Leave `UI_URL` unset and build the UI with `NEXT_PUBLIC_API_URL` empty.
  [TLS and reverse proxies](tls-and-proxies.md) has nginx and Caddy starting points.
- **Separate host.** Build the UI with `NEXT_PUBLIC_API_URL=https://id.example.com` and
  set `UI_URL` on the server to where the pages are hosted. rIDM sends browsers to
  `{UI_URL}/login/`, `{UI_URL}/consent/` and the other pages, admits the UI's origin for
  cross-origin calls, and registers the built-in console clients with redirect URIs
  under `UI_URL`.

Either way the static host must add the framing headers the pages cannot set
themselves (see [Security controls](../admin/security-controls.md#security-headers)).
In development the UI runs under `next dev` with the API proxied; see
[Run rIDM locally](../quickstarts/local.md).

A tenant's [custom domain](../admin/custom-domains.md) moves its issuer and endpoints to
that host. With the embedded UI its sign-in pages and account console move there too;
with the UI hosted separately they stay at `UI_URL`.

## Outbound connections

Nodes make outbound requests, so egress rules need to allow whichever of these a
deployment uses:

| Destination | When |
|-------------|------|
| SMTP server or HTTP mail API | any tenant sends email |
| SMS webhook | a tenant configured SMS |
| Webhook receivers | a tenant registered webhooks |
| Upstream identity providers (discovery, token and JWKS endpoints) | a tenant uses [identity brokering](../concepts/brokering.md) |
| Client JWKS URLs | a client authenticates with `private_key_jwt` and a `jwks_uri` |
| `https://api.pwnedpasswords.com/range/` or `BREACH_CHECK_URL` | a tenant turns on the breached-password check; `BREACH_CHECK_URL=off` disables it for the deployment |
| `AUDIT_SINK_URL` | audit export is configured |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | trace export is configured |

URLs a tenant administrator or a client registration chooses (webhook receivers,
back-channel logout URIs, client `jwks_uri`, identity-provider endpoints, a tenant's HTTP
email or SMS gateway, a CAPTCHA `verify_url`, a tenant's SMTP host) are only ever
connected to at public addresses: private, loopback, link-local and similar ranges are
refused unless `OUTBOUND_ALLOW_NETWORKS` opens that network for internal applications,
redirects are not followed, and `HTTP(S)_PROXY` is ignored. The URLs the
operator sets in the environment (`AUDIT_SINK_URL`, `BREACH_CHECK_URL`, the collector,
the deployment's `SMTP_HOST`) are not filtered. See
[Rate limits, IP rules and CAPTCHA](../admin/security-controls.md).

## Where to go next

- [docker-compose](docker-compose.md): the compose file in `deploy/`, for evaluation and
  development.
- [Container image](container.md): building and running the image, migrations, health checks.
- [TLS and reverse proxies](tls-and-proxies.md): `PUBLIC_URL`, `TRUSTED_PROXIES`, cookies.
- [Postgres and Valkey](postgres-valkey.md): roles, row level security, pools, topologies.
- [Scaling and performance](scaling.md) and [Observability](observability.md).
- [Production checklist](checklist.md).
- Every environment variable: [Server configuration](../reference/configuration.md).
