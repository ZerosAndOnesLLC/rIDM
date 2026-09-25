# rIDM

[![ci](https://github.com/ZerosAndOnesLLC/rIDM/actions/workflows/ci.yml/badge.svg)](https://github.com/ZerosAndOnesLLC/rIDM/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A modern, multi-tenant Identity Management server: OpenID Connect provider, JWT issuer,
user/group/role management, MFA, and identity brokering, with a bundled admin console and
end-user account console.

> **Status:** v0.1.0, the first release. Until 1.0.0 a minor version may break
> compatibility; [`CHANGELOG.md`](CHANGELOG.md) says how under **Upgrade notes**. See
> [`working-plan.md`](working-plan.md) for the roadmap and what is still to come.

**Website:** <https://zerosandonesllc.github.io/rIDM/>

**Documentation:** <https://zerosandonesllc.github.io/rIDM/docs/> — concepts,
quickstarts, the admin guide, the API reference, deployment and migration from Keycloak
or Auth0. The source is in [`docs/`](docs/); the website's is in [`site/`](site/).

## Why rIDM

- **Cloud-agnostic.** Runs anywhere a container, Postgres, and Valkey run: bare metal,
  docker-compose, Kubernetes, any cloud. No provider-specific dependencies in the
  default build.
- **Multi-tenant from the first migration.** Every tenant has its own issuer
  (`{PUBLIC_URL}/t/{slug}`), signing keys, users, clients, policies, branding, and
  admins. Every tenant-scoped table is protected by forced Postgres row level security
  bound per transaction, with composite foreign keys so rows can never cross tenants.
- **Standards, not surprises.** Authorization code + PKCE, client credentials, refresh
  token rotation with reuse detection, device flow, backchannel sign-in (CIBA), PAR,
  JAR/JARM, DCR, RP-initiated, back-channel and front-channel logout, token exchange,
  DPoP, mutual-TLS client authentication and certificate-bound tokens, a per-client
  FAPI 2.0 Security Profile, and SAML 2.0 both ways: as an identity
  provider and as the service provider of upstream SAML IdPs (SSO over both browser
  bindings, front-channel Single Logout). LDAP and Active Directory directories, and
  Kerberos desktop sign-in (SPNEGO). No implicit, hybrid, or password grants.
- **One image.** A deployment is the API image plus Postgres and Valkey. The image
  compiles the UI's static export into the server, which serves the sign-in pages and
  both consoles on its own origin; the same export can also go on any static host or
  CDN.
- **Config as code.** Every tenant exports to one JSON document and imports
  idempotently, for GitOps and reproducible environments.
- **Built for scale.** Stateless API nodes, cache-first reads, short-lived JWTs, Valkey
  for sessions and flow state, indexes that lead with `tenant_id`.

## Features

Each links to its page in the documentation.

- **OpenID Connect provider** per tenant: discovery, JWKS, `/authorize`, PAR, `/token`,
  `/userinfo`, introspection, revocation, logout, dynamic client registration and
  WebFinger ([endpoints](https://zerosandonesllc.github.io/rIDM/docs/reference/endpoints.html),
  [tokens](https://zerosandonesllc.github.io/rIDM/docs/concepts/tokens.html),
  [token claims](https://zerosandonesllc.github.io/rIDM/docs/reference/token-claims.html)).
- **Browser sign-in flows**: password, magic link, email and SMS codes, self-registration,
  invitations, password reset, consent, CAPTCHA, localized pages and messages, session
  policy and security notices
  ([flows and sessions](https://zerosandonesllc.github.io/rIDM/docs/concepts/flows-and-sessions.html)).
- **MFA and passkeys**: TOTP, email and SMS codes, WebAuthn passkeys (passwordless or as a
  second step), recovery codes, per-tenant and per-role policy, client step-up
  ([MFA](https://zerosandonesllc.github.io/rIDM/docs/concepts/mfa.html),
  [MFA policy](https://zerosandonesllc.github.io/rIDM/docs/admin/mfa-policy.html)).
- **Adaptive authentication**: risk scoring on new devices, new countries, impossible
  travel and velocity, with step-up and block thresholds
  ([adaptive auth](https://zerosandonesllc.github.io/rIDM/docs/admin/adaptive-auth.html)).
- **Users, groups, roles, organizations** and resource servers with scopes and
  permissions ([users, groups and roles](https://zerosandonesllc.github.io/rIDM/docs/concepts/users-groups-roles.html),
  [organizations](https://zerosandonesllc.github.io/rIDM/docs/concepts/organizations.html),
  [resource servers](https://zerosandonesllc.github.io/rIDM/docs/concepts/resource-servers.html)).
- **Identity brokering**: upstream OIDC and social providers, SAML IdPs, LDAP and Active
  Directory, Kerberos desktop sign-in
  ([brokering](https://zerosandonesllc.github.io/rIDM/docs/concepts/brokering.html),
  [SAML upstream](https://zerosandonesllc.github.io/rIDM/docs/admin/saml-upstream.html),
  [LDAP](https://zerosandonesllc.github.io/rIDM/docs/admin/ldap.html),
  [Kerberos](https://zerosandonesllc.github.io/rIDM/docs/admin/kerberos.html)).
- **SAML 2.0 identity provider** for SAML applications
  ([SAML IdP](https://zerosandonesllc.github.io/rIDM/docs/admin/saml-idp.html)).
- **High-assurance clients**: CIBA, FAPI 2.0, mutual TLS, DPoP, token exchange
  ([CIBA and FAPI](https://zerosandonesllc.github.io/rIDM/docs/admin/ciba-fapi.html),
  [mTLS](https://zerosandonesllc.github.io/rIDM/docs/admin/mtls.html),
  [clients](https://zerosandonesllc.github.io/rIDM/docs/concepts/clients.html)).
- **Administration**: an admin API guarded by per-tenant permissions, the admin and account
  consoles, the `ridm` command line, impersonation, SCIM 2.0 provisioning, webhooks and an
  audit log ([access](https://zerosandonesllc.github.io/rIDM/docs/admin/access.html),
  [consoles](https://zerosandonesllc.github.io/rIDM/docs/admin/consoles.html),
  [CLI](https://zerosandonesllc.github.io/rIDM/docs/admin/cli.html),
  [admin API](https://zerosandonesllc.github.io/rIDM/docs/reference/admin-api.html),
  [SCIM](https://zerosandonesllc.github.io/rIDM/docs/admin/scim.html),
  [webhooks and audit](https://zerosandonesllc.github.io/rIDM/docs/admin/webhooks-audit.html)).
- **Security controls**: rate limits, IP rules, CAPTCHA, breached-password check, custom
  domains ([security controls](https://zerosandonesllc.github.io/rIDM/docs/admin/security-controls.html),
  [custom domains](https://zerosandonesllc.github.io/rIDM/docs/admin/custom-domains.html)).
- **Keys**: per-tenant signing keys with rotation, a master key encrypting secrets at rest,
  optionally held in an HSM or KMS
  ([keys](https://zerosandonesllc.github.io/rIDM/docs/concepts/keys.html),
  [key custody](https://zerosandonesllc.github.io/rIDM/docs/deploy/key-custody.html)).
- **Operations**: Valkey cluster and sentinel, Postgres read replicas, per-region data
  residency, Prometheus metrics and OpenTelemetry traces
  ([Postgres and Valkey](https://zerosandonesllc.github.io/rIDM/docs/deploy/postgres-valkey.html),
  [data residency](https://zerosandonesllc.github.io/rIDM/docs/deploy/data-residency.html),
  [observability](https://zerosandonesllc.github.io/rIDM/docs/deploy/observability.html)).
- **`ridm-auth`**: a crate that validates rIDM tokens in your own Rust API
  ([protect an API](https://zerosandonesllc.github.io/rIDM/docs/quickstarts/protect-an-api.html)).

## Quick start (docker-compose)

```bash
export MASTER_KEY=$(openssl rand -hex 32)      # keep this safe; it encrypts secrets at rest
docker compose -f deploy/docker-compose.yml --profile dev up -d
curl http://localhost:8080/readyz
```

The `dev` profile adds [Mailpit](http://localhost:8025) to catch outbound email and, on
first run, seeds a global administrator in the `master` tenant (`admin@ridm.local` /
`ChangeMe-Now-1234`, changed at first sign-in). The admin console is at
<http://localhost:8080/console/>. See
[Run rIDM locally](https://zerosandonesllc.github.io/rIDM/docs/quickstarts/local.html) and
[docker-compose](https://zerosandonesllc.github.io/rIDM/docs/deploy/docker-compose.html); for
production, start with the
[deployment overview](https://zerosandonesllc.github.io/rIDM/docs/deploy/overview.html) and the
[production checklist](https://zerosandonesllc.github.io/rIDM/docs/deploy/checklist.html).

## Configuration

Entirely environment-driven; the same image runs everywhere. Every variable is listed in
[`.env.example`](.env.example) and documented in
[Server configuration](https://zerosandonesllc.github.io/rIDM/docs/reference/configuration.html).
Tenants are configured through the admin API, the consoles or one JSON document per tenant
([tenant configuration document](https://zerosandonesllc.github.io/rIDM/docs/reference/tenant-document.html)).

## Documentation

| Section | What's there |
|---------|--------------|
| [Concepts](https://zerosandonesllc.github.io/rIDM/docs/concepts/tenants.html) | tenants, clients, users, tokens, keys, flows, brokering, events |
| [Quickstarts](https://zerosandonesllc.github.io/rIDM/docs/quickstarts/local.html) | run locally, protect an API, SPA, server-side web app, machine-to-machine |
| [Admin guide](https://zerosandonesllc.github.io/rIDM/docs/admin/consoles.html) | consoles, CLI, tenants, users, clients, MFA, SAML, LDAP, SCIM, webhooks, keys |
| [Reference](https://zerosandonesllc.github.io/rIDM/docs/reference/endpoints.html) | endpoints, admin API (OpenAPI), token claims, configuration, errors |
| [Deployment](https://zerosandonesllc.github.io/rIDM/docs/deploy/overview.html) | compose, container, Helm, TLS, scaling, backup, upgrades, checklist |
| [Migration](https://zerosandonesllc.github.io/rIDM/docs/migrate/overview.html) | from Keycloak or Auth0 |

To work on rIDM itself, see [CONTRIBUTING.md](CONTRIBUTING.md) and
[GETTING-STARTED.md](GETTING-STARTED.md).

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
| `deploy/` | docker-compose for evaluation (`docker-compose.yml`), the production compose stack (`deploy/production`, smoke test in `deploy/production/smoke`), reverse-proxy configurations for nginx, Caddy and Traefik (`deploy/proxy`), the Helm chart (`deploy/helm/ridm`, smoke test in `deploy/helm/smoke`) |
| `docs/` | the documentation site (mdBook): concepts, quickstarts, admin guide, reference, deployment, migration |
| `site/` | the project website (static HTML), published with the docs to GitHub Pages by `scripts/pages/build.sh` |
| `api/fuzz/` | cargo-fuzz targets and their seed corpora |
| `perf/` | k6 load tests: the PR smoke and the release baseline |
| `conformance/` | the OpenID Foundation conformance rig |
| `scripts/release/` | release checks: every version agrees with the tag, notes from `CHANGELOG.md` |
| `.github/` | CI workflows (the `release` workflow publishes signed images, the chart and static binaries from a `v*` tag), issue and PR templates |

## Releases

Each `v*` tag publishes a signed multi-arch image (`ghcr.io/zerosandonesllc/ridm`, amd64
and arm64, with an SBOM), the Helm chart (`oci://ghcr.io/zerosandonesllc/charts/ridm`),
static Linux binaries of `ridm-api` and `ridm`, and a GitHub release with signed
checksums; see [Releases and verification](https://zerosandonesllc.github.io/rIDM/docs/deploy/releases.html)
and [`CHANGELOG.md`](CHANGELOG.md). The roadmap is in [`working-plan.md`](working-plan.md).

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md): environment setup, conventions, test matrix, CI, PR
  checklist.
- [SECURITY.md](SECURITY.md): how to report vulnerabilities privately.
- [THREAT_MODEL.md](THREAT_MODEL.md): what rIDM protects, from whom, what stops each
  attack today, and what it leaves to the deployment.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT. See [LICENSE](LICENSE).
