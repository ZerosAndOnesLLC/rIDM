# Introduction

rIDM is a self-hosted, multi-tenant identity server written in Rust. It is an
OpenID Connect provider and JWT issuer with user, group and role management,
multi-factor authentication, passkeys and identity brokering, plus two web
consoles: one for administrators and one for end users managing their own
account.

A deployment is the `ridm-api` server, Postgres and Valkey (or Redis). Every
tenant it hosts has its own issuer, signing keys, users, clients, policies and
administrators. Applications sign users in through the standard authorization
code flow, and APIs accept the resulting access tokens by checking them
against the tenant's published keys (or, for clients that ask for opaque access
tokens, at the tenant's introspection endpoint).

> **Status:** `0.1.0`, the first release. Until 1.0.0 a minor version may break
> compatibility, and the [changelog](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/CHANGELOG.md)
> says how. `ridm-auth` is not on crates.io yet. The [working plan](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/working-plan.md)
> lists what is done and what is still to come.

## Who it is for

- **Operators** who want an identity provider they run themselves: on bare
  metal, in docker-compose, on Kubernetes or on any cloud, with the same image
  and nothing but environment variables to configure it.
- **Application and API developers** who need standard OAuth 2.0 and OpenID
  Connect behaviour to integrate against, without provider-specific SDKs. A Rust
  API can use the [`ridm-auth`](https://github.com/ZerosAndOnesLLC/rIDM/tree/main/crates/ridm-auth)
  crate to validate tokens; anything else uses an ordinary OIDC or JWT library.
- **Teams serving several customers or business units** from one deployment,
  each as a tenant with its own login page, policies and administrators.
- **Teams leaving another identity provider**, who need password hashes,
  users and configuration to come across without forcing every user to reset.

## What it deliberately does not do

rIDM implements the parts of OAuth 2.0 and OpenID Connect that current security
guidance recommends and refuses the rest, so that a misconfigured client cannot
fall back to a weaker flow.

- **No implicit flow, no hybrid flow, no resource owner password credentials
  grant.** `/authorize` accepts `response_type=code` only, and the password
  never travels to an application. Discovery advertises `response_types_supported:
  ["code"]`.
- **No `plain` PKCE.** A code challenge must use `S256`; public clients must
  always send one.
- **No cloud-specific dependencies.** The default build needs a container
  runtime, Postgres and Valkey and nothing else. Email goes out over SMTP or an
  HTTP webhook, text messages over an HTTP gateway, and secrets at rest are
  encrypted with a master key you supply. Integrations with cloud key
  management services and HSMs are planned, not present.

Some things are not built yet, and this book says so where you would look for
them: mutual-TLS client authentication, HSM and cloud KMS key custody, and
per-tenant database routing are planned.

## How this book is organised

| Section | Read it for | Starts at |
|---------|-------------|-----------|
| Concepts | The model: tenants, clients, roles, tokens, keys, sessions, and why they work the way they do | [Tenants and issuers](concepts/tenants.md) |
| Quickstarts | A running server and a first integration, one scenario per page | [Run rIDM locally](quickstarts/local.md) |
| Admin guide | Day-to-day administration through the consoles, the `ridm` CLI and the admin API | [The admin and account consoles](admin/consoles.md) |
| Reference | Endpoints, the admin API, token claims, environment variables, the tenant document, errors | [HTTP endpoints](reference/endpoints.md) |
| Deployment | Running rIDM in production: containers, TLS, Postgres and Valkey, scaling, observability | [Deployment overview](deploy/overview.md) |
| Migration | Moving users and configuration from another identity provider | [Migrating to rIDM](migrate/overview.md) |

The concepts pages explain the reasoning; the admin guide and reference hold
the exhaustive lists of settings, fields and endpoints.

## Where to start

**Running rIDM.** Start with [Run rIDM locally](quickstarts/local.md) to have a
server, the consoles and a first administrator on screen, then read the
[Deployment overview](deploy/overview.md) before putting it anywhere others can
reach. [Tenants and issuers](concepts/tenants.md) and
[Signing keys and the master key](concepts/keys.md) explain the two decisions
you cannot easily undo later: your public URL and your master key.

**Integrating an application or API.** To accept rIDM tokens in an API, read
[Protect a Rust API with ridm-auth](quickstarts/protect-an-api.md). To sign
users in from a browser application, read
[Sign in from a single-page app](quickstarts/spa.md), or
[Sign in from a server-side web app](quickstarts/web-app.md) for an application
that keeps a secret. [Clients](concepts/clients.md),
[Resource servers, scopes and permissions](concepts/resource-servers.md) and
[Tokens](concepts/tokens.md) explain what you are configuring.

**Moving from another provider.** Read [Migrating to rIDM](migrate/overview.md),
then the page for your current provider.
