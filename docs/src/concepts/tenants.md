# Tenants and issuers

A tenant is an isolated identity domain: its own users, groups, roles, clients,
signing keys, policies, branding and administrators. One rIDM deployment hosts
any number of them. A user of one tenant does not exist in another, a token
issued by one tenant is not valid in another, and an administrator of one
tenant cannot see another unless they are a global administrator.

Tenants suit anything that needs a separate login experience or separate
policy: customers of a SaaS product, business units, or simply `staging` and
`production` side by side.

## One issuer per tenant

Every tenant is its own OpenID Connect issuer. With `PUBLIC_URL` set to
`https://id.example.com`, the tenant with slug `acme` is the issuer
`https://id.example.com/t/acme`, and every protocol endpoint lives under that
prefix:

| Endpoint | Path |
|----------|------|
| Discovery | `/t/acme/.well-known/openid-configuration` |
| JWKS | `/t/acme/.well-known/jwks.json` |
| Authorization | `/t/acme/authorize` |
| Token | `/t/acme/token` |
| UserInfo | `/t/acme/userinfo` |

The full list is in [HTTP endpoints](../reference/endpoints.md).

A separate issuer per tenant is what keeps tenants apart at the protocol level.
Each tenant publishes its own keys, so a relying party that trusts
`https://id.example.com/t/acme` cannot be handed a token signed for another
tenant: the `iss` claim differs and the signing key is not in the set it
fetched. Tokens also carry the tenant's id as `tid`, which a relying party that
serves several tenants of one deployment can key on.

Because the issuer is derived from `PUBLIC_URL`, choose that value before
anything depends on it. Changing it changes every tenant's issuer, and every
relying party configured with the old one stops accepting tokens.

A tenant's **slug** is 1 to 63 lower-case letters, digits and hyphens, and
cannot start or end with a hyphen. It appears in every URL, so treat it as
permanent.

A tenant can instead be served on a host of its own, such as
`https://login.acme.com`, which then becomes its issuer; see
[Custom domains](#custom-domains) below.

## Custom domains

A tenant with `settings.custom_domain` set is served on that host as if every
request had come in under `/t/{slug}`: `https://login.acme.com/authorize` is
the tenant's authorization endpoint, and the issuer is
`https://login.acme.com`. A custom domain serves its own tenant and nothing
else. Only these paths pass through unchanged:

- the health probes `/healthz` and `/readyz`, which a load balancer asks
  whatever host it uses;
- `/.well-known/webfinger` and `/.well-known/security.txt`;
- the tenant's own `/t/{slug}/...` and `/scim/v2/{slug}/...` paths.

Every other path is rewritten under the tenant's prefix, so the admin API,
`/metrics`, `/docs`, `/openapi.json` and other tenants' `/t/{other}/...`
paths answer `404` on a custom domain. A customer's host can never be used to
reach the operator's administration surface or another customer's tenant.
Session cookies are named per tenant with `Path=/` (see
[The SSO session](flows-and-sessions.md#the-sso-session)), so single sign-on
works on the custom domain as it does on the primary host. Setting one up is
covered in [Custom domains](../admin/custom-domains.md).

## The master tenant

Every deployment has a tenant called `master`, created by the first migration.
It is an ordinary tenant with one extra role: it hosts the **global
administrators**. An administrative role held in `master` applies to every
tenant; the same role held in any other tenant applies to that tenant only.
Only global administrators can create tenants, and `master` itself can be
neither deleted nor disabled.

The first global administrator is created by the bootstrap step (see
[Run rIDM locally](../quickstarts/local.md)). Keep `master` for administrators;
put applications and their users in tenants of their own, so that the tenant
holding the keys to every other tenant has as few users and clients as
possible.

## What a new tenant starts with

Creating a tenant seeds it with everything it needs to work at once:

- the standard scopes `openid`, `profile`, `email`, `phone`, `address` and
  `offline_access`;
- the built-in resource server `urn:ridm:admin`, carrying the catalogue of
  `ridm:*` admin permissions, and five built-in roles that hold them
  (`ridm:owner`, `ridm:admin`, `ridm:user-manager`, `ridm:client-manager`,
  `ridm:viewer`);
- the built-in resource server `urn:ridm:account`, the audience of the
  self-service account API;
- two built-in public clients, `ridm-admin-console` and `ridm-account-console`,
  through which the consoles sign in to this tenant;
- default settings for every policy.

Signing keys are not created up front: the tenant's first key is generated the
first time something needs to sign with it (see
[Signing keys and the master key](keys.md)).

## Tenant settings

A tenant's policies live in one settings document, edited in the admin console
under Settings, through `PATCH /admin/tenants/{slug}` as a JSON merge patch, or
as part of the [tenant configuration document](config-as-code.md). Every
section has defaults, so an empty document is a valid configuration.

| Section | Governs |
|---------|---------|
| `password` | length, character classes, history, expiry, breached-password check |
| `session` | SSO idle and absolute timeouts, concurrent sessions, trusted-device lifetime, default token lifetimes |
| `mfa`, `mfa_methods` | who must pass a second step, and which second-step methods are offered |
| `auth` | which first-factor methods the login page offers (password, magic link, email or SMS code, passkey) |
| `registration` | self-registration, email verification, terms, allowed email domains |
| `lockout`, `captcha`, `rate_limits` | brute-force protection and request ceilings |
| `keys` | signing algorithm, RSA key size, rotation interval and overlap |
| `locale`, `branding` | languages offered, and the login page's look |
| `dcr`, `discovery` | dynamic client registration and WebFinger email domains |
| `notifications`, `audit`, `account` | security notices to users, audit retention, self-service rights |
| `custom_domain`, `features` | the tenant's own host, and free-form feature flags |

[Tenants and tenant settings](../admin/tenants.md) goes through them one by one,
and [Tenant configuration document](../reference/tenant-document.md) gives
every field and default.

A tenant has a status of `active` or `disabled`. A disabled tenant's endpoints
answer `403` (discovery, sign-in and token requests alike), while its
administrators can still read and re-enable it through the admin API.

## Isolation in the database

All tenants share one Postgres database. Every tenant-scoped table carries a
`tenant_id` column, every index on those tables leads with it, and foreign keys
between tenant-scoped tables include it, so a row can never point at a row of
another tenant.

On top of that, every tenant-scoped table has a **forced row level security**
policy keyed on a per-transaction setting, `app.tenant_id`. The server opens
each unit of work in a transaction bound to one tenant, and within it Postgres
itself hides every other tenant's rows. A query that forgets its
`WHERE tenant_id = ...` returns nothing from other tenants rather than leaking
them. The setting is bound with `set_config(..., true)`, so it ends with the
transaction and can never carry over to the next request on a pooled
connection. The few operations that must see every tenant (bootstrap, the
background jobs, the global audit chain) open an explicitly marked cross-tenant
transaction instead.

Row level security is defence in depth against mistakes in the server's own
queries, not a boundary against someone who holds database credentials. It
does, however, depend on how the server connects: Postgres superusers bypass
row level security and table owners can disable it, so `DATABASE_URL` must name
a non-superuser role with data-manipulation rights only, and migrations are
applied by the schema owner (`ridm-api migrate`). See [Postgres and Valkey](../deploy/postgres-valkey.md).

## Outbound requests

Some URLs rIDM calls are chosen by tenant administrators or by clients
registering themselves, not by the operator: webhook targets, back-channel
logout URIs, client `jwks_uri`s, upstream identity provider endpoints, a
tenant's HTTP email or SMS gateway, its CAPTCHA `verify_url` and its SMTP
host. Left unchecked, any of them could point rIDM at the operator's own
network (server-side request forgery). rIDM therefore resolves these hosts
itself and connects only to public addresses:

- private, loopback, link-local, carrier-grade NAT, unique-local,
  documentation, benchmarking and reserved ranges are refused, including IPv6
  forms that embed such an IPv4 address;
- the check happens when the connection is made, not only when the URL is
  saved, so a public name that later resolves to a private address (DNS
  rebinding) is still refused;
- redirects are not followed, since a redirect would be a second, unchecked
  target, and `HTTP_PROXY`/`HTTPS_PROXY` are ignored, since a proxy would
  resolve the name out of the check's sight;
- for development, loopback stays allowed when it is named as such: the host
  `localhost` or a loopback IP literal.

A tenant SMTP host that is a private IP literal is refused when it is saved.
When sending, rIDM connects to the address it vetted (the first allowed one)
and verifies TLS against the configured hostname.

URLs the operator sets in the environment, such as the audit sink and the
breached-password check, are trusted and not filtered.

## Tenants and the cache

Tenants are looked up on every request, so they are read through the two-level
cache (in-process, then Valkey) and evicted on every write, on every node. A
settings change takes effect on the next request everywhere; there is nothing
to restart.
