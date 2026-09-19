# Custom domains

By default a tenant lives under the deployment's own host: its issuer is
`{PUBLIC_URL}/t/{slug}`, for example `https://id.example.com/t/acme`. A tenant can
instead be served on a host of its own, such as `login.acme.example`, so that its
issuer, discovery document and endpoints carry the customer's name.

## What changes

With `settings.custom_domain` set to `login.acme.example`:

| | Without a custom domain | With one |
|--|-------------------------|----------|
| Issuer (`iss` in every token) | `https://id.example.com/t/acme` | `https://login.acme.example` |
| Discovery | `https://id.example.com/t/acme/.well-known/openid-configuration` | `https://login.acme.example/.well-known/openid-configuration` |
| Endpoints in discovery | `https://id.example.com/t/acme/token`, … | `https://login.acme.example/token`, … |
| JWKS | `…/t/acme/.well-known/jwks.json` | `https://login.acme.example/.well-known/jwks.json` |
| Identity-provider callback | `…/t/acme/broker/{alias}/callback` | `https://login.acme.example/broker/{alias}/callback` |
| Passkey relying party id | the UI's host | `login.acme.example` |
| Sign-in pages and account console (embedded UI) | `https://id.example.com/login/`, `/account/` | `https://login.acme.example/login/`, `/account/` |

Every tenant endpoint answers on the custom host without the `/t/{slug}` prefix:
discovery, JWKS, `/authorize`, `/par`, `/token`, `/userinfo`, `/introspect`, `/revoke`,
`/end_session`, dynamic registration, the flow API, branding and brokering. The prefixed
paths on the primary host keep working, and report the custom issuer too: the issuer is
a property of the tenant, not of the URL a document was fetched from.

## What the custom host serves

A custom host serves its tenant and nothing else. Every request on it is mapped onto the
tenant's routes by prefixing the path with `/t/{slug}`, except:

| Path on the custom host | Served as |
|-------------------------|-----------|
| `/healthz`, `/readyz` | The deployment's probes, unchanged, so a load balancer can probe any host |
| `/.well-known/webfinger`, `/.well-known/security.txt` | The host-wide documents, unchanged |
| `/t/acme/…` (the tenant's own prefix) | Unchanged, for pages or clients that name the tenant explicitly |
| `/scim/v2/acme/…` (the tenant's own SCIM base) | Unchanged |
| A file of the embedded UI (`/login/`, `/consent/`, `/account/`, `/_next/static/…`), GET or HEAD | The page, when the server serves the embedded UI; not the admin console (`/console/`) or the root page |

Everything else lands under the tenant's prefix, so it reaches only the tenant's routes or
nothing: another tenant's `/t/{other}/…` and `/scim/v2/{other}/…`, the admin API
(`/admin/…`), `/metrics`, `/docs` and `/openapi.json` all answer `404` on the custom
host. The primary host is unchanged and keeps serving everything.

Other effects:

- **CORS**: `https://login.acme.example` is admitted as an origin under the tenant's
  paths, alongside the origins registered on its clients.
- **DPoP**: a proof's `htu` may name either the primary URL or the custom one.
- **Registration management**: `registration_client_uri` for dynamically registered
  clients uses the custom host.

Only exact files of the UI pass: a page named without its trailing slash is left to the
tenant's routes, which own `/account/me`, `/register` and the like, so `/login` (no
slash) is a `404` on the custom host rather than a redirect.

**The sign-in pages move with the tenant.** When the server serves the
[embedded UI](../deploy/overview.md#where-the-ui-is-served-from), every page it sends the
tenant's users to is on the custom host: `/authorize` (on either host) redirects to
`https://login.acme.example/login/`, and logout, the device page, and the links in
recovery, invitation, verification and magic-link emails all point there. The pages call
the tenant's flow API on the same host, so the session they set is the one `/authorize`
on the custom host sees, and passkeys (whose relying party id is the custom domain) work
there. The account console is served on the custom host too, and its built-in client
accepts `https://login.acme.example/account/callback/` alongside the primary host's,
updated whenever the domain changes. The admin console is not: administer the tenant
through the primary host. With the UI hosted separately (`UI_URL` on another origin, or
a binary without the embedded UI), the pages stay at `UI_URL`; see the caveat below.

## Setting a domain

Console: Settings → General → Custom domain. Admin API, with `ridm:tenants:write`:

```bash
curl -X PATCH https://id.example.com/admin/tenants/acme \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"settings": {"custom_domain": "login.acme.example"}}'
```

Send `null` or an empty string to remove it. The value is also part of the
[tenant configuration document](../reference/tenant-document.md), so it can be set by
import.

The value is validated and lower-cased: a hostname of DNS labels (letters, digits and
hyphens, 253 characters at most), optionally with a port for development
(`login.acme.test:8443`). It must not be one of the deployment's own hosts
(`PUBLIC_URL` or `UI_URL`) and must not be claimed by another tenant (`409`). A change
takes effect at once on every node: the host-to-tenant lookup is cached and evicted
whenever the tenant changes.

rIDM does not verify that the tenant owns the name: there is no DNS challenge. A
domain does nothing until DNS points it at your deployment and your proxy has a
certificate for it, and only administrators holding `ridm:tenants:write` on the tenant
can set it, so ownership is established by whoever operates DNS and TLS. If tenant
administrators are not the same people as the operators, have operators set the domain.

## DNS, TLS and the reverse proxy

The issuer is always `https://<domain>`; there is no plain-http form. So before setting
the domain:

1. Point the name at the deployment (a `CNAME` to the primary host, or the same
   addresses).
2. Obtain a certificate for it and terminate TLS for it: at your reverse proxy or load
   balancer, or natively with `TLS_CERT`/`TLS_KEY` if one certificate can cover every
   host the node answers for.
3. Make the proxy pass the requested host through. rIDM picks the tenant from:
   - `X-Forwarded-Host`, but only when the TCP peer is in `TRUSTED_PROXIES`;
   - otherwise the `Host` header;
   - otherwise the request's authority (HTTP/2).

   Behind a proxy that rewrites `Host`, set `X-Forwarded-Host` and list the proxy in
   `TRUSTED_PROXIES`, or the request lands on the primary host's routes and answers
   `404`. The RFC 7239 `Forwarded: host=` parameter is not read.
4. Check `https://login.acme.example/.well-known/openid-configuration` answers with
   `"issuer": "https://login.acme.example"` before moving any client over.

See [TLS and reverse proxies](../deploy/tls-and-proxies.md) for proxy configuration in
general.

## Moving an existing tenant

Setting, changing or removing a custom domain changes the tenant's issuer for every
client at the same moment. Plan it as a migration:

- **Relying parties** that validate `iss` against a configured issuer, or that
  discovered endpoints once and stored them, reject new tokens until they are
  reconfigured. Tokens issued before the change carry the old issuer. Coordinate the
  switch with every client owner, or move clients whose issuer you control first.
- **Resource servers** validating access tokens need the new issuer too
  (`ridm-auth` takes the issuer as configuration; see
  [Protect a Rust API](../quickstarts/protect-an-api.md)).
- **Upstream identity providers** must have the new callback URL
  (`https://<domain>/broker/{alias}/callback`) added to their redirect URIs before the
  switch; the console shows the callback URL on each provider.
- **Passkeys are bound to their relying party id.** Passkeys enrolled under the UI's
  host stop working for this tenant once the relying party id becomes the custom
  domain, and the reverse holds when a domain is removed. Users fall back to their other
  factors and enrol again.
- Redirect URIs of your clients are unaffected: they name the client's own URLs.

## Caveats

- **Browser sessions on the custom host.** The session and trusted-device cookies are
  host-only with `Path=/`, and carry the tenant in their name
  (`__Host-ridm_session_acme`, `__Host-ridm_device_acme`; see
  [Sign-in flows and sessions](../concepts/flows-and-sessions.md)). A session set on the custom host
  is therefore sent back to every path there, `/authorize` included. A cookie is still
  bound to the host that set it, though. With the embedded UI the pages run on the custom
  host and this needs nothing. With the UI hosted separately, the sign-in pages at
  `UI_URL` call the flow API on the host they were built against, so a session they
  create belongs to that host, an authorization on the custom host does not see it, and
  passkeys (bound to the custom domain) cannot be used from pages on another host. Test
  the browser flows your clients use end to end on the custom host before moving
  production traffic; machine-to-machine traffic (`client_credentials`, token exchange,
  introspection) is unaffected.
- The admin API and the admin console do not answer on a custom host, and the built-in
  admin console client is not configured for one; administer the tenant through the
  primary host.
