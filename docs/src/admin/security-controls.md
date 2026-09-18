# Rate limits, IP rules and CAPTCHA

rIDM's sign-in and OAuth endpoints are exposed to the internet by design, so they carry
several layers of abuse protection. This page covers each control, what it counts or
matches, its defaults and where to change it, and the deployment settings that decide
which address a request comes from.

| Control | Scope | Configured in |
|---------|-------|---------------|
| [Request ceilings](#request-ceilings) | per address, per client, per tenant, per deployment | `settings.rate_limits`, `RATE_LIMITS`, `RATE_LIMIT_IP_PER_MINUTE` |
| [IP rules](#ip-rules) | tenant-wide and per client | `/admin/tenants/{slug}/ip-rules` |
| [Account lockout](#account-lockout-and-address-throttling) | per user, per address | `settings.lockout` |
| [CAPTCHA](#captcha) | per sign-in flow | `settings.captcha` and `/admin/tenants/{slug}/captcha` |
| [Breached passwords](#breached-password-check) | every password set | `settings.password.check_breached`, `BREACH_CHECK_URL` |
| [Cross-origin policy](#cross-origin-requests) | every response | client `cors_origins` |
| [Security headers](#security-headers) | every response | `HSTS_MAX_AGE` |
| [Outbound request policy](#outbound-request-policy) | every URL a tenant or client chooses | fixed |

All of them depend on knowing the client's address correctly, so start with
[the client address](#the-client-address).

## The client address

rIDM uses the TCP peer's address unless the peer is a trusted proxy.
`TRUSTED_PROXIES` lists the proxies and load balancers in front of rIDM, as CIDRs or
single addresses, comma-separated:

```bash
TRUSTED_PROXIES=10.0.0.0/8,192.0.2.10
```

When the peer is in that list, rIDM reads `X-Forwarded-For` (and, when that is absent,
the RFC 7239 `Forwarded` header) **from the right**: it skips entries that are
themselves trusted proxies and takes the first one that is not. Proxies such as AWS load
balancers and nginx with `$proxy_add_x_forwarded_for` append to whatever the caller
sent, so the leftmost entry is attacker-controlled; the rightmost untrusted entry is the
address your outermost proxy actually saw. An unparsable entry stops the walk.

That one address is what request ceilings count, what IP rules match, what the lockout
throttle and CAPTCHA verification see, and what the audit log records. Get it wrong
and every control misbehaves:

- `TRUSTED_PROXIES` empty behind a proxy: every client appears as the proxy, so one
  busy office exhausts the per-address limits for everyone and IP rules match the
  proxy.
- A proxy listed that does not overwrite or append the header: callers choose their own
  address.

`TRUSTED_PROXIES` also decides whether `X-Forwarded-Host` is believed, which matters for
[custom domains](custom-domains.md). See [TLS and reverse proxies](../deploy/tls-and-proxies.md).

## Request ceilings

### What is limited

Three endpoint families have ceilings; each has its own per-address limit.

| Family | Endpoints (under `/t/{slug}`) | Refusal format |
|--------|-------------------------------|----------------|
| token | `/token`, `/introspect`, `/revoke`, `/userinfo`, `/device_authorization` | OAuth JSON: `429`, `{"error": "slow_down"}` |
| authorize | `/authorize` (HTML page), `/par` and dynamic registration (OAuth JSON) | as noted |
| flows | the flow API, recovery, email verification, invitations, device verification (`application/problem+json`); brokering (HTML page) | as noted |

Discovery, JWKS, WebFinger, branding, `/end_session`, the account API, the admin API
and SCIM are outside these families and not limited by them.

Each request is counted in up to four fixed-window buckets in Valkey, shared by every
node:

| Bucket | Key | Limit |
|--------|-----|-------|
| deployment, per address | `ridm:rl:ip:{addr}` | `RATE_LIMIT_IP_PER_MINUTE` per 60 s, across every tenant and family |
| tenant, per address and family | `ridm:rl:t:{tenant}:{family}:ip:{addr}` | `token_per_ip`, `authorize_per_ip` or `flows_per_ip` per window |
| tenant, per client | `ridm:rl:t:{tenant}:client:{client}` | `token_per_client` per window, token family only |
| tenant total | `ridm:rl:t:{tenant}:all` | `tenant_total` per window, every limited request of the tenant |

The per-client bucket is charged once the client is identified and **before** its
secret or assertion is checked, so guessing a client secret is bounded by it too.

### Defaults

Per tenant, `settings.rate_limits` (console: Settings → Rate limits):

| Setting | Default | Meaning |
|---------|---------|---------|
| `enabled` | `true` | switch the tenant's own buckets off (the deployment bucket still applies) |
| `window_secs` | `60` | window length, 1–3600 seconds |
| `token_per_ip` | `600` | token family, per address |
| `token_per_client` | `1200` | token family, per client |
| `authorize_per_ip` | `300` | authorize family, per address |
| `flows_per_ip` | `600` | flows family, per address |
| `tenant_total` | `0` | everything together; `0` = no ceiling |

Any individual limit set to `0` is off. The defaults are generous on purpose: they are
meant to hold for a busy office behind one NAT address. Tighten `authorize_per_ip` and
`flows_per_ip` for consumer-facing tenants.

For the deployment:

| Variable | Default | Meaning |
|----------|---------|---------|
| `RATE_LIMITS` | `true` | master switch; `false` disables every ceiling, for tests and local experiments only |
| `RATE_LIMIT_IP_PER_MINUTE` | `6000` | per-address ceiling across all tenants; `0` = off |

```bash
curl -X PATCH https://id.example.com/admin/tenants/acme \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"settings": {"rate_limits": {"authorize_per_ip": 60, "tenant_total": 20000}}}'
```

### What a client sees

Every limited response carries the fields of the tightest bucket:

```http
RateLimit-Limit: 600
RateLimit-Remaining: 587
RateLimit-Reset: 42
```

A refused request is `429` with `Retry-After` (seconds until the bucket's window ends),
in the family's format from the table above. Browser navigations (`/authorize`,
brokering) get a plain HTML page rather than a redirect to the client. These headers
are exposed to browsers through CORS.

### Caveats

- Valkey being unreachable **fails open**: requests are allowed and a warning is
  logged. The ceilings protect against abuse; they are not an authorization control.
- Windows are fixed, not sliding: a client can send up to twice a limit across a window
  boundary.
- A request whose address cannot be determined counts only against the tenant total.

## IP rules

IP rules allow or deny networks, either for the whole tenant or for one client.

### How they decide

Rules form two scopes: tenant-wide (no client) and per client. Within a scope:

1. the **most specific** rule whose network contains the address decides (a `/32`
   beats a `/24`), whether it says `allow` or `deny`;
2. an address that matches no rule passes, **unless the scope has any `allow` rule**, in
   which case the scope is an allow list and the address is refused.

A request must pass both scopes. The tenant scope is checked on every endpoint of the
[three families](#what-is-limited), before rate limiting and before anything else runs.
The client scope is checked once the client is known: at `/authorize` (a refusal is an
HTML page, never a redirect to the client) and at every client-authenticated endpoint
(`access_denied`, before the secret is examined).

| Where | Refusal |
|-------|---------|
| flow API | `403`, `application/problem+json` |
| OAuth JSON endpoints | `403` with an OAuth error body |
| `/authorize`, brokering | `403` HTML page |

If the rules cannot be read (the database and cache both unavailable), requests are
refused with `503`, not waved through.

### Managing rules

Console: **IP rules** (`/console/ip-rules/`). Admin API, with `ridm:tenants:read` /
`ridm:tenants:write`:

```bash
# Only the office and the VPN may sign in to this tenant
curl -X POST https://id.example.com/admin/tenants/acme/ip-rules \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"action": "allow", "cidr": "203.0.113.0/24", "description": "Office"}'

# Except one address in it
curl -X POST https://id.example.com/admin/tenants/acme/ip-rules \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"action": "deny", "cidr": "203.0.113.77"}'

# A machine client that may only be used from its build network
curl -X POST https://id.example.com/admin/tenants/acme/ip-rules \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"client_id": "<client uuid>", "action": "allow", "cidr": "2001:db8:42::/48"}'
```

`action` defaults to `deny`. `cidr` takes a network or a single IPv4 or IPv6 address and
is stored in canonical form (`203.0.113.9/24` becomes `203.0.113.0/24`). One network
may appear once per scope (`409` otherwise). `client_id` is the client's internal id.
`GET …/ip-rules?client_id=…` or `?tenant_wide=true` filters the list; `PATCH` changes
`action`, `cidr` or `description`; `DELETE` removes a rule. Changes take effect at once
on every node.

### Caveats

- An allow rule turns its scope into an allow list. Adding your office network as
  `allow` locks out everyone else, including remote administrators signing in to the
  console through this tenant. Keep a way in (another tenant, such as `master`, holds
  global administrators) before creating the first tenant-wide allow rule.
- Rules apply to the endpoint families above, not to the admin API, the account API,
  SCIM, discovery or JWKS.
- The address is the one described in [The client address](#the-client-address); with
  `TRUSTED_PROXIES` wrong, every request appears to come from the proxy.

## Account lockout and address throttling

`settings.lockout` (console: Settings → Passwords & lockout) protects password
sign-in against guessing:

| Setting | Default | Meaning |
|---------|---------|---------|
| `max_failures` | `10` | consecutive wrong passwords before the account is locked; `0` = off |
| `lock_minutes` | `15` | how long the lock lasts |
| `ip_max_failures` | `100` | failed password attempts from one address within the window before that address is throttled; `0` = off |
| `ip_window_minutes` | `15` | the window, and the `Retry-After` of a throttled address |

A successful sign-in resets the account's failure count. Reaching `max_failures` raises
`user.locked`; while locked, even the right password is refused. An administrator can
lift the lock early with `POST /admin/tenants/{slug}/users/{user}/unlock` or the
Unlock button on the user's page. The address throttle answers `429` before the
password is even checked. Attempts are recorded as login attempts (and the
`login.failed` event) with a reason: `invalid_credentials`, `locked` or `disabled`.

A lockout policy is a trade-off: `max_failures` lets anyone who knows a username lock
that user out. Rely on the address throttle, the request ceilings and CAPTCHA for
volume, and keep `max_failures` high enough not to become a denial-of-service tool.

## CAPTCHA

rIDM supports Cloudflare Turnstile and hCaptcha. A tenant has at most one provider:

```bash
curl -X PUT https://id.example.com/admin/tenants/acme/captcha \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"provider": "turnstile", "site_key": "0x4AAAAAAA…", "secret": "0x4AAAAAAA…"}'
```

`provider` is `turnstile` or `h_captcha`; `site_key` and `secret` are required;
`verify_url` optionally replaces the vendor's siteverify endpoint (for a proxy or tests).
The configuration is stored encrypted; `GET …/captcha` returns it with the secret
replaced by `secret_set: true` (or `204` when none is configured) and `DELETE` removes
it. In the console it sits under Settings → Passwords & lockout, beside the
two settings below, and saves once both keys are present. The permissions are `ridm:tenants:read` / `ridm:tenants:write`.

When a challenge is demanded is `settings.captcha`:

| Setting | Default | Meaning |
|---------|---------|---------|
| `after_failures` | `3` | demand a challenge once a sign-in flow has this many failed attempts; `0` = never |
| `on_registration` | `true` | demand a challenge on every self-registration |

The flow state tells the sign-in page when a challenge is due (provider and site key),
and the page renders the widget. A missing token is refused as a validation error on
`captcha_token` (`captcha_required`), a rejected one as `captcha_failed`. If the
vendor cannot be reached, the attempt fails with `503` rather than skipping the check.

Without a configured provider there is no challenge at all, whatever `settings.captcha`
says. `settings.captcha.on_registration` is the only registration switch: an earlier
`settings.registration.captcha` flag was removed (a migration carried any `true` value
over into `captcha.on_registration`, and a `PATCH` that names it is refused with `400`).

The `verify_url`, like every URL a tenant administrator chooses, is reached under the
[outbound request policy](#outbound-request-policy).

## Breached-password check

With `settings.password.check_breached` on (default off; console: Settings → Passwords
& lockout), every password a user or administrator sets (registration, recovery,
forced change, the account console, an administrator's reset, and imports carrying a
plaintext password) is looked up in a Have I Been Pwned compatible range API. Only the
first five hex digits of the password's SHA-1 leave the server; the request asks for a
padded answer and the match is made locally. A password that appears in the corpus is
refused as a validation error on `password`.

| Variable | Default | Meaning |
|----------|---------|---------|
| `BREACH_CHECK_URL` | `https://api.pwnedpasswords.com/range/` | the range endpoint; `off`, `none`, `false` or empty disables the check for the whole deployment (air-gapped installs), and the tenant toggle is then inert |

A lookup that fails (timeout after 5 seconds, an error status) is logged and lets the
password through, so an outage of the corpus never blocks sign-ups or resets. To keep
the check without reaching the internet, host a mirror of the range API and point
`BREACH_CHECK_URL` at it.

## Cross-origin requests

One rule set decides which browser origins may call the API, with credentials:

| Origin | Admitted on |
|--------|-------------|
| the UI's and the API's own origins (`UI_URL`, `PUBLIC_URL`) | everything |
| any origin | discovery, JWKS and branding of every tenant, WebFinger, `/.well-known/security.txt` |
| the tenant's custom domain (`https://<domain>`) | that tenant's paths |
| any origin in the `cors_origins` of one of the tenant's active clients | that tenant's paths |
| anything else | nothing: no CORS headers are sent, so the browser refuses the response |

The union of client origins is cached per tenant and evicted on every client change.
Because a preflight cannot say which client a `/token` call is for, client-authenticated
endpoints check again once the client is known: a browser `Origin` that is neither the
UI's, the API's, the custom domain's nor registered on that very client is refused with
`invalid_request`, even though the tenant as a whole admits it. Server-side clients
send no `Origin` and are never checked. A single-page app therefore needs its origin in
its own client's `cors_origins`; see [Registering clients](clients.md).

Preflights are cached by browsers for ten minutes. Allowed methods are `GET`, `POST`,
`PUT`, `PATCH`, `DELETE` and `OPTIONS`; allowed request headers are `Authorization`,
`Content-Type`, `Accept`, `Accept-Language`, `If-None-Match`, `DPoP` and
`X-Requested-With`; `Retry-After`, `WWW-Authenticate`, `Location`, `ETag`,
`DPoP-Nonce` and the three `RateLimit-*` headers are exposed.

## Security headers

Every API response carries, unless the handler set its own:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` (under `/docs`, only `frame-ancestors 'none'`, since Swagger UI needs its scripts) |
| `Strict-Transport-Security` | `max-age=<HSTS_MAX_AGE>; includeSubDomains`, only when `PUBLIC_URL` is `https` |

The HTML pages the API renders itself (authorization errors, refusals) use
`default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`.
`HSTS_MAX_AGE` defaults to `63072000` (two years); `0` turns the header off. Because of
`includeSubDomains`, only serve `PUBLIC_URL` over https on a domain whose subdomains are
all https too.

The UI is a static export with its own `Content-Security-Policy` meta tag on every
page. A meta tag cannot forbid framing, so whatever serves the UI files should add
`X-Frame-Options: DENY` (or `frame-ancestors 'none'`) and `Strict-Transport-Security`.

Cookies set by the API are `HttpOnly`, `SameSite=Lax`, host-only with `Path=/`, named
per tenant (`__Host-ridm_session_acme`, `__Host-ridm_device_acme`), and `Secure` unless
`COOKIE_SECURE=false`, which is only for plain-http development and drops the `__Host-`
prefix. See [TLS and reverse proxies](../deploy/tls-and-proxies.md#cookies).

## Outbound request policy

Several URLs rIDM connects to are chosen by tenant administrators or by whoever
registers a client, not by the operator. Left unchecked, any of them could point the
server at its own network (server-side request forgery). These are covered:

| Target | Chosen by |
|--------|-----------|
| Webhook receivers | tenant administrator |
| Back-channel logout URIs | client registration |
| Client `jwks_uri` (for `private_key_jwt`) | client registration |
| Identity-provider discovery, token, userinfo and JWKS endpoints | tenant administrator |
| A tenant's HTTP email gateway and SMS webhook | tenant administrator |
| A tenant's CAPTCHA `verify_url` | tenant administrator |
| A tenant's SMTP server | tenant administrator |

For all of them:

- **Names resolve to public addresses only.** The check is made when the connection is
  made, not only when the URL is saved, so a name that later resolves to a private
  address (DNS rebinding) is refused too. Refused ranges: private (RFC 1918), loopback,
  link-local (including `169.254.169.254`), unspecified, broadcast, multicast,
  carrier-grade NAT (`100.64.0.0/10`), unique-local IPv6 (`fc00::/7`), documentation,
  benchmarking and reserved ranges, and IPv6 forms that embed one of them
  (IPv4-mapped, IPv4-compatible, NAT64, 6to4). A name with no public address left fails.
- **IP literals** in a private range are refused before any request is sent; webhook
  URLs and tenant SMTP hosts that are private literals are refused when saved (`400`).
- **Redirects are not followed**, since a redirect would be a second, unchecked target.
- **`HTTP_PROXY` and `HTTPS_PROXY` are ignored** for these requests, because a proxy
  would resolve the name out of the check's sight.
- **Development allowance**: loopback literals (`127.0.0.0/8`, `::1`) and the host
  name `localhost` may reach loopback. Any other name resolving to loopback is refused.

A tenant's SMTP server is resolved just before each connection; rIDM connects to the
first allowed address it found (only that one is tried) while TLS still verifies the
certificate against the configured host name.

The URLs the operator sets in the environment are trusted and not filtered: the
deployment's `SMTP_HOST` (a private relay is the usual case), `AUDIT_SINK_URL`,
`BREACH_CHECK_URL` and `OTEL_EXPORTER_OTLP_ENDPOINT`. An egress firewall remains the
place to restrict where nodes may connect at all; see
[Deployment overview](../deploy/overview.md#outbound-connections).
