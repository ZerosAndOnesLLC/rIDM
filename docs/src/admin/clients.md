# Registering clients

A client is an application that asks rIDM for tokens. This page covers registering
and maintaining clients: every field, the type-driven defaults, secrets and their
rotation, `private_key_jwt`, and dynamic client registration. For the concepts, see
[Clients](../concepts/clients.md).

Client routes are under `/admin/tenants/{slug}/clients` and need `ridm:clients:read`
or `ridm:clients:write`. `{client}` is either the internal id or the public
`client_id`.

## Where to register one

| Where | How |
|-------|-----|
| Console | Clients (`/console/clients/`) → New client: a four-step wizard (kind of client; grants and authentication; URIs; scopes and audiences) with the type's defaults preselected. The result shows the client ID and any secret once |
| CLI | `ridm --tenant acme client create --name "Acme SPA" --type spa --redirect-uri https://app.acme.example/callback` |
| API | `POST /admin/tenants/{slug}/clients` |
| Configuration as code | A `clients` entry in the [tenant document](../reference/tenant-document.md) |
| The client itself | [Dynamic client registration](#dynamic-client-registration), when the tenant allows it |

The console's client detail page (`?client=<id>`) saves every field as you go, and the
**playground** (`/console/playground/`) runs the client's flow for real and shows the
tokens it gets back. Its sign-in opens in a popup (allow pop-ups for the console); the
console tab keeps the run in memory, a pasted client secret and the tokens included,
and writes none of it to browser storage.

## Client types and their defaults

`client_type` picks the defaults for everything not given. Anything given explicitly
wins.

| Type | For | Auth method | Grants | PKCE | Scopes |
|------|-----|-------------|--------|------|--------|
| `spa` | Browser apps | `none` (public) | `authorization_code`, `refresh_token` | required | standard scopes |
| `web` (default) | Server-side web apps | `client_secret_basic` | `authorization_code`, `refresh_token` | required | standard scopes |
| `native` | Mobile and desktop apps | `none` (public) | `authorization_code`, `refresh_token` | required | standard scopes |
| `machine` | Service-to-service | `client_secret_basic` | `client_credentials` | not required | none |
| `device` | TVs, CLIs, kiosks | `none` (public) | device code, `refresh_token` | required | standard scopes |

The standard scopes are `openid`, `profile`, `email`, `phone`, `address` and
`offline_access`. PKCE (S256) is always required of a public client, whatever
`require_pkce` says.

## Fields

```http
POST /admin/tenants/acme/clients
Content-Type: application/json

{
  "name": "Acme Portal",
  "client_type": "web",
  "redirect_uris": ["https://portal.acme.example/auth/callback"],
  "post_logout_redirect_uris": ["https://portal.acme.example/"],
  "allowed_scopes": ["openid", "profile", "email", "offline_access"],
  "allowed_audiences": ["https://api.acme.example"],
  "backchannel_logout_uri": "https://portal.acme.example/auth/backchannel-logout",
  "require_consent": false
}
```

### Identity and display

| Field | Default | Notes |
|-------|---------|-------|
| `client_id` | generated | 1–128 characters of `A-Z a-z 0-9 . _ : -`, starting alphanumeric; cannot change later |
| `name` | required | 1–255 characters; shown on the consent screen |
| `client_type` | `web` | See the table above |
| `description` | `null` | For administrators |
| `logo_uri`, `client_uri`, `tos_uri`, `policy_uri` | `null` | Shown on the consent screen and in the account console's application list |
| `status` | `active` | `PATCH` only: `disabled` stops the client from getting tokens |

### Authentication

| Field | Default | Notes |
|-------|---------|-------|
| `token_endpoint_auth_method` | by type | `none`, `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth`. The client must authenticate with exactly the method registered |
| `tls_client_auth_subject_dn`, `tls_client_auth_san_dns`, `tls_client_auth_san_uri`, `tls_client_auth_san_ip`, `tls_client_auth_san_email` | `null` | For `tls_client_auth`, exactly one: the name its certificate must carry. See [Mutual TLS](mtls.md#registering-a-client) |
| `jwks` | `null` | Inline JWK set (`{"keys": [...]}`) for `private_key_jwt`, signed request objects and ID token encryption |
| `jwks_uri` | `null` | The same, fetched over HTTPS |

`client_credentials` needs client authentication, so it cannot be combined with
`none`. `private_key_jwt` needs `jwks` or `jwks_uri`; `self_signed_tls_client_auth`
needs its certificate in `jwks` (a key's `x5c`) or a `jwks_uri`.

### Redirects, logout and CORS

| Field | Default | Notes |
|-------|---------|-------|
| `redirect_uris` | `[]` | At least one when `authorization_code` is allowed. Matched as exact strings, except that a `native` client's `http` loopback redirect may use any port (RFC 8252 §7.3) |
| `post_logout_redirect_uris` | `[]` | Where RP-initiated logout may return to |
| `cors_origins` | `[]` | Browser origins (`scheme://host[:port]`, no path) allowed to call the token, userinfo and other endpoints from JavaScript |
| `backchannel_logout_uri` | `null` | Receives a signed logout token when a session the client took part in ends |
| `frontchannel_logout_uri` | `null` | Loaded in an iframe on the logout page when a session ends. Browsers that block third-party cookies (Safari, Firefox, private windows in every browser, Android WebView) do not send the application's own session cookie to that iframe, so it cannot end the application's session there: use `backchannel_logout_uri` wherever the application can receive it |
| `initiate_login_uri` | `null` | Where a third party may start a login at the client |

Redirect and post-logout URIs must be `https`, `http` only on a loopback host
(`localhost`, `127.0.0.1`, `[::1]`), or, for `native` clients only, a custom scheme
(RFC 8252). Fragments are refused.

### Grants, scopes and audiences

| Field | Default | Notes |
|-------|---------|-------|
| `allowed_grants` | by type | Any of `authorization_code`, `refresh_token`, `client_credentials`, `urn:ietf:params:oauth:grant-type:device_code`, `urn:ietf:params:oauth:grant-type:token-exchange`, `urn:openid:params:grant-type:ciba` (confidential clients only; see [Backchannel sign-in](ciba-fapi.md)). An empty list means no grant at all |
| `backchannel_token_delivery_mode` | `poll` with the CIBA grant | `poll` or `ping`; only with the CIBA grant |
| `backchannel_client_notification_endpoint` | `null` | Where a `ping` client is told; required in `ping` mode |
| `allowed_scopes` | by type | Scopes the client may ask for; each must exist in the tenant |
| `allowed_audiences` | `[]` | Resource servers (by identifier) the client may get access tokens for; each must exist. Empty means any resource server except the built-in ones. `urn:ridm:admin` makes admin API tokens possible (see [Administrator access](access.md)) |

A scope or audience that does not exist is refused at registration, rather than
surfacing later as `invalid_scope` or `invalid_target` at the token endpoint.

A token request without a `resource` parameter gets the client's `allowed_audiences` as
its audience; a client with an empty list then gets a token whose audience is the
client itself. A request that names `resource` may only name audiences the client is
allowed. The built-in resource servers (the admin and account APIs) are never implied
by an empty list: a client must list them explicitly. A scope bound to a resource
server adds that server's audience when it is requested, and is refused with
`invalid_scope` if the client may not target it. See
[Resource servers, scopes and permissions](../concepts/resource-servers.md).

### Consent and PKCE

| Field | Default | Notes |
|-------|---------|-------|
| `require_consent` | `true` | Show the consent screen. Set `false` for first-party applications |
| `require_pkce` | by type | Only meaningful for confidential clients; public clients always need PKCE |

### Token lifetimes and format

| Field | Default | Notes |
|-------|---------|-------|
| `access_token_ttl_secs` | `null` | Overrides the tenant's `session.access_token_ttl_secs` (default 300) |
| `refresh_token_ttl_secs` | `null` | Overrides `session.refresh_token_ttl_secs` (default 30 days) |
| `id_token_ttl_secs` | `null` | Overrides `session.id_token_ttl_secs` (default 300) |
| `access_token_format` | `jwt` | `jwt`, or `opaque`: see [Opaque access tokens](#opaque-access-tokens). The built-in console clients refuse `opaque` |
| `subject_type` | `public` | `pairwise` gives each client (or sector) its own `sub` for a user |
| `sector_identifier_uri` | `null` | Groups clients that should share pairwise subjects |
| `id_token_scope_claims` | `false` | Also put the claims released by the granted scopes (each scope's `claims` list, `profile`, `email`, `address` and `phone` included) in the ID token; by default they are only at `/userinfo` (OIDC Core §5.4) |
| `id_token_encryption` | `null` | `{"alg": "RSA-OAEP-256" \| "RSA-OAEP", "enc": "A256GCM" \| "A128GCM"}`; needs the client's `jwks` or `jwks_uri` |

A resource server may cap the lifetime of access tokens issued for it, choose the
algorithm they are signed with, and refuse `offline_access`; see
[Resource servers, scopes and permissions](../concepts/resource-servers.md). What the
tokens contain is in [Token claims](../reference/token-claims.md).

### Opaque access tokens

With `access_token_format: "opaque"` the client receives access tokens of the form
`at_<random>` instead of JWTs. The claims a JWT would have carried are kept in Valkey
until the token expires; the token itself carries nothing.

- A resource server learns what the token stands for from `POST /t/{slug}/introspect`.
  It cannot validate the token locally, so [`ridm-auth`](../quickstarts/protect-an-api.md),
  which validates JWTs only, does not accept opaque tokens.
- rIDM's own endpoints accept them: `/userinfo`, `/introspect`, `/revoke`, token
  exchange (as `urn:ietf:params:oauth:token-type:access_token`), and the account and
  admin APIs.
- Losing Valkey's data ends every opaque token early; the client refreshes or signs in
  again. See [Postgres and Valkey](../deploy/postgres-valkey.md#if-valkey-is-lost).
- Refresh tokens and ID tokens are unchanged.

Choose opaque tokens when the audience must not be able to read the token's contents,
or when you want every use checked centrally (revocation takes effect at the next
introspection), and accept the introspection round trip that costs.

### PAR, JAR, DPoP, mTLS and FAPI 2.0

| Field | Default | Notes |
|-------|---------|-------|
| `dpop_bound_access_tokens` | `false` (`true` under FAPI 2.0 unless certificate-bound) | Every token request must carry a DPoP proof, and the tokens are bound to its key |
| `tls_client_certificate_bound_access_tokens` | `false` | Every token request must come over mutual TLS, and the access tokens are bound to the client certificate (RFC 8705 §3). See [Mutual TLS](mtls.md#certificate-bound-tokens) |
| `require_pushed_authorization_requests` | `false` | `/authorize` refuses the client's requests unless they came through PAR (RFC 9126 §6) |
| `security_profile` | `none` | `fapi2` holds the client to the FAPI 2.0 Security Profile: see [Backchannel sign-in and FAPI 2.0](ciba-fapi.md#the-fapi-20-security-profile) |

Pushed authorization requests (`POST /t/{slug}/par`) and JWT-secured authorization
requests (a `request` parameter signed with one of the client's `jwks` keys) are
available to every client; `require_pushed_authorization_requests` (or the FAPI 2.0
profile) makes PAR the only way in. Any client may also present DPoP proofs
voluntarily; `dpop_bound_access_tokens` makes them compulsory. See
[Tokens](../concepts/tokens.md).

## Changing a client

`PATCH /admin/tenants/{slug}/clients/{client}` is a merge patch over the client's
metadata: send only what changes. `null` clears an optional field or resets a defaulted
one to its type's default. `client_id` cannot change. Switching to a secret-based auth
method mints a secret and returns it once in `client_secret`.

`DELETE …/clients/{client}` removes the client with its client-scoped roles, refresh
tokens and consents.

The built-in `ridm-admin-console` and `ridm-account-console` clients cannot be deleted
and are left out of tenant exports. Their redirect URIs follow `UI_URL` and are
restored at start-up; other fields, such as token lifetimes and CORS origins, may be
changed.

## Secrets

A confidential client using `client_secret_basic` or `client_secret_post` has a secret
(`cs_…`, 256 random bits) generated at creation. It is returned once, in the `201`
response's `client_secret`, and stored only as a SHA-256 hash. `GET` shows each
secret's id, creation time and expiry, never the value.

**Rotate** with `POST …/clients/{client}/secrets`:

```json
{ "grace_secs": 86400 }
```

The response carries the new secret, once. The previous secret keeps working for
`grace_secs` (default 86 400, one day; `0` retires it at once; at most 30 days), so
deployments can move to the new one without an outage. Any older secret is dropped.
In the console: client detail → Secrets → Rotate, then revoke the retiring secret once
everything has moved.

**Revoke** one secret early with `DELETE …/clients/{client}/secrets/{secret_id}`. The
last secret of a confidential client cannot be revoked; rotate instead.

## private_key_jwt

With `token_endpoint_auth_method: "private_key_jwt"`, the client proves itself with a
JWT signed by its own private key (RFC 7523) instead of a shared secret. Register the
public half as `jwks` or `jwks_uri`:

```json
{
  "name": "Acme Billing",
  "client_type": "machine",
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://billing.acme.example/.well-known/jwks.json",
  "allowed_audiences": ["https://api.acme.example"]
}
```

At the token endpoint, send `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
and `client_assertion`, a JWT that:

- is signed with an asymmetric algorithm, by a key in the registered set;
- has `iss` and `sub` equal to the `client_id`;
- has `aud` equal to the token endpoint URL or the tenant's issuer;
- carries `exp` and a `jti`, lives no more than 600 seconds, and is not replayed (each
  `jti` is accepted once).

A `jwks_uri` is fetched over HTTPS and cached for an hour. An unknown `kid` triggers
one re-fetch, at most once a minute per client, so a rotated client key is picked up
without an administrator.

## Service accounts

A client with the `client_credentials` grant can have a service account: a user named
`svc-<client_id>` that its tokens are issued for, so it can hold roles and groups like
anyone else. `PUT …/clients/{client}/service-account` creates it (or returns the
existing one), `DELETE` removes it. See [Administrator access](access.md#automation) for
giving a service account admin permissions, and
[Machine-to-machine access](../quickstarts/machine-to-machine.md).

## Dynamic client registration

Applications can register themselves at `POST /t/{slug}/register` (RFC 7591) and
manage their registration at `GET`, `PUT` and `DELETE /t/{slug}/register/{client_id}`
(RFC 7592) with the registration access token they received. The tenant's
`settings.dcr` decides whether that is allowed. In the console: Settings → Keys,
discovery & audit.

| Key | Default | Meaning |
|-----|---------|---------|
| `mode` | `disabled` | `disabled`: registration answers `403`. `open`: anyone may register, within the tenant's rate limits. `initial_access_token`: registration needs a bearer initial access token |
| `allowed_grants` | `[]` | Grant types a registered client may ask for; empty allows every supported grant |
| `require_pkce` | `true` | Whether registered confidential clients must use PKCE (public clients always must). The OpenID Connect basic profile registers confidential clients without PKCE, so conformance testing needs it off |

```json
{ "settings": { "dcr": { "mode": "open", "allowed_grants": ["authorization_code", "refresh_token"] } } }
```

How registered metadata maps onto a client:

- `token_endpoint_auth_method` defaults to `client_secret_basic`; `none`,
  `client_secret_post` and `private_key_jwt` are accepted.
- `grant_types` defaults to `["authorization_code"]`; only the `code` response type is
  supported.
- The type is `native` for `application_type: "native"`, else derived from the grants
  and auth method (`device`, `machine`, `spa` or `web`).
- `scope` sets the allowed scopes; audiences, CORS origins and token lifetimes cannot
  be registered.
- Every registered client gets `require_consent: true`.
- `require_pushed_authorization_requests` is stored and enforced.
- `backchannel_token_delivery_mode` (`poll` or `ping`) and
  `backchannel_client_notification_endpoint` register a CIBA client; signed
  backchannel requests and user codes are refused. `security_profile` cannot be
  registered: an administrator sets it.

The response carries the `client_id`, any `client_secret` (with
`client_secret_expires_at: 0`), and a `registration_access_token` for the management
endpoints. An administrator can issue a new registration access token for any client
with `POST /admin/tenants/{slug}/clients/{client}/registration-token` (or on the
console's client detail page), which replaces the previous one; it is shown once.

Registrations are recorded in the audit log with the system as actor, and are
ordinary clients afterwards: administrators see, edit and delete them like any other.

### Initial access tokens

With `dcr.mode` set to `initial_access_token`, `POST /t/{slug}/register` demands a
bearer token issued by an administrator (RFC 7591 §1.2). A missing token is answered
`401` with `invalid_token`; an unknown, revoked, expired or used-up one the same way.
Each successful registration spends one use; the check and the count are one statement,
so two registrations racing for a token's last use cannot both succeed.

```http
POST /t/acme/register
Authorization: Bearer iat_Vt4cN9…
Content-Type: application/json

{ "client_name": "Build agent", "redirect_uris": ["https://ci.acme.example/cb"] }
```

Tokens are managed under the client permissions, since a token lets its holder create
clients:

| Route | Permission | Does |
|-------|------------|------|
| `GET /admin/tenants/{slug}/dcr/initial-access-tokens` | `ridm:clients:read` | List the tenant's tokens, newest first, never their values |
| `POST /admin/tenants/{slug}/dcr/initial-access-tokens` | `ridm:clients:write` | Issue a token; answers `201` with the record and `token`, shown this once |
| `DELETE /admin/tenants/{slug}/dcr/initial-access-tokens/{id}` | `ridm:clients:write` | Revoke it (`204`) |

The request body is optional in every field:

| Field | Default | Rules |
|-------|---------|-------|
| `description` | `null` | What the token is for; at most 200 characters |
| `expires_in_secs` | no expiry | 1 second to ten years |
| `max_uses` | no limit | Registrations it allows in all; at least 1 |

```bash
curl -X POST https://id.example.com/admin/tenants/acme/dcr/initial-access-tokens \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"description": "CI agents", "expires_in_secs": 86400, "max_uses": 5}'
```

A listed token shows `id`, `description`, `max_uses`, `uses`, `expires_at`,
`last_used_at`, `revoked_at` and `created_at`. Tokens are stored in Postgres as SHA-256
hashes; the value (`iat_…`) exists only in the issuing response. Issuing and revoking
raise `dcr_token.created` and `dcr_token.revoked` (see
[Webhooks and the audit log](webhooks-audit.md#event-catalogue)).

The same is available as `ridm client iat create | list | revoke` (see
[The ridm command line](cli.md#client)) and in the console under Settings → Keys,
discovery & audit, where an **Initial access tokens** block appears while the mode is
`initial_access_token`: issue a token with a description, lifetime and use limit, see
each token's state (active, expired, used up, revoked), and revoke it.
