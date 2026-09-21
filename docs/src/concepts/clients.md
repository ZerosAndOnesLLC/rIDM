# Clients

A client is an application registered with a tenant: something that sends users
to the tenant's login page, or that asks the token endpoint for tokens on its
own behalf. Every client has a public `client_id`, a type, a way of proving who
it is at the token endpoint, and a set of grants, redirect URIs, scopes and
audiences it is allowed to use. Anything a client is not explicitly allowed is
refused.

Register clients in the admin console, with `ridm client create`, through
`POST /admin/tenants/{slug}/clients`, in the
[tenant configuration document](config-as-code.md), or (when the tenant allows
it) by dynamic registration. [Registering clients](../admin/clients.md) covers
the fields one by one.

## Client types

The type describes what kind of application the client is and sets sensible
defaults for everything else. Every default can be overridden.

| Type | What it is | Default authentication | Default grants |
|------|------------|------------------------|----------------|
| `spa` | Browser application; cannot keep a secret | `none` (public, PKCE) | `authorization_code`, `refresh_token` |
| `web` | Server-side web application | `client_secret_basic` | `authorization_code`, `refresh_token` |
| `native` | Mobile or desktop application | `none` (public, PKCE) | `authorization_code`, `refresh_token` |
| `machine` | Service calling other services, no user | `client_secret_basic` | `client_credentials` |
| `device` | TV, CLI or kiosk that cannot show a browser | `none` (public) | `urn:ietf:params:oauth:grant-type:device_code`, `refresh_token` |

A sixth type, `saml`, is a SAML 2.0 service provider: it has no redirect URIs, grants
or secret, and is registered and edited through the SAML routes, not these (see
[SAML identity provider](../admin/saml-idp.md)).

A client created without a type is a `web` client. Clients other than
`machine` are allowed the standard scopes by default; a `machine` client starts
with none.

The type also decides which redirect URIs are acceptable. Every client may use
`https` redirect URIs, and plain `http` only for loopback addresses
(`localhost`, `127.0.0.1`, `[::1]`). Only `native` clients may register custom
URI schemes such as `com.example.app:/callback` (RFC 8252), and only `native`
clients may use a registered loopback redirect with any port at request time,
because a desktop application picks a free port when it starts. Every other
comparison is an exact string match: no prefix matching, no wildcards.

## Public and confidential

A **confidential** client can keep a credential secret (it runs on a server); a
**public** client cannot (its code is in the user's browser or on their
device). The difference is the token endpoint authentication method:

| Method | How the client proves itself |
|--------|------------------------------|
| `client_secret_basic` | its secret in an HTTP Basic `Authorization` header |
| `client_secret_post` | its secret as `client_secret` in the form body |
| `private_key_jwt` | a JWT assertion (RFC 7523) signed with a private key whose public half is registered as `jwks` or at `jwks_uri` |
| `none` | nothing: a public client, identified only by `client_id` |

A client must authenticate with the method it registered; presenting a
different one is `invalid_client`, even if the credential would have been
valid. This closes the door on a leaked secret being used against a client that
was meant to authenticate with a key.

Secrets are 256-bit random values, shown once when they are created and stored
only as a SHA-256 hash. A client can hold two secrets at once so that rotation
needs no downtime: rotating issues a new secret and keeps the previous one
working for a grace period (24 hours by default, at most 30 days).
`private_key_jwt` assertions are accepted once each (their `jti` is remembered
for the assertion's lifetime), and a `jwks_uri` is re-fetched when an
assertion names a key rIDM has not seen, so the client can rotate its own keys.
A `jwks_uri` must be reachable at a public address: rIDM does not fetch from
private networks (see [Outbound requests](tenants.md#outbound-requests)).

Public clients can never use `client_credentials`: a grant that issues tokens
to the client itself makes no sense for a client anyone can impersonate.

## Grants

| Grant | Used for |
|-------|----------|
| `authorization_code` | Signing a user in through the browser. Always with PKCE `S256` for public clients, and by default for confidential ones too (`require_pkce`). |
| `refresh_token` | Renewing tokens without sending the user back to the login page. Refresh tokens rotate on every use. |
| `client_credentials` | A confidential client acting as itself. With a service account, it acts as a user that holds roles. |
| `urn:ietf:params:oauth:grant-type:device_code` | Signing a user in on a device without a usable browser (RFC 8628). |
| `urn:ietf:params:oauth:grant-type:token-exchange` | Trading an access token for one aimed at another API, optionally on behalf of another party (RFC 8693). |

**Refused by design:** the implicit grant, the hybrid flow and the resource
owner password credentials grant. `/authorize` accepts only
`response_type=code`, and none of these can be switched on. The implicit and
hybrid flows put tokens in the browser's address bar and history; the password
grant hands the user's password to the application. Authorization code with
PKCE does everything they did, without either problem.

The authorization response can be returned as a query string, a fragment, a
`form_post`, or a signed JWT (JARM: `jwt`, `query.jwt`, `fragment.jwt`,
`form_post.jwt`). Requests can be pushed first (PAR, `/par`) or sent as signed
request objects (JAR).

## Scopes and audiences

A client lists the scopes it may request (`allowed_scopes`) and the resource
servers it may obtain tokens for (`allowed_audiences`). An authorization
request naming a scope outside the list is refused with `invalid_scope`; one
naming a resource outside it is refused with `invalid_target`. A request with
no `scope` at all receives the tenant's default scopes (those marked
`is_default`) that are in the client's `allowed_scopes`, and a scope bound to a
resource server adds that resource server to the token's audiences; see
[Scopes](resource-servers.md#scopes-what-the-user-agreed-to).

An empty `allowed_audiences` means "any of the tenant's resource servers", with
two exceptions: the built-in `urn:ridm:admin` audience must always be listed
explicitly, so no third-party client can obtain admin tokens by accident, and
token exchange only ever issues tokens for listed audiences. See
[Resource servers, scopes and permissions](resource-servers.md).

## Consent

With `require_consent` on (the default), the user is asked to approve the scopes
a client requests the first time, and again whenever it asks for a scope they
have not granted. Grants are remembered per user and client, listed in the
account console, and can be withdrawn there, which also cancels the client's
refresh tokens. Turning `require_consent` off makes a client first-party: its
users are never shown the consent screen. The built-in console clients are
first-party.

## Other per-client settings

Clients also carry: token lifetimes that override the tenant's defaults; a
`subject_type` of `public` (the user's id as `sub`) or `pairwise` (a different,
stable `sub` for each client or sector, so clients cannot correlate users);
optional ID token encryption to the client's own key (`RSA-OAEP-256` or
`RSA-OAEP` with `A256GCM` or `A128GCM`); `dpop_bound_access_tokens`, which
requires every token to be sender-constrained; `require_pushed_authorization_requests`
and a `security_profile` (`fapi2` holds the client to the FAPI 2.0 Security Profile);
the CIBA delivery mode for [backchannel sign-in](../admin/ciba-fapi.md); `cors_origins` for browser
clients calling the token endpoint; and back-channel and front-channel logout
URIs (a back-channel URI must resolve to a public address, like every URL rIDM
calls on a client's behalf). See [Tokens](tokens.md) and
[Registering clients](../admin/clients.md).

`access_token_format` chooses between `jwt` (the default) and `opaque` access
tokens. A client with `opaque` receives `at_...` tokens that carry nothing
readable and that its APIs must check at `/introspect`, because they cannot be
validated locally (`ridm-auth` accepts JWTs only); see
[Opaque access tokens](tokens.md#opaque-access-tokens). The built-in console
clients always use JWTs.

## Service accounts

A `client_credentials` token normally has the client itself as its subject
(`sub` is the `client_id`) and carries no roles. When the client needs
permissions on an API, give it a **service account**: a user named
`svc-<client_id>` created for the client, which can then hold roles and join
groups like anyone else. Tokens from `client_credentials` are then issued for
that user, with its roles and permissions. See
[Machine-to-machine access](../quickstarts/machine-to-machine.md).

## Dynamic client registration

A tenant can let applications register themselves (RFC 7591) at
`/t/{slug}/register` and manage their registration afterwards (RFC 7592). The
tenant's `settings.dcr.mode` decides whether that is `disabled` (the default),
`open`, or `initial_access_token`: allowed only to a caller presenting, as a
bearer token, an initial access token issued by an administrator.
`settings.dcr.allowed_grants` limits the grants a registered client may ask
for, and `settings.dcr.require_pkce` (on by default) decides whether a
dynamically registered confidential client must use PKCE; public clients
always must.

Initial access tokens (`iat_...`) are issued with an optional description, an
optional expiry and an optional limit on the number of registrations each
allows; without those, a token neither expires nor runs out. Each is shown
once and stored as a SHA-256 hash, and administrators with the client
permissions can list and revoke them:

```bash
ridm --tenant acme client iat create --description "partner onboarding" \
    --expires-in 86400 --max-uses 5
ridm --tenant acme client iat list
ridm --tenant acme client iat revoke <id>
```

The admin API equivalents are `GET` and `POST
/admin/tenants/{slug}/dcr/initial-access-tokens` and `DELETE
/admin/tenants/{slug}/dcr/initial-access-tokens/{id}` (`ridm:clients:read` to
list, `ridm:clients:write` to issue and revoke); the console offers the same on
the Keys, discovery and audit settings page while the mode is
`initial_access_token`. Issuing and revoking raise `dcr_token.created` and
`dcr_token.revoked`. A registration with a missing, expired, exhausted or
revoked token is refused with `401 invalid_token`.

## Built-in clients

Every tenant has two clients that rIDM manages itself: `ridm-admin-console`
and `ridm-account-console`, the public clients the two consoles sign in with.
Their redirect URIs follow `UI_URL` and are brought back in line whenever it
changes. They cannot be deleted, and they are left out of tenant exports, so
configuration as code never has to mention them. Their token lifetimes and
CORS origins can still be tuned.
