# Tokens

rIDM issues three kinds of token at a tenant's `/token` endpoint, each with one
job:

| Token | Format | For | Default lifetime |
|-------|--------|-----|------------------|
| Access token | signed JWT, `typ: at+jwt` (RFC 9068); or opaque `at_...` for clients that ask for it | calling an API | 5 minutes |
| ID token | signed JWT, `typ: JWT`, optionally encrypted | telling the client who signed in | 5 minutes |
| Refresh token | opaque string starting `rt_` | getting new tokens without the user | 30 days |

Every claim is listed in [Token claims](../reference/token-claims.md); this page
explains how the tokens behave.

## Access tokens

An access token is a JWT signed with the tenant's active key (or, when its
[resource server](resource-servers.md#token-lifetime-and-signing-per-api) asks
for one, the tenant's active key of that algorithm). An API validates
it locally against the tenant's JWKS, without calling rIDM, which is what lets
token validation scale with the APIs rather than with the identity server.
It carries:

- who: `sub` (the user, or the `client_id` for a client acting as itself),
  `client_id` and `azp` (the client it was issued to), `tid` (the tenant);
- what for: `aud` (the [resource servers](resource-servers.md) it is meant for),
  `scope`, and `permissions` for those resource servers;
- about the user: `roles`, `groups`, profile attributes whose schema lists
  `access_token` in `visible_in`, plus anything claim mappers add;
- about the sign-in: `sid`, `auth_time`, `amr`, `acr`;
- the usual `iss`, `iat`, `nbf`, `exp` and a unique `jti`.

The `typ: at+jwt` header matters. ID tokens are JWTs signed with the same keys,
and an API that only checked the signature and issuer would accept an ID token
as if it were an access token. Requiring `at+jwt` (as `ridm-auth` does) closes
that gap.

Access tokens are short-lived on purpose. A JWT cannot be recalled from every
API that has already accepted it, so the lifetime is the bound on how long a
leaked or revoked token remains usable. rIDM does keep a revocation list:
revoking an access token at `/revoke` adds its `jti` to a denylist in Valkey
until it would have expired, and rIDM's own endpoints (`/userinfo`,
`/introspect`, the account and admin APIs) refuse it at once. An API that
validates tokens locally does not see that list; one that must react to
revocation within seconds should call `/introspect` instead.

### Opaque access tokens

A client registered with `access_token_format: opaque` receives access tokens
of the form `at_` followed by 256 random bits instead of JWTs. The claims a JWT
would have carried are kept in Valkey under the token's SHA-256 hash until the
token expires, so nothing needs cleaning up; the price is that losing Valkey
ends every opaque token early, the same way it ends SSO sessions.

An opaque token reveals nothing to whoever holds it and cannot be validated
locally: a resource server must call `/introspect` for every token (or cache
the answer briefly). `ridm-auth` validates JWTs only, so an API built on it
needs its callers' clients to use the default `jwt` format. rIDM's own
endpoints accept opaque tokens wherever they accept JWT access tokens:
`/userinfo`, `/introspect`, `/revoke` (which deletes the entry at once), token
exchange (as `urn:ietf:params:oauth:token-type:access_token`, never the `jwt`
type), and the account and admin APIs. The built-in console clients cannot be
switched to opaque.

## ID tokens

An ID token is addressed to the client (`aud` is its `client_id`) and says who
signed in and how: `sub`, `auth_time`, `amr`, `acr`, `sid`, `tid`, `nonce` when
the request carried one, and `at_hash` binding it to the access token issued
with it. It is issued whenever the granted scopes include `openid` and there is
a user.

The claims the granted scopes release are served by `/userinfo`, not put in
the ID token, because an access token is always issued alongside (OIDC Core
§5.4). Each scope releases the claims named in its `claims` list; the standard
scopes (`profile`, `email`, `phone`, `address`) are seeded with the OIDC
claim sets, and an administrator can edit those lists like any other (see
[Scopes](resource-servers.md#scopes-what-the-user-agreed-to)). A client that
wants the scope claims in the ID token as well sets `id_token_scope_claims`.
Profile attributes whose schema lists `id_token` or `userinfo` in `visible_in`
are added to that token or response under the attribute's name, without
overwriting a claim a scope released; claim mappers run last and may override
either.

**Subject identifiers.** With `subject_type: public` (the default), `sub` is
the user's id, the same for every client. With `pairwise`, each client (or each
group of clients sharing a `sector_identifier_uri`) sees a different, stable
`sub` for the same user, derived from the sector, the user and a per-tenant
secret salt, so unrelated clients cannot correlate their users.

**Encryption.** A client that registers its own public key can have its ID
tokens encrypted to it (JWE, `RSA-OAEP-256` or `RSA-OAEP` with `A256GCM` or
`A128GCM`), for deployments where the front channel must not see identity
claims.

## Lifetimes

Each lifetime has a tenant default under `settings.session`
(`access_token_ttl_secs`, `id_token_ttl_secs`, `refresh_token_ttl_secs`), which
a client can override with its own value. For access tokens, a resource server
can override both: a token for a resource server with `token_ttl_secs` set lives
that long, and a token for several resource servers gets the shortest of their
lifetimes. A token obtained by token exchange never outlives the token it was
exchanged for.

## Refresh tokens

A refresh token is an opaque random string (`rt_` followed by 256 random bits).
rIDM stores only its SHA-256 hash, so a database leak does not yield usable
refresh tokens. It is issued by the authorization code and device grants when
the client is allowed the `refresh_token` grant; it is never issued by
`client_credentials` (the client can simply ask again) or by token exchange.

**Rotation.** Every use returns a new refresh token and spends the old one.
The new token belongs to the same *family* (everything descending from one
sign-in) and keeps the family's original expiry: rotation never extends a
session beyond `refresh_token_ttl_secs` from the original sign-in. A refresh
may narrow the scope but never widen it, and may name a
[resource](resource-servers.md#audiences-one-token-one-api) to narrow the new
access token's audience to one or more of the original grant's audiences, never
a new one. A scope or resource outside the original grant is refused
(`invalid_scope` or `invalid_target`) before the refresh token is spent, so the
client can retry with the same token. ID tokens minted from a refresh repeat
the original `auth_time`, `amr` and `acr`, which the family stores.

**Reuse detection.** Presenting a refresh token that has already been spent
means two parties hold it, and rIDM cannot tell which is legitimate. It
assumes theft: the whole family is revoked, the request fails with
`invalid_grant`, and a `token.refresh_reuse_detected` event is raised. The
legitimate client's next refresh fails too, and the user signs in again. This
is the OAuth 2.0 Security BCP's answer to refresh tokens held by public
clients, which cannot authenticate themselves.

**Session binding and `offline_access`.** A refresh token issued without the
`offline_access` scope lives only as long as the SSO session it was issued in
(OIDC Core §11): once that session ends in any way, by sign-out, idle timeout
or absolute timeout, the next refresh revokes the family and fails with
`invalid_grant`. Each refresh counts as activity and extends the session's
idle window, so an application in active use keeps its session alive. A
refresh token granted `offline_access` outlives the session's timeouts, up to
its own `refresh_token_ttl_secs`, but not an explicit sign-out. `offline_access`
is only granted when the client is allowed it and every resource server the
token is for has `allow_offline_access` on; otherwise it is dropped from the
grant rather than refused. A device-flow client that has to keep working for
days (a TV, a CLI) should request `offline_access`, because the browser session
that approved it will time out long before.

A refresh token is also bound to the client it was issued to, and stops working
when the user is no longer active, when its session is signed out (by the
user, "sign out everywhere", an administrator revoking it, a password change or
reset that ends other sessions, or the user being disabled or deleted),
whether or not it carries `offline_access`, when the user withdraws the
client's consent, or when it is revoked at `/revoke`, which revokes the whole
family. A code exchanged after its session was signed out is refused.

**Authorization codes** are single-use as well. Replaying a code revokes
everything its first exchange produced: the refresh family, and the access
token through the denylist (RFC 6749 §4.1.2).

## Introspection and revocation

`/introspect` (RFC 7662) answers for access tokens (JWT or opaque), refresh
tokens and personal access tokens, to an authenticated confidential client. ID
tokens are not access tokens and are always `{"active": false}`. A client learns the
details of a token only if the token was issued to it or names one of its
audiences; anything else, including unknown, expired and revoked tokens, is
`{"active": false}`. `/revoke` (RFC 7009) accepts access and refresh tokens and
answers success for unknown ones, as the RFC requires.

## DPoP: sender-constrained tokens

A bearer token works for whoever holds it. DPoP (RFC 9449) binds a token to a
key the client holds, so a stolen token is useless without the private key.

The client sends a `DPoP` header on the token request: a short JWT signed with
its key, naming the method and URL. rIDM binds every token of the response to
that key's thumbprint: the access token carries `cnf.jkt`, `token_type` is
`DPoP`, and a public client's refresh token is bound too, so a later refresh
needs a proof from the same key. At a resource, the client sends a fresh proof
with every request, including `ath`, the hash of the token.

Proofs are single-use within a five-minute window, may be at most five minutes
old and thirty seconds in the future, and must match the request's method and
URL. `/userinfo`, the account API and the admin API refuse a bound token
presented without a matching proof. A client registered with
`dpop_bound_access_tokens` must always use DPoP. Server-provided DPoP nonces
and the `dpop_jkt` authorization parameter are not implemented.

`ridm-auth` refuses tokens carrying `cnf.jkt` rather than accepting them as
bearer tokens, because it verifies no proofs.

## Token exchange

Token exchange (RFC 8693) lets a client that is allowed the
`urn:ietf:params:oauth:grant-type:token-exchange` grant trade an access token of
the tenant for a new one aimed at another API: typically a service that received
a user's token and needs to call a downstream service as that user.

- The new token keeps the subject, the session and the sign-in context
  (`amr`, `acr`), never outlives the original, and can only narrow the scope.
- Unlike every other grant, an empty `allowed_audiences` does not mean "any":
  the exchanging client may only obtain tokens for audiences it lists, because
  the token it presents may have been minted for someone else.
- With an `actor_token`, the result is a delegation: its `act` claim names the
  acting party, nesting any earlier `act` on re-exchange.
- A DPoP-bound subject token can only be exchanged by a request proving the
  same key, so exchange cannot strip a binding.

## Other tokens

Two further credentials are not issued by `/token` but are accepted by rIDM's
own APIs: **personal access tokens** (`rpat_...`), long-lived tokens users mint in
the account console for scripts and the `ridm` CLI, whose permissions are
narrowed at every use to what the user still holds; and **SCIM tokens**
(`rscim_...`) for provisioning systems. Both are shown once and stored hashed.
See [Administrator access](../admin/access.md) and
[SCIM provisioning](../admin/scim.md).
