# Errors

rIDM answers errors in the format each protocol expects, so a client library written for that protocol understands them without special handling:

| Where | Format |
|-------|--------|
| OAuth 2.0 / OIDC endpoints (`/token`, `/par`, `/device_authorization`, `/introspect`, `/revoke`, `/register`) | RFC 6749 §5.2 JSON: `{"error", "error_description"?}` |
| `/authorize` | an HTML page, or a redirect to the client with `error` |
| `/userinfo`, and the resource side of `ridm-auth` | RFC 6750 `WWW-Authenticate` challenge plus a JSON body |
| Admin API, account API, flow API and the other browser endpoints | RFC 9457 `application/problem+json` |
| SCIM | RFC 7644 §3.12 SCIM error documents |

The types are defined in [`api/src/error.rs`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/api/src/error.rs).

## OAuth and OIDC errors

Token, PAR, device-authorization, introspection and revocation errors are JSON with `Cache-Control: no-store`:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{"error": "invalid_grant", "error_description": "invalid authorization code"}
```

`invalid_client` answers `401` with `WWW-Authenticate: Basic realm="ridm"`. The codes rIDM emits:

| `error` | Status | Typical cause |
|---------|--------|---------------|
| `invalid_request` | 400 | missing or repeated parameter; `/token` body not `application/x-www-form-urlencoded` |
| `invalid_client` | 401 | unknown client, wrong secret or assertion, a method other than the registered one; a public client at `/introspect` |
| `invalid_grant` | 400 | code or refresh token invalid, expired, used, or issued to another client; PKCE verifier mismatch; user no longer active; a code whose browser session was signed out before it was exchanged; a refresh token without `offline_access` whose session has ended (its family is revoked); bad token-exchange subject or actor token |
| `unauthorized_client` | 400 | the client is not allowed this grant type |
| `unsupported_grant_type` | 400 | a grant type rIDM does not know |
| `invalid_scope` | 400 | a scope the client may not request; a scope bound to a resource server the client may not target; a refresh `scope` naming a scope the original grant did not carry (checked before the refresh token is spent, so it stays usable); `openid`/`offline_access` with `client_credentials` |
| `invalid_target` | 400 | an unknown `resource`/`audience`, or one the client is not allowed (RFC 8707); at code exchange, a `resource` the authorization request did not name; on refresh, a `resource` outside the original grant's audiences (checked before the token is spent); audiences whose resource servers need different signing algorithms in one request |
| `invalid_dpop_proof` | 400 | malformed, replayed, stale or mismatched `DPoP` proof, or none from a client that must present one (RFC 9449) |
| `authorization_pending` | 400 | device grant: the user has not approved yet (RFC 8628) |
| `slow_down` | 400 | device grant: polling faster than the interval |
| `expired_token` | 400 | device grant: the device code expired |
| `access_denied` | 400 | device grant: the user denied; dynamic registration disabled (`403`); a forbidden operation |
| `temporarily_unavailable` | 503 | a dependency (for example the IP-rule store) could not be read |
| `server_error` | 500 | an internal failure; details are logged, never returned |

A rate-limited OAuth request answers `429` with `{"error": "slow_down", "error_description": "too many requests; retry after N seconds"}` and `Retry-After` (see [Rate limits](#rate-limits)).

### Dynamic client registration

`/register` and `/register/{client_id}` (RFC 7591, RFC 7592) use the same JSON shape with the registration codes: `invalid_redirect_uri` and `invalid_client_metadata` (400), `access_denied` (403, registration disabled for the tenant), and `invalid_token` with a `Bearer` challenge (401) when an initial access token (under `dcr.mode: initial_access_token`) or a registration access token is missing, unknown, revoked, expired or used up.

### Authorization endpoint

`/authorize` follows the order RFC 6749 §4.1.2.1 requires. Problems found before the redirect URI can be trusted are shown to the user as an HTML page with the code and description, because redirecting would send the browser somewhere unverified:

| Code on the page | Cause |
|------------------|-------|
| `invalid_request` | unknown or disabled client, unregistered `redirect_uri`, a POST that is not form-encoded (`415`) |
| `invalid_request_object` | a `request` JWT that does not verify against the client's keys (RFC 9101) |
| `invalid_request_uri` | an unknown, expired or already used PAR `request_uri` |
| `access_denied` | the client's own IP rules refuse the address (tenant-wide rules are refused the same way by the guard, `403`) |

Every other error returns to the client's redirect URI in the requested response mode, with `error`, `error_description`, `state` and `iss` (RFC 9207):

```text
https://app.example.com/callback?error=login_required&error_description=...&state=af0ifjsldkj&iss=https%3A%2F%2Fid.example.com%2Ft%2Facme
```

| `error` | Cause |
|---------|-------|
| `invalid_request` | missing or malformed parameter, missing PKCE where required |
| `unsupported_response_type` | anything other than `code` |
| `invalid_scope` | a scope the client may not request |
| `unauthorized_client` | the client may not use the authorization code grant |
| `request_not_supported` | a `request` parameter inside a request object |
| `request_uri_not_supported` | a `request_uri` that `/par` did not issue |
| `login_required`, `consent_required` | `prompt=none` and the user would have to sign in or consent |
| `access_denied` | the user denied consent or cancelled the flow |

## Bearer token errors (RFC 6750)

`/userinfo` refuses a bad access token with a challenge and a JSON body:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", error_description="access token is invalid or expired"
Cache-Control: no-store

{"error": "invalid_token", "error_description": "access token is invalid or expired"}
```

| Status | `error` | Cause |
|--------|---------|-------|
| 401 | `invalid_request` | no token presented |
| 401 | `invalid_token` | the token does not verify, is expired or revoked, is neither a `typ: at+jwt` JWT nor a live opaque `at_…` token, or its client or user no longer exists |
| 403 | `insufficient_scope` | the token lacks the `openid` scope |

A DPoP-bound token presented as a plain bearer token, without a proof or with another key's proof answers `401` with a challenge naming both schemes and the accepted proof algorithms (RFC 9449 §7.1):

```text
WWW-Authenticate: DPoP error="invalid_token", error_description="...", algs="ES256 ES384 RS256 RS384 RS512 PS256 PS384 PS512 EdDSA", Bearer error="invalid_token"
```

### ridm-auth

The [`ridm-auth`](../quickstarts/protect-an-api.md) crate answers the same way on your own API. Its `AuthError` keeps "not acceptable" (401), "not enough" (403) and "could not check" (503) apart, because a caller that cannot tell them apart cannot retry correctly:

| Failure | Status | `WWW-Authenticate` | Body |
|---------|--------|--------------------|------|
| No `Authorization: Bearer` header | 401 | `Bearer realm="<realm>"` (no error code) | `{"error_description"}` |
| Malformed token, unknown `kid`, bad signature, unacceptable `alg`, wrong `typ`, expired, not yet valid, wrong issuer or audience, missing or malformed claim, sender-constrained token the validator cannot verify | 401 | `Bearer realm="<realm>", error="invalid_token", error_description="..."` | `{"error": "invalid_token", "error_description"}` |
| Missing scope, permission or role | 403 | `Bearer realm="<realm>", error="insufficient_scope", error_description="..."` | `{"error": "insufficient_scope", "error_description"}` |
| Key set or discovery document unreachable | 503 | none | `{"error_description"}`, with `Retry-After: 5` |
| Validator misconfigured | 500 | none | `{"error_description"}` |

The realm defaults to `api`. `AuthError::is_transient()` is true only for the 503 family. Every response carries `Cache-Control: no-store`.

`ridm-auth` validates JWT access tokens only. An opaque `at_…` token, issued to a client registered with `access_token_format: opaque`, is refused as a malformed token (`401 invalid_token`); an API that must accept those checks them at `/introspect` instead.

## Problem documents (RFC 9457)

The admin API, the account API, the flow API, recovery, verification, invitations and device verification answer errors as `application/problem+json`:

```http
HTTP/1.1 403 Forbidden
Content-Type: application/problem+json

{
  "type": "urn:ridm:error:forbidden",
  "title": "Forbidden",
  "status": 403,
  "detail": "missing permission `ridm:users:write`"
}
```

| Field | Meaning |
|-------|---------|
| `type` | a stable URN identifying the kind of error (below); match on this, not on `detail` |
| `title` | the HTTP reason phrase |
| `status` | the HTTP status |
| `detail` | a human-readable explanation; omitted for `5xx`, whose details are logged instead |
| `errors` | for `validation` only: `[{"field", "message"}]` |

| `type` | Status | Meaning |
|--------|--------|---------|
| `urn:ridm:error:bad-request` | 400 | malformed input, a failed business rule, an invalid cursor, a JSON body that does not parse or has unknown fields, a reference to something that does not exist |
| `urn:ridm:error:validation` | 400 | field-level validation failure, listed in `errors` |
| `urn:ridm:error:unauthorized` | 401 | no token, or a token that is not acceptable |
| `urn:ridm:error:forbidden` | 403 | authenticated but not allowed: a missing permission, a token scoped to another tenant, an inactive account, a refused IP address, a wrong CSRF token |
| `urn:ridm:error:reauthentication-required` | 403 | a security change needs a recent sign-in (below) |
| `urn:ridm:error:not-found` | 404 | the resource (or tenant) does not exist or is not visible to the caller |
| `urn:ridm:error:conflict` | 409 | a uniqueness violation (`already exists`) or a conflicting state |
| `urn:ridm:error:rate-limited` | 429 | a rate limit refused the request; `Retry-After` is set |
| `urn:ridm:error:unavailable` | 503 | a dependency (CAPTCHA provider, IP-rule store, a mail or SMS backend) failed |
| `urn:ridm:error:internal` | 500 | a database, cache or internal error; no `detail` |

Admin and account API `401` responses also carry `WWW-Authenticate: Bearer realm="ridm-admin"` (with `error="invalid_token"` when a token was presented but refused) and `Cache-Control: no-store`. The account API shares the admin API's realm.

### Reauthentication required

Security changes in the account API (second factors, the password, contact details, linked identities, trusted devices, sessions, personal access tokens, deleting the account) need a sign-in from the last 15 minutes, and with a second factor once the account has one. Otherwise:

```json
{
  "type": "urn:ridm:error:reauthentication-required",
  "title": "Forbidden",
  "status": 403,
  "detail": "sign in again with your second step to change security settings"
}
```

The client re-authorizes with `max_age=0` (and an MFA class in `acr_values` when the detail asks for the second step) and retries with the new token.

### Flow API

Problems in the flow API use the same types; CAPTCHA enforcement reports `validation` with `{"field": "captcha_token", "message": "captcha_required"}` or `"captcha_failed"`. A refused credential is not a problem document but a plain `401` the sign-in page shows inline, carrying the flow's failed-attempt count:

```json
{"error": "invalid_credentials", "error_description": "incorrect identifier or password", "attempts": 2}
```

| `error` | Step |
|---------|------|
| `invalid_credentials` | password |
| `account_locked` | password, after `settings.lockout.max_failures` |
| `invalid_code` | one-time codes, magic links, second-step codes |
| `invalid_passkey` | passkey sign-in and second step |

## SCIM errors

The SCIM endpoints answer RFC 7644 §3.12 error documents as `application/scim+json`:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "400",
  "scimType": "invalidFilter",
  "detail": "unexpected token at position 14"
}
```

`scimType` is one of `invalidFilter`, `invalidSyntax`, `invalidPath`, `invalidValue`, `noTarget`, `uniqueness` (409) and `tooMany` (a non-indexed user filter over more than 2,000 users, or `startIndex` beyond 2,000). A missing or invalid provisioning token is `401` with `WWW-Authenticate: Bearer realm="scim"`.

Adding members to a group whose roles grant any `ridm:*` admin permission is `403` with no `scimType` (RFC 7644 defines none for an operation the credentials do not permit), and nothing is changed; see [SCIM provisioning](../admin/scim.md#how-a-scim-group-maps-onto-a-group).

## Rate limits

The OAuth, authorization and flow endpoint families are rate limited (see [Rate limits, IP rules and CAPTCHA](../admin/security-controls.md)). Every response of a limited family carries the tightest bucket's state:

```http
RateLimit-Limit: 600
RateLimit-Remaining: 0
RateLimit-Reset: 42
Retry-After: 42
```

A refused request is `429` with `Retry-After` in seconds, rendered in the family's own format:

| Family | Body |
|--------|------|
| `/token`, `/introspect`, `/revoke`, `/userinfo`, `/device_authorization`, `/par`, `/register` | `{"error": "slow_down", "error_description": "too many requests; retry after 42 seconds"}` |
| flow API, recovery, verification, invitations, device verification | problem document of type `urn:ridm:error:rate-limited` |
| `/authorize`, brokering | an HTML error page with the code `slow_down` |

A tenant IP rule that refuses the address is `403` in the same three formats (`access_denied` for OAuth and HTML, `urn:ridm:error:forbidden` for problems). If Valkey is unreachable the limiter fails open with a warning in the log; the IP-rule check fails closed (`503`).
