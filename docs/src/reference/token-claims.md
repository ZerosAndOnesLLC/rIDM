# Token claims

What each token rIDM issues carries, claim by claim, as built in [`api/src/services/tokens.rs`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/api/src/services/tokens.rs), [`claims.rs`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/api/src/services/claims.rs) and [`api/src/oidc/token.rs`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/api/src/oidc/token.rs). For how tokens are used, see [Tokens](../concepts/tokens.md).

Every JWT is a JWS signed with one of the tenant's active signing keys and names that key in the `kid` header. The algorithm is `settings.keys.default_alg` (`RS256` by default), except for access tokens whose audience is a resource server with its own `signing_alg` (`RS256`, `RS384`, `RS512`, `ES256` or `EdDSA`), which are signed with the tenant's active key of that algorithm. Audiences that disagree on the algorithm cannot share one token (`invalid_target`; request them separately). The keys are published at `{issuer}/.well-known/jwks.json`.

## JOSE `typ` headers

The `typ` header says what a JWT is, which is what stops one kind being replayed as another: rIDM's own endpoints and `ridm-auth` refuse an access token whose `typ` is not `at+jwt`.

| Token | `typ` |
|-------|-------|
| Access token | `at+jwt` (RFC 9068) |
| ID token | `JWT` |
| Back-channel logout token | `logout+jwt` |
| JARM authorization response (`response_mode=*.jwt`) | `JWT` |

An ID token for a client with `id_token_encryption` configured is additionally encrypted as a JWE (`RSA-OAEP-256` or `RSA-OAEP`, with `A256GCM` or `A128GCM`) to the client's RSA key from its `jwks` (a key with `use: enc` is preferred).

## Access token

Access tokens are JWTs unless the client is registered with `access_token_format: opaque`. Such a client receives `at_<random>` instead: the claims below are assembled the same way but kept in Valkey, keyed by the token's SHA-256, until the token expires. Only `/introspect` reveals them to a resource server; `/userinfo`, `/revoke`, token exchange and the account and admin APIs accept the opaque form directly. [`ridm-auth`](../quickstarts/protect-an-api.md) validates JWTs only. See [Registering clients](../admin/clients.md#opaque-access-tokens).

| Claim | Present | Value |
|-------|---------|-------|
| `iss` | always | the tenant's issuer: `{PUBLIC_URL}/t/{slug}`, or `https://{custom_domain}` |
| `sub` | always | the user's subject (below); for `client_credentials` without a service account, the `client_id` |
| `aud` | always | the resource servers the token is for (a string when one, an array when several), plus audiences from `audience` claim mappers; the `client_id` when there is none |
| `client_id` | always | the client the token was issued to |
| `azp` | always | the same `client_id` |
| `iat`, `nbf` | always | issue time (seconds since the epoch) |
| `exp` | always | expiry; see [lifetimes](#lifetimes) |
| `jti` | always | a UUIDv7; revocation denylists it until `exp` |
| `tid` | always | the tenant's UUID. A relying party serving several tenants of one deployment keys on it |
| `org_id` | the sign-in acts in an organization | the organization's UUID (see [Organizations](../concepts/organizations.md)). It comes from the session, so the same user signing in to another organization gets another value; no mapper can write it |
| `scope` | always | the granted scopes, space-separated (see [Scopes in the token](#scopes-in-the-token)) |
| `roles` | a user subject | names of the user's effective roles: direct, inherited through groups and their ancestors, and expanded composites; a `roles` claim mapper replaces it |
| `groups` | a user subject | names (not paths) of the user's groups, including ancestor groups; a `groups` claim mapper replaces it |
| `permissions` | a user subject whose roles hold permissions on a requested resource server | permission names, e.g. `orders:read` |
| `sid` | the token came from a browser session | the session's UUID |
| `auth_time` | the token came from an authentication | when the user authenticated |
| `amr` | the token came from an authentication | authentication methods (below) |
| `acr` | the session has a class | `urn:ridm:acr:single`, `urn:ridm:acr:mfa`, or the `*:mfa` class the client asked for |
| `cnf` | a DPoP proof bound the token | `{"jkt": "<RFC 7638 thumbprint of the proof key>"}` (RFC 9449 §6.1) |
| `act` | token exchange with an `actor_token` | `{"sub", "client_id"}` of the acting party, nesting any previous `act` (RFC 8693 §4.1) |
| profile attributes | the attribute lists `access_token` in its `visible_in` and the user has a value | one claim per attribute, named after it (see [Profile attributes](#profile-attributes)) |

A `client_credentials` token for a client with a service account is issued for that account's user, so it carries `roles`, `groups` and `permissions` like any user token. A token exchanged under RFC 8693 keeps the subject token's `sub`, `sid`, `amr` and `acr`, and never outlives it.

### Scopes in the token

The `scope` claim holds what the grant carries, which can be less than what was asked:

- **Default scopes.** A request that names no scope (at `/authorize`, the device
  endpoint or `client_credentials`) gets the tenant's scopes marked `is_default` that the
  client may hold; `client_credentials` never gets `openid` or `offline_access` this way.
- **Bound scopes.** A scope bound to a resource server (`resource_server_id`) adds that
  server to the audiences, and is refused with `invalid_scope` when the client may not
  target it. A bound scope is left out of any token whose audience lacks its server, so
  a refreshed or narrowed token does not keep it.
- **`offline_access`** is kept only when every resource server in the audience has
  `allow_offline_access` on; otherwise it is dropped silently (OIDC Core §11 lets the
  provider decline it) and no refresh token outliving the session is issued.
- **Refresh and code exchange** may narrow the scopes and audiences of the original
  grant, never widen them (`invalid_scope`, `invalid_target`).

See [Resource servers, scopes and permissions](../concepts/resource-servers.md).

### Permissions

`permissions` is computed per request: for each resource server in `aud`, the permissions the user's effective roles hold on it, de-duplicated. A token for the admin API (`aud` `urn:ridm:admin`) therefore lists the caller's `ridm:*` permissions. The admin and account APIs do not trust this claim; they resolve permissions again on every request. See [Resource servers, scopes and permissions](../concepts/resource-servers.md).

### Subject identifiers

With the client's `subject_type` `public` (the default), `sub` is the user's UUID. With `pairwise` it is `base64url(SHA-256(sector | "|" | user id | "|" | tenant salt))`, where the sector is the host of the client's `sector_identifier_uri`, else the host of its first redirect URI, else its `client_id`. The same user therefore has different, stable subjects at clients of different sectors (OIDC Core §8). `sub` is computed the same way in the ID token, the userinfo response and the logout token.

## ID token

Issued from the token endpoint when the scope includes `openid` and there is a user.

| Claim | Present | Value |
|-------|---------|-------|
| `iss`, `sub` | always | as in the access token |
| `aud` | always | the `client_id` |
| `azp` | always | the `client_id` |
| `iat`, `exp` | always | issue time and expiry |
| `auth_time` | always | when the user authenticated; a token minted from a refresh token repeats the original value (OIDC Core §12.2) |
| `tid` | always | the tenant's UUID |
| `org_id` | the sign-in acts in an organization | as in the access token |
| `nonce` | the authorization request had one | echoed |
| `sid` | a browser session exists | the session's UUID, the value back- and front-channel logout name |
| `amr`, `acr` | as in the access token | refresh-derived ID tokens repeat the original values |
| `at_hash` | always (an access token is always issued alongside) | left half of the hash of the access token, using the hash of the signing algorithm (SHA-256 for `RS256`/`ES256`, SHA-384 for `RS384`, SHA-512 for `RS512` and `EdDSA`) |

The claims released by the granted scopes (below) are **not** in the ID token by default: an access token is always issued with it, so they are read from `/userinfo` (OIDC Core §5.4). A client that wants them in the ID token as well sets `id_token_scope_claims`. Profile attributes listing `id_token` in `visible_in`, and claim mappers with `id` in `include_in`, add claims to the ID token either way.

## Userinfo response

`GET` or `POST {issuer}/userinfo` with an access token carrying the `openid` scope returns plain JSON (never signed or encrypted):

- `sub` (as above);
- the claims released by the token's scopes (below), read from the user record now, not from the time of sign-in;
- profile attributes listing `userinfo` in `visible_in`;
- the claims of mappers with `userinfo` in `include_in`.

Each scope releases the claims named in its `claims` list, which administrators edit on the scope (console: Scopes; admin API: `/admin/tenants/{slug}/scopes`). The standard scopes are seeded with the OIDC Core §5.4 sets:

| Scope | Seeded `claims` |
|-------|-----------------|
| `profile` | `name`, `family_name`, `given_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` |
| `email` | `email`, `email_verified` |
| `phone` | `phone_number`, `phone_number_verified` |
| `address` | `address` |

A claim name is resolved against the user as follows: `preferred_username` is the username, `email`/`email_verified` and `phone_number`/`phone_number_verified` come from the user's contact fields (only when the user has that address or number), `locale` and `updated_at` from the record, `address` from the profile attribute `address` when it is a JSON object. Any other name is a top-level user field of that name (`username`, `email`, `phone`, `locale`, …) or else the profile attribute of that name; `attributes.<name>` names the profile attribute explicitly. A claim with no value for the user is left out. Protected claims and `roles`, `groups` and `permissions` are never released this way. A custom scope with a `claims` list releases those claims the same way.

`roles`, `groups` and `permissions` are not part of userinfo unless a mapper adds them. The `claims` request parameter (OIDC Core §5.5) is not implemented; discovery reports `claims_parameter_supported: false`.

## Profile attributes

An attribute of the tenant's [profile schema](../admin/users.md#profile-schema) whose `visible_in` lists `id_token`, `userinfo` or `access_token` appears there as a claim named after the attribute, when the user has a non-null value. It is applied after the scope claims and before the claim mappers: it never overwrites a claim a scope already released, never writes a protected claim or `roles`, `groups` or `permissions`, and a mapper writing the same claim wins.

## Logout token

Back-channel logout (OIDC Back-Channel Logout 1.0 §2.4) posts `logout_token=<jwt>` as a form to the client's `backchannel_logout_uri`, with a five-second timeout and no redirects followed.

| Claim | Value |
|-------|-------|
| `iss` | the tenant's issuer |
| `sub` | the user's subject as that client sees it |
| `aud` | the `client_id` |
| `iat` | issue time |
| `exp` | `iat` + 120 seconds |
| `jti` | a UUIDv7 |
| `sid` | the ended session's UUID |
| `events` | `{"http://schemas.openid.net/event/backchannel-logout": {}}` |

Front-channel logout loads each client's `frontchannel_logout_uri` with `iss` and `sid` query parameters appended.

## Introspection response

`POST {issuer}/introspect` (RFC 7662) answers `{"active": false}` for anything unknown, expired, revoked, issued to another client, or belonging to an inactive user, and for ID tokens, which are not access tokens. For an active access token, JWT or opaque, it returns `active: true`, `token_type` (`DPoP` when the token carries `cnf`, else `Bearer`), `typ: "at+jwt"` (JWTs only), whichever of `scope`, `client_id`, `sub`, `aud`, `iss`, `exp`, `iat`, `nbf`, `jti`, `sid`, `tid`, `roles`, `permissions`, `cnf` and `act` the token holds, and `username`. Refresh tokens report `token_type: "refresh_token"`, personal access tokens `token_type: "personal_access_token"`.

## `amr` values

`amr` lists how the session was established (RFC 8176 names), with `mfa` added once a second factor passed.

| Method | `amr` |
|--------|-------|
| Password | `pwd` |
| Magic link, email one-time code, invitation acceptance | `otp` |
| SMS one-time code | `otp`, `sms` |
| Passkey sign-in with user verification | `hwk`, `user`, `mfa` |
| Passkey sign-in without user verification | `hwk` |
| Upstream identity provider (brokering) | `fed` |
| Second step: authenticator app, email code | adds `otp`, `mfa` |
| Second step: recovery code | adds `mfa` only |
| Second step: SMS code | adds `otp`, `sms`, `mfa` |
| Second step: passkey | adds `hwk` (and `user` when verified), `mfa` |

Tokens issued by `client_credentials` carry no `amr`. A device-code token repeats the approving session's values; a refresh-derived token repeats the original ones.

## `acr` values

| Value | Meaning |
|-------|---------|
| `urn:ridm:acr:single` | one factor. Every session carries a class, so a request with `acr_values` always gets an `acr` back (OIDC Core §3.1.2.1) |
| `urn:ridm:acr:mfa` | a second factor passed (or a passkey with user verification signed in) |
| any class ending in `:mfa` | the class the client asked for in `acr_values`, asserted once a second factor passed |

`acr_values` is a preference list: rIDM honours the first class it recognises. A `*:mfa` class first is a step-up request and demands a second factor even on a trusted device; `urn:ridm:acr:single` ahead of it means the client will settle for one factor. Both built-in classes are listed in `acr_values_supported`. See [MFA and passkeys](../concepts/mfa.md).

## Claim mappers

Claim mappers add claims to the access token, the ID token and the userinfo response. A mapper is tenant-wide or belongs to one client, and is stored as `{name, client_id?, config}`, where `config` is `{"type": ..., <type fields>, "include_in": [...]}`. `include_in` names at least one of `access`, `id`, `userinfo`. Manage them with `/admin/tenants/{slug}/claim-mappers` (`ridm:mappers:read` / `write`); changes reach tokens at once.

| `type` | Fields | Produces |
|--------|--------|----------|
| `user_attribute` | `attribute`, `claim`, `json_type` (`string` default, `number`, `boolean`, `json`) | the user value `attribute` names, coerced to `json_type` (a value that cannot be coerced is skipped): `attributes.<name>` is that profile attribute; any other name is a top-level user field (`id`, `username`, `email`, `email_verified`, `phone`, `phone_verified`, `locale`, `created_at`, `updated_at`) or else the profile attribute of that name |
| `groups` | `claim`, `full_path` (default `false`) | the user's group names, or `parent/child` paths with `full_path` |
| `roles` | `claim`, `client_id` (optional) | without `client_id`, the user's tenant-wide roles; with it, only the roles scoped to that client (named by its public `client_id`) |
| `hardcoded` | `claim`, `value` (any JSON) | the fixed value |
| `template` | `claim`, `template` | a Handlebars template rendered over `user`, `tenant` (`slug`, `id`, `display_name`), `client` (`client_id`), `roles`, `groups` and `scopes`; an empty result adds nothing. Templates must compile when saved |
| `audience` | `audience` | adds an audience to access tokens only (no claim) |

```json
{
  "name": "department",
  "config": {
    "type": "user_attribute",
    "attribute": "attributes.department",
    "claim": "department",
    "json_type": "string",
    "include_in": ["access", "id"]
  }
}
```

Behaviours worth knowing:

- Mappers run after the scope claims and profile attributes, so a mapper may override
  either.
- Only a `roles` mapper may write a claim named `roles`, and only a `groups` mapper one
  named `groups`. In an access token their output replaces the built-in claim (to emit
  one client's roles, or group paths). No mapper may write `permissions`, which is
  computed from the audience's grants. A mapper breaking these rules is refused when
  saved.
- A `roles` mapper's `client_id` is resolved to the client when the tenant's mappers are
  loaded into the cache, which lasts up to five minutes; a mapper naming a client created
  after that takes effect once the cache refreshes.

### Protected claims

Mappers can never set these claims, and neither can scope claims or profile attributes. A mapper targeting one is refused when saved; one stored before that rule is skipped with a warning in the log:

`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `azp`, `at_hash`, `c_hash`, `nonce`, `auth_time`, `amr`, `acr`, `sid`, `tid`, `client_id`, `scope`, `typ`, `cnf`, `act`.

## Lifetimes

| Token | Default | Overridden by |
|-------|---------|---------------|
| Access token | 300 s (`settings.session.access_token_ttl_secs`) | the client's `access_token_ttl_secs`; then the shortest `token_ttl_secs` of the requested resource servers; token exchange caps it at the subject token's remaining life |
| ID token | 300 s (`settings.session.id_token_ttl_secs`) | the client's `id_token_ttl_secs` |
| Refresh token | 30 days (`settings.session.refresh_token_ttl_secs`) | the client's `refresh_token_ttl_secs`. Without `offline_access` it also ends with the browser session it was issued in (sign-out, idle or absolute timeout) |
| Logout token | 120 s | fixed |

Refresh tokens are opaque (`rt_...`), not JWTs; personal access tokens are opaque (`rpat_...`), and so are access tokens of clients registered as `opaque` (`at_...`). None has claims a holder can read; introspection describes them.
