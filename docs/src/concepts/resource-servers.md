# Resource servers, scopes and permissions

A **resource server** is an API that accepts rIDM access tokens: your orders
service, your billing API, rIDM's own admin API. Registering it with the
tenant gives it an identifier, which becomes the `aud` (audience) of tokens
meant for it, and a set of permissions that roles can be granted on it.

Three separate ideas meet here, and they answer different questions:

| Concept | Question it answers | Who decides | Where it shows up |
|---------|---------------------|-------------|-------------------|
| Audience | Which API is this token for? | the client asks, the client's configuration allows | `aud` |
| Scope | What has the user let this application do on their behalf? | the client asks, the user consents | `scope` |
| Permission | What is this user allowed to do in this API? | administrators, through roles | `permissions` |

## Audiences: one token, one API

A resource server's `identifier` is an opaque string, conventionally a URL such
as `https://orders.example`, up to 512 characters. It cannot be changed after
creation, because tokens and APIs depend on it.

An access token names the API it is for in `aud`, and an API must refuse tokens
whose `aud` does not name it. That is what stops a token minted for a
low-value API being replayed against a high-value one in the same tenant: both
trust the same issuer and the same keys, so the signature alone cannot tell them
apart. [`ridm-auth`](../quickstarts/protect-an-api.md) checks the audience for
you; any other JWT library must be configured to.

A client obtains a token for an API in one of two ways:

- **Resource indicators (RFC 8707).** The client sends one or more `resource`
  parameters naming resource server identifiers, at `/authorize` and again at
  `/token`:

  ```http
  GET /t/acme/authorize?response_type=code&client_id=acme-spa
      &scope=openid%20profile&resource=https%3A%2F%2Forders.example
      &redirect_uri=...&code_challenge=...&code_challenge_method=S256
  ```

  A `resource` that is not a registered resource server, or that the client is
  not allowed, is refused with `invalid_target`. On a refresh, `resource`
  narrows the new access token to some of the audiences the original grant
  carried, so one refresh token obtained for several APIs can mint a narrow
  token for each in turn; naming an audience the grant did not carry is
  `invalid_target`, and without `resource` the refresh repeats the original
  audiences.
- **The client's defaults.** With no `resource` parameter, the token is issued
  for every audience in the client's `allowed_audiences`.

Requesting a scope that is bound to a resource server (see below) also targets
that resource server, on top of the audiences chosen either way.

A client with an empty `allowed_audiences` may request any of the tenant's
resource servers, except the built-in ones, which must always be listed
explicitly. A token requested for no resource server at all has the client's
own `client_id` as its audience.

## Scopes: what the user agreed to

Scopes are the OAuth vocabulary for delegation: `openid`, `profile`, `email`,
`phone`, `address`, `offline_access`, plus any the tenant defines. A client may
only request scopes in its `allowed_scopes`, and with consent required the user
approves them on the consent screen, where each scope's `description` is shown.
The granted scopes appear space-separated in the token's `scope` claim.

**Default scopes.** A request that names no scope at all is given the tenant's
scopes marked `is_default` that the client is allowed. That applies to
`/authorize`, the device flow and `client_credentials` (which never receives
`openid` or `offline_access` this way). An authorization or device request
that names no scope and has no default to fall back on is refused with
`invalid_scope`; a `client_credentials` token may carry no scope at all.

**Released claims.** Every scope, standard or custom, has a `claims` list, and
granting the scope releases those claims from the user's record at
`/userinfo` (and in the ID token for clients with `id_token_scope_claims`). A
claim name is looked up as an OIDC standard claim (`preferred_username` is the
username, `phone_number` the phone, `email_verified`, `locale`, `updated_at`,
`address`), then as a top-level user field, then as a profile attribute of that
name; `attributes.<name>` names a profile attribute explicitly. The standard
scopes are seeded with the OIDC Core §5.4 claim sets: `profile` the name
fields, `preferred_username`, `locale` and the rest, `email` the address and
whether it is verified, `phone` the number, `address` the postal address.
Editing a standard scope's `claims` changes what it releases. Claims the token
service owns (`sub`, `aud`, `roles`, `permissions` and the like) are never
released this way. [Claim mappers](users-groups-roles.md#claims-from-users-groups-and-roles)
add or reshape claims on top.

**Bound scopes.** A scope linked to a resource server (`resource_server_id`)
belongs to that API. Requesting it adds the resource server to the token's
audiences, and is refused with `invalid_scope` if the client may not target
that resource server. A token that does not carry that audience (a refresh
narrowed to another resource, say) has the scope dropped from its `scope`
claim.

Standard scopes can have their descriptions and claims changed but cannot be
deleted.

## Permissions: what the user is allowed to do

A permission is a name defined on one resource server, such as `orders:read`
or `orders:refund`, and granted to roles. When a token is issued for a
resource server, rIDM takes the subject's [effective roles](users-groups-roles.md#effective-roles),
collects every permission those roles hold on that resource server, and puts
the result in the access token's `permissions` claim:

```json
{
  "iss": "https://id.example.com/t/acme",
  "sub": "0199a0c4-7e1b-7c52-9d0e-5f3b2c1a4d77",
  "aud": "https://orders.example",
  "scope": "openid profile",
  "roles": ["support"],
  "permissions": ["orders:read", "orders:refund"]
}
```

With several audiences in one token, the claim holds the union of the
permissions across them.

### Why permissions and scopes are separate

A scope says what the *application* may do for the user; a permission says
what the *user* may do at all. An intern's browser and a finance manager's
browser run the same single-page app, request the same scopes and get the
same consent screen, but only one of them should be able to issue refunds.
Encoding that in scopes would mean giving the client every scope any user
might need and trusting it to ask for less. Permissions keep the decision on
the server: the administrator grants `orders:refund` to the `finance` role, and
the API checks for `orders:refund` in `permissions`.

An API should therefore check the audience, then the permission; it may also
check the scope when it wants to know that the user delegated that kind of
access to this particular application.

## Token lifetime and signing per API

A resource server may set its own access token lifetime (`token_ttl_secs`),
which overrides the client's and the tenant's for tokens aimed at it. A token
for several resource servers gets the shortest of their lifetimes, so a
sensitive API can insist on very short-lived tokens without every client
having to be reconfigured.

**Signing algorithm.** A resource server that can only verify one algorithm
sets `signing_alg` (`RS256`, `RS384`, `RS512`, `ES256` or `EdDSA`). Access
tokens for it are signed with the tenant's active key of that algorithm; saving
the resource server generates such a key if the tenant has none, and the
scheduled rotation keeps it fresh like the default key (see
[Signing keys and the master key](keys.md)). Without `signing_alg` the tenant's
`default_alg` is used. A token has one signature, so a request for several
resource servers that name different algorithms is refused with
`invalid_target`: request them separately.

**Offline access.** `allow_offline_access` (on by default) decides whether a
token for this API may carry `offline_access`, the scope that lets a refresh
token outlive the user's sign-in session (see
[Tokens](tokens.md#refresh-tokens)). When any audience of a grant has it off,
`offline_access` is dropped from the grant, and the refresh token ends with
the session.

## Built-in resource servers

Every tenant carries two resource servers that rIDM owns:

| Identifier | Used by |
|------------|---------|
| `urn:ridm:admin` | the admin API (`/admin/...`); its permissions are the `ridm:*` catalogue |
| `urn:ridm:account` | the self-service account API (`/t/{slug}/account/...`); no permissions, a token may only act on its own subject |

They cannot be changed or deleted. A client only obtains a token for either of
them when it lists the identifier in `allowed_audiences`; an otherwise
unrestricted client never gets one implied. Anyone holding an admin token can
change users and clients, so this is not left to defaults.

Resource servers are cached by identifier on every node and evicted when
written, and the permissions a set of roles holds are cached under the
tenant's roles version, so issuing a token does not query the permission tables
on the hot path.
