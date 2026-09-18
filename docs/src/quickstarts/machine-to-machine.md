# Machine-to-machine access

A program with no user behind it (a nightly job, a backend calling another
backend, a CI pipeline) gets an access token with the OAuth 2.0
`client_credentials` grant: it authenticates as itself and receives a token for
one API. By the end of this page a job called `orders-job` places an order
through the example orders API.

This page uses the `demo` tenant and the orders API from
[Run rIDM locally](local.md) and [Protect a Rust API](protect-an-api.md):

```bash
export RIDM_URL=http://localhost:8090
export RIDM_TOKEN=rpat_...        # ridm:clients:*, ridm:users:*, ridm:roles:read

RIDM_ISSUER=http://localhost:8090/t/demo RIDM_AUDIENCE=https://orders.example \
RIDM_ALLOW_HTTP=true cargo run -p ridm-example-axum-api      # :8081, in another terminal
```

## 1. Register a machine client

```bash
ridm --tenant demo client create \
  --name "Orders nightly job" \
  --client-id orders-job \
  --type machine \
  --audience https://orders.example \
  --scope orders:read --scope orders:write
```

```text
Client `orders-job` created (Orders nightly job).
client secret: cs_...
  (shown once — store it now)
```

`--type machine` means: token endpoint auth method `client_secret_basic`, the
`client_credentials` grant only, no redirect URIs, no PKCE, and no scopes unless
you list them. `--audience` limits which resource servers the client may get
tokens for; leave it out and any non-built-in resource server of the tenant is
allowed, which is rarely what you want.

The secret is shown once. Store it like a database password.

## 2. Get a token

```bash
CLIENT_SECRET=cs_...
curl -s -u "orders-job:$CLIENT_SECRET" \
  -d grant_type=client_credentials \
  -d resource=https://orders.example \
  -d scope="orders:read orders:write" \
  http://localhost:8090/t/demo/token | jq
```

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6…",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "orders:read orders:write"
}
```

| Parameter | Meaning |
|-----------|---------|
| `-u client_id:secret` | `client_secret_basic`: the credentials in the `Authorization` header. rIDM accepts only the method registered for the client. |
| `grant_type=client_credentials` | refused for public clients (`unauthorized_client`) |
| `resource` | RFC 8707: the resource server the token is for. It becomes `aud`. Repeat it for several. It must be an absolute URI naming a resource server of the tenant that is in the client's `allowed_audiences`; otherwise `invalid_target`. |
| `scope` | optional; every scope must exist in the tenant and be allowed for the client (`invalid_scope` otherwise). `openid` and `offline_access` are refused: there is no user to identify and nothing to refresh. Without `scope`, the token gets the tenant's default scopes (`is_default`) that the client is allowed, other than those two, which is often none. A scope bound to a resource server (as `orders:read` is to `https://orders.example` in the demo tenant) also adds that resource server to `aud`. |

Without `resource`, the token is minted for every audience in the client's
`allowed_audiences`; with that list empty too, `aud` is the client's own
`client_id`, which no API accepts. Send `resource` every time.

There is no refresh token: when the access token expires (five minutes by
default), ask for a new one. Cache the token and reuse it until shortly before
`expires_in` runs out rather than requesting one per call. The token endpoint is
rate-limited per tenant and per client address; see
[Rate limits, IP rules and CAPTCHA](../admin/security-controls.md).

## 3. Call the API, and be refused

```bash
TOKEN=$(curl -s -u "orders-job:$CLIENT_SECRET" \
  -d grant_type=client_credentials -d resource=https://orders.example \
  http://localhost:8090/t/demo/token | jq -r .access_token)

curl -s -H "Authorization: Bearer $TOKEN" localhost:8081/whoami | jq
curl -i -H "Authorization: Bearer $TOKEN" localhost:8081/orders
```

`/whoami` answers, because the token is valid for `https://orders.example`:

```json
{
  "subject": "orders-job",
  "tenant": "…",
  "client": "orders-job",
  "scopes": [],
  "roles": [],
  "permissions": [],
  "client_only": true
}
```

`GET /orders` answers `403 insufficient_scope`: the token is missing permission
`orders:read`. The subject is the client itself (`sub` equals `client_id`), and a
client on its own holds no roles, so the token carries no `permissions`.

Scopes are a different matter. An API can gate on the scopes a client was allowed
(`Guard::scope("orders:read")` in `ridm-auth`), and a token requested with
`scope=orders:read` carries it. The orders API checks permissions, which come
from roles, and roles belong to users. That is what a service account is for.

## 4. Give the client a service account

A **service account** is a user of the tenant, named `svc-{client_id}`, that the
client's `client_credentials` tokens are issued for. It holds roles and groups
like any other user, so the token carries their permissions.

```bash
SVC=$(curl -s -X PUT -H "Authorization: Bearer $RIDM_TOKEN" \
  "$RIDM_URL/admin/tenants/demo/clients/orders-job/service-account" | jq -r .service_account.id)

ROLE=$(curl -s -H "Authorization: Bearer $RIDM_TOKEN" \
  "$RIDM_URL/admin/tenants/demo/roles" | jq -r '.[] | select(.name=="orders-manager") | .id')

curl -s -X PUT -H "Authorization: Bearer $RIDM_TOKEN" \
  "$RIDM_URL/admin/tenants/demo/users/$SVC/roles/$ROLE" | jq .effective
```

| Request | Effect |
|---------|--------|
| `PUT /admin/tenants/{slug}/clients/{client}/service-account` | creates the `svc-orders-job` user and links it to the client; returns the client and `service_account`. Idempotent. Needs `ridm:clients:write`, and the client must allow `client_credentials`. |
| `DELETE …/service-account` | unlinks and deletes that user |
| `PUT /admin/tenants/{slug}/users/{user}/roles/{role_id}` | assigns a role; assigning one twice is not an error. Needs `ridm:users:write`, and an administrator can grant only permissions it holds. |

In a configuration document the same client reads `"service_account": true`;
role assignments are not part of the document, so they stay an admin API (or
console) step. See [Configuration as code](../concepts/config-as-code.md).

Request a new token (the old one keeps what it was minted with) and try again:

```bash
TOKEN=$(curl -s -u "orders-job:$CLIENT_SECRET" \
  -d grant_type=client_credentials -d resource=https://orders.example \
  http://localhost:8090/t/demo/token | jq -r .access_token)

curl -s -H "Authorization: Bearer $TOKEN" localhost:8081/whoami | jq '{subject, roles, permissions, client_only}'
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"item":"Anvil","quantity":2}' localhost:8081/orders
```

Now `subject` is the service account's user id, `roles` is `["orders-manager"]`,
`permissions` is `["orders:read", "orders:write"]`, `client_only` is `false`, and
the order is placed (`201`). In `ridm-auth`, `Claims::is_client_only()` tells a
client acting on its own from one with a service account.

## Administering rIDM from a machine client

The admin API is itself a resource server, `urn:ridm:admin`. It is built in, so a
client must list it in `allowed_audiences` explicitly; an empty list does not
imply it. With that audience, a service account holding administrator roles in
`master` or the tenant, and a secret, the CLI runs non-interactively:

```bash
printf '%s' "$CI_CLIENT_SECRET" |
  ridm login --url https://id.example.com --tenant acme --client-id ci-bot --client-secret-stdin
```

See [The ridm command line](../admin/cli.md) and
[Administrator access](../admin/access.md).

## Stronger client authentication: private_key_jwt

A client secret is a shared secret: rIDM stores only its hash, but whoever holds
the secret can use it, and it has to travel to every place the job runs. With
`private_key_jwt` (RFC 7523) the client instead holds a private key that never
leaves it, and rIDM holds the public key. Each token request carries a short
signed assertion in place of a secret.

`ridm client create` has no flag for the client's keys, so register this kind of
client through the admin API, with either an inline `jwks` or a `jwks_uri` the
client publishes (rIDM refetches a `jwks_uri` when an assertion names a key it has
not seen, so the client can rotate its own keys):

```bash
curl -s -X POST "$RIDM_URL/admin/tenants/demo/clients" \
  -H "Authorization: Bearer $RIDM_TOKEN" -H 'content-type: application/json' \
  -d '{
        "client_id": "orders-sync",
        "name": "Orders sync service",
        "client_type": "machine",
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks_uri": "https://sync.acme.example/.well-known/jwks.json",
        "allowed_audiences": ["https://orders.example"]
      }'
```

No secret is minted. The assertion is a JWT the client signs with its private
key:

| Claim or header | Value |
|-----------------|-------|
| `alg` | an asymmetric algorithm; HMAC (`HS256` …) is refused |
| `kid` | the key's id in the client's key set (may be omitted when the set has exactly one key) |
| `iss`, `sub` | both the `client_id` |
| `aud` | the tenant's token endpoint URL, or its issuer |
| `exp` | at most 600 seconds after `iat` |
| `jti` | unique; a reused `jti` is refused for the assertion's lifetime |

```bash
curl -s \
  -d grant_type=client_credentials \
  -d resource=https://orders.example \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion="$ASSERTION" \
  https://id.example.com/t/demo/token
```

Everything after authentication (audience, scopes, service account,
permissions) works exactly as with a secret. The confidential web app in
[Sign in from a server-side web app](web-app.md) can use `private_key_jwt` the
same way.

## Troubleshooting

| Answer from `/token` | Cause |
|----------------------|-------|
| `401 invalid_client` | wrong secret, a secret sent with a method other than the registered one, a retired secret, or a bad assertion |
| `400 unauthorized_client` | the client is public, or not allowed `client_credentials` |
| `400 invalid_scope` | a scope the tenant does not define, one the client is not allowed, one bound to a resource server the client may not target, or `openid` / `offline_access` |
| `400 invalid_target` | `resource` is not an absolute URI, names no resource server, or names one outside `allowed_audiences` |

Every error code is listed in [Errors](../reference/errors.md); the claims in
these tokens are in [Token claims](../reference/token-claims.md).
