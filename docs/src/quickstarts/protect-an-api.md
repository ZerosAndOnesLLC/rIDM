# Protect a Rust API with ridm-auth

An API that accepts rIDM access tokens, built with axum and
[`ridm-auth`](https://github.com/ZerosAndOnesLLC/rIDM/tree/main/crates/ridm-auth).
By the end, an invoices API answers `401` without a token, `403` for a token
without the right permission, and `200` for one with it.

A resource server holds no sessions, cookies or users. It verifies a signed JWT
against the issuer's published keys, checks the token was minted for *this* API,
and decides whether the subject's permissions allow the request. `ridm-auth` does
those three steps; getting a token is the client's job (the other quickstarts).

This page assumes a local rIDM on `http://localhost:8090` and a `ridm` CLI logged
in, as set up in [Run rIDM locally](local.md). In production the issuer would
be `https://id.example.com/t/acme`.

```bash
export RIDM_URL=http://localhost:8090
export RIDM_TOKEN=rpat_...      # a token with ridm:tenants:*, ridm:users:*, ridm:roles:*, ridm:clients:*
```

## 1. Register the API in rIDM

rIDM calls an API a **resource server**. Its `identifier` is the value access
tokens for it carry in `aud`; it has to be an absolute URI and it never changes.
Its **permissions** are what roles grant, and what the API checks. See
[Resource servers, scopes and permissions](../concepts/resource-servers.md).

Create a tenant and describe the API in a configuration document, `acme.json`:

```json
{
  "format": "ridm.tenant/1",
  "tenant": { "slug": "acme", "display_name": "Acme" },
  "resource_servers": [
    {
      "identifier": "https://invoices.acme.example",
      "name": "Invoices API",
      "permissions": [
        { "name": "invoices:read", "description": "See invoices" },
        { "name": "invoices:write", "description": "Issue invoices" }
      ]
    }
  ],
  "scopes": [
    { "name": "invoices:read", "description": "See your invoices",
      "resource_server": "https://invoices.acme.example" },
    { "name": "invoices:write", "description": "Issue invoices on your behalf",
      "resource_server": "https://invoices.acme.example" }
  ],
  "roles": [
    { "name": "invoices-reader", "description": "May see invoices",
      "permissions": ["https://invoices.acme.example#invoices:read"] },
    { "name": "invoices-clerk", "description": "May see and issue invoices",
      "permissions": [
        "https://invoices.acme.example#invoices:read",
        "https://invoices.acme.example#invoices:write"
      ] }
  ],
  "clients": [
    {
      "client_id": "invoices-smoke",
      "name": "Invoices smoke test",
      "client_type": "machine",
      "allowed_audiences": ["https://invoices.acme.example"],
      "allowed_scopes": ["invoices:read", "invoices:write"],
      "service_account": true
    }
  ]
}
```

```bash
ridm tenant create acme --name "Acme"
ridm --tenant acme tenant import -f acme.json --yes
```

The import prints `client invoices-smoke secret: cs_…` once. Keep it: that machine
client is how step 4 gets a token to test with.

A permission in a role is written `{resource server identifier}#{permission}`.
The token carries only the permission name (`invoices:read`), and only when the
token was minted for that resource server. The two scopes are bound to the
resource server, so a client that requests `invoices:read` also gets the
invoices API added to its token's audience.

A resource server can also carry `signing_alg`, when the API can only verify
one algorithm (`ridm-auth` accepts all five rIDM signs with: `RS256`, `RS384`,
`RS512`, `ES256`, `EdDSA`), and `allow_offline_access` (on by default), which
decides whether refresh tokens behind tokens for this API may outlive the
user's sign-in session. See
[Resource servers, scopes and permissions](../concepts/resource-servers.md#token-lifetime-and-signing-per-api).

A configuration document reconciles the whole tenant section, `settings`
included. On a new tenant that is what you want; on an existing one, start from
`ridm tenant export` and edit that, and check with `ridm tenant diff` first. See
[Configuration as code](../concepts/config-as-code.md).

The same objects can be created one at a time through the admin API:

| Step | Request |
|------|---------|
| resource server | `POST /admin/tenants/acme/resource-servers` with `identifier`, `name` |
| permission | `POST /admin/tenants/acme/resource-servers/{rs}/permissions` with `name`, `description` |
| role | `POST /admin/tenants/acme/roles` with `name`, `description` |
| grant a permission to a role | `PUT /admin/tenants/acme/roles/{role}/permissions/{permission_id}` |

The [Admin API reference](../reference/admin-api/index.html) has the bodies.

## 2. Add ridm-auth

`ridm-auth` is not on crates.io yet, so depend on the repository at a release tag.
It needs Rust 1.98 or later.

```toml
[package]
name = "invoices-api"
version = "0.1.0"
edition = "2024"

[dependencies]
ridm-auth = { git = "https://github.com/ZerosAndOnesLLC/rIDM", tag = "v0.1.0" }
axum = "0.8"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
serde_json = "1"
```

The default features are `axum` (the extractor, the guard and the error
responses) and `rustls` (TLS for the crate's own calls to the issuer).

## 3. Write the API

`src/main.rs`:

```rust
use std::sync::Arc;

use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use axum::{Json, Router};
use ridm_auth::Validator;
use ridm_auth::axum::{Guard, RidmClaims, guard};
use serde_json::{Value, json};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = std::env::var("RIDM_ISSUER")?; // http://localhost:8090/t/acme
    let audience = std::env::var("RIDM_AUDIENCE")?; // https://invoices.acme.example
    let allow_http = std::env::var("RIDM_ALLOW_HTTP").is_ok_and(|v| v == "true");

    // One validator for the whole process: it holds the key-set cache.
    let validator: Arc<Validator> = Validator::builder(&issuer)
        .audience(&audience)
        .allow_http(allow_http)
        .discover()
        .await?
        .shared();
    // Optional: fetch the keys now, so a wrong issuer fails at startup.
    validator.warm().await?;

    let read = Router::new()
        .route("/invoices", get(list_invoices))
        .route_layer(from_fn_with_state(
            Guard::new(validator.clone())
                .permission("invoices:read")
                .realm("invoices"),
            guard,
        ));
    let write = Router::new()
        .route("/invoices", post(issue_invoice))
        .route_layer(from_fn_with_state(
            Guard::new(validator.clone())
                .permission("invoices:write")
                .realm("invoices"),
            guard,
        ));

    let app = Router::new()
        .route("/whoami", get(whoami)) // any valid token, no permission needed
        .merge(read)
        .merge(write)
        .with_state(validator);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8082").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn whoami(RidmClaims(claims): RidmClaims) -> Json<Value> {
    Json(json!({
        "subject": claims.sub,
        "client": claims.client_id,
        "scopes": claims.scopes().collect::<Vec<_>>(),
        "roles": claims.roles,
        "permissions": claims.permissions,
    }))
}

async fn list_invoices(RidmClaims(claims): RidmClaims) -> Json<Value> {
    Json(json!({ "invoices": [], "for": claims.sub }))
}

async fn issue_invoice(RidmClaims(claims): RidmClaims) -> Json<Value> {
    Json(json!({ "issued_by": claims.sub }))
}
```

What each piece does:

- **`Validator::builder(issuer)`** names the tenant whose tokens are accepted.
  `.audience(...)` is required: `build` and `discover` refuse a validator without
  one, because it would accept a token minted for any API of the tenant.
- **`.discover()`** reads `jwks_uri` from
  `{issuer}/.well-known/openid-configuration` and checks that the document names
  the same issuer. `.build()` skips discovery and assumes
  `{issuer}/.well-known/jwks.json`.
- **`.allow_http(true)`** is needed for a local `http://` issuer and for nothing
  else; an `http://` issuer or key set is refused otherwise.
- **`Guard`** validates once for a route subtree and refuses anything short of
  what it asks for: `.permission`, `.scope` and `.role` each add a requirement
  (all must hold). `.realm` names the realm in the `WWW-Authenticate` challenge
  (default `api`).
- **`RidmClaims`** hands a handler the verified claims. Behind a guard it reuses
  what the guard verified; on an unguarded route (`/whoami`) it validates the
  `Authorization` header itself and asks for nothing more.
  `OptionalRidmClaims` does the same for a route that also serves anonymous
  callers; a token that *is* presented must still be valid.

Every check `ridm-auth` makes:

| Check | Refused as |
|-------|------------|
| signature, against the issuer's JWKS (cached; refetched when a token names an unknown `kid`) | `invalid_token` |
| JOSE `typ` is `at+jwt`, so an ID token cannot be spent as an access token | `invalid_token` |
| `alg` is asymmetric, allowed, and matches the published key | `invalid_token` |
| `iss` is the configured issuer, `aud` contains the configured audience | `invalid_token` |
| `exp` and `nbf`, with 60 seconds of leeway | `invalid_token` |
| no `cnf` (a DPoP-bound token is refused, not downgraded; a certificate-bound one passes `validate_with_certificate` with its certificate) | `invalid_token` |
| the scopes, permissions and roles the guard or builder asked for | `insufficient_scope` |

It does not check revocation: a verified token is accepted until it expires.
Access tokens live five minutes by default; an API that must notice a revocation
sooner should call the tenant's `/introspect` endpoint instead. See
[Tokens](../concepts/tokens.md).

`ridm-auth` validates JWT access tokens only. A client registered with
`access_token_format: opaque` receives `at_...` tokens that carry no claims and
no signature; an API serving such clients has to send each token to
`/introspect` (as a confidential client of the tenant) instead of using
`ridm-auth`. See [Opaque access tokens](../concepts/tokens.md#opaque-access-tokens).

Without axum, the same checks are two calls:

```rust
let claims = validator.validate(token).await?;          // or validate_authorization(header)
claims.require_permission("invoices:read")?;            // Err(AuthError::MissingPermission)
```

`AuthError::status()` and `AuthError::www_authenticate(realm)` give the response
to send.

Run it:

```bash
RIDM_ISSUER=http://localhost:8090/t/acme \
RIDM_AUDIENCE=https://invoices.acme.example \
RIDM_ALLOW_HTTP=true \
cargo run
```

## 4. Get a token to test with

The `invoices-smoke` client from step 1 has a **service account**: a user named
`svc-invoices-smoke` that its `client_credentials` tokens are issued for, so it can
hold roles like anyone else. Give it the reader role:

```bash
SVC=$(curl -s -X PUT -H "Authorization: Bearer $RIDM_TOKEN" \
  "$RIDM_URL/admin/tenants/acme/clients/invoices-smoke/service-account" | jq -r .service_account.id)
ROLE=$(curl -s -H "Authorization: Bearer $RIDM_TOKEN" \
  "$RIDM_URL/admin/tenants/acme/roles" | jq -r '.[] | select(.name=="invoices-reader") | .id')
curl -s -X PUT -H "Authorization: Bearer $RIDM_TOKEN" \
  "$RIDM_URL/admin/tenants/acme/users/$SVC/roles/$ROLE" -o /dev/null
```

The `PUT` on `service-account` is idempotent: it returns the existing account.
Then ask for a token for the invoices API:

```bash
SECRET=cs_...   # what the import printed
TOKEN=$(curl -s -u "invoices-smoke:$SECRET" \
  -d grant_type=client_credentials \
  -d resource=https://invoices.acme.example \
  "$RIDM_URL/t/acme/token" | jq -r .access_token)
```

[Machine-to-machine access](machine-to-machine.md) explains each part.

## 5. Call it

```bash
curl -s -H "Authorization: Bearer $TOKEN" localhost:8082/whoami | jq
curl -i -H "Authorization: Bearer $TOKEN" localhost:8082/invoices
```

`/whoami` shows `"permissions": ["invoices:read"]` and `"roles": ["invoices-reader"]`,
and `GET /invoices` answers `200`.

## What a refusal looks like

Every refusal is an RFC 6750 response: a status, a `WWW-Authenticate` challenge,
`Cache-Control: no-store`, and a JSON body. Your handlers write none of it.

No token:

```bash
curl -i localhost:8082/invoices
```

```http
HTTP/1.1 401 Unauthorized
content-type: application/json
cache-control: no-store
www-authenticate: Bearer realm="invoices"

{"error_description":"no bearer token was presented"}
```

A token that is not acceptable (expired, wrong audience, bad signature, an ID
token):

```http
HTTP/1.1 401 Unauthorized
www-authenticate: Bearer realm="invoices", error="invalid_token", error_description="the token has expired"

{"error":"invalid_token","error_description":"the token has expired"}
```

A valid token without the permission. The reader cannot issue invoices:

```bash
curl -i -X POST -H "Authorization: Bearer $TOKEN" localhost:8082/invoices
```

```http
HTTP/1.1 403 Forbidden
www-authenticate: Bearer realm="invoices", error="insufficient_scope", error_description="the token is missing permission `invoices:write`"

{"error":"insufficient_scope","error_description":"the token is missing permission `invoices:write`"}
```

Assign `invoices-clerk` to the service account as in step 4, request a new token
(the old one keeps the permissions it was minted with), and the same `POST`
answers `200`.

When the issuer's key set cannot be reached and nothing usable is cached, the
answer is `503` with `Retry-After: 5` and no challenge: the token was never
judged, so the caller should retry rather than re-authenticate. While the issuer
is down, the last good key set keeps answering.

## Notes for production

- Build one `Validator` per issuer at startup and share it. A validator per
  request would fetch the key set on every request.
- Key rotation needs no restart: a token signed with a new key names a `kid` the
  cache has not seen, which triggers a refetch. `jwks_max_age` (default 10
  minutes) bounds how long a cached set is trusted, so a revoked key stops
  verifying within that window; `min_refresh_interval` (default 30 seconds) is
  the floor between fetches, so tokens naming made-up keys cannot turn your API
  into a load generator against rIDM. See [Rotating keys](../admin/key-rotation.md).
- A browser app calling this API from another origin needs a CORS layer on the
  API (`tower-http`'s `CorsLayer`, allowing the `Authorization` header), as the
  [orders example](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/examples/axum-api/src/main.rs)
  does.
- Permission is decided per route. Which *rows* a subject may see is still your
  query's job: `claims.sub` is who is calling.

The finished, runnable version of this page is
[`examples/axum-api`](https://github.com/ZerosAndOnesLLC/rIDM/tree/main/examples/axum-api).
Token contents are listed in [Token claims](../reference/token-claims.md).
