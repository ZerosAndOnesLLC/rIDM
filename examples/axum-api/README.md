# Example: an axum resource server

A Rust API that accepts rIDM access tokens. About 200 lines, of which the
authentication is three:

```rust
let validator = Validator::builder(&issuer).audience(&audience).discover().await?.shared();

Router::new()
    .route("/orders", get(list_orders))
    .route_layer(from_fn_with_state(
        Guard::new(validator).permission("orders:read"),
        ridm_auth::axum::guard,
    ));
```

Everything else is orders in a `Vec`.

## Running it

```bash
RIDM_ISSUER=http://localhost:8090/t/demo \
RIDM_AUDIENCE=https://orders.example \
RIDM_ALLOW_HTTP=true \
cargo run -p ridm-example-axum-api
```

| Variable | Default | Meaning |
|----------|---------|---------|
| `RIDM_ISSUER` | — | `https://{host}/t/{tenant}`: the `iss` of every token this API accepts |
| `RIDM_AUDIENCE` | — | the resource server identifier a token must name in `aud` |
| `RIDM_ALLOW_HTTP` | `false` | trust an `http://` issuer — development only |
| `BIND_ADDR` | `127.0.0.1:8081` | |
| `CORS_ORIGINS` | the two example clients | browser origins allowed to send `Authorization` |

## What it serves

| Route | Needs |
|-------|-------|
| `GET /healthz` | nothing |
| `GET /whoami` | a valid token, nothing more |
| `GET /orders` | `orders:read` |
| `POST /orders` | `orders:write` |

Try it with a token from a machine client. `demo-tenant.json` does not define
one; the [machine-to-machine quickstart](../../docs/src/quickstarts/machine-to-machine.md)
creates `orders-job` in the `demo` tenant and gives it a service account that
holds the permissions.

```bash
TOKEN=$(curl -s -u orders-job:<secret> \
  -d grant_type=client_credentials -d resource=https://orders.example \
  http://localhost:8090/t/demo/token | jq -r .access_token)

curl -i http://localhost:8081/orders                      # 401, WWW-Authenticate: Bearer
curl -H "Authorization: Bearer $TOKEN" localhost:8081/whoami
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d '{"item":"Anvil","quantity":2}' localhost:8081/orders
```

A token whose subject lacks `orders:write` gets

```
HTTP/1.1 403 Forbidden
www-authenticate: Bearer realm="orders", error="insufficient_scope",
  error_description="the token is missing permission `orders:write`"
```

which is [`ridm_auth::AuthError`](../../crates/ridm-auth/README.md) answering as
RFC 6750 says it should. Nothing in this file writes that response.

## Two things worth copying

**One validator for the process.** It holds the key-set cache; one per request
would fetch the key set on every request. `warm()` at startup turns a
misconfigured issuer into a startup failure rather than a 503 on someone's
first call.

**The permission belongs to the route, not the handler.** A `Guard` per subtree
says what that subtree needs, before any handler runs. The guard leaves the
claims in the request extensions, so a `RidmClaims` argument in the handler
below reuses what the guard already verified.

## What a real one would add

Orders live in a `Vec` behind a `Mutex` and everyone who may read sees
everything. A real API would scope the query — `claims.sub` is the customer,
and a role or permission is what widens it to an operator.
