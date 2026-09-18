# ridm-auth

Validate [rIDM](https://github.com/ZerosAndOnesLLC/rIDM) access tokens in a Rust API.

rIDM issues signed JWT access tokens (unless a client is registered for opaque
ones; see below). A resource server that accepts one has to
verify its signature against the issuer's published keys, check that the token
was meant for *it* and not for some other API of the same tenant, and decide
whether the subject may do what it is asking. This crate is those three steps,
and nothing else.

The crate is not on crates.io yet; it is published with rIDM's first release.
Until then, depend on it from the repository:

```toml
[dependencies]
ridm-auth = { git = "https://github.com/ZerosAndOnesLLC/rIDM" }
```

## Verifying a token

```rust
use ridm_auth::Validator;

let validator = Validator::builder("https://idp.example/t/acme")
    .audience("urn:orders")       // the resource server identifier
    .discover()                   // reads jwks_uri from the discovery document
    .await?
    .shared();

let claims = validator.validate(token).await?;
claims.require_permission("orders:read")?;
println!("{} may read orders", claims.sub);
```

Build one validator per issuer at startup and share it: it holds the key-set
cache, so a per-request validator would fetch the key set on every request.

## With axum

The default `axum` feature adds an extractor, a route guard, and RFC 6750
responses for every refusal.

```rust
use std::sync::Arc;
use axum::{Router, routing::get, middleware::from_fn_with_state};
use ridm_auth::{Validator, axum::{Guard, RidmClaims, guard}};

let app = Router::new()
    .route("/orders", get(list_orders))
    .route_layer(from_fn_with_state(
        Guard::new(validator.clone()).permission("orders:read"),
        guard,
    ))
    .with_state(validator);

async fn list_orders(RidmClaims(claims): RidmClaims) -> String {
    format!("hello {}", claims.sub)
}
```

The guard validates once for the whole subtree and puts the claims in the
request extensions, so a `RidmClaims` argument in the handler costs nothing
more. Use `OptionalRidmClaims` on a route that also serves anonymous callers —
a token that *is* presented must still be valid.

`AuthError` answers as RFC 6750 says it should: 401 `invalid_token` for a token
that is not acceptable, 403 `insufficient_scope` for one that is valid but does
not carry enough, 503 with `Retry-After` when the issuer's key set could not be
reached, each with a `WWW-Authenticate` challenge and `Cache-Control: no-store`.

## What it checks

* The signature, against the issuer's JWKS — cached, and refreshed when a token
  names a key the cache has not seen. Two clocks govern that: `jwks_max_age`
  (default 10 minutes) is how long a cached set is trusted even when it answers,
  so a revoked key stops verifying within that window; `min_refresh_interval`
  (default 30 seconds) is the floor between fetches, so tokens naming keys that
  do not exist cannot turn your API into a load generator against the issuer.
  While the issuer is unreachable the last good set keeps answering.
* `typ` is `at+jwt` — which is what stops an ID token being spent as an access
  token. Pass `.token_type(None)` to accept any.
* `alg` is asymmetric, is one of `DEFAULT_ALGORITHMS`, and matches what the key
  was published for. rIDM signs with the algorithm the resource server names
  (`RS256`, `RS384`, `RS512`, `ES256` or `EdDSA`), or the tenant's default.
* `iss` is the configured issuer and `aud` names this API. An audience is
  required: without one, any token from the tenant would open your API.
* `exp` and `nbf`, forgiving 60 seconds of clock skew by default.
* Whatever scopes, permissions and roles the builder or the guard asked for.

## What it does not

* **Revocation.** A verified token is accepted until it expires. rIDM's access
  tokens are short-lived by design; an API that must react to a revocation
  sooner should call the introspection endpoint instead.
* **DPoP proofs.** A sender-constrained token (`cnf.jkt`) is refused rather than
  silently downgraded to a bearer token. Turn on
  `.allow_sender_constrained(true)` only if something ahead of your API verifies
  the proof.
* **Opaque access tokens.** A client registered with
  `access_token_format: opaque` receives `at_…` references, not JWTs; only
  rIDM's introspection endpoint can say what one means. An API that serves such
  clients must call `/introspect` for their tokens.
* **Encrypted tokens.** rIDM encrypts ID tokens, never access tokens.
* **Getting a token.** This is the resource-server half; it is not a client
  library.

## Features

| Feature | Default | What it adds |
|---------|---------|--------------|
| `axum` | yes | `axum::RidmClaims`, `axum::guard`, `IntoResponse for AuthError` |
| `rustls` | yes | rustls for the outbound HTTPS this crate makes |

There is deliberately no `native-tls` alternative: rIDM uses rustls throughout.
To use another TLS stack, turn off `rustls` and hand the builder a client of
your own with `.http_client(...)`.

Against a local rIDM over plain HTTP, add `.allow_http(true)`; an `http://`
issuer is refused otherwise.

## Licence

MIT, as the rest of rIDM.
