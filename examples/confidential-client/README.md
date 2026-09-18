# Example: a confidential client

A server-side web app that signs users in with rIDM. The browser never sees a
token: the authorization code comes back to this app, this app spends it with
its client secret, and what the browser gets is a session cookie. That is the
whole reason to be a confidential client rather than a SPA.

## Running it

```bash
RIDM_ISSUER=http://localhost:8090/t/demo \
RIDM_CLIENT_ID=orders-web \
RIDM_CLIENT_SECRET=<the secret setup.sh printed> \
RIDM_ALLOW_HTTP=true \
cargo run -p ridm-example-confidential-client
```

| Variable | Default | Meaning |
|----------|---------|---------|
| `RIDM_ISSUER` | — | `https://{host}/t/{tenant}` |
| `RIDM_CLIENT_ID` / `RIDM_CLIENT_SECRET` | — | the confidential client's credentials |
| `BASE_URL` | `http://localhost:3200` | where this app is reachable; the redirect URIs derive from it |
| `API_URL` / `API_AUDIENCE` | `http://localhost:8081` / `https://orders.example` | the resource server it calls |
| `SCOPES` | `openid profile email offline_access orders:read orders:write` | |
| `RIDM_ALLOW_HTTP` | `false` | trust an `http://` issuer — development only |
| `BIND_ADDR` | `127.0.0.1:3200` | |

Register `{BASE_URL}/callback` as a redirect URI, `{BASE_URL}/` as a
post-logout redirect URI, and `{BASE_URL}/backchannel-logout` as the
back-channel logout URI. [`demo-tenant.json`](../demo-tenant.json) already does.

## The flow, and where to look

| File | What it holds |
|------|---------------|
| `config.rs` | the environment, and the discovery document the endpoints come from |
| `oidc.rs` | the authorization URL, the token endpoint, refresh, revoke, end-session |
| `session.rs` | sessions, and the sign-ins waiting for a callback |
| `main.rs` | the routes, and the two validators |

1. **`/login`** mints `state`, `nonce` and a PKCE verifier, remembers them, and
   redirects. `resource=https://orders.example` (RFC 8707) is what makes the
   access token good for the orders API rather than for this client.
2. **`/callback`** refuses anything it cannot account for: an error parameter, a
   missing code, a `state` it did not issue or has already spent, a token
   endpoint refusal, an ID token that does not verify, a `nonce` that does not
   match. Only then does a session open.
3. **Calling the API** refreshes the access token when it has run out. rIDM
   rotates refresh tokens, so what comes back replaces what went in —
   presenting the old one again ends the whole family.
4. **`/logout`** hands the refresh token back (RFC 7009), clears the cookie, and
   *then* redirects to the end-session endpoint. Without that last step the next
   sign-in is silent and instant, and the user thinks the sign-out failed.
5. **`/backchannel-logout`** ends the session here when the user signed out
   somewhere else — another app, an administrator revoking the session, a
   password reset. No browser is involved, so the answer is a status code.

## What `ridm-auth` does here

Two validators, differing only in what they will accept:

```rust
let id_tokens = Validator::builder(&issuer)
    .audience(&client_id)        // an ID token is addressed to the client
    .token_type(Some("JWT"))     // an access token is `at+jwt`
    .discover().await?;

let logout_tokens = Validator::builder(&issuer)
    .audience(&client_id)
    .token_type(Some("logout+jwt"))
    .discover().await?;
```

Same keys, same issuer, different `typ` — which is what stops one kind of token
being spent as another. The app then checks the claims only it can know about:
the `nonce` on the ID token, and the logout event on the logout token.

## What a real one would change

Sessions and pending sign-ins live in a `HashMap`, so a restart signs everybody
out and a second replica shares nothing. Put both in Redis or a database and
that is fixed. The pages are `format!`-ed HTML, which a real app would not do,
but a templating engine would be the most interesting thing in an example that
is meant to be about OpenID Connect.
