# Sign in from a server-side web app

A web application with a server of its own: the authorization code comes back to
the server, the server spends it with its client secret, and the browser only
ever holds a session cookie. The same app refreshes access tokens as they run
out, signs the user out of rIDM as well as itself, and ends its session when rIDM
tells it the user signed out elsewhere.

The complete app is
[`examples/confidential-client`](https://github.com/ZerosAndOnesLLC/rIDM/tree/main/examples/confidential-client),
an axum server of about 1,200 lines including its HTML pages and tests. This
page follows it step by step.

## Try the example first

With [the local stack and the demo tenant](local.md) running, the orders API
from [Protect a Rust API](protect-an-api.md), and the `orders-web` secret that
`examples/setup.sh` printed:

```bash
RIDM_ISSUER=http://localhost:8090/t/demo RIDM_AUDIENCE=https://orders.example \
RIDM_ALLOW_HTTP=true cargo run -p ridm-example-axum-api      # :8081

RIDM_ISSUER=http://localhost:8090/t/demo \
RIDM_CLIENT_ID=orders-web \
RIDM_CLIENT_SECRET=cs_... \
RIDM_ALLOW_HTTP=true \
cargo run -p ridm-example-confidential-client                 # :3200
```

Open <http://localhost:3200/> and sign in as `dana` (password
`Demo-Passw0rd!2026`). If you lost the secret, mint a new one with
`POST /admin/tenants/demo/clients/orders-web/secrets` (see
[Registering clients](../admin/clients.md)).

| Variable | Default | Meaning |
|----------|---------|---------|
| `RIDM_ISSUER` | none | `https://{host}/t/{tenant}` |
| `RIDM_CLIENT_ID`, `RIDM_CLIENT_SECRET` | none | the client's credentials |
| `BASE_URL` | `http://localhost:3200` | where the app is reachable; the redirect URIs derive from it |
| `API_URL`, `API_AUDIENCE` | `http://localhost:8081`, `https://orders.example` | the API it calls |
| `SCOPES` | `openid profile email offline_access orders:read orders:write` | |
| `RIDM_ALLOW_HTTP` | `false` | trust an `http://` issuer; development only |
| `BIND_ADDR` | `127.0.0.1:3200` | |

## 1. Register the client

```bash
ridm --tenant acme client create \
  --name "Acme billing" \
  --client-id billing-web \
  --type web \
  --redirect-uri https://billing.acme.example/callback \
  --post-logout-redirect-uri https://billing.acme.example/ \
  --audience https://invoices.acme.example \
  --scope openid --scope profile --scope email --scope offline_access \
  --scope invoices:read --scope invoices:write \
  --no-consent
```

`--type web` defaults to `client_secret_basic`, the `authorization_code` and
`refresh_token` grants, and PKCE required. The secret is printed once
(`client secret: cs_…`); store it where the app's other secrets live.

`ridm client create` has no flag for the back-channel logout URI, so set it with
a merge patch on the client:

```bash
curl -s -X PATCH "$RIDM_URL/admin/tenants/acme/clients/billing-web" \
  -H "Authorization: Bearer $RIDM_TOKEN" -H 'content-type: application/json' \
  -d '{"backchannel_logout_uri":"https://billing.acme.example/backchannel-logout"}'
```

Or put the whole client in the tenant's configuration document, as
[`examples/demo-tenant.json`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/examples/demo-tenant.json)
does for `orders-web`:

```json
{
  "client_id": "billing-web",
  "name": "Acme billing",
  "client_type": "web",
  "token_endpoint_auth_method": "client_secret_basic",
  "redirect_uris": ["https://billing.acme.example/callback"],
  "post_logout_redirect_uris": ["https://billing.acme.example/"],
  "backchannel_logout_uri": "https://billing.acme.example/backchannel-logout",
  "allowed_grants": ["authorization_code", "refresh_token"],
  "allowed_scopes": ["openid", "profile", "email", "offline_access",
                     "invoices:read", "invoices:write"],
  "allowed_audiences": ["https://invoices.acme.example"],
  "require_pkce": true,
  "require_consent": false
}
```

No CORS origin is needed: the browser never calls rIDM's token endpoint, the
server does.

## 2. Start a sign-in (`/login`)

Discover the endpoints once at startup from
`{issuer}/.well-known/openid-configuration`, checking that the document names
the issuer you asked. Then, per sign-in, mint `state`, `nonce` and a PKCE verifier,
store them server-side keyed by `state`, and redirect:

```http
GET /t/acme/authorize?response_type=code
    &client_id=billing-web
    &redirect_uri=https%3A%2F%2Fbilling.acme.example%2Fcallback
    &scope=openid%20profile%20email%20offline_access%20invoices%3Aread%20invoices%3Awrite
    &state=…&nonce=…
    &code_challenge=…&code_challenge_method=S256
    &resource=https%3A%2F%2Finvoices.acme.example
Host: id.example.com
```

A confidential client has a secret, so PKCE is not what authenticates it, but
rIDM requires it by default for `web` clients and it closes authorization code
injection at no cost. `resource` (RFC 8707) names the API the access token is
for. Without it the token is minted for every audience in the client's
`allowed_audiences` (plus the resource server of any resource-bound scope
requested), and for the client itself only when there are none. `offline_access`
asks for a refresh token that outlives the user's rIDM session; see step 4.

Expire pending sign-ins after a few minutes (the example keeps them ten).

## 3. Finish it (`/callback`)

Treat every callback as a refusal until each check passes:

1. an `error` parameter means rIDM refused; show `error_description`;
2. `state` must be one you issued and have not spent; take it out of the store
   as you read it;
3. spend the code, authenticating with the secret in the `Authorization`
   header (`client_secret_basic`):

   ```bash
   curl -s -u "billing-web:$CLIENT_SECRET" \
     -d grant_type=authorization_code \
     -d code="$CODE" \
     -d redirect_uri=https://billing.acme.example/callback \
     -d code_verifier="$VERIFIER" \
     https://id.example.com/t/acme/token
   ```

   The answer carries `access_token`, `id_token`, `refresh_token` and
   `expires_in`. rIDM accepts only the authentication method registered for the
   client; the same secret sent as `client_secret_post` is `invalid_client`.
4. verify the ID token's signature and claims. `ridm-auth` does this with a
   validator configured for ID tokens: the audience is the client, and the JOSE
   `typ` is `JWT` rather than `at+jwt`:

   ```rust
   let id_tokens = Validator::builder(&issuer)
       .audience(&client_id)
       .token_type(Some("JWT"))
       .discover()
       .await?
       .shared();

   let claims = id_tokens.validate(&id_token).await?;
   if claims.claim("nonce").and_then(|n| n.as_str()) != Some(pending.nonce.as_str()) {
       // not the answer to this sign-in
   }
   ```

5. open a session: store the tokens server-side, and give the browser only an
   opaque session id:

   ```http
   Set-Cookie: session=…; Path=/; HttpOnly; SameSite=Lax; Secure
   ```

   `HttpOnly` keeps it away from scripts. `SameSite=Lax` still sends it on the
   top-level redirect back from rIDM. `Secure` once the app is on https. Keep
   the session's `sid` claim from the ID token: back-channel logout uses it.

## 4. Call the API, refreshing as needed

Access tokens live five minutes by default. Before using one, check its expiry
(the example allows ten seconds of margin) and refresh if needed:

```bash
curl -s -u "billing-web:$CLIENT_SECRET" \
  -d grant_type=refresh_token \
  -d refresh_token="$REFRESH_TOKEN" \
  -d resource=https://invoices.acme.example \
  https://id.example.com/t/acme/token
```

rIDM rotates refresh tokens: the answer's `refresh_token` replaces the one you
sent, and must be stored before anything else happens. Presenting a spent refresh
token again is treated as theft: the whole family is revoked and the answer is
`invalid_grant` ("refresh token reuse detected"). With two replicas of your app,
make sure two concurrent requests for the same session cannot both refresh with
the same token (serialise per session, or share the session store).

A refresh fails with `invalid_grant` once the refresh token has been revoked,
which happens whenever the rIDM session it was issued in is signed out: the user
signing out from any application in the session or from the account console,
an administrator revoking the session or signing the user out everywhere, a
password change or reset that ends other sessions, or the user being disabled.
A refresh token issued without `offline_access` also stops once the session
times out (30 minutes idle, 12 hours absolute by default; each refresh counts
as activity). One with `offline_access`, which rIDM grants only when every API
the token is for allows it, survives the timeouts but not a sign-out. Either
way, `invalid_grant` is the signal to drop the local session and show the
signed-out page.

## 5. Sign out (`/logout`)

In this order:

1. revoke the refresh token (RFC 7009), authenticating as the client:

   ```bash
   curl -s -u "billing-web:$CLIENT_SECRET" \
     -d token="$REFRESH_TOKEN" -d token_type_hint=refresh_token \
     https://id.example.com/t/acme/revoke
   ```

   Revocation answers `200` whatever it finds; a failure must not stop the
   sign-out.
2. delete the local session and clear the cookie (`Max-Age=0`);
3. redirect the browser to the end-session endpoint (RP-initiated logout):

   ```http
   GET /t/acme/end_session?id_token_hint=…
       &post_logout_redirect_uri=https%3A%2F%2Fbilling.acme.example%2F
       &client_id=billing-web
   Host: id.example.com
   ```

Skip step 3 and the SSO session survives: the next `/login` is silent and instant
and the user concludes sign-out did not work. With a valid `id_token_hint` for
the browser's session, rIDM ends it at once and redirects to the registered
`post_logout_redirect_uri`; without one it asks the user to confirm, so a link
from elsewhere cannot sign users out.

## 6. Back-channel logout (`/backchannel-logout`)

Whenever an rIDM session is signed out, rIDM revokes the session's refresh
tokens and POSTs a **logout token** to the `backchannel_logout_uri` of every
client that took part in the session. That covers the end-session endpoint,
whichever application started it, and every other sign-out: the user in the
account console, an administrator revoking one or all of the user's sessions,
a password change or reset that signs out other sessions, the user being
disabled or deleted (also through SCIM), and the oldest session being evicted
under the tenant's `max_concurrent` limit. No browser is involved:

```http
POST /backchannel-logout
Content-Type: application/x-www-form-urlencoded

logout_token=eyJ…
```

The logout token is a JWT signed with the tenant's keys, JOSE `typ` `logout+jwt`,
with `iss`, `aud` (your `client_id`), `iat`, `exp` (two minutes), `jti`, `sub`,
`sid`, and `events` containing `http://schemas.openid.net/event/backchannel-logout`.
Verify it with a third validator:

```rust
let logout_tokens = Validator::builder(&issuer)
    .audience(&client_id)
    .token_type(Some("logout+jwt"))
    .discover()
    .await?
    .shared();

let claims = logout_tokens.validate(&form.logout_token).await?;
let is_logout = claims
    .claim("events")
    .and_then(|e| e.as_object())
    .is_some_and(|e| e.contains_key("http://schemas.openid.net/event/backchannel-logout"));
if !is_logout || claims.claim("nonce").is_some() {
    // refuse: 400
}
// end every local session whose `sid` matches claims.sid
```

The different `typ` values are what stop an ID token being accepted as a logout
token or the other way round. Answer `200` with `Cache-Control: no-store` when
the session is ended (or was already gone) and `400` for a token you refuse.
rIDM makes one attempt per client with a five-second timeout and does not
retry, so the endpoint should be quick and must be reachable from rIDM. It
must also resolve to a public address: rIDM refuses to deliver to private,
loopback (other than `localhost` itself, for development) and other internal
addresses, and follows no redirects (see
[Outbound requests](../concepts/tenants.md#outbound-requests)).

A missed logout token is not fatal: the session's refresh tokens are revoked
either way, so the app also finds out at its next refresh, within one
access-token lifetime. See
[Sign-in flows and sessions](../concepts/flows-and-sessions.md#signing-out).

## Production notes

- The example keeps sessions and pending sign-ins in a `HashMap`, so a restart
  signs everyone out and replicas share nothing. Use Redis, Valkey or a database.
- Treat the client secret like a database password. Rotate it with
  `POST /admin/tenants/{slug}/clients/{client}/secrets`: the old secret keeps
  working for a grace period (24 hours unless the body sets `grace_secs`, at
  most 30 days), so a rolling deploy does not lock the app out. See
  [Registering clients](../admin/clients.md).
- `private_key_jwt` replaces the shared secret with a key pair; see
  [Machine-to-machine access](machine-to-machine.md#stronger-client-authentication-private_key_jwt).
- Token contents are listed in [Token claims](../reference/token-claims.md).
