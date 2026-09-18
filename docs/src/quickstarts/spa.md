# Sign in from a single-page app

A browser app that signs users in with rIDM and calls an API with their access
token: authorization code with PKCE, no client secret, tokens in memory, and a
silent sign-in after a reload. This page walks through the protocol steps; the
complete app is
[`examples/nextjs-spa`](https://github.com/ZerosAndOnesLLC/rIDM/tree/main/examples/nextjs-spa),
a few hundred lines of TypeScript with no OIDC library.

A single-page app is a **public client**: everything it ships is readable by
whoever loads it, so it cannot keep a secret. PKCE replaces the secret. The app
proves that whoever spends the authorization code is whoever asked for it, by
presenting a random verifier whose hash went out with the request.

## Try the example first

With [the local stack and the demo tenant](local.md) running, plus the
[orders API](protect-an-api.md) example:

```bash
RIDM_ISSUER=http://localhost:8090/t/demo RIDM_AUDIENCE=https://orders.example \
RIDM_ALLOW_HTTP=true cargo run -p ridm-example-axum-api      # :8081

cd examples/nextjs-spa && npm install && npm run dev          # :3100
```

Open <http://localhost:3100/>, sign in as `dana` or `sam` (password
`Demo-Passw0rd!2026`), and reload the page: you stay signed in without seeing
rIDM. `sam` can list orders but is refused `403 insufficient_scope` when placing
one.

The app reads four build-time variables, none of them secret:

| Variable | Default |
|----------|---------|
| `NEXT_PUBLIC_RIDM_ISSUER` | `http://localhost:8090/t/demo` |
| `NEXT_PUBLIC_CLIENT_ID` | `orders-spa` |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8081` |
| `NEXT_PUBLIC_API_AUDIENCE` | `https://orders.example` |

If port 3100 is taken, the app still works on any port: it derives its redirect
URI from the origin it is served on. Register that origin's URIs on the client,
as below.

## 1. Register the client

For your own app, on tenant `acme` with the API from
[Protect a Rust API](protect-an-api.md):

```bash
ridm --tenant acme client create \
  --name "Acme invoices" \
  --client-id invoices-spa \
  --type spa \
  --redirect-uri https://app.acme.example/callback/ \
  --post-logout-redirect-uri https://app.acme.example/ \
  --cors-origin https://app.acme.example \
  --audience https://invoices.acme.example \
  --scope openid --scope profile --scope email --scope offline_access \
  --scope invoices:read --scope invoices:write \
  --no-consent
```

| Setting | Why |
|---------|-----|
| `--type spa` | public: token endpoint auth method `none`, grants `authorization_code` and `refresh_token`, PKCE required |
| `--redirect-uri` | compared as an exact string. `https://app.acme.example/callback` and `…/callback/` are different URIs; a static export with trailing slashes needs the slash. Plain `http://` is accepted only for `localhost`, `127.0.0.1` and `[::1]`. |
| `--post-logout-redirect-uri` | where rIDM may send the browser after sign-out |
| `--cors-origin` | an origin (`scheme://host[:port]`, no path), because the app calls the token and revocation endpoints from the browser. The token endpoint admits only the origins of the client that is authenticating. |
| `--audience` | the resource servers this client may get tokens for |
| `--scope` | the scopes it may ask for; given none, a `spa` gets `openid profile email phone address offline_access` |
| `--no-consent` | skip the consent screen, for a first-party app. Leave it off for a third-party one. |

The demo tenant registers `orders-spa` the same way in
[`examples/demo-tenant.json`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/examples/demo-tenant.json),
with `http://localhost:3100/callback/`. See [Registering clients](../admin/clients.md)
for every client setting.

## 2. Discover the endpoints

```ts
const issuer = "https://id.example.com/t/acme";
const discovery = await (await fetch(`${issuer}/.well-known/openid-configuration`)).json();
if (discovery.issuer.replace(/\/$/, "") !== issuer) throw new Error("issuer mismatch");
```

The endpoints to use are `authorization_endpoint`, `token_endpoint`,
`revocation_endpoint` and `end_session_endpoint`. Read them rather than
assembling URLs: a tenant on a [custom domain](../admin/custom-domains.md) has
a different issuer. Checking that the document names the issuer it was fetched
from is OIDC Discovery §4.3.

## 3. Send the browser to sign in

Mint three random values, keep them in `sessionStorage` until the callback, and
redirect:

```ts
const state = randomToken();     // ties the callback to this request
const nonce = randomToken();     // ties the ID token to this request
const verifier = randomToken();  // PKCE: 32 random bytes, base64url
sessionStorage.setItem("signin", JSON.stringify({ state, nonce, verifier }));

const challenge = base64url(
  new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
);
const query = new URLSearchParams({
  response_type: "code",
  client_id: "invoices-spa",
  redirect_uri: `${location.origin}/callback/`,
  scope: "openid profile email offline_access invoices:read invoices:write",
  state,
  nonce,
  code_challenge: challenge,
  code_challenge_method: "S256",
  resource: "https://invoices.acme.example",
});
location.assign(`${discovery.authorization_endpoint}?${query}`);
```

- `code_challenge_method` must be `S256`. rIDM refuses `plain`, and refuses a
  challenge with no method because RFC 7636 would then default to `plain`.
- `resource` (RFC 8707) says which API the access token is for, and must name a
  resource server in the client's `allowed_audiences`. Without it, rIDM mints the
  token for every audience in `allowed_audiences`; with that list empty too, the
  token's `aud` is the client itself and no API will accept it. Always sending
  `resource` keeps the audience explicit. (A scope that the tenant binds to a
  resource server, such as `invoices:read` bound to the invoices API, also adds
  that API to the audience when requested.)
- `offline_access` asks for a refresh token that survives the end of the
  user's SSO session; see step 6.

rIDM shows its own sign-in pages (password, MFA, consent as the tenant requires)
and then redirects to the `redirect_uri` with `code` and `state`, or with
`error` and `error_description`.

## 4. Spend the code

On the callback page, check `state`, then post the code with the verifier:

```ts
const params = new URLSearchParams(location.search);
const pending = JSON.parse(sessionStorage.getItem("signin")!);
sessionStorage.removeItem("signin");
if (params.get("state") !== pending.state) throw new Error("unknown sign-in");

const response = await fetch(discovery.token_endpoint, {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code: params.get("code")!,
    redirect_uri: `${location.origin}/callback/`,
    code_verifier: pending.verifier,
    client_id: "invoices-spa",
  }),
});
const tokens = await response.json(); // access_token, id_token, refresh_token, expires_in
```

A public client sends `client_id` in the body and no `Authorization` header. Then
check the ID token: `iss` is the issuer, `aud` contains the client id, `exp` is in
the future, and `nonce` equals the one you stored. The example does not verify the
ID token's signature: it came straight from the token endpoint over TLS, which
OIDC Core §3.1.3.7 accepts in place of a signature check for this case. The API
verifies its own token fully.

Replace the callback URL (with the router, not a full page load) so the code does
not sit in history.

## 5. Keep tokens in memory

Hold the tokens in a module variable, not `localStorage`. Anything in
`localStorage` is readable by every script on the origin, so one compromised
dependency can take a token and spend it until it expires. Memory is lost on
reload, which step 7 recovers from.

Call the API with the access token:

```ts
await fetch("https://api.acme.example/invoices", {
  headers: { authorization: `Bearer ${tokens.access_token}` },
});
```

The API is on another origin, so it must answer CORS preflights that carry the
`Authorization` header. A `401 invalid_token` means the token is no longer
acceptable; a `403 insufficient_scope` means the user lacks the permission, which
is an answer, not a failure.

## 6. Refresh, and keep what comes back

Access tokens live five minutes by default. Before one runs out, trade the
refresh token for a new pair:

```ts
const refreshed = await (await fetch(discovery.token_endpoint, {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: tokens.refresh_token,
    resource: "https://invoices.acme.example",
    client_id: "invoices-spa",
  }),
})).json();
```

rIDM rotates refresh tokens on every use: the response carries a new
`refresh_token`, and the old one is spent. Presenting a spent refresh token again
is treated as theft and revokes the whole family, so replace the stored token
every time. `resource` on a refresh may only name audiences the original
sign-in was granted.

rIDM issues refresh tokens to any client allowed the `refresh_token` grant, but
how long one keeps working depends on `offline_access`:

- **Without it**, the refresh token lives only as long as the user's SSO
  session at rIDM: it stops at sign-out or when the session times out (30
  minutes idle, 12 hours absolute by default). Each refresh counts as activity
  and keeps the session's idle clock running, so an open tab that refreshes
  every few minutes stays signed in.
- **With it**, the refresh token outlives the session's timeouts, up to the
  refresh token lifetime (30 days by default, or the client's own), though an
  explicit sign-out still ends it. rIDM grants `offline_access` only when the
  client is allowed it and every API the token is for has
  `allow_offline_access` on; otherwise it is left out of the grant.

If the refresh fails, drop the session and sign in again.

## 7. Sign in silently after a reload

With nothing in memory, send the browser to the same authorization request with
`prompt=none` added:

```ts
query.set("prompt", "none");
location.assign(`${discovery.authorization_endpoint}?${query}`);
```

If the browser still has an SSO session with rIDM, the callback arrives with a
`code` and the user never sees a page. If it does not, the callback carries
`error=login_required` (or `consent_required` when consent is still owed), which
means "nobody is signed in", not a failure: show a sign-in button. Remember
in `sessionStorage` that a silent attempt was made, or a signed-out user bounces
to rIDM on every load.

This is a top-level navigation to rIDM's own origin, so the SSO cookie is
first-party. There is no hidden iframe and no dependence on third-party cookies.

## 8. Sign out

Revoke the refresh token, forget the tokens, then end the SSO session:

```ts
await fetch(discovery.revocation_endpoint, {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    token: tokens.refresh_token,
    token_type_hint: "refresh_token",
    client_id: "invoices-spa",
  }),
});
const logout = new URLSearchParams({
  id_token_hint: tokens.id_token,
  post_logout_redirect_uri: `${location.origin}/`,
  client_id: "invoices-spa",
});
location.assign(`${discovery.end_session_endpoint}?${logout}`);
```

Without the last step the next sign-in is silent and instant, and the user
concludes the sign-out did not work. With a valid `id_token_hint` for the current
session rIDM signs out at once and redirects to the registered
`post_logout_redirect_uri`; without one it asks the user to confirm first, so a
third party cannot sign users out by linking to the endpoint. Other applications
in the same session are told through back-channel or front-channel logout; see
[Sign-in flows and sessions](../concepts/flows-and-sessions.md).

## What can go wrong

| Symptom | Cause |
|---------|-------|
| error page at rIDM, "redirect_uri" | the URI is not registered exactly, trailing slash included |
| the token request fails in the browser with a CORS error | the app's origin is not in the client's `cors_origins` |
| `invalid_target` | `resource` names a resource server the tenant does not have, or one outside the client's `allowed_audiences` |
| `invalid_scope` | a scope the client is not allowed, one the tenant does not define, or one bound to a resource server the client may not target |
| `invalid_grant` on refresh | the refresh token was already used, revoked, or has expired, or the SSO session it belongs to was signed out (or, without `offline_access`, timed out) |
| the API answers `401 invalid_token` with an audience message | the token was minted without `resource` for a client whose `allowed_audiences` does not include the API |

The token endpoint's errors are listed in [Errors](../reference/errors.md).
