# Example: a Next.js single-page app

A public OAuth client: authorization code with PKCE, no client secret, and no
server of its own. `npm run build` writes a static export to `out/`, which any
static host serves — the whole point of PKCE is that a browser app can sign
users in without a backend to keep a secret in.

## Running it

```bash
npm install
npm run dev        # http://localhost:3100
```

| Variable | Default | Meaning |
|----------|---------|---------|
| `NEXT_PUBLIC_RIDM_ISSUER` | `http://localhost:8090/t/demo` | `https://{host}/t/{tenant}` |
| `NEXT_PUBLIC_CLIENT_ID` | `orders-spa` | |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8081` | the orders API |
| `NEXT_PUBLIC_API_AUDIENCE` | `https://orders.example` | what the access token must be minted for |

They are baked in at build time, which is fine: none of them is a secret. The
client must have `http://localhost:3100/callback/` as a redirect URI and
`http://localhost:3100` as a CORS origin — [`demo-tenant.json`](../demo-tenant.json)
does both.

## Where to look

| File | What it holds |
|------|---------------|
| `src/lib/oidc.ts` | discovery, PKCE, the authorization redirect, the token endpoint |
| `src/lib/session.ts` | where the tokens live, and refreshing them |
| `src/lib/api.ts` | calling the orders API |
| `src/app/callback/page.tsx` | the redirect back |

## Three decisions worth reading

**Tokens live in memory.** Not `localStorage`, which every script on the origin
can read, so one bad dependency walks off with a token it can spend until it
expires. A module variable is lost on reload, which is the trade — and the next
point is how the app recovers from it.

**A reload re-authenticates silently.** On load with nothing in memory the app
sends the browser to `/authorize?prompt=none`. If the SSO session is still
alive the user comes straight back signed in without seeing anything; if it is
not, the callback carries `error=login_required` and the app shows a sign-in
button. A flag in `sessionStorage` stops a signed-out user bouncing there on
every load. The redirect is a top-level navigation to rIDM's own origin, so no
third-party cookie is involved and nothing depends on an iframe being allowed.

**The ID token's signature is not verified here.** It came straight from the
token endpoint over TLS, which OIDC Core §3.1.3.7 accepts in place of checking
the signature for exactly this case. The issuer, the audience, the expiry and
the `nonce` *are* checked, because those say the token answers this app's own
request. The API the app calls verifies its own token properly, with
[`ridm-auth`](../../crates/ridm-auth/README.md) — a token is only ever worth
what the service that consumes it checks.

## What a real one would add

Error handling beyond a paragraph of red text; a route guard so deep links do
not flash the signed-out page; and a decision about `prompt=none` on every route
rather than only the first load.
