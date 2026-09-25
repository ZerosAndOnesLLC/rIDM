# Examples

Three relying parties against one rIDM tenant, each showing a different half of
the protocol:

| Example | What it is | Runs on |
|---------|------------|---------|
| [`axum-api/`](axum-api/) | A **resource server**: a Rust API that accepts rIDM access tokens through [`ridm-auth`](../crates/ridm-auth/README.md). No sessions, no user table. | `:8081` |
| [`nextjs-spa/`](nextjs-spa/) | A **public client**: a Next.js single-page app, authorization code + PKCE, no secret, tokens in memory. | `:3100` |
| [`confidential-client/`](confidential-client/) | A **confidential client**: a server-side web app that holds a secret, keeps a session cookie, refreshes, and handles back-channel logout. | `:3200` |

Both clients call the same API, so you can watch one token travel: minted for
`https://orders.example`, verified by a service that has never heard of the user.

## Setting the demo tenant up

You need a running rIDM (see [Development environment](../CONTRIBUTING.md#development-environment) and [`GETTING-STARTED.md`](../GETTING-STARTED.md)), the
`ridm` CLI, which is in this repository, and an admin token in `RIDM_TOKEN`:

```bash
cargo build -p ridm-cli                       # target/debug/ridm
export RIDM_URL=http://localhost:8090
export RIDM_TOKEN=rpat_...                    # a personal access token
```

`setup.sh` exits unless `RIDM_TOKEN` is exported: it passes it to `ridm` and
also calls the admin API directly with `curl`, which cannot read a token that
`ridm login` stored in its profile. Mint the token in the account console as a
global administrator (see [GETTING-STARTED.md](../GETTING-STARTED.md#getting-an-admin-token-for-the-cli)
for doing it without a browser); it needs `ridm:tenants:*`, `ridm:users:*` and
`ridm:roles:*`, and creating the tenant needs `ridm:tenants:create`, which only
`ridm:owner` holds. On a development machine `make token` mints one for the owner
into `target/dev/token`, and `make seed` runs this script with it.

Then, from the repository root:

```bash
examples/setup.sh
```

It creates the tenant `demo`, imports [`demo-tenant.json`](demo-tenant.json) —
the orders resource server and its two permissions, the scopes, the
`orders-reader` and `orders-manager` roles, and the two clients — then creates
two users and gives them one role each. It prints the confidential client's
secret at the end; that secret is shown exactly once.

The clients are registered for `http://localhost:3100` and `:3200`. To run
either somewhere else, give the script its origin — `SPA_URL=http://localhost:3101`,
`WEB_URL=…` — and it substitutes that into the document as it imports it.

`demo-tenant.json` is an ordinary tenant configuration document, so
`ridm --tenant demo tenant diff -f examples/demo-tenant.json` tells you at any
point whether the tenant still matches it.

## Running them

Four terminals, or one with `&`:

```bash
# 1. rIDM itself, on :8090 (BIND_ADDR and PUBLIC_URL in .env, see GETTING-STARTED.md)
UI_URL=http://localhost:3110 cargo run -p ridm-api

# 2. the orders API
RIDM_ISSUER=http://localhost:8090/t/demo \
RIDM_AUDIENCE=https://orders.example \
RIDM_ALLOW_HTTP=true \
cargo run -p ridm-example-axum-api

# 3. the SPA
cd examples/nextjs-spa && npm install && npm run dev

# 4. the server-side web app
RIDM_ISSUER=http://localhost:8090/t/demo \
RIDM_CLIENT_ID=orders-web \
RIDM_CLIENT_SECRET=<the secret setup.sh printed> \
RIDM_ALLOW_HTTP=true \
cargo run -p ridm-example-confidential-client
```

The end-user pages (sign-in, consent, MFA) are rIDM's own UI, which in
development runs separately — `cd ui && API_PROXY=http://localhost:8090 npx next dev -p 3110`,
matching the `UI_URL` above.

Sign in at <http://localhost:3100/> or <http://localhost:3200/> as `dana`
(`orders-manager`: may place orders) or `sam` (`orders-reader`: may only see
them, and the API answers `403 insufficient_scope` for the rest).

`RIDM_ALLOW_HTTP=true` is what lets an `http://` issuer be trusted at all; it
belongs in development and nowhere else.

## Smoke test

`smoke/run.sh` runs all of this unattended, and CI runs it on every pull request
(the `examples-smoke` job): it starts `deploy/docker-compose.yml` from a built
image, bootstraps the first administrator and a token with
`ridm bootstrap --issue-token`, runs `setup.sh` (twice — the second run must
change nothing), starts the three examples and rIDM's sign-in pages, and then
drives headless Chromium through `smoke/smoke.mjs`:

- the orders API refuses an anonymous call with a `Bearer` challenge;
- `dana` signs in to the web app with her password and places an order;
- the SPA, in the same browser, signs her in silently (no login form) and sees
  and places orders against the same API;
- signing out of the SPA ends the rIDM session, and back-channel logout ends
  the web app's session with it;
- `sam` sees the orders in both apps, and the API refuses his order with `403`.

```bash
docker build -f api/Dockerfile -t ridm:smoke .
(cd ui && npm ci && npx playwright install chromium)
RIDM_IMAGE=ridm:smoke examples/smoke/run.sh
```

Every port moves with an environment variable (the script's header lists
them), so it can run beside a development stack; logs and failure screenshots
land in `target/smoke/`.

## What each example is for

**`axum-api`** is the one to copy if you are writing a service that accepts
tokens. It is about 200 lines, and the authentication in it is one `Validator`,
a `Guard` per route subtree, and a `RidmClaims` argument where a handler wants
to know who is calling.

**`nextjs-spa`** is the one to read if you are wondering where a browser app
should keep tokens (in memory), how it gets a session back after a reload
(`prompt=none`), and why a public client needs PKCE.

**`confidential-client`** is the one to read for the parts a SPA cannot do:
a client secret that never reaches the browser, a server-side session, refresh
token rotation, and a back-channel logout endpoint that ends a session when the
user signed out somewhere else entirely.

None of them is production code — the two Rust examples keep state in a
`HashMap`, which is the first thing you would replace. What they are careful
about is the protocol.
