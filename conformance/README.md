# OpenID conformance

The [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
runs against rIDM from its released images (`conformance/docker-compose.yml`, dev mode)
and is driven by the suite's own `run-test-plan.py` (vendored under
`suite/` with its two helper modules; refresh them from the suite's `scripts/` when
moving to a newer release).

```bash
# rIDM publishes itself as https://ridm.local (the Caddy front in the compose
# file, certificates from conformance/certs.sh), listens on all interfaces
# with rate limits off, and the static UI export is served on 3110.
conformance/certs.sh   # also writes conformance/.env with this host's address
PUBLIC_URL=https://ridm.local UI_URL=https://ridm.local BIND_ADDR=0.0.0.0:8090 \
  RATE_LIMITS=false COOKIE_SECURE=false \
  SSL_CERT_FILE=$PWD/conformance/certs/bundle.crt cargo run -p ridm-api &
(cd ui && npm run build && npx -y serve@latest -l 3110 out) &
docker compose -f conformance/docker-compose.yml up -d        # suite API on :18443
OP_ISSUER=https://ridm.local/t/master OP_UI_URL=https://ridm.local \
  OP_USER=<user> OP_PASSWORD=<password> conformance/run.sh [plan ...]
```

The UI must be the static export: the Next.js dev server refuses cross-origin
`/_next` requests from behind the front, and the pages never load their flow.

Back-channel logout has the OP call the suite, so the suite publishes itself at this
host's own address (`SUITE_HOST`, written by `certs.sh`), which its browser and the OP
both reach, with a certificate from the same private CA. `SSL_CERT_FILE` is the system
roots plus that CA; without it the OP refuses the call and the back-channel plan hangs.

The tenant needs open dynamic registration allowing `authorization_code` and
`refresh_token` (the plans register their clients) with `dcr.require_pkce` off (the
basic profile's confidential clients send no code challenge), and the user must sign in
with a password without a forced change.

The suite's own browser is HtmlUnit, which cannot run rIDM's React pages, so the test
configuration carries no browser tasks and `run.sh` starts `driver.mjs` in a Playwright
container on the suite's network: it polls the suite for every URL a running test leaves
pending, opens it in headless Chromium (one context per test module, so a module's
authorizations share a session while modules start signed out), signs in through the
stable selectors (`name=identifier`, `name=password`, `#login-submit`), approves consent
(`#consent-approve`), confirms logout (`#logout-confirm`) and lets the suite's callback
page mark the visit. Its log is saved to `results/driver.log`. The rIDM under test sits
behind `https://ridm.local`, a Caddy front with a certificate from a private CA
(`certs.sh`) that the suite trusts through a mounted Java truststore.

The driver verifies the suite's certificate: `certs.sh` issues it for `nginx` among
other names, and `run.sh` mounts the CA into the container as `NODE_EXTRA_CA_CERTS`.
`DRIVER_INSECURE_TLS=1 conformance/run.sh` gives that up, for a rig whose certificates
came from somewhere else; the driver never turns verification off by itself. The browser
it drives is the exception — Chromium takes no CA file and the image carries no NSS
tooling to import one — so those contexts accept the rig's certificates through
Playwright's `ignoreHTTPSErrors`.

Plans run by default: configuration, basic (discovery + dynamic registration), and
RP-initiated, back-channel and front-channel logout, all with `response_type=code`
(rIDM issues no implicit or hybrid responses, so the dynamic and hybrid plans do not
apply). Tests that need a screenshot as evidence (`oidcc-prompt-login`, `oidcc-max-age-1`,
`oidcc-ensure-registered-redirect-uri`) wait for an upload before they finish; the
driver fills every placeholder a running module leaves with a JPEG of the login page it
last drove.

`expected-failures.json` lists findings accepted with a reason and
`expected-skips.json` the tests that do not apply (rIDM signs every ID token and every
request object, so nothing offers the `none` algorithm). The CI workflow `conformance`
fails on anything else. Results land in `conformance/results/`.
