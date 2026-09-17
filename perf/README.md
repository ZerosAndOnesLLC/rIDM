# Load tests

`token.js` drives the token endpoint (`client_credentials`) and the discovery and
JWKS documents (with `If-None-Match` revalidation) with [k6](https://k6.io).

```bash
# a client to test with: open dynamic registration on the tenant with the
# client_credentials grant, or pass CLIENT_ID / CLIENT_SECRET of an existing one
docker run --rm --network host -v "$PWD/perf:/perf" grafana/k6 run \
  -e BASE_URL=http://localhost:8090 -e TENANT=master -e SMOKE=1 /perf/token.js
```

Two shapes:

| Run | Load | Thresholds | Where |
|-----|------|------------|-------|
| smoke (`SMOKE=1`) | 20 VUs on `/token`, 2 on the documents, 30 s | errors < 1 %, token p95 < 500 ms, documents p95 < 200 ms | every PR (`load-smoke` job, debug build) |
| baseline | 200 VUs, 2 min (`VUS`, `DURATION`) | errors < 1 %, token p99 < 50 ms, documents p99 < 10 ms | the `release` workflow, on a release build, when a `v*` tag is pushed (or on demand, with `vus`/`duration` inputs); target 5,000 token requests per second per node |

Run the API with `RATE_LIMITS=false` for any load test: the request guard would
otherwise refuse the test's single address after its per-address ceiling (600 token
requests a minute per tenant by default, 6,000 across tenants). The `load-smoke` job does.
A 30-second smoke on a debug build on a developer machine (WSL2, 22 VUs, everything on
one box) gave about 2,500 requests per second in total (token and documents) with token
p95 ≈ 15 ms and no failures; the number to publish is the release baseline. That smoke
also caught a real fault: the client document cached in Valkey carried no secret hashes,
so a confidential client failed to authenticate on every node fifteen seconds after the
first lookup (fixed in Phase 9.10, regression test `api/tests/client_cache.rs`).

The baseline needs a release build (`cargo build --release`), the argon2 defaults
(client secrets are SHA-256 hashed, so `/token` does no password hashing), and
Postgres and Valkey on the same network. The `release` workflow does all of that on a
hosted runner and uploads `baseline.json`/`baseline.txt` as an artifact with the summary
in the job output — a shared runner is not the machine to publish a number from, so run
it again on the hardware a release is measured on and record that result, with the
machine, in the release notes.
