// k6 load test for the token endpoint (client_credentials), discovery and JWKS.
//
//   k6 run -e BASE_URL=http://localhost:8090 -e TENANT=master perf/token.js
//
// setup() registers a confidential client through dynamic client registration
// (the tenant must allow open registration with the client_credentials grant),
// or uses CLIENT_ID / CLIENT_SECRET when given. Thresholds are the PR smoke
// (SMOKE=1: 20 VUs for 30 s on a debug build); the release baseline runs
// `-e VUS=200 -e DURATION=2m` and expects 5k token req/s per node.

import http from "k6/http";
import { check, fail } from "k6";

const BASE = __ENV.BASE_URL || "http://localhost:8090";
const TENANT = __ENV.TENANT || "master";
const SMOKE = __ENV.SMOKE === "1";
const VUS = Number(__ENV.VUS || (SMOKE ? 20 : 200));
const DURATION = __ENV.DURATION || (SMOKE ? "30s" : "2m");

export const options = {
  scenarios: {
    token: { executor: "constant-vus", vus: VUS, duration: DURATION, exec: "token" },
    documents: { executor: "constant-vus", vus: Math.max(2, Math.floor(VUS / 10)), duration: DURATION, exec: "documents" },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    "http_req_duration{scenario:token}": SMOKE ? ["p(95)<500"] : ["p(99)<50"],
    "http_req_duration{scenario:documents}": SMOKE ? ["p(95)<200"] : ["p(99)<10"],
  },
};

export function setup() {
  if (__ENV.CLIENT_ID && __ENV.CLIENT_SECRET) {
    return { id: __ENV.CLIENT_ID, secret: __ENV.CLIENT_SECRET };
  }
  const res = http.post(
    `${BASE}/t/${TENANT}/register`,
    JSON.stringify({
      client_name: `k6-${Date.now()}`,
      grant_types: ["client_credentials"],
      redirect_uris: [],
      token_endpoint_auth_method: "client_secret_basic",
    }),
    { headers: { "Content-Type": "application/json" } },
  );
  if (res.status !== 201) fail(`dynamic registration failed: ${res.status} ${res.body}`);
  const body = res.json();
  return { id: body.client_id, secret: body.client_secret };
}

export function token(data) {
  const res = http.post(
    `${BASE}/t/${TENANT}/token`,
    { grant_type: "client_credentials" },
    { headers: { Authorization: `Basic ${encoding.b64encode(`${data.id}:${data.secret}`)}` } },
  );
  check(res, {
    "token 200": (r) => r.status === 200,
    "bearer": (r) => r.status === 200 && r.json("token_type") === "Bearer",
  });
}

export function documents() {
  const disc = http.get(`${BASE}/t/${TENANT}/.well-known/openid-configuration`);
  check(disc, { "discovery 200": (r) => r.status === 200 });
  const etag = disc.headers["Etag"] || disc.headers["ETag"];
  const jwks = http.get(`${BASE}/t/${TENANT}/.well-known/jwks.json`);
  check(jwks, { "jwks 200": (r) => r.status === 200 });
  if (etag) {
    const again = http.get(`${BASE}/t/${TENANT}/.well-known/openid-configuration`, { headers: { "If-None-Match": etag } });
    check(again, { "discovery 304": (r) => r.status === 304 });
  }
}

import encoding from "k6/encoding";
