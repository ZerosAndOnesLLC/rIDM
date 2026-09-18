# Scaling and performance

rIDM scales out by adding nodes. Nodes are stateless and identical: any node serves any
request, runs its share of background work, and needs nothing from the others except
what they share through Postgres and Valkey. There is no leader to elect and no node
to configure differently.

## Adding nodes

Run more copies of the image with the same configuration (see
[Deployment overview](overview.md#stateless-nodes) for what must match) behind a load
balancer that health-checks `/readyz`. No session affinity is needed: browser sessions,
flows in progress, authorization codes and rate-limit counters are all in Valkey.

What grows with the node count:

- **Postgres connections**: each node may open up to `DB_POOL_MAX` (default 20), and as
  many again to a read replica. Lower `DB_POOL_MAX` as you add nodes; see
  [Postgres and Valkey](postgres-valkey.md#connection-pools).
- **Valkey connections**: up to `REDIS_POOL_MAX` (default 32) per node, plus one pub/sub
  subscription per node.

Rolling restarts are safe. On `SIGTERM` a node stops accepting connections and gives
in-flight requests up to 20 seconds to finish. `/readyz` does not change on shutdown,
so deregister the node from the load balancer first (orchestrators do this when a pod
terminates) so new requests go elsewhere. Schema migrations
run as a separate step before the rollout (see
[Container image](container.md#running-migrations)); there is no tested upgrade path
between versions yet (plan items 11.5 and 11.7).

## Background jobs on many nodes

Every node runs the same scheduler. Each job waits 30 seconds plus up to 5 seconds of
jitter after startup, then runs on its interval plus up to 30 seconds of jitter. At the
start of each pass it tries to take a Valkey lock, `ridm:lock:<job>`, with `SET NX PX`;
a node that does not get it skips that pass. The lock is released with a
compare-and-delete, so a node can only release a lock it holds, and it carries a
time-to-live so a node that dies mid-pass cannot hold it forever.

| Job | Every | Lock time-to-live | What it does |
|-----|-------|-------------------|--------------|
| `key_rotation` | 1 h | 10 min | Rotates and retires signing keys per each tenant's key policy |
| `audit_retention` | 24 h | 30 min | Creates upcoming audit partitions, purges audit rows past the tenant's retention |
| `user_purge` | 24 h | 30 min | Hard-deletes soft-deleted users past the tenant's retention |
| `webhook_delivery` | 30 s | 2 min | Retries webhook deliveries whose backoff has elapsed |
| `message_delivery` | 30 s | 2 min | Sends queued and retrying email and SMS |
| `cleanup` | 1 h | 10 min | Deletes spent rows older than `RETENTION_DAYS` (default 30), in batches of 5,000 |

So however many nodes there are, each job runs on one node at a time, and adding nodes
does not add job load. Webhooks and messages are first attempted as soon as the event
happens, by the node that handled the request; the delivery jobs only pick up retries
and anything left queued. A tenant's first signing key is created under a similar lock,
so two nodes answering the tenant's first request do not both create one.

Each pass's outcome is counted in `ridm_job_runs_total{job,outcome}` and stored as the
job's last run in the Valkey hash `ridm:jobs:last_run` (no API endpoint exposes it yet;
read it with `HGETALL ridm:jobs:last_run`). See [Observability](observability.md).

## Caching and invalidation across nodes

The token path is built to touch the database as little as possible. Reads go through
two layers:

1. an in-process cache on each node (about 15 seconds; 30 seconds for "does not exist"
   answers, so unknown tenant slugs cannot hammer the database);
2. Valkey, shared by all nodes, with longer lifetimes (minutes);
3. Postgres, only on a miss in both.

Tenants, clients, signing keys, scopes, claim mappers, resource servers, IP rules and
CORS origins go through this path, as do a user's effective roles and groups and the
permissions a set of roles holds on a resource server.

A write evicts the affected keys from its own node's cache, deletes them from Valkey
and publishes them on the pub/sub channel `ridm:cache:invalidate`; every other node
evicts them from its in-process cache on receipt. Role-derived entries are keyed under a
per-tenant version that any role, group, membership, grant or permission change moves,
so stale entries simply stop being read. The JWKS document is keyed the same way under a
per-tenant keys version, so a document read before a key change is never served after
it.

If a node's subscription drops, it reconnects with backoff and clears its whole
in-process cache on reconnect, because it may have missed invalidations. The worst case
for a missed message is therefore the in-process lifetime, about 15 seconds.

Discovery and JWKS documents are served with an `ETag` and `Cache-Control: max-age=300`
and answer `304` to `If-None-Match`, so relying parties and CDNs revalidate cheaply.

## CPU and memory

The expensive operation is password hashing. argon2id defaults to 19 MiB of memory and
2 iterations per hash (`ARGON2_M_COST_KIB`, `ARGON2_T_COST`, `ARGON2_P_COST`), and each
password sign-in, registration, password change and reset does one. Size node memory
for the number of concurrent password operations you expect times the memory cost, and
expect password sign-ins, not token requests, to dominate CPU. Raising the cost
parameters upgrades existing hashes as each user next signs in.

Client secrets are SHA-256 hashed, so `/token` does no password hashing.

## Load testing

The load tests live in [`perf/`](https://github.com/ZerosAndOnesLLC/rIDM/tree/main/perf):
a [k6](https://k6.io) script, `token.js`, that drives `/token` with the
`client_credentials` grant and revalidates the discovery and JWKS documents with
`If-None-Match`.

| Run | Load | Thresholds | Where it runs |
|-----|------|------------|---------------|
| smoke (`SMOKE=1`) | 20 VUs on `/token`, 2 on the documents, 30 s | errors below 1 %, token p95 below 500 ms, documents p95 below 200 ms | every pull request (`load-smoke` job, debug build) |
| baseline | 200 VUs, 2 min (`VUS`, `DURATION`) | errors below 1 %, token p99 below 50 ms, documents p99 below 10 ms | the `release` workflow, on a release build |

The baseline's target is 5,000 token requests per second per node. No published figure
exists yet: the release workflow runs the baseline on a shared CI runner, which is not
the machine to publish a number from, and there has been no release. The one measurement
recorded so far is a 30-second smoke on a debug build on a developer machine (WSL2, 22
VUs, everything on one box): about 2,500 requests per second in total, with token p95
around 15 ms and no failures.

### Running it

The API under test needs `RATE_LIMITS=false`: the test comes from one address, and the
per-address ceilings (600 token requests a minute per tenant, 6,000 across tenants,
by default) would refuse it otherwise. Never set that in production.

The script needs a confidential client with the `client_credentials` grant. Either pass
one:

```bash
docker run --rm --network host -v "$PWD/perf:/perf" grafana/k6 run \
  -e BASE_URL=http://localhost:8080 -e TENANT=acme \
  -e CLIENT_ID=<id> -e CLIENT_SECRET=<secret> /perf/token.js
```

or leave `CLIENT_ID` and `CLIENT_SECRET` out and open dynamic client registration on the
tenant, in which case the script's setup registers one. `TENANT` defaults to `master`
and `BASE_URL` to `http://localhost:8090`. Add `-e SMOKE=1` for the smoke shape, or
`-e VUS=200 -e DURATION=2m` for the baseline.

For a meaningful baseline: a release build (`cargo build --release` or the container
image), the default argon2 parameters, Postgres and Valkey on the same network as the
node, and k6 on a separate machine so it does not compete for CPU. Record the hardware
alongside the result.
