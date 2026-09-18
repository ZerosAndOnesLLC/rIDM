# Postgres and Valkey

rIDM keeps its system of record in Postgres and its short-lived shared state in Valkey.
Both are required; a node that cannot reach either fails `/readyz` and most requests.
Neither should be reachable from the internet: rIDM authenticates to them, but cannot
protect them from anyone else who can connect.

## Versions

| Service | Supported | Tested |
|---------|-----------|--------|
| Postgres | 16 or later | 18.6 (CI, compose) |
| Valkey | Valkey 9; Redis-compatible servers with `GETDEL` (Redis 6.2+) should work but are not tested | 9.1.2 (CI, compose) |

The first migration runs `CREATE EXTENSION IF NOT EXISTS pgcrypto`. `pgcrypto` is a
trusted extension, so the migrator role can create it without being a superuser, but a
managed Postgres service has to offer it.

## Two roles and row level security

rIDM is built to connect as two different Postgres roles:

| Role | Default name (compose) | Privileges | Used by |
|------|------------------------|------------|---------|
| migrator | `ridm_migrator` | Owns the schema: `CONNECT, CREATE, TEMP` on the database, `ALL` on schema `public` | `ridm-api migrate` |
| app | `ridm_app` | `CONNECT, TEMP`; `USAGE` on the schema; `SELECT, INSERT, UPDATE, DELETE` on tables, `USAGE, SELECT` on sequences, `EXECUTE` on functions | the running servers and `ridm-api bootstrap` (`DATABASE_URL`) |

Neither is a superuser and both are `NOBYPASSRLS`. The compose file creates them with
[`deploy/postgres/init-app-role.sh`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/deploy/postgres/init-app-role.sh).
On a database you run yourself, do the same as a superuser before the first migration:

```sql
CREATE ROLE ridm_migrator LOGIN PASSWORD '...'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE ridm_app LOGIN PASSWORD '...'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

GRANT CONNECT, CREATE, TEMP ON DATABASE ridm TO ridm_migrator;
GRANT ALL ON SCHEMA public TO ridm_migrator;

GRANT CONNECT, TEMP ON DATABASE ridm TO ridm_app;
GRANT USAGE ON SCHEMA public TO ridm_app;
ALTER DEFAULT PRIVILEGES FOR ROLE ridm_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ridm_app;
ALTER DEFAULT PRIVILEGES FOR ROLE ridm_migrator IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO ridm_app;
ALTER DEFAULT PRIVILEGES FOR ROLE ridm_migrator IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO ridm_app;
```

The default privileges are what give the app role access to tables the migrator creates
later, so every migration must run as the migrator. A migration run as some other role
(a superuser, say) creates tables the app role cannot see.

### What row level security does here

Every tenant-scoped table has row level security enabled and forced (so it applies to
the table owner too), with one policy: a row is visible when its `tenant_id` equals the
transaction's `app.tenant_id` setting, or when the transaction has set `app.bypass_rls`
to `on`. The server binds the tenant at the start of each transaction with
`set_config(..., true)`, which resets at commit or rollback, so a pooled connection never
carries one request's tenant into the next. A transaction that binds nothing sees no
tenant rows at all. Explicitly cross-tenant work (bootstrap, global administration,
background jobs) sets the bypass flag for its own transaction.

That makes row level security a second line behind the application's own tenant
checks: a query that forgets its tenant filter returns nothing from other tenants. It
is not a boundary against code running as the app role, which can set the bypass flag
itself. The role split is about DDL: a superuser ignores row level security outright,
and a table owner can switch it off or rewrite the policies, so the running server
holds neither power.

`MIGRATE_ON_START=true` applies migrations only when some are pending. With the
server running as the app role, that is harmless once `ridm-api migrate` has brought
the schema up to date; if a migration is pending, startup fails because the app role
cannot apply it. Running the server as the migrator instead, so that it can migrate
itself, gives up the split. See [Container image](container.md#running-migrations).

### Audit partitions under the two-role setup

The audit log is partitioned by month. Migrations create the current month's
partition and the next two; after that the daily `audit_retention` job creates upcoming
partitions by calling `audit_ensure_partitions`, as the server's role. The DML-only app
role has no `CREATE` privilege, so the function is `SECURITY DEFINER`: it runs with the
rights of its owner (the migrator), with a pinned `search_path`. `EXECUTE` on it is
revoked from `PUBLIC` and granted, when the migration runs, to every role that holds
`INSERT` on `audit_events`, which under the setup above is the app role.

An app role created after that migration ran does not get the grant automatically.
Give it by hand, as the migrator:

```sql
GRANT EXECUTE ON FUNCTION audit_ensure_partitions(integer) TO ridm_app;
```

If partition creation fails anyway, the job logs the error and still runs its retention
purge; rows written meanwhile land in the `audit_events_default` partition, where the
purge reaches them. A month whose range already has rows in the default partition is
skipped rather than failing the whole call, because Postgres refuses to create such a
partition. Failures show in `ridm_job_runs_total{job="audit_retention",outcome="error"}`
only when the purge itself fails, so watch the server log for
`audit: creating partitions failed` (see [Observability](observability.md)).

## Migrations

Migrations live in [`api/migrations`](https://github.com/ZerosAndOnesLLC/rIDM/tree/main/api/migrations),
are embedded in the binary, and are recorded in sqlx's `_sqlx_migrations` table. They
are forward-only. `ridm-api migrate` applies whatever is pending, under an advisory lock
so concurrent runs are safe, and exits; `sqlx migrate run --source api/migrations` from a
checkout does the same. How to run them in each environment is in
[Container image](container.md#running-migrations). An upgrade guide is planned (11.5);
take a backup before applying a new release's migrations.

## Connection pools

Each node opens one pool to `DATABASE_URL` and, when `DATABASE_READ_URL` is set, a second
pool of the same size to the replica.

| Setting | Default | Meaning |
|---------|---------|---------|
| `DB_POOL_MIN` | 2 | Connections kept open per pool |
| `DB_POOL_MAX` | 20 | Upper bound per pool; must be at least `DB_POOL_MIN` |
| `REDIS_POOL_MAX` | 32 | Valkey connections per node |

Fixed behaviour: a request waits at most 5 seconds for a Postgres connection, idle
connections close after 10 minutes, every connection is recycled after 30 minutes, and
statements slower than 250 ms are logged as warnings. Connections identify themselves
as `application_name` `ridm-api` (primary) and `ridm-api-read` (replica), which is how
to find them in `pg_stat_activity`. Valkey connections time out after 5 seconds
waiting, creating or recycling.

Sizing: the connections rIDM can open are `nodes × DB_POOL_MAX` against the primary,
plus the same against the replica if there is one, plus a migrate job. Keep that under
the server's `max_connections` (the compose file sets 200) with room for maintenance.
The README's rule of thumb for `DB_POOL_MAX` is roughly twice the database server's CPU
count divided by the number of API nodes.

A connection pooler such as PgBouncer is not tested. rIDM's tenant binding is
transaction-local, which suits transaction pooling in principle, but sqlx uses
prepared statements, so a pooler in transaction mode must support them.

## Read replicas

`DATABASE_READ_URL` names a streaming replica. When set, listings and statistics run
there inside read-only transactions: users, clients, groups, roles, invitations,
webhook deliveries, the audit log and the console overview. A write sent there by
mistake fails rather than succeeding somewhere unexpected. Everything else, and every
read that feeds a decision (sign-in, token issuance, permission checks), stays on the
primary. A listing may trail a change by the replica's lag. Use the same app role on the
replica; unset, the primary serves both.

## Valkey

### Topologies

`REDIS_URL` selects the topology by its scheme:

| Form | Topology |
|------|----------|
| `redis://host:6379` or `redis://host:6379/2` | One server (the path picks the database number) |
| `rediss://host:6380` | One server over TLS |
| `redis+cluster://host1:7000,host2:7001` | A cluster; the listed nodes are seeds |
| `redis+sentinel://sentinel1:26379,sentinel2:26379/mymaster` | Sentinel-managed replication; the pool follows the current master of `mymaster` |

Credentials go before an `@` and apply to every listed host:
`redis+cluster://:secret@host1:7000,host2:7001`. The cluster and Sentinel forms build
plain `redis://` connections to each host, so TLS to Valkey is available only in the
single-server `rediss://` form.

Cache invalidation between nodes uses pub/sub on one channel. Under Sentinel the
subscriber resolves the current master when it connects, and reconnects with backoff
after a failover.

### What lives in Valkey

| In Valkey (short-lived, shared) | In Postgres (durable) |
|--------------------------------|-----------------------|
| Browser (SSO) sessions and each user's set of live sessions | A durable record of each session (`sso_sessions`) |
| Authorization codes, PAR requests, device codes and user codes | Refresh tokens, consents, personal access tokens |
| Login and logout flows in progress, one-time codes, magic links, email verification and password-reset tokens, TOTP and passkey enrolment state, identity-brokering state | Users, credentials, groups, roles, clients, resource servers |
| The access-token denylist (revoked `jti`s until they expire) | Signing keys (encrypted), tenant settings, provider settings |
| Opaque access tokens: the claims behind each `at_…` token, keyed by its SHA-256, until it expires | DCR initial access tokens (hashed) |
| Rate-limit counters | Audit log, webhook deliveries, message queue |
| Background-job leader locks and each job's last run (`ridm:jobs:last_run`) | Invitations, trusted devices, login attempts |
| Cached copies of tenants, clients, scopes, JWKS, discovery documents, roles, IP rules | |

Keys are prefixed `ridm:`, so a shared Valkey is possible, though a dedicated one is
simpler to size and secure.

### Memory and eviction

Size Valkey so it does not reach `maxmemory`. With an `allkeys-lru` or `volatile-*`
policy a full Valkey evicts whatever it likes, including live browser sessions (users
are signed out) and denylist entries (revoked access tokens pass rIDM's checks again
until they expire). With `noeviction` a full Valkey refuses writes and requests fail loudly
instead. The compose file's 256 MB with `allkeys-lru` suits evaluation only. Enable
append-only persistence (`appendonly yes`, as the compose file does) so a restart keeps
sessions.

### If Valkey is lost

Losing Valkey's data (a flush, a restart without persistence, a failover to an empty
replica) loses no durable data, but:

- every browser session ends; users sign in again. Refresh tokens issued with
  `offline_access` keep working, being in Postgres; refresh tokens without it are bound
  to the session and stop with it;
- opaque access tokens (`at_…`) end early, since their claims were only in Valkey;
  clients refresh or sign in again;
- sign-ins, authorization codes, device authorizations and emailed links in flight fail
  and must be started again;
- **revoked access tokens that have not yet expired pass rIDM's own checks again**
  (introspection, userinfo, the account API), because the denylist is gone; APIs that
  validate JWTs locally never consulted it. Revoke again if that matters, or wait out
  the access-token lifetime;
- rate-limit windows start from zero;
- caches refill from Postgres, and each node clears its in-process cache when its
  invalidation subscriber reconnects.

While Valkey is unreachable, rather than empty, `/readyz` returns 503 and requests that
need a session, a flow or the cache fail. The rate limiter alone fails open (with a
warning), since it protects against abuse and is not an authorization control.

## Backups

Back up Postgres; Valkey holds nothing that cannot be lost at the cost above. A Postgres
backup contains encrypted secrets that decrypt only with the master key in use (and any
listed in `MASTER_KEY_PREVIOUS`), so keep a copy of the key, stored apart from the
backups, for as long as you keep the backups. Backups hold user data and credential
hashes: encrypt them and control access. A backup and restore guide, including the
master key, is planned (plan item 11.5).
