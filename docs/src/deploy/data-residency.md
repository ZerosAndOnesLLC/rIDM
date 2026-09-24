# Data residency

A customer under GDPR, a public-sector contract or a sector regulator may need its
users' data stored in one jurisdiction. rIDM can place each tenant's data in a
**regional database**: one deployment serves every tenant, and a tenant created in
`eu` keeps its users, credentials, sessions, clients, keys and audit log in the `eu`
database (and, optionally, the `eu` Valkey), never in the others.

```text
                      ┌──────────────────────────────┐
  every node ────────►│ home  DATABASE_URL           │  tenant registry, master tenant,
                      │                              │  master-key generations, and the
                      │                              │  tenants without a region
                      └──────────────────────────────┘
             ────────►┌──────────────────────────────┐
                      │ eu    DATABASE_URL_EU        │  everything of the tenants in eu
                      │       REDIS_URL_EU (optional)│  (their sessions and cached rows)
                      └──────────────────────────────┘
             ────────►┌──────────────────────────────┐
                      │ us    DATABASE_URL_US        │  everything of the tenants in us
                      └──────────────────────────────┘
```

## Configure regions

Every node lists the same regions and can reach every regional database:

```sh
DATA_REGIONS=eu,us
DATABASE_URL_EU=postgres://ridm_app:…@pg.eu.internal:5432/ridm
DATABASE_READ_URL_EU=postgres://ridm_app:…@pg-replica.eu.internal:5432/ridm   # optional
REDIS_URL_EU=rediss://valkey.eu.internal:6379                                  # optional
DATABASE_URL_US=postgres://ridm_app:…@pg.us.internal:5432/ridm
```

A region's name is 1-32 lowercase letters, digits and hyphens starting with a letter;
the variables use it in upper case with `-` as `_` (`eu-west` → `DATABASE_URL_EU_WEST`).
Each also has a `_FILE` form for secret mounts. See
[Server configuration](../reference/configuration.md#database-and-cache).

A regional database runs **the same schema** as the home one. `ridm-api migrate`
migrates every configured database (home first), and `MIGRATE_ON_START` does the same,
so a region is set up like the home database: an empty database, the migrator role
owning the schema and the DML-only application role (see
[Postgres and Valkey](postgres-valkey.md)).

### Kubernetes

The Helm chart takes the region names and two Secrets you manage: one with the
application role's `DATABASE_URL_<NAME>` (and any `DATABASE_READ_URL_<NAME>`,
`REDIS_URL_<NAME>`) for the pods, one with the schema owner's `DATABASE_URL_<NAME>`
for the migration Job, which then migrates every region before each upgrade:

```yaml
dataRegions:
  names: [eu, us]
  existingSecret: ridm-regions              # DATABASE_URL_EU, DATABASE_URL_US, REDIS_URL_EU…
  migrationsExistingSecret: ridm-regions-owner
```

## Place a tenant

A tenant's region is chosen when it is created, in the console (*Tenants → New
tenant → Data region*, shown when the deployment has regions) or through the admin API:

```sh
curl -X POST "$RIDM/admin/tenants" -H "Authorization: Bearer $TOKEN" \
  -d '{"slug": "acme-eu", "display_name": "Acme EU", "data_region": "eu"}'
```

`GET /admin/regions` lists the regions, how many tenants each holds, and whether it
has a Valkey of its own. An unknown region is refused. A tenant's `data_region`
(`null`: home) is part of its admin API representation; it cannot be changed with a
`PATCH`, only by [moving the tenant](#move-a-tenant).

## What lives where

| Data | Where |
|------|-------|
| Every tenant-scoped row (users, credentials, sessions, refresh tokens, consents, clients, roles, groups, organizations, identity providers, signing and SAML keys, webhooks and deliveries, outbound messages, login history, the audit chain and its checkpoints) | the tenant's database |
| Sessions, sign-in flows, codes, per-tenant rate-limit counters, cached rows, the claims of opaque access tokens | the region's Valkey when it has one (`REDIS_URL_<NAME>`), else the shared Valkey |
| The tenant registry (`tenants`: slug, display name, settings, `data_region`) | the home database; each regional database also holds a copy of its tenants' rows, for its foreign keys |
| The master tenant and global administrators, the global audit chain, master-key generations | the home database |
| Leader locks, cache-invalidation messages, the deployment-wide per-address rate limit, the mapping from an opaque token's hash to its tenant | the shared Valkey |

The routing happens below every query: a tenant's transaction opens on the database
the registry names, and a Valkey key of a tenant (`ridm:t:{tenant}:…`) goes to its
region's Valkey. Background jobs (cleanup, webhook and message delivery, the audit
sink and verification, LDAP sync, SAML metadata refresh) and master-key rotation run
over every database.

**Processing is not pinned.** Any node may serve any tenant, reading and writing the
tenant's regional database over the network. Data at rest stays in the region;
requests are processed wherever the node that answers them runs. When the processing
location matters too, run nodes in the region and route the tenant's traffic to them
(its [custom domain](../admin/custom-domains.md) pointed at a regional load balancer);
every node still needs every database.

## Move a tenant

```sh
ridm-api move-tenant acme --region eu          # home → eu
ridm-api move-tenant acme --region us          # eu → us
ridm-api move-tenant acme --region home        # back to the home database
```

The move is **offline**: the tenant answers `503` while it runs, and everything else
keeps working. It:

1. marks the tenant as moving in the registry and waits (`--drain-seconds`, 20 by
   default and at least 16: nodes trust a placement they read for 15 seconds) until no
   node still serves it from the old database;
2. copies every tenant-scoped table in foreign-key order, inside one transaction on
   the target, from one consistent snapshot of the source, and checks the row count of
   every table;
3. re-verifies the copied audit chain;
4. copies the tenant's Valkey keys with their remaining lifetimes, when the two sides
   use different Valkeys (sessions survive the move);
5. points the registry at the target, which ends the outage;
6. deletes the source's copy, rows and keys, and records `tenant.moved` in the
   tenant's audit log.

It prints a JSON report (rows per table, keys copied, audit rows verified). A failure
before step 5 deletes whatever reached the target and leaves the tenant where it was.
A failure after it leaves a stale copy in the source; **running the same command
again** finishes the job, and running it for a tenant already in the named region
removes stale copies from every other database. One move per tenant runs at a time.

Run it as a one-off job with the deployment's configuration (the application role is
enough), like `ridm-api rotate-master-key`. Both databases must be on the same schema:
run `ridm-api migrate` first after an upgrade. The move takes about as long as copying
the tenant's rows; a tenant with millions of users is unavailable for minutes, so plan
a window. Audit events of the tenant raised during the move are recorded once it ends.

The master tenant cannot move.

## Operating regions

- **Backups**: every regional database is a database of record. Back each one up, on
  the same schedule as the home database, and restore them together; see
  [Backup and restore](backup-restore.md).
- **Readiness**: `/readyz` reports each region under `checks.regions` but does not
  fail on one: a region's outage is an outage of its tenants (their requests fail),
  and taking every node out of the load balancer for it would take all tenants down.
  Alert on `checks.regions.*` instead.
- **A region down at start-up**: nodes still start (a region's connections open
  lazily, and the migration, master-key and Valkey checks log the region and go on);
  the tenants of that region fail until it is back.
- **Upgrades**: `ridm-api migrate` migrates every database and fails if one cannot be
  reached; run it again once the region is back. A node starting with
  `MIGRATE_ON_START` while a region is down migrates the others and logs the one it
  skipped.
- **Removing a region**: move its tenants elsewhere first. A tenant whose region is not
  configured on a node answers `503` there.
- **Connections**: each node opens `DB_POOL_MAX` connections to each database; size the
  regional servers for the number of nodes.
- **Writing migrations**: a migration that seeds something for every tenant must skip
  the home database's registry-only rows (`… FROM tenants WHERE NOT registry_only`), or
  it would write a regional tenant's rows at home. A test enforces it.
