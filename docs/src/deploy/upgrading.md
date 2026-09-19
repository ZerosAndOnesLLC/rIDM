# Upgrading

An upgrade is a new binary or image plus, usually, database migrations. The binary
carries its migrations; you apply them as the schema owner, then roll the servers.
Nothing else changes: the master key, Valkey and your configuration stay as they are
unless the release notes say otherwise.

## Versions and what they promise

Releases follow [Semantic Versioning](https://semver.org/). From 1.0, a patch or minor
release upgrades in place with no configuration changes; a major release may need some,
and its notes say what. **Before 1.0, a minor release (0.1 to 0.2) may break
compatibility** (a renamed setting, a changed admin API field), and its notes say how.
A patch release never does.

Every release's notes, on its GitHub release and in
[`CHANGELOG.md`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/CHANGELOG.md), have an
**Upgrade notes** heading whenever there is something to do beyond replacing the binary,
including a release whose migrations are not compatible with the release before it
(next section). Read the notes of every release between yours and the target.

## Rolling upgrades and the one-release rule

During a rolling upgrade the old release keeps serving on the migrated schema until its
last node is replaced; the Helm chart and the compose stack both migrate first and roll
second. That only works if the migrations leave the old code working, so the rule for
rIDM's own migrations is:

> A release's migrations keep **the release immediately before it** working. They add
> tables, columns with defaults and indexes; they do not drop, rename or retype what
> the previous release reads or writes. A removal happens in two releases: the first
> stops using the thing, the next drops it.

The same holds for what nodes share in Valkey (sessions, flows in progress, cached
documents) and for the cache invalidation messages they exchange: old and new nodes
read each other's entries during the roll.

A release that has to break the rule says so under **Upgrade notes**, and then the
upgrade is stop-the-world: scale to zero, migrate, start the new release.

Because the rule covers one step, **skipping releases** (1.2 straight to 1.5) is also a
stop-the-world upgrade: migrations are cumulative, and `migrate` applies all of them in
order, but a 1.2 node is not promised to work on the 1.5 schema. Stop every old node
first, or upgrade one release at a time with a rolling upgrade each.

## Before you upgrade

1. **Read the release notes**, back to the release you run.
2. **Take a backup** of the database, or check that point-in-time recovery covers the
   present ([Backup and restore](backup-restore.md)). A migration cannot be undone any
   other way.
3. **Verify the release** you are about to run ([Releases and verification](releases.md)),
   and pin it by version or, better, by image digest.
4. **Try it on a copy first** when the notes list migrations on large tables: restore
   last night's backup into a staging environment and time the migration there. Most
   migrations take milliseconds; one that builds an index on a table of millions of rows
   takes as long as that index takes, and holds its locks meanwhile.

## Upgrading

### Helm

```bash
helm upgrade ridm oci://ghcr.io/zerosandonesllc/charts/ridm --version 1.2.3 -f values.yaml
```

The chart's `pre-upgrade` hook runs `ridm-api migrate` in a Job as the migrator role.
The Deployment rolls only after the Job succeeds, with `maxUnavailable: 0`, so capacity
never drops; if the migration fails, the running pods are untouched and `helm upgrade`
reports the failure. See [Kubernetes (Helm)](kubernetes.md#upgrading).

### docker-compose

Set the new image in `.env` (`RIDM_IMAGE=ghcr.io/zerosandonesllc/ridm:1.2.3`, or
`…@sha256:…`), then:

```bash
docker compose pull
docker compose up -d
```

The one-shot `migrate` service runs first with the new image and the server is
recreated only if it succeeds. The stack is one node, so requests fail for the few
seconds the server takes to restart. See
[Production with docker-compose](production-compose.md#operating-it).

### Static binaries and other setups

1. Install the new binaries next to the old ones.
2. Run `ridm-api migrate` once, with `DATABASE_URL` set to the migrator role. It takes an
   advisory lock, so a second run started by mistake waits and then finds nothing to do.
3. Restart the nodes one at a time with the new `ridm-api`, waiting for `/readyz` on each
   before the next. The server finishes in-flight requests for up to 20 seconds after
   `SIGTERM`.

With `MIGRATE_ON_START=true` and the server running as the schema owner, the first new
node migrates as it starts; see [Container image](container.md#running-migrations) for
why the separate step is preferred.

## After the upgrade

- `/readyz` answers `200` on every node, and `/healthz` reports the new `version`.
- The start-up log has no `database migrations are pending` warning.
- Sign in to the admin console, and let a client get a token.
- Watch the error rate and the job metrics for an hour
  ([Observability](observability.md)).

## Rolling back

Migrations are forward-only: there are no down migrations. What a rollback takes
depends on what the new release migrated.

- **No migrations in between:** run the previous release again. Nothing else changed.
- **Migrations that kept the one-release rule:** the previous release runs on the new
  schema, as it did during the roll, so running it again works. It logs a warning at
  start-up:

  ```text
  WARN the database has migrations this release does not know: a newer release migrated it. Run that release, or restore the backup taken before the upgrade count=1 newest=20270301120000
  ```

  The warning stays until you upgrade again. Its `ridm-api migrate` refuses to run
  (`migration 20270301120000 was previously applied but is missing in the resolved
  migrations`), which is correct: there is nothing it could apply. Upgrade again once
  the problem is fixed, rather than staying on the older release indefinitely.
- **Migrations the notes marked incompatible, or a skip over several releases:** the
  previous release is not promised to work on the new schema. Restore the backup taken
  before the upgrade ([Backup and restore](backup-restore.md#restoring)), with the
  consequences listed there for everything since.

Never restore a backup made by a newer release and run an older release on it; that is
the same as the last case.

## The master key and signing keys

Upgrades do not touch either. Rotating the master key is a separate, online operation
([Rotating keys](../admin/key-rotation.md)); do not combine it with an upgrade, so that
a problem in one is not mistaken for the other. Each node checks at start-up that the
master key decrypts the database's signing keys and refuses to start if not, so a node
that comes up after an upgrade with a mistyped secret stops with a clear message instead
of failing sign-ins.
