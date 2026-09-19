# Backup and restore

An rIDM deployment keeps its durable state in one place, the Postgres database, and
encrypts the secrets in it under a key that is deliberately kept somewhere else. A
backup you can restore is therefore two things kept apart: the database, and the
master key it was written with.

## What to back up

| What | Back up | Why |
|------|---------|-----|
| The Postgres database | Yes, continuously or at least daily | Everything durable: tenants, users, password hashes, clients, keys (encrypted), sessions' durable records, refresh tokens (hashed), consents, audit log |
| The master key, every generation still in use | Yes, once per generation, **apart from the database backups** | Without it the database's secrets cannot be read (below) |
| Configuration and the other secrets | Yes, with the rest of your deployment configuration | Environment variables, database and Valkey passwords, `METRICS_TOKEN`, SMTP password, TLS certificates, proxy configuration |
| The Postgres roles | Recorded, not dumped | `pg_dump` covers one database; roles belong to the server. Keep the SQL that creates them ([Postgres and Valkey](postgres-valkey.md#two-roles-and-row-level-security)) |
| Valkey | No | Sessions, flows in progress, caches and counters. Losing them signs users out and nothing more lasting; see [If Valkey is lost](postgres-valkey.md#if-valkey-is-lost) |
| The release you run | Its version or image digest | Restore with the same release or a newer one, never an older one ([Upgrading](upgrading.md#rolling-back)) |

## The master key

The master key encrypts signing keys' private halves, second-factor secrets, SMTP, SMS
and CAPTCHA credentials, upstream identity providers' client secrets and webhook
secrets ([the full list](../concepts/keys.md#the-master-key)). rIDM never writes it
anywhere, so it exists only where you put it.

- **Keep it apart from the backups.** On its own, a database backup exposes personal
  data and password hashes, but its secrets stay encrypted. Together with the key it
  is everything. Store the
  key in a secret manager with its own access control, and keep a second copy offline
  (a sealed printout, a hardware token, a vault in another account) in case the secret
  manager is the thing you lose. Never put it in the same bucket, account or
  credentials as the database backups.
- **Keep every generation a retained backup needs.** After a
  [master-key rotation](../admin/key-rotation.md), the backups taken before it are
  encrypted under the old generation. Keep the old key, with its version number, for as
  long as you keep those backups.
- **Record the generation with each backup.** `ridm-api rotate-master-key --status` (or
  `ridm master-key status`) prints how many rows each generation holds; normally that is
  the current `MASTER_KEY_VERSION` alone.

## Backing up Postgres

Use Postgres's own tools; there is nothing rIDM-specific to export. Two approaches:

### Physical backups and point-in-time recovery

For production, prefer continuous archiving: the managed service's automated backups and
point-in-time restore, or [pgBackRest](https://pgbackrest.org/),
[Barman](https://pgbarman.org/) or [WAL-G](https://github.com/wal-g/wal-g) on a server
you run. They copy the data files and the write-ahead log, so a restore can land on any
moment in the retention window, losing seconds rather than a day. They work below row
level security, so the roles question below does not arise.

### Logical backups with `pg_dump`

`pg_dump` is simple and portable, and fine for a small deployment or as a second copy
next to physical backups. It takes a consistent snapshot while rIDM keeps running.

**It must run as a role that bypasses row level security.** rIDM forces row level
security on every tenant table, for the tables' owner too, and `pg_dump` refuses rather
than silently dump nothing. Run as `ridm_migrator` or `ridm_app` it stops with:

```text
pg_dump: error: query failed: ERROR:  query would be affected by row-level security policy for table "claim_mappers"
```

Any of these works:

- **A dedicated backup role** (preferred): read-only, and nothing else. Create it once as
  a superuser:

  ```sql
  CREATE ROLE ridm_backup LOGIN PASSWORD '...'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;
  GRANT pg_read_all_data TO ridm_backup;
  ```

  ```bash
  pg_dump -h db.internal -U ridm_backup -d ridm -Fc \
      -f ridm-$(date -u +%Y%m%dT%H%M%SZ).dump
  ```

- **A superuser**, such as `ridm` in the compose stacks:

  ```bash
  docker compose exec -T postgres pg_dump -U ridm -Fc ridm > ridm.dump
  ```

- **The migrator, asking the policy to let it through**, for a managed service where you
  cannot create a `BYPASSRLS` role. The policy admits a transaction that sets
  `app.bypass_rls`, so pass it as a connection option and tell `pg_dump` to run with row
  security on:

  ```bash
  PGOPTIONS='-c app.bypass_rls=on' pg_dump -h db.internal -U ridm_migrator -d ridm \
      --enable-row-security -Fc -f ridm.dump
  ```

All three produce the same dump. Use the custom format (`-Fc`): it is compressed, and
`pg_restore` can restore it in parallel or pick parts out of it.

### Protecting the backups

A backup holds every user's personal data, password hashes (argon2id) and the
encrypted secrets. Encrypt it before it leaves the database host (for example with
[age](https://age-encryption.org/) or your backup tool's own encryption), keep it in
storage only your operators can read, and delete it on the schedule your data
protection policy sets. A backup outlives erasure requests made after it was taken;
decide how your restore procedure handles them.

### Test the restore

A backup nobody has restored is a hope. Restore into a scratch database on a schedule,
start a node against it (next section) and check that a token can be issued: that
proves the dump, the roles and the master key together.

## Restoring

The procedure below restores into a new database and switches to it, so the old one is
there to fall back on until you are satisfied.

### 1. Stop rIDM

Stop every node: `docker compose stop ridm`, `kubectl scale deployment/ridm
--replicas=0`, or your service manager. Nodes left running would keep writing to the
old database and hold its state in their caches.

### 2. Prepare an empty database

If the Postgres server is new, create the two roles first, with the SQL in
[Postgres and Valkey](postgres-valkey.md#two-roles-and-row-level-security). Then, as a
superuser, create the database and its grants (the same grants that SQL gives, for the
new database):

```sql
CREATE DATABASE ridm_restored;
GRANT CONNECT, CREATE, TEMP ON DATABASE ridm_restored TO ridm_migrator;
GRANT CONNECT, TEMP ON DATABASE ridm_restored TO ridm_app;
\c ridm_restored
GRANT ALL ON SCHEMA public TO ridm_migrator;
GRANT USAGE ON SCHEMA public TO ridm_app;
```

The table grants and default privileges for `ridm_app` come back with the dump.

### 3. Restore

From a `pg_dump` file, as the migrator, so that it owns what it restores:

```bash
pg_restore -h db.internal -U ridm_migrator -d ridm_restored \
    --no-owner --single-transaction --exit-on-error ridm.dump
```

This works without bypassing row level security: `pg_dump` puts the data before the
policies, so the rows are loaded before row level security is switched on. The result
matches the original: tables owned by the migrator, row level security forced, the app
role's privileges and the `audit_ensure_partitions` grant in place. A superuser can
restore instead, without `--no-owner`, which keeps the original owners (the roles must
exist under the same names).

From a physical backup, follow your tool's or provider's restore procedure; the roles,
grants and policies are part of the data files.

### 4. Switch to it

Point `DATABASE_URL` (and the migrator's URL) at the new database, or swap the names as
a superuser once nothing is connected:

```sql
ALTER DATABASE ridm RENAME TO ridm_before_restore;
ALTER DATABASE ridm_restored RENAME TO ridm;
```

### 5. Clear rIDM's keys from Valkey

Valkey still holds the old database's state: cached tenants, clients, JWKS and role
sets, and sessions pointing at records the restored database may not have. Remove
everything rIDM put there. On a Valkey used by rIDM alone:

```bash
valkey-cli -h valkey.internal FLUSHDB
```

On a shared one, delete only the `ridm:` keys:

```bash
valkey-cli -h valkey.internal --scan --pattern 'ridm:*' | xargs -r valkey-cli -h valkey.internal unlink
```

In a cluster, run it against every primary. Users sign in again; see
[If Valkey is lost](postgres-valkey.md#if-valkey-is-lost) for everything else this
drops.

### 6. Start with the backup's master key

Configure the master key that was current when the backup was taken, with its
`MASTER_KEY_VERSION`, and any older generation the backup still holds in
`MASTER_KEY_PREVIOUS`. If you have rotated the master key since the backup, you can
keep the new key current and list the backup's generation in `MASTER_KEY_PREVIOUS`
instead, then run `ridm-api rotate-master-key` to bring the restored rows up to date.

If the restore is onto a newer release than the backup was made with, run
`ridm-api migrate` (or let the compose `migrate` service or the Helm hook do it) before
starting the servers; migrations apply to a restored database as to any other.

Then start one node. At start-up every node decrypts a signing key of each generation
the database holds, and **refuses to start** when the configured keys cannot read them:

```text
fatal error=the configured master keys do not decrypt this database's signing keys (generation(s) [1]; MASTER_KEY_VERSION is 1). After a restore, configure the master key that was current when the backup was taken, and any older generation still in use in MASTER_KEY_PREVIOUS
```

That message means the wrong key, not a damaged backup. Other secrets (webhook,
identity provider and messaging credentials, second factors) are sampled too; one that
fails is logged as an error with its table and generation, and the node starts.

### 7. Check it

- `/readyz` answers `200` on every node.
- `ridm-api rotate-master-key --status` shows only generations you have keys for.
- A global administrator can sign in to the admin console.
- A client can get a token, and the tenant's JWKS lists the keys you expect.

Then start the remaining nodes.

## What restoring to an earlier point undoes

A restore returns the database to the moment of the backup. Everything after it is
gone, and some of that matters more than the rest:

- **Security actions since the backup are undone.** A signing key revoked after the
  backup is back and published again; a disabled user, a removed administrator, a
  revoked personal access token, SCIM token or refresh token, a rotated client secret
  and a changed password are back to their earlier state. Re-apply them before letting
  traffic in. If you ship the audit log off the host with `AUDIT_SINK_URL`, the sink
  holds the events that happened after the backup and is the list to work from; the
  database's own audit log ends at the backup.
- **Users sign in again.** Browser sessions went with Valkey. Refresh tokens issued or
  rotated after the backup are unknown to the restored database, so those clients sign
  in again too.
- **Changes are lost**: registrations, enrolled second factors and passkeys, clients,
  consents, tenant settings. Users who registered after the backup must register again.
- **Queued work may run twice.** Webhook deliveries and email or SMS messages that were
  queued when the backup was taken and sent afterwards are queued again. A receiver
  that ignores a repeated `X-RIDM-Delivery` is unaffected
  ([webhooks](../admin/webhooks-audit.md)).
- Signing keys created after the backup are gone. Tokens they signed stop verifying at
  rIDM; they were short-lived anyway.

## If the master key is lost

The database can be recovered without its master key, but the secrets encrypted under
it cannot: that is what the key is for. What remains is everything hashed rather than
encrypted (passwords, client secrets, refresh tokens, personal access tokens, SCIM
tokens) and all the plain data. Recovering means discarding the unreadable secrets and
creating them again:

1. Generate a new master key (`openssl rand -hex 32`) and give it a
   `MASTER_KEY_VERSION` higher than any generation in the database, so the old rows
   read as a generation no configured key belongs to, rather than as the current one.
2. With every node stopped, delete the secrets that cannot be read, as the migrator:

   ```sql
   BEGIN;
   SELECT set_config('app.bypass_rls', 'on', true);
   DELETE FROM signing_keys;
   DELETE FROM credentials;
   DELETE FROM tenant_provider_settings;
   COMMIT;
   ```

3. Start the nodes with the new key. Each tenant gets a new signing key the first time
   it signs. The start-up check logs an error for each identity provider and webhook
   whose secret it cannot read, until you re-enter them.
4. Re-enter what was deleted or unreadable:
   - **Identity providers:** set the client secret again, in the console or with
     `PATCH /admin/tenants/{slug}/identity-providers/{idp}` and a new `client_secret`.
   - **Webhooks:** issue a new secret (`POST /admin/tenants/{slug}/webhooks/{webhook}/secret`,
     or the console) and give it to the receiver.
   - **Email, SMS and CAPTCHA settings** of tenants that had their own:
     [Email, SMS and templates](../admin/messaging.md),
     [CAPTCHA](../admin/security-controls.md).
5. Tell relying parties. Every token issued before is signed with a key that no longer
   exists, so it stops verifying once they fetch the new JWKS. Refresh tokens are
   hashed, not encrypted, and keep working: clients holding one get a new token signed
   with the new key, and the rest sign in again.
6. Tell users. Their authenticator apps, passkeys and recovery codes are gone. They sign
   in with their password (or a magic link, where the tenant allows one) and, under a
   `required` MFA policy, enrol a factor during sign-in
   ([MFA policy](../admin/mfa-policy.md)). A user who signed in with a passkey alone
   needs a password reset or a magic link first.

This is a disruptive recovery; the way to never need it is the second, offline copy of
the key.
