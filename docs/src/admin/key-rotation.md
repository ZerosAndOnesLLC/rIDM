# Rotating keys

rIDM has two kinds of key, and they rotate differently:

- **Signing keys** belong to one tenant. They sign every token the tenant issues and are
  published in its JWKS so that relying parties can verify those tokens. Rotating one
  is routine and can be automatic.
- **The master key** belongs to the deployment. It encrypts secrets at rest (the private
  halves of signing keys, MFA credentials, identity-provider client secrets, webhook
  secrets and provider settings such as SMTP passwords). Rotating it means rolling a new
  key out to every node and re-encrypting stored rows.

For how the two fit together see [Signing keys and the master key](../concepts/keys.md).

## Signing keys

### Lifecycle

| Status | Signs tokens | In the JWKS |
|--------|:------------:|:-----------:|
| `pending` | no | yes |
| `active` | yes | yes |
| `retiring` | no | yes, until `expires_at` |
| `revoked` | no | no |

A tenant has at most one active key per algorithm. Tokens are signed with the active
key of the tenant's default algorithm (`settings.keys.default_alg`), except access
tokens for a resource server that sets its own `signing_alg`, which are signed with the
active key of that algorithm. Saving such a resource server makes sure a key of its
algorithm exists, so a tenant can have several active keys at once, one per algorithm
in use. Every key's `kid` is
its RFC 7638 JWK thumbprint. When a tenant has no key at all, the first token request or
JWKS fetch creates one; a lock makes sure only one node generates it.

Activating a key moves the previous active key of the same algorithm to `retiring`, with
`expires_at` set to now plus the overlap. Tokens signed by the old key keep verifying
until then; the `key_rotation` job revokes retiring keys whose overlap has passed.
Revoking a key unpublishes it immediately, and every token it signed stops verifying:
that is the emergency action for a key you believe is compromised, not part of a normal
rotation.

### Key policy

`settings.keys`, in the console under Settings → Keys, discovery & audit:

| Setting | Default | Meaning |
|---------|---------|---------|
| `default_alg` | `RS256` | algorithm for new keys and for signing: `RS256`, `RS384`, `RS512`, `ES256` or `EdDSA` |
| `rsa_bits` | `B2048` | RSA modulus for new RSA keys: `B2048`, `B3072` or `B4096` |
| `rotation_interval_days` | `90` | rotate the active key when it is this old; `0` turns automatic rotation off |
| `retire_overlap_hours` | `24` | how long a retired key stays published |

`retire_overlap_hours` must comfortably exceed the longest lifetime of a token signed by
the key: the access and ID token lifetimes of the tenant, its clients and its resource
servers (five minutes by default), plus the time relying parties may cache the JWKS.
Refresh tokens are not affected; they are not signed JWTs checked against the JWKS.

### Automatic rotation

The `key_rotation` job runs every hour on one node at a time. For each active tenant it
revokes retiring keys whose `expires_at` has passed, then, when `rotation_interval_days`
is not 0, rotates every active key whose `not_before` (its creation time, unless one was
given) is that many days in the past: a new key of the same algorithm is generated and
made active at once, and the old one retires with the overlap. Keys of the default
algorithm and of resource servers' algorithms follow the same schedule. Rotations are audited as
`signing_key.created` and `signing_key.status_changed` with the `system` actor.

### Rotating by hand

Console: **Signing keys** (`/console/keys/`) shows every key on a timeline with
buttons for "Rotate now", "New pending key", activate, retire and revoke.

CLI:

```bash
ridm --tenant acme key list                  # KID, ALG, STATUS, NOT BEFORE, EXPIRES
ridm --tenant acme key list --status retiring
ridm --tenant acme key rotate                # new key, active at once; the old one retires
```

Admin API, under `ridm:keys:read` / `ridm:keys:write` (owners and administrators):

| Route | Does |
|-------|------|
| `GET /admin/tenants/{slug}/keys?status=` | list keys |
| `POST /admin/tenants/{slug}/keys/rotate` | new key with the default algorithm, active at once (rotate another algorithm's key by creating one with `activate: true`) |
| `POST /admin/tenants/{slug}/keys` | new key, `pending` unless `activate` is true |
| `GET /admin/tenants/{slug}/keys/{key}` | one key with its public JWK |
| `POST …/keys/{key}/activate` | start signing with it; the previous active key of its algorithm retires |
| `POST …/keys/{key}/retire` | stop signing; stays published for the overlap |
| `POST …/keys/{key}/revoke` | unpublish now |

`POST …/keys` takes an optional body: `alg` and `rsa_bits` (2048, 3072 or 4096) default
to the key policy, `activate` defaults to `false`, and `not_before` is recorded as the
key's start (the age automatic rotation measures from) but does not delay activation.

### Rotation without a verification gap

A rotation (manual or automatic) activates the new key in the same step that creates
it, so a relying party holding a cached JWKS meets a `kid` it has never seen. The JWKS is
served with `Cache-Control: public, max-age=300, must-revalidate` and a strong `ETag`,
and well-behaved libraries (including [`ridm-auth`](../quickstarts/protect-an-api.md))
refetch the key set when a token names an unknown `kid`. For relying parties that do
not, publish the key before using it:

```bash
# 1. Publish only
curl -X POST https://id.example.com/admin/tenants/acme/keys \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{}'
# 2. Wait longer than the JWKS max-age (5 minutes) plus any caching of your own
# 3. Start signing with it
curl -X POST https://id.example.com/admin/tenants/acme/keys/<id>/activate \
  -H "Authorization: Bearer $TOKEN"
```

Changing the signing algorithm works the same way: create a pending key with the new
`alg`, wait, activate it, then set `settings.keys.default_alg` to the new algorithm, and
finally retire the old algorithm's key. Changing `default_alg` alone makes the next
token request generate and activate a key of the new algorithm on the spot, with no
pre-publication.

### JWKS publication

`GET /t/{slug}/.well-known/jwks.json` (or `/.well-known/jwks.json` on the tenant's
[custom domain](custom-domains.md)) lists the public halves of every pending, active and
retiring key, as `application/jwk-set+json`, answerable from any origin. Each JWK carries
`kid`, `alg` and `use: "sig"`. The document is cached per tenant under a version that
every key change replaces, so a change is visible on every node at once; clients honour
`ETag` with `If-None-Match` for cheap revalidation.

## The master key

### How it works

Each encrypted value is sealed with XChaCha20-Poly1305 under the master key, bound to
the row it belongs to, and stored with the *generation* (key version) that sealed it. A
node knows its current key (`MASTER_KEY` or `MASTER_KEY_FILE`, generation
`MASTER_KEY_VERSION`) and, optionally, older generations (`MASTER_KEY_PREVIOUS`). New
writes always use the current generation; reads use whichever generation the row
records. With a [key custody backend](../deploy/key-custody.md) (`KEY_WRAPPER`) the
generations are data keys an HSM or KMS wrapped instead, made with
`new-generation` ([below](#with-a-key-custody-backend)); the rest of this section is
the same for both.

| Variable | Default | Meaning |
|----------|---------|---------|
| `MASTER_KEY` | required, unless `MASTER_KEY_FILE` or `KEY_WRAPPER` is set | 32 bytes, hex or base64. Generate with `openssl rand -hex 32` |
| `MASTER_KEY_FILE` | unset | read the key from a file (a mounted secret) instead |
| `MASTER_KEY_VERSION` | `1` | the current key's generation, at least 1 |
| `MASTER_KEY_PREVIOUS` | empty | older keys as `version=key` pairs, comma-separated, e.g. `1=9f86…,2=4e07…`; every version must be lower than `MASTER_KEY_VERSION` |

Re-encryption covers six columns: `signing_keys.private_key_enc`,
`credentials.data_enc` (TOTP secrets, passkeys, recovery codes),
`tenant_provider_settings.config_enc` (SMTP, SMS and CAPTCHA settings),
`identity_providers.client_secret_enc` (OIDC client secrets, LDAP bind passwords),
`webhooks.secret_enc` and `saml_signing_keys.private_key_enc`. Client secrets,
personal access tokens and provisioning tokens are stored as hashes and are not
involved.

### Procedure

1. **Generate the new key** and keep the old one:

   ```bash
   openssl rand -hex 32
   ```

2. **Roll it out to every node**: the new key as `MASTER_KEY`, `MASTER_KEY_VERSION`
   incremented, the old key in `MASTER_KEY_PREVIOUS`. For a deployment on generation 1:

   ```bash
   MASTER_KEY=<new key>
   MASTER_KEY_VERSION=2
   MASTER_KEY_PREVIOUS=1=<old key>
   ```

   Restart or redeploy every node. From here on new secrets are written under
   generation 2 and old rows still decrypt.

3. **Re-encrypt** everything still on an older generation, once, from anywhere:

   ```bash
   ridm master-key status          # current generation, rows still on older ones
   ridm master-key rotate          # asks first; --yes (-y) for scripts
   ```

   or on a host with the server's configuration (the same environment as the nodes):

   ```bash
   ridm-api rotate-master-key --status
   ridm-api rotate-master-key
   ```

   The console's **Signing keys** page shows the same status to global administrators
   and has a button to re-encrypt. Through the admin API it is
   `GET /admin/master-key` and `POST /admin/master-key/rotate`, which need a global
   administrator with `ridm:keys:read` / `ridm:keys:write`.

4. **Check** that nothing is left: `ridm master-key status` must report 0 rows on an
   older generation, and the rotation report must show no `failed` rows.

5. **Remove the old key** from `MASTER_KEY_PREVIOUS` on every node and restart.

### With a key custody backend

There is no key to generate or roll out: the backend wraps a new data key.

```bash
ridm master-key new-generation     # POST /admin/master-key/generations
ridm master-key rotate
```

or `ridm-api rotate-master-key --new-generation`, which creates the generation and
re-encrypts in one run, or **New generation** then **Re-encrypt pending rows** on the
console. The creating node switches at once and the others within a minute, so the
rollout window below does not apply; a pass run before every node has switched simply
leaves a few rows for the next one. Creating a generation is audited as
`master_key.generation_created`.

Re-encryption runs online, in batches of 200 rows per table. Each row is rewritten only
if its generation has not changed since it was read, so it is safe alongside live
traffic and alongside a second rotation run. The report lists rows rewritten and rows
that failed per table, and a pass that rewrote anything is audited as
`master_key.rotated` in the global chain. `ridm-api rotate-master-key` exits 0 on
success, 1 when rows failed or the database or Valkey could not be reached, and 2 on a
configuration error; `ridm master-key rotate` exits 1 when rows failed.

### Caveats

- **The rollout window.** Between the first node starting on the new key and the last
  one, a node still on the old configuration cannot read secrets that an updated node
  has just written (a newly enrolled authenticator, a new signing key, a changed SMTP
  password): it does not know generation 2 yet. Roll the configuration out to all nodes
  together, and avoid key-generating operations while the rollout is in progress.
- **Failed rows** mean a row's generation is not among the keys the node knows, or its
  ciphertext is damaged. The usual cause is an incomplete `MASTER_KEY_PREVIOUS`. Fix the
  configuration and run the rotation again; rows that succeeded are not touched twice.
- **Removing an old key early** makes every row still on it unreadable: signing keys
  fail to load, users cannot pass MFA, messaging and webhooks stop. Always check the
  status first.
- **Losing the master key** loses every secret it protects. Keep it in a secret store
  with its own backup, separate from database backups.
- Decrypted provider settings are cached in each node's memory for up to a minute; this
  does not affect rotation, which reads the stored rows.
- To keep the master key in an HSM or a cloud KMS instead of the environment, see
  [Key custody: HSM and KMS](../deploy/key-custody.md).
