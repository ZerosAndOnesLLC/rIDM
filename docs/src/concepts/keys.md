# Signing keys and the master key

rIDM holds two kinds of key material, with very different jobs:

- **Signing keys** belong to one tenant each. They sign the tenant's tokens, and
  their public halves are published so that anyone can verify those tokens.
  They rotate routinely and without anyone noticing.
- **The master key** belongs to the deployment. It encrypts every secret rIDM
  stores (signing keys' private halves among them). It is never stored in the
  database, and losing it means losing those secrets.

## Signing keys

Every tenant has its own set of signing keys, so a key compromised in one
tenant says nothing about another, and each tenant can choose its own
algorithm and rotation schedule. The tenant's `settings.keys` policy decides:

| Setting | Default | Meaning |
|---------|---------|---------|
| `default_alg` | `RS256` | algorithm for new keys: `RS256`, `RS384`, `RS512`, `ES256` or `EdDSA` (Ed25519) |
| `rsa_bits` | 2048 | modulus size for new RSA keys: 2048, 3072 or 4096 |
| `rotation_interval_days` | 90 | rotate the active key once it is this old (0 = never automatically) |
| `retire_overlap_hours` | 24 | how long a replaced key stays published |

`RS256` is the default because every OIDC library supports it; `ES256` and
`EdDSA` give much smaller keys and signatures for relying parties that support
them. Tokens are signed with the tenant's active key for `default_alg`, with
one exception: an access token for a
[resource server](resource-servers.md#token-lifetime-and-signing-per-api) that
names its own `signing_alg` is signed with the tenant's active key of that
algorithm, which is generated when the resource server is saved if the tenant
has none yet. A key's `kid` is its RFC 7638 thumbprint.

A tenant's first key is generated the first time it is needed. On a
multi-node deployment exactly one node generates it while the others wait for
it, and the database allows only one active key per tenant and algorithm, so
there is never a token signed with a key missing from the published set.

### Lifecycle

A key moves through four states:

| Status | Signs tokens | Published in JWKS |
|--------|:------------:|:-----------------:|
| `pending` | no | yes |
| `active` | yes | yes |
| `retiring` | no | yes, until its overlap ends |
| `revoked` | no | no |

The published set, `/t/{slug}/.well-known/jwks.json`, holds every pending,
active and retiring key. It is served with an `ETag` and
`Cache-Control: max-age=300`, and the cached document is replaced the moment
any key changes.

**Rotation** creates a key with the tenant's policy, makes it active, and moves
the previous active key of the same algorithm to `retiring`, where it stays
published for `retire_overlap_hours`. The overlap exists for the tokens the old
key already signed: they keep verifying until they expire. Since access and ID
tokens live minutes, the default day is generous. After the overlap, the
hourly `key_rotation` job revokes the old key, and the same job rotates every
active key older than `rotation_interval_days`, one per algorithm in use, so a
key kept for a resource server's `signing_alg` rotates on the same schedule as
the default one.

A rotated key signs immediately. Relying parties that cache the JWKS must
refetch it when a token names a `kid` they have not seen (`ridm-auth` does, and
most JWT libraries can be configured to). A relying party that cannot do that
can be given time instead: create the new key as `pending` (published, not
signing), wait until every relying party has picked it up, then activate it.

**Revoking** a key unpublishes it at once, and every token it signed stops
verifying at rIDM and at every relying party that refetches. That is the
response to a leaked key, not a routine operation.

Changing `default_alg` takes effect at the next signing: a key for the new
algorithm is generated and used, while the old algorithm's key stays active and
published until you retire it.

See [Rotating keys](../admin/key-rotation.md) for the console, CLI and API
steps.

## The master key

Secrets rIDM must be able to read back are encrypted at rest under the master
key:

| What | Where |
|------|-------|
| Signing keys' private halves | `signing_keys` |
| MFA secrets: authenticator app seeds, passkeys, recovery codes (hashed, then encrypted), email and SMS factor records | `credentials` |
| SMTP, SMS gateway and CAPTCHA credentials | `tenant_provider_settings` |
| Upstream identity provider client secrets | `identity_providers` |
| Webhook signing secrets | `webhooks` |

Secrets rIDM only ever needs to *compare* are hashed instead and cannot be
decrypted at all: passwords (argon2id), client secrets, refresh tokens,
personal access tokens, SCIM tokens and dynamic registration initial access
tokens (SHA-256). Opaque access tokens are not stored in the database at all:
Valkey holds their claims under the token's SHA-256 hash.

Encryption is XChaCha20-Poly1305 with a fresh random nonce per value. Each
ciphertext is bound to its table, tenant and row as associated data, so a
ciphertext copied into another row, or another tenant's row, fails to decrypt
rather than being read in the wrong place. Private signing keys are decrypted
only on the node that signs with them and kept in memory there, never in
Valkey.

The master key is 32 bytes, supplied as hex or base64 in `MASTER_KEY` or in a
file named by `MASTER_KEY_FILE` (for container secrets). It must be the same on
every node. rIDM never writes it anywhere, so **back it up separately from the
database**: a database backup without its master key can be restored, but its
signing keys, MFA enrolments, IdP secrets and webhook secrets cannot be read.
A node checks at start-up that its keys decrypt the database's signing keys and
refuses to start if they do not. See [Backup and restore](../deploy/backup-restore.md),
which also covers recovering from a lost key.

### Rotating the master key

Every ciphertext records the master-key *generation* (`MASTER_KEY_VERSION`) that
produced it, and a node can hold previous generations for decryption, so the
master key rotates without downtime:

1. Roll out a new `MASTER_KEY` with `MASTER_KEY_VERSION` incremented, keeping
   the old key in `MASTER_KEY_PREVIOUS` as `<old version>=<old key>`. New
   writes use the new generation; existing rows still decrypt.
2. Re-encrypt every row under the current generation: `ridm-api
   rotate-master-key` on any node, or `ridm master-key rotate` over the admin
   API. `ridm-api rotate-master-key --status` (or `ridm master-key status`)
   shows how many rows remain on each generation.
3. Once nothing remains on the old generation, remove it from
   `MASTER_KEY_PREVIOUS`.

See [Rotating keys](../admin/key-rotation.md).

### Key custody

Instead of the environment, an HSM (PKCS#11) or a key-management service (AWS
KMS, Vault / OpenBao Transit, Google Cloud KMS, Azure Key Vault) can hold the
master key (`KEY_WRAPPER`). Each generation is then a random data key the
backend wrapped, stored wrapped in `master_key_generations`; nodes unwrap it
at start-up, so the backend is never on a request's path, and neither the
configuration nor a backup can decrypt anything without it. Generations from
the environment and from a backend coexist, which is how a deployment moves
onto one online. See [Key custody: HSM and KMS](../deploy/key-custody.md).
