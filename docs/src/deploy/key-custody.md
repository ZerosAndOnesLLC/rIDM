# Key custody: HSM and KMS

By default the master key that encrypts secrets at rest comes from the environment
(`MASTER_KEY`), so anyone who can read the deployment's configuration can read every
signing key, second-factor secret and SMTP password in a database backup. With a **key
custody backend** an HSM or a key-management service holds the master key instead, and
neither the configuration nor a backup is enough to decrypt anything without it.

| Backend | `KEY_WRAPPER` | Cargo feature | Binds the generation | Authentication |
|---------|---------------|---------------|----------------------|----------------|
| PKCS#11 HSM (Thales Luna, Entrust nShield, YubiHSM 2, AWS CloudHSM, SoftHSM...) | `pkcs11` | `hsm-pkcs11` | yes (AES-GCM additional data) | the token's user PIN |
| AWS KMS | `aws-kms` | `kms-aws` | yes (encryption context) | the AWS SDK's chain: IRSA or EKS Pod Identity, ECS task role, instance profile, SSO, environment |
| HashiCorp Vault or OpenBao, Transit engine | `vault` | `kms-vault` | by key reference | a token, or the Kubernetes auth method with the pod's service-account token |
| Google Cloud KMS | `gcp-kms` | `kms-gcp` | yes (additional authenticated data) | a service-account key, workload identity federation, or the metadata server (GKE Workload Identity, Cloud Run, Compute Engine) |
| Azure Key Vault or Managed HSM | `azure-key-vault` | `kms-azure` | by key id | workload identity (AKS, or any cluster federated with Entra ID), a client secret, or a managed identity |

Each backend is an optional cargo feature, so a plain `cargo build` stays
provider-neutral. The [container image](container.md) is built with all of them; the
static (musl) release binaries with all but PKCS#11, because a static binary cannot
load the HSM vendor's library. A build without the backend `KEY_WRAPPER` names refuses
to start and names the feature.

## How it works

This is envelope encryption. Every master-key *generation* is a random 256-bit data
key. The backend encrypts ("wraps") it once, when the generation is created, and only
the wrapped form is stored, in the `master_key_generations` table. Each node asks the
backend to unwrap every generation when it starts and keeps the data keys in memory;
rows are then encrypted and decrypted locally, exactly as under `MASTER_KEY`
(XChaCha20-Poly1305, bound to the row, tagged with the generation).

What that means in practice:

- **No request waits on the backend.** Signing a token, checking a TOTP code or
  sending a webhook never calls the HSM or KMS, pays for a KMS request or counts
  against its rate limit. The backend is asked once per generation per node start.
- **An outage of the backend does not stop running nodes.** A node that cannot reach
  it at start-up refuses to start (it would otherwise run on the wrong key), so
  scaling out and restarts wait for the backend.
- **The data keys are in the nodes' memory**, as `MASTER_KEY` always was. Custody
  protects the key at rest, in backups, in configuration and in CI; it does not make a
  compromised node's memory safe.
- **Revoking rIDM's access to the backend key** stops every new node from starting.
  Deleting the backend key destroys every secret still under a generation it wrapped:
  treat it like losing the master key.

Generations from the environment and from the backend can coexist: the environment's
`MASTER_KEY` / `MASTER_KEY_PREVIOUS` stay readable next to wrapped generations, which is
how an existing deployment moves onto a backend without downtime. A generation number
is never reused, and a wrapped generation is always numbered above every generation a
stored row carries.

## Settings

| Variable | Meaning |
|----------|---------|
| `KEY_WRAPPER` | The backend new generations are wrapped by. Setting it makes `MASTER_KEY` optional. |
| `KEY_WRAPPER_PREVIOUS` | Further backends, comma-separated, that still hold older generations while rows move off them (switching from one backend to another). |

### PKCS#11

| Variable | Default | Meaning |
|----------|---------|---------|
| `PKCS11_MODULE` | required | Path of the vendor's PKCS#11 library (`.so`). In the image, mount it and its dependencies into the container. |
| `PKCS11_TOKEN_LABEL` | unset | The token, by label; else `PKCS11_SLOT`; else the first slot with a token. |
| `PKCS11_SLOT` | unset | The token, by slot id. |
| `PKCS11_PIN` / `PKCS11_PIN_FILE` | required | The user PIN. |
| `PKCS11_KEY_LABEL` | `ridm-master-key` | The AES-256 key (`CKA_LABEL`) that wraps the data keys, with AES-GCM. |
| `PKCS11_GENERATE_KEY` | `false` | Create that key on the token (sensitive, non-extractable) when it is missing. Leave off in production, where the HSM's administrators create keys under their own ceremony; handy with SoftHSM. |

The HSM must allow AES-GCM with a caller-supplied IV for `C_Encrypt`/`C_Decrypt` on
that key.

### AWS KMS

| Variable | Default | Meaning |
|----------|---------|---------|
| `AWS_KMS_KEY_ID` | required | A symmetric key: id, ARN or `alias/...`. Each generation records the key's ARN, so re-pointing an alias later leaves older generations on their key. |
| `AWS_KMS_ENDPOINT` | unset | Another endpoint (a VPC endpoint's DNS name). `AWS_ENDPOINT_URL_KMS` works too. |

Region and credentials come from the SDK's standard chain (`AWS_REGION`, IRSA, EKS Pod
Identity, the ECS task role, an instance profile, `AWS_PROFILE`, SSO). The generation
is sent as the encryption context `ridm:master-key = ridm:master-key:v<N>`, so a key
policy can require it and CloudTrail shows which generation a node unwrapped. The
least the role needs:

```json
{
  "Effect": "Allow",
  "Action": ["kms:Encrypt", "kms:Decrypt"],
  "Resource": "arn:aws:kms:us-east-1:123456789012:key/…",
  "Condition": { "StringLike": { "kms:EncryptionContext:ridm:master-key": "ridm:master-key:v*" } }
}
```

KMS automatic key rotation is transparent: older generations keep decrypting.

### Vault and OpenBao (Transit)

| Variable | Default | Meaning |
|----------|---------|---------|
| `VAULT_ADDR` | required | The server, e.g. `https://vault.example.com:8200`. |
| `VAULT_TRANSIT_KEY` | required | The Transit key's name. |
| `VAULT_TRANSIT_MOUNT` | `transit` | Where the Transit engine is mounted. |
| `VAULT_TOKEN` / `VAULT_TOKEN_FILE` | | A token, unless `VAULT_KUBERNETES_ROLE` is set. |
| `VAULT_KUBERNETES_ROLE` | unset | Log in through the Kubernetes auth method as this role, with the pod's service-account token. Works the same on OpenShift. |
| `VAULT_KUBERNETES_MOUNT` | `kubernetes` | Where that auth method is mounted. |
| `VAULT_KUBERNETES_TOKEN_FILE` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | The service-account token to present (a projected token with Vault's audience, if you use one). |
| `VAULT_NAMESPACE` | unset | Vault Enterprise / HCP namespace. |
| `VAULT_CACERT` | unset | PEM file of the CA(s) to trust for `VAULT_ADDR` instead of the system's. |

The policy rIDM needs:

```hcl
path "transit/encrypt/ridm" { capabilities = ["update"] }
path "transit/decrypt/ridm" { capabilities = ["update"] }
```

Rotating the Transit key (`vault write -f transit/keys/ridm/rotate`) is transparent;
keep `min_decryption_version` at or below the oldest version a generation used.

### Google Cloud KMS

| Variable | Default | Meaning |
|----------|---------|---------|
| `GCP_KMS_KEY` | required | `projects/P/locations/L/keyRings/R/cryptoKeys/K`, a symmetric encrypt/decrypt key. |
| `GOOGLE_APPLICATION_CREDENTIALS` | unset | A service-account key file, or a workload identity federation file (`external_account` with a `credential_source.file`, such as a Kubernetes projected token, optionally impersonating a service account). Unset: the metadata server. |
| `GCE_METADATA_HOST` | `metadata.google.internal` | The metadata server's host. |
| `GCP_KMS_ENDPOINT` | `https://cloudkms.googleapis.com` | Another endpoint (Private Service Connect). |

The service account needs `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key. Key
rotation in Cloud KMS is transparent.

### Azure Key Vault and Managed HSM

| Variable | Default | Meaning |
|----------|---------|---------|
| `AZURE_KEY_VAULT_URL` | required | `https://<name>.vault.azure.net` or `https://<name>.managedhsm.azure.net`. |
| `AZURE_KEY_VAULT_KEY` | required | The key's name. |
| `AZURE_KEY_VAULT_KEY_VERSION` | the current version | Pin a version. Each generation records the version it used either way. |
| `AZURE_KEY_VAULT_ALGORITHM` | `RSA-OAEP-256` | `RSA-OAEP-256` or `RSA-OAEP` for an RSA key; `A256KW`, `A192KW` or `A128KW` for an AES key in a Managed HSM. |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` | unset | The application (or a user-assigned managed identity's client id). |
| `AZURE_FEDERATED_TOKEN_FILE` | unset | Workload identity: the federated token the AKS webhook (or your own projection) provides, re-read on every call. |
| `AZURE_CLIENT_SECRET` / `AZURE_CLIENT_SECRET_FILE` | unset | A client secret, when there is no federated token. |
| `AZURE_AUTHORITY_HOST` | `https://login.microsoftonline.com` | Entra ID's host (sovereign clouds). |
| `IDENTITY_ENDPOINT`, `IDENTITY_HEADER` | unset | App Service / Container Apps managed identity. |

Without tenant and client ids and a federated token or secret, rIDM asks the managed
identity endpoint, then the instance metadata service. The identity needs the
`wrapKey` and `unwrapKey` key permissions (the *Key Vault Crypto User* role). Creating a
new key version is transparent as long as the older versions stay enabled.

## Starting a new deployment on a backend

Set `KEY_WRAPPER` and the backend's settings, and leave `MASTER_KEY` unset. The first
node to start creates generation 1: it has the backend wrap a random data key, checks
that the backend gives the same key back, and stores the wrapped form. Every later
node unwraps it. The global audit chain records `master_key.generation_created`.

## Moving an existing deployment onto a backend

1. **Add the backend** to every node, keeping `MASTER_KEY` (and `MASTER_KEY_VERSION`,
   `MASTER_KEY_PREVIOUS`) as they are, and restart. The first node creates the first
   wrapped generation, numbered after the environment's; new secrets are written under
   it and the old ones still decrypt.
2. **Re-encrypt** what is still under the environment's generations:
   `ridm master-key rotate`, `ridm-api rotate-master-key`, or the console's
   **Re-encrypt pending rows** (see [Rotating keys](../admin/key-rotation.md#the-master-key)).
3. **Check** with `ridm master-key status` that no row is left under the environment's
   generations.
4. **Remove `MASTER_KEY`** (and `MASTER_KEY_VERSION`, `MASTER_KEY_PREVIOUS`) from every
   node and restart. Destroy the old key once you no longer need to read backups taken
   before step 2.

Going back works the same way the other way round: `MASTER_KEY` current,
`KEY_WRAPPER` unset, the backend in `KEY_WRAPPER_PREVIOUS` until the rotation is done.
Moving from one backend to another likewise: the new one as `KEY_WRAPPER`, the old one
in `KEY_WRAPPER_PREVIOUS`.

## New generations

A new data key is a new generation:

```bash
ridm master-key new-generation     # over the admin API
ridm-api rotate-master-key --new-generation   # with the server's configuration; also re-encrypts
```

or **New generation** on the console's **Signing keys** page, or
`POST /admin/master-key/generations` (a global administrator with `ridm:keys:write`).
The node that creates it starts encrypting under it at once; the other nodes adopt it
within a minute (they look for new generations every minute, and load one on first
sight of a row under it). Then re-encrypt as above. Rotating the backend's own key
(KMS automatic rotation, a new Transit or Key Vault key version) needs nothing from
rIDM.

With the master key in the environment there is no such command: a generation is
rolled out by changing `MASTER_KEY` and `MASTER_KEY_VERSION`, and the endpoint answers
`409`.

## Status

`ridm master-key status`, `ridm-api rotate-master-key --status`, `GET /admin/master-key`
and the console show the backend, every generation (from the environment or which
backend and key wrapped it, and whether this node could unwrap it) and how many rows
each table has under each generation.

At start-up a node logs each generation it cannot unwrap. That is fatal only for the
backend's current generation, or when no signing key decrypts (the
[start-up check](backup-restore.md)); rows under an unreadable older generation fail
to decrypt until its backend is configured again.

## Backups

A database backup holds only wrapped data keys. To restore one you need the backend
key that wrapped them (and, for rows still under the environment's generations, those
master keys). Do not schedule deletion of a KMS key, destroy a Transit key or purge a
Key Vault key while `master_key_generations` or any backup you may restore still names
it.

## Kubernetes and OpenShift

The [Helm chart](kubernetes.md) takes the backend under `keyCustody`: `wrapper`,
`previous`, the non-secret settings in `env`, the secret ones (`VAULT_TOKEN`,
`PKCS11_PIN`, `AZURE_CLIENT_SECRET`) from a Secret of yours named in
`existingSecret`, and `mountServiceAccountToken: true` for Vault's Kubernetes auth
method. Workload identity needs no secret at all: annotate the service account
(`serviceAccount.annotations`, e.g. `eks.amazonaws.com/role-arn`,
`iam.gke.io/gcp-service-account`, `azure.workload.identity/client-id`) and add the pod
label `azure.workload.identity/use: "true"` for Azure. With a backend, `masterKey` may
be left empty. The migration Job never receives the master key or the backend's
settings: migrations do not read secrets.
