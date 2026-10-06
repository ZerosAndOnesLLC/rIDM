# FIPS 140-3

> **Status: planned.** This page describes the FIPS build as it is being built. The
> work is tracked in [#7](https://github.com/ZerosAndOnesLLC/rIDM/issues/7), and each
> section below names the issue that delivers it. Until those issues are closed, no
> released rIDM build is a FIPS build.

FIPS 140-3 is the US and Canadian government standard for cryptographic modules. Some
organizations must run software whose cryptography comes only from a module that NIST
has validated. Typical examples are US federal agencies, their contractors (FedRAMP,
CMMC) and regulated industries. These organizations often run FIPS-mode clusters, such
as OpenShift on RHEL CoreOS installed with `fips: true`.

**Most deployments don't need any of this.** The standard build and image are the
default and are unaffected. Nothing on this page changes how they behave or how you
configure them. You only need to read further if your organization requires FIPS.

## Two builds, one codebase

rIDM has a single build switch, the `fips` cargo feature, which is off by default.
Every feature works in both builds:

| | Standard build (default) | FIPS build |
|---|---|---|
| How to get it | `cargo build`, or the `ghcr.io/zerosandonesllc/ridm:<version>` image | `--features fips`, or the `ghcr.io/zerosandonesllc/ridm:<version>-fips` image |
| Cryptographic module | aws-lc-rs (AWS-LC) | aws-lc-rs on the **AWS-LC FIPS module**, and the host's validated OpenSSL for passkeys |
| New password hashes | argon2id | PBKDF2-HMAC-SHA512 |
| Secrets at rest | XChaCha20-Poly1305, AES-256-GCM from the next release (reads both) | AES-256-GCM |
| TLS | TLS 1.2 and 1.3 with every rustls suite and group, including ChaCha20 and X25519 | TLS 1.2 and 1.3 with AES-GCM suites only, and the P-256, P-384 and X25519MLKEM768 groups |
| Starts on a host without FIPS mode | yes | no, unless `FIPS_ALLOW_NON_FIPS_HOST=true` (development and CI only) |
| Platforms | image (amd64, arm64) and static musl binaries | image only (see [What isn't covered](#what-isnt-covered)) |

The two builds use the same database schema, the same tenant documents and the same
configuration. You can move a deployment from one build to the other in either
direction (see [Moving an existing deployment](#moving-an-existing-deployment)).

Wherever the FIPS-approved way of doing something is just as good for everyone, both
builds share it, so there is only one path to test. This applies to hashing, HMAC,
key generation, random numbers, TOTP and Kerberos crypto, all of which go through
aws-lc-rs in both builds. Both builds also read both ciphers for secrets at rest; the
standard build keeps writing XChaCha20-Poly1305 for one more release, so a rolling
update or a rollback to the release before never meets a value it can't read. The builds only
differ where the standard build has a better choice for the average deployment, such as
argon2id for passwords, or where FIPS needs a different library, such as OpenSSL for
passkeys.

## Building the FIPS image

Each release publishes the FIPS image as `ghcr.io/zerosandonesllc/ridm:<version>-fips`
(also `<major>.<minor>-fips` and `latest-fips`), for linux/amd64 and linux/arm64. It's
signed and carries an SBOM like the standard image (see
[Releases and verification](releases.md)). Pin it by digest.

To build it yourself, use [`api/Dockerfile.fips`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/api/Dockerfile.fips)
from the repository root:

```bash
docker build -f api/Dockerfile.fips -t ridm:fips .
```

It's built on Red Hat Universal Base Image 9 (`ubi9/ubi` for the build, `ubi9/ubi-minimal`
at run time). Every package it installs comes from the freely available UBI
repositories, so **no RHEL subscription is needed to build it**. It builds the same way
on an entitled OpenShift cluster, a RHEL host or a laptop. The build stage:

- installs `golang`, `cmake`, `clang` and `perl`. The AWS-LC FIPS module is compiled
  from source by `aws-lc-fips-sys`, and its build needs Go;
- installs `openssl-devel`. Passkey verification links against the system OpenSSL
  instead of a vendored copy, so on a FIPS host it runs inside RHEL's validated OpenSSL
  FIPS provider (`ubi-minimal` ships it);
- builds with `--no-default-features --features fips,embedded-ui,kerberos,hsm-pkcs11,kms-aws,kms-vault,kms-gcp,kms-azure`.
  Every feature of the standard image is included;
- fails if the binary links anything but the FIPS module's AWS-LC, links `ring`, or
  carries a vendored OpenSSL ([`scripts/fips/check-binary.sh`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/scripts/fips/check-binary.sh)).

The runtime image runs as the same non-root user (65532) as the standard one, with the
same healthcheck and environment. Outside a container, the build command is:

```bash
cargo build --release --locked -p ridm-api \
  --no-default-features \
  --features fips,embedded-ui,kerberos,hsm-pkcs11,kms-aws,kms-vault,kms-gcp,kms-azure
```

## Running it

- **The host must be in FIPS mode.** For OpenShift, that means installing the cluster
  with `fips: true`. For RHEL, run `fips-mode-setup --enable` and reboot.
- **At start-up** the server runs the FIPS module's self-test, checks that the host is
  in FIPS mode (`/proc/sys/crypto/fips_enabled` is `1`), and logs the module version:

  ```text
  INFO FIPS build: the AWS-LC FIPS module passed its self-test module_version="4.2.0" fips_version=Some(4) host_fips=true
  ```

  Every TLS configuration it builds (the HTTPS and mutual-TLS listeners, LDAP, the
  audit syslog sink, the healthcheck) must pass rustls' FIPS check. If any check fails,
  the server refuses to start and says which. The `ridm` command line and every
  `ridm-api` subcommand, the container healthcheck included, run the same checks.
- **Developing or running CI on a machine that isn't in FIPS mode:** set
  `FIPS_ALLOW_NON_FIPS_HOST=true`. The module self-test still has to pass, and the server
  prints a warning at start-up and logs it again. Never set this in production. A host
  that isn't in FIPS mode isn't a FIPS-validated configuration.
- **Postgres:** connect with client-certificate authentication over TLS (`sslmode=verify-full` with
  `sslcert`/`sslkey`) rather than a password. The Postgres driver sqlx still
  implements password authentication (SCRAM) with non-validated code. That's tracked
  upstream in transact-rs/sqlx#4416. Valkey, SMTP, LDAP, webhooks and the KMS backends
  all use the FIPS TLS provider.

### Settings only the FIPS build reads

| Variable | Default | Meaning |
|---|---|---|
| `PBKDF2_ITERATIONS` | `210000` | PBKDF2-HMAC-SHA512 iterations for new password hashes. It can't be set below 210,000. |
| `FIPS_TRANSITION` | `false` | Allows the one-time legacy operations described below. Turn it off when the move is done. |
| `FIPS_ALLOW_NON_FIPS_HOST` | `false` | Lets the FIPS build start on a host that isn't in FIPS mode, with a warning. For development and CI only. |

The standard build ignores these variables, and its `ARGON2_*` settings are unchanged.

## Moving an existing deployment

Some data that a standard deployment already holds can only be read with algorithms
that FIPS doesn't approve:

- password hashes made with argon2id, and imported bcrypt, MD5 or salted-digest
  hashes;
- secrets at rest written before the AES-256-GCM change, which use XChaCha20-Poly1305.

No library can make reading this data FIPS-approved, but rIDM doesn't make you throw it
away either. Turning on `FIPS_TRANSITION=true` lets the FIPS build do those reads
during a migration window. Every one of them is logged as a warning and counted in the
`ridm_fips_non_approved_total` metric (labelled with the operation), so you can watch
it drop to zero. With the flag off, which is the default, the FIPS build refuses them
and says why: a FIPS server that finds XChaCha20 secrets in its database refuses to
start, and names the steps below.

1. **Upgrade to a release that includes the FIPS work**, still on the standard build.
   It reads AES-256-GCM as well as XChaCha20-Poly1305, so you can go back to it later.
2. **Switch to the `-fips` image** with `FIPS_TRANSITION=true`. It writes new secrets
   with AES-256-GCM.
3. **Re-encrypt secrets at rest** with `ridm-api rotate-master-key` (or `ridm master-key
   rotate`) on the FIPS build. It rewrites every XChaCha20 row onto AES-256-GCM,
   including rows already under the current master-key generation, so you don't need
   a new master key. `rotate-master-key --status` shows what's left in
   `legacy_cipher_rows`.
4. **Let passwords move over.** When a user with an older hash signs in, rIDM checks
   the password once with the old algorithm and stores a PBKDF2 hash. The admin
   console lists the accounts that haven't moved yet, and you can require those users
   to reset their password whenever you decide.
5. **Turn `FIPS_TRANSITION` off.** From then on, the deployment runs only approved
   operations.

To import users with legacy hashes later, for example from another identity provider,
turn the flag on for the import and the sign-ins that follow, then turn it off again.

**Going back** to the standard build needs no preparation. The standard build reads
PBKDF2 hashes and AES-256-GCM rows, and it re-hashes passwords to argon2id as users
sign in.

## Feature by feature

| Feature | In the FIPS build | Issue |
|---|---|---|
| TLS (listener, mutual TLS, outbound connections) | Uses rustls' FIPS provider: AES-GCM suites only, with the P-256, P-384 and X25519MLKEM768 key exchange groups. X25519MLKEM768 is a post-quantum hybrid. rustls allows it in FIPS mode under NIST SP 800-56C rev 2, which permits a hybrid shared secret when one part (here ML-KEM, FIPS 203) is approved. Each configuration rIDM builds is checked with `ServerConfig::fips()` / `ClientConfig::fips()`. | [#1](https://github.com/ZerosAndOnesLLC/rIDM/issues/1) |
| Token signing (RS256/384/512, ES256) | Runs on aws-lc-rs, as it already does in both builds. | [#5](https://github.com/ZerosAndOnesLLC/rIDM/issues/5) |
| EdDSA signing keys | Available in both builds. Whether Ed25519 is inside the AWS-LC FIPS module boundary is being confirmed against the module's security policy. If it isn't, the FIPS build marks EdDSA as non-approved, and admins can turn it off per tenant. | [#5](https://github.com/ZerosAndOnesLLC/rIDM/issues/5) |
| Key generation, hashing, HMAC, random numbers | Uses aws-lc-rs in both builds. Random values come from the module's SP 800-90A DRBG. | [#5](https://github.com/ZerosAndOnesLLC/rIDM/issues/5) |
| TOTP (authenticator apps) | RFC 6238 on aws-lc-rs HMAC in both builds. Existing enrolments keep working. | [#5](https://github.com/ZerosAndOnesLLC/rIDM/issues/5) |
| Secrets at rest | AES-256-GCM under a key derived per value (HKDF-SHA-256 with a random salt), with the IV generated inside the module. The standard build reads it too, and writes it from the next release. | [#3](https://github.com/ZerosAndOnesLLC/rIDM/issues/3) |
| Passwords | PBKDF2-HMAC-SHA512 (SP 800-132). Older hashes move over at sign-in. | [#4](https://github.com/ZerosAndOnesLLC/rIDM/issues/4) |
| Passkeys (WebAuthn) | Verified through the host's validated OpenSSL, which is linked dynamically. | [#2](https://github.com/ZerosAndOnesLLC/rIDM/issues/2) |
| Kerberos desktop sign-in | AES encryption types on aws-lc-rs in both builds. The SHA-2 encryption types (RFC 8009) are added because FIPS-mode KDCs may refuse the SHA-1 ones. | [#6](https://github.com/ZerosAndOnesLLC/rIDM/issues/6) |
| AWS KMS | Uses the AWS SDK, as in the standard build. Its TLS goes through the FIPS provider. Its request signing is the SDK's own code (see [What isn't covered](#what-isnt-covered)). | [#1](https://github.com/ZerosAndOnesLLC/rIDM/issues/1) |
| Vault, Google Cloud KMS, Azure Key Vault | REST over the FIPS TLS provider. The key itself is protected by the service's own validation. | — |
| PKCS#11 HSM | The HSM performs the key operations, so its own FIPS validation is the one that counts. | — |
| SAML and OIDC | SHA-1 signatures are already refused. RSA-OAEP with SHA-1 (JWE `RSA-OAEP`, SAML `rsa-oaep-mgf1p`) stays available for compatibility with existing integrations. NIST plans to retire SHA-1, so the FIPS build may make it opt-in. | [#7](https://github.com/ZerosAndOnesLLC/rIDM/issues/7) |

## What isn't covered

- **The static musl release binaries.** These are standard builds only. The AWS-LC FIPS
  module is validated on specific operating environments, and a static musl binary
  isn't one of them.
- **The Postgres driver's own code** for password authentication, migration checksums
  and advisory-lock hashing, which still uses non-validated hashing.
  rIDM's own advisory locks are hashed by the Postgres server. Using client-certificate
  authentication avoids the password path. The rest is tracked upstream in
  transact-rs/sqlx#4416, #4418 and #4421.
- **The AWS SDK's request signing** (SigV4, for `KEY_WRAPPER=aws-kms`), which uses
  its own, non-validated HMAC. The AWS SDK tracks this upstream. If you need every piece
  validated, the other key custody backends don't have this gap.
- **The Postgres driver's TLS settings.** sqlx builds its own TLS configuration, which
  offers the non-approved ChaCha20 and X25519 next to the approved suites. A Postgres
  server in FIPS mode only accepts approved ones, so the connection still uses an
  approved suite.
- **Everything outside the rIDM process**: your load balancer or ingress, Postgres,
  Valkey and the users' browsers. Each needs its own FIPS configuration.

FIPS validation belongs to the cryptographic modules (AWS-LC and RHEL's OpenSSL), not to rIDM.
The FIPS build makes sure every security function runs inside one of those modules.
Whether a particular deployment counts as compliant is up to your assessor.

## Checking a build

```bash
# The binary links only the FIPS module's AWS-LC:
nm target/release/ridm-api | grep -oE 'aws_lc_(fips_)?[0-9]+_[0-9]+_[0-9]+' | sort -u

# ChaCha20 and plain X25519 are refused:
openssl s_client -connect ridm.example.com:443 -tls1_3 -groups X25519   # must fail
openssl s_client -connect ridm.example.com:443 -tls1_2 -cipher ECDHE-RSA-CHACHA20-POLY1305   # must fail
```

The `nm` line should print only `aws_lc_fips_...`. `cargo tree` still lists `aws-lc-sys`,
because rustls' `fips` feature compiles it alongside the FIPS module, but nothing in
the build uses it and the linker drops it. `scripts/fips/check-binary.sh` runs these
checks (and the OpenSSL one) on a binary, and `scripts/fips/smoke.sh <image>` boots an
image and probes its TLS. CI runs both on every pull request, along with a `cargo deny`
ban list for the FIPS build (`deny-fips.toml`).
