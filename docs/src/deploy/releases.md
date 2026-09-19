# Releases and verification

Every release is built by the `release` workflow from a `v*` tag and published in three
forms: a container image, a Helm chart and static Linux binaries. Each is signed with
[Sigstore](https://www.sigstore.dev/) keyless signing, so you can check that what you
run was built by this repository's release workflow from that tag and not altered
since. The release notes on GitHub come from
[`CHANGELOG.md`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/CHANGELOG.md).

The first release is `v0.1.0`.

## What a release publishes

| Artifact | Where | Platforms |
|----------|-------|-----------|
| Container image | `ghcr.io/zerosandonesllc/ridm:{version}` | linux/amd64, linux/arm64 |
| Helm chart | `oci://ghcr.io/zerosandonesllc/charts/ridm`, and `ridm-{version}.tgz` on the GitHub release | |
| Static binaries | `ridm-{version}-linux-amd64.tar.gz`, `ridm-{version}-linux-arm64.tar.gz` on the GitHub release | linux x86_64, aarch64 |
| SBOM | attached to the image (BuildKit's attestation, and an SPDX document attested with cosign), and `ridm-{version}.spdx.json` on the GitHub release | |
| Checksums | `SHA256SUMS` and its Sigstore bundle `SHA256SUMS.sigstore.json` on the GitHub release | |

### Image tags

A release `1.2.3` is tagged `1.2.3`, `1.2` and `latest`. A pre-release such as
`0.2.0-rc.1` gets only its own tag and never moves `latest` or a minor tag. The image is
one multi-arch index; Docker, containerd and Kubernetes pick the architecture.

Deploy by digest rather than by tag: tags move, a digest names exactly one image. The
release notes give the digest, and so does

```bash
docker buildx imagetools inspect ghcr.io/zerosandonesllc/ridm:1.2.3
```

In the Helm chart, set `image.digest` to it; see [Kubernetes (Helm)](kubernetes.md).

### The Helm chart

```bash
helm install ridm oci://ghcr.io/zerosandonesllc/charts/ridm --version 1.2.3 -f values.yaml
```

The chart's version is the release's version, and its image tag defaults to the same.

### Static binaries

Each tarball holds `ridm-api` (the server, with the UI compiled in), `ridm` (the admin
CLI), `LICENSE`, `README.md` and `CHANGELOG.md`. Both binaries are statically linked
against musl and run on any Linux of their architecture, with no libc or OpenSSL
requirement; the server uses mimalloc, since musl's own allocator scales poorly across
threads.

```bash
tar -xzf ridm-1.2.3-linux-amd64.tar.gz
sudo install -m 0755 ridm-1.2.3-linux-amd64/ridm-api ridm-1.2.3-linux-amd64/ridm /usr/local/bin/
```

The server is configured by environment variables exactly as in the image
([Server configuration](../reference/configuration.md)), and runs migrations with
`ridm-api migrate` as the schema owner. Under systemd, a unit along these lines keeps it
confined:

```ini
[Unit]
Description=rIDM
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ridm-api
EnvironmentFile=/etc/ridm/ridm.env
# Secrets as files, read through the *_FILE variables:
LoadCredential=master_key:/etc/ridm/master_key
Environment=MASTER_KEY_FILE=%d/master_key
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
Restart=on-failure
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
```

## Verifying a release

Install [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 3 or
later (the release workflow signs with cosign 3, whose Sigstore bundle format older
versions do not read). Every signature was made by the release workflow with its GitHub identity, so
verification names that workflow and GitHub's token issuer:

```bash
IDENTITY='^https://github.com/ZerosAndOnesLLC/rIDM/\.github/workflows/release\.yml@refs/tags/v'
ISSUER=https://token.actions.githubusercontent.com
```

**The image:**

```bash
cosign verify ghcr.io/zerosandonesllc/ridm:1.2.3 \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```

**Its SBOM** (an SPDX document, attested by the same identity):

```bash
cosign verify-attestation --type spdxjson ghcr.io/zerosandonesllc/ridm:1.2.3 \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" \
  | jq -r '.payload' | base64 -d | jq '.predicate.packages | length'
```

**The chart:**

```bash
cosign verify ghcr.io/zerosandonesllc/charts/ridm:1.2.3 \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```

**The binaries and everything else on the GitHub release:** verify the checksum file's
signature, then the files against it:

```bash
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
sha256sum --check --ignore-missing SHA256SUMS
```

A check that fails means the artifact was not produced by this repository's release
workflow for a `v*` tag, or was changed afterwards. Do not run it.

## How a release is cut

For maintainers, in
[CONTRIBUTING.md](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/CONTRIBUTING.md#cutting-a-release):
bump the version everywhere it lives, move the changelog's Unreleased notes under the
new version, merge, then push the tag. The workflow refuses a tag that disagrees with any
version in the tree or has no changelog section, and a pull request that changes the
workflow runs every build step without publishing, so a broken release build is found
before a tag depends on it.
