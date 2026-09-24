# Kubernetes (Helm)

The chart in
[`deploy/helm/ridm`](https://github.com/ZerosAndOnesLLC/rIDM/tree/main/deploy/helm/ridm)
runs rIDM on any Kubernetes 1.27 or later: a Deployment of the image (which serves the
UI itself), a Service, and optionally an Ingress, a HorizontalPodAutoscaler, a
PodDisruptionBudget and a Prometheus Operator ServiceMonitor. Migrations run in a Job
before every install and upgrade. It does not run Postgres or Valkey: bring your own
(a managed service, an operator such as CloudNativePG, or your own StatefulSets).

Each release publishes the chart to `oci://ghcr.io/zerosandonesllc/charts/ridm`, signed
([Releases and verification](releases.md)); it can also be installed from a checkout.

## Before installing

1. **Postgres 16+ with two roles**, as described in
   [Postgres and Valkey](postgres-valkey.md): a schema owner for migrations
   (`ridm_migrator`) and the DML-only role the pods connect as (`ridm_app`).
   `deploy/postgres/init-app-role.sh` creates both.
2. **Valkey 9+ or Redis 8+**, standalone, Sentinel or Cluster.
3. **A master key**, 32 random bytes, kept somewhere you will not lose it:

   ```bash
   kubectl create namespace ridm
   kubectl -n ridm create secret generic ridm-master-key --from-literal=key="$(openssl rand -hex 32)"
   ```

4. **The public URL** browsers and relying parties will use, with TLS in front of it.

## Installing

A minimal values file, with the connection strings in a Secret you manage:

```bash
kubectl -n ridm create secret generic ridm-db \
  --from-literal=app='postgres://ridm_app:...@postgres:5432/ridm' \
  --from-literal=owner='postgres://ridm_migrator:...@postgres:5432/ridm' \
  --from-literal=valkey='redis://valkey:6379'
```

```yaml
# ridm-values.yaml
publicUrl: https://id.example.com
trustedProxies: 10.0.0.0/8          # the ingress controller's pod network
database:
  existingSecret: {name: ridm-db, key: app}
redis:
  existingSecret: {name: ridm-db, key: valkey}
masterKey:
  existingSecret: {name: ridm-master-key, key: key}
migrations:
  database:
    existingSecret: {name: ridm-db, key: owner}
ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: 32m   # bulk user import
  hosts:
    - host: id.example.com
      paths: [{path: /, pathType: Prefix}]
  tls:
    - secretName: id-example-com-tls
      hosts: [id.example.com]
```

```bash
helm install ridm oci://ghcr.io/zerosandonesllc/charts/ridm --version 0.1.0 \
  -n ridm -f ridm-values.yaml --wait
# or, from a checkout:
helm install ridm deploy/helm/ridm -n ridm -f ridm-values.yaml --wait
```

Every secret value can instead be given inline (`database.url`, `redis.url`,
`masterKey.value`, `migrations.database.url`, `smtp.password`, `metrics.token`,
`bootstrap.adminPassword`); the chart then keeps it in a Secret of its own. A reference
to your own Secret wins over an inline value. The chart refuses to render without
`publicUrl`, a database, a cache and a master key, and a `values.schema.json` rejects
misspelled or mistyped values.

Then create the first administrator, once:

```bash
kubectl -n ridm exec -i deploy/ridm -- /ridm-api bootstrap --email you@example.com --password-stdin < password.txt
```

or install with `bootstrap.enabled=true`, `bootstrap.adminEmail` and a password; the
first pod to start creates the administrator and the rest find it. Either way the
password must be changed at first sign-in, at `https://id.example.com/console/`.

## What the chart does

| Piece | Behaviour |
|-------|-----------|
| Migrations | A `pre-install`/`pre-upgrade` hook Job runs `ridm-api migrate` as the schema owner. Its credential lives in a hook Secret deleted with the Job on success, so the pods never hold it. A failed Job stays for its logs until the next attempt. `migrations.enabled=false` leaves migrations to you |
| Pods | Non-root (UID 65532), read-only root filesystem, no capabilities, `RuntimeDefault` seccomp, no service-account token (rIDM never calls the Kubernetes API; `keyCustody.mountServiceAccountToken` mounts it for Vault's Kubernetes auth method) |
| Master key | Mounted read-only at `/run/secrets/ridm/master-key` and read through `MASTER_KEY_FILE`, out of the process environment (`masterKey.asFile`, default on). Or held by an HSM or KMS instead (`keyCustody`, below). The migration Job never receives it |
| Probes | Startup and liveness on `/healthz`, readiness on `/readyz` (database and cache). The startup probe allows five minutes: start-up brings every tenant's built-in clients in line, which takes a while on a large database |
| Start-up | Replicas starting together take turns at bootstrap and the built-in clients under a Postgres advisory lock |
| Rollouts | Rolling updates with no pod unavailable; pods restart when the chart's configuration or secrets change (checksum annotations). `terminationGracePeriodSeconds` is 30, above the server's 20-second drain |
| Spreading | Soft topology spread across nodes and zones unless you set your own constraints |
| Availability | A PodDisruptionBudget (`maxUnavailable: 1`) whenever more than one replica runs |
| Scaling | `autoscaling.enabled` adds an HPA on CPU (and memory if set). Nodes are stateless; see [Scaling and performance](scaling.md) |
| Metrics | `metrics.serviceMonitor.enabled` scrapes `/metrics`, with the bearer token from `metrics.token` or its Secret |

## Configuration

The chart's [`values.yaml`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/deploy/helm/ridm/values.yaml)
documents every value. They map onto the server's
[environment variables](../reference/configuration.md): `publicUrl` → `PUBLIC_URL`,
`uiUrl` → `UI_URL`, `embeddedUi` → `EMBEDDED_UI`, `trustedProxies` → `TRUSTED_PROXIES`,
`cookieSecure`, `logFormat`, `logLevel` (`RUST_LOG`), `docsEnabled`, `migrateOnStart`,
the pool sizes, `masterKey.version`/`previous` for a
[master key rotation](../admin/key-rotation.md), `keyCustody.*` for
[an HSM or KMS holding the master key](key-custody.md#kubernetes-and-openshift),
`dataRegions.*` for [regional databases](data-residency.md#kubernetes),
`mtls.*` for [mutual TLS](../admin/mtls.md#kubernetes),
`smtp.*` for the deployment's mail defaults. Anything else goes in `env` (plain values), `extraEnv` (full `EnvVar` entries)
or `extraEnvFrom`:

```yaml
env:
  RETENTION_DAYS: 14
  OTEL_EXPORTER_OTLP_ENDPOINT: http://otel-collector.observability:4318
  OUTBOUND_ALLOW_NETWORKS: 10.20.0.0/16
```

Keep `trustedProxies` accurate: behind an ingress controller the TCP peer is always the
controller, so without it every client shares one address for rate limits and IP rules
(see [TLS and reverse proxies](tls-and-proxies.md#trusted_proxies-and-the-client-address)).

A tenant's [custom domain](../admin/custom-domains.md) needs its own Ingress rule (and
certificate) pointing at the same Service with the `Host` header preserved, which every
common ingress controller does.

## Upgrading

`helm upgrade` runs the migration Job first; the Deployment rolls only after it
succeeds, and a failed migration leaves the running pods untouched. Read the release
notes before upgrading across versions; see [Upgrading](upgrading.md).

## Testing the chart

`deploy/helm/smoke/run.sh` installs the chart into a throwaway
[kind](https://kind.sigs.k8s.io/) cluster with Postgres and Valkey beside it, checks
readiness, discovery, the key set and the embedded pages through a port-forward, checks
that no pod restarted and that the migration Job and its Secret are gone, upgrades (the
hook runs again and the pods roll), uninstalls, and deletes the cluster. CI's
`helm-smoke` job runs it on every pull request against the image built there:

```bash
docker build -f api/Dockerfile -t ridm:smoke .
RIDM_IMAGE=ridm:smoke deploy/helm/smoke/run.sh
```
