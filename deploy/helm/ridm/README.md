# rIDM Helm chart

Runs [rIDM](https://github.com/ZerosAndOnesLLC/rIDM), a multi-tenant OpenID Connect
provider, on Kubernetes 1.27+. The image serves the API and the embedded sign-in pages
and consoles; Postgres 16+ and Valkey 9+ (or Redis 8+) are yours to provide.

```bash
helm install ridm deploy/helm/ridm -n ridm --create-namespace \
  --set publicUrl=https://id.example.com \
  --set database.existingSecret.name=ridm-db --set database.existingSecret.key=app \
  --set redis.existingSecret.name=ridm-db --set redis.existingSecret.key=valkey \
  --set masterKey.existingSecret.name=ridm-master-key --set masterKey.existingSecret.key=key \
  --set migrations.database.existingSecret.name=ridm-db \
  --set migrations.database.existingSecret.key=owner
```

Required: `publicUrl`; a database, a cache and a master key (each inline or from a
Secret); and a schema-owner database URL for the migration Job unless
`migrations.enabled=false`. Every value is documented in [`values.yaml`](values.yaml)
and validated by [`values.schema.json`](values.schema.json).

| Resource | When |
|----------|------|
| Deployment, Service, ConfigMap, ServiceAccount | always |
| Secret | when any secret value is given inline |
| Job (+ hook Secret) running `ridm-api migrate` | `pre-install`/`pre-upgrade`, `migrations.enabled` |
| Ingress | `ingress.enabled` |
| HorizontalPodAutoscaler | `autoscaling.enabled` |
| PodDisruptionBudget | `podDisruptionBudget.enabled` and more than one replica |
| ServiceMonitor | `metrics.serviceMonitor.enabled` (Prometheus Operator) |

The full guide is the documentation's
[Kubernetes (Helm)](../../../docs/src/deploy/kubernetes.md) page. `ci/` holds the value
sets the chart is linted and schema-checked with; `../smoke/run.sh` installs it into a
throwaway kind cluster.
