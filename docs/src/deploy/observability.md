# Observability

rIDM gives an operator four signals: structured logs, Prometheus metrics, OpenTelemetry
traces, and the audit log with an optional export sink. This page covers each, and the
two health endpoints.

## Health probes

| Endpoint | Checks | Response |
|----------|--------|----------|
| `GET /healthz` | Nothing beyond the process answering HTTP | Always `200 {"status":"ok","version":"0.1.0-dev"}` while the server runs |
| `GET /readyz` | `SELECT 1` on the primary Postgres pool and `PING` to Valkey, in parallel | `200 {"status":"ok","checks":{"database":"ok","cache":"ok"}}`, or `503` with `"status":"degraded"` and `"fail"` against the failed check |

Use `/healthz` for liveness and `/readyz` for readiness and load-balancer health checks.
A failed readiness check is also logged as a warning with the error. Neither probe
checks the read replica, the job scheduler or outbound services. Neither endpoint is
rate limited or authenticated, and neither reveals more than the version.

Inside the container, `/ridm-api --healthcheck` probes `/healthz` at the bind address,
over https when `TLS_CERT` is set; the image's `HEALTHCHECK` runs it. See
[Container image](container.md#health-checks).

## Logs

Logs go to standard output through `tracing`.

| Variable | Default | Values |
|----------|---------|--------|
| `LOG_FORMAT` | `json` | `json` for production; `pretty` (or `text`) for a terminal |
| `RUST_LOG` | `info` | A tracing filter, e.g. `info,ridm_api=debug,sqlx=warn` |

JSON lines carry the event's fields flattened at the top level, with `timestamp`,
`level`, `target` and the current span. Secret-bearing fields are excluded from
serialisation, and the server's own log lines do not print tokens.

Worth alerting on:

| Log | Level | Meaning |
|-----|-------|---------|
| `job failed` (field `job`) | error | A background job pass failed |
| `readiness: database check failed`, `readiness: cache check failed` | warn | `/readyz` is returning 503 |
| `cache invalidation listener disconnected` | warn | A node lost its pub/sub subscription; it will reconnect |
| `audit: could not record event` | error | An audit row was not written |
| `audit: event bus lagged, events not recorded` | warn | The in-process event bus overflowed and audit rows were skipped |
| `audit: creating partitions failed` | error | The `audit_retention` job could not create next months' audit partitions; rows fall into the default partition (see [Postgres and Valkey](postgres-valkey.md#audit-partitions-under-the-two-role-setup)) |
| `audit sink queue full; row dropped` | warn | The export sink fell behind |
| `audit sink delivery failed; rows dropped` | warn | A sink batch failed after its attempts |
| `webhook delivery dead-lettered` | warn | A webhook exhausted its retries |
| slow statement warnings from `sqlx` | warn | A query took more than 250 ms |

## Metrics

`GET /metrics` serves Prometheus text format (`text/plain; version=0.0.4`). It is open
unless `METRICS_TOKEN` is set, in which case it demands `Authorization: Bearer <token>`
(compared in constant time) and answers `401` otherwise. Either set a token or keep the
path off the public proxy; the [TLS and reverse proxies](tls-and-proxies.md) snippets do
the latter.

```yaml
scrape_configs:
  - job_name: ridm
    authorization:
      credentials_file: /etc/prometheus/ridm_metrics_token
    static_configs:
      - targets: ["10.0.1.11:8080", "10.0.1.12:8080"]
```

Scrape every node: counters are per process.

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `ridm_http_requests_total` | counter | `method`, `route`, `status` | Every request. `route` is the matched pattern (`/t/{slug}/token`), or `unmatched`, never the raw path |
| `ridm_http_request_duration_seconds` | histogram | `method`, `route` | Request latency |
| `ridm_token_requests_total` | counter | `grant`, `outcome` | `/token` requests; `outcome` is `issued` or the OAuth error code |
| `ridm_logins_total` | counter | `method`, `outcome` | First-factor sign-ins. Password failures carry the reason (`invalid_credentials`, `locked`, `disabled`, ...); successes carry the first authentication method |
| `ridm_sessions_created_total` | counter | | Browser sessions opened |
| `ridm_rate_limit_rejections_total` | counter | | Requests refused by a rate limit |
| `ridm_ip_rule_rejections_total` | counter | `scope` (`tenant`, `client`) | Requests refused by an IP rule |
| `ridm_webhook_deliveries_total` | counter | `outcome` (`delivered`, `retry`, `dead`) | Webhook delivery attempts |
| `ridm_webhook_deliveries_pending` | gauge | | Deliveries waiting, refreshed by the delivery job |
| `ridm_messages_queued` | gauge | | Email and SMS waiting, refreshed by the delivery job |
| `ridm_job_runs_total` | counter | `job`, `outcome` (`ok`, `error`) | Background job passes |
| `ridm_job_duration_seconds` | histogram | `job` | Background job pass duration |
| `ridm_cleanup_rows_total` | counter | `table` | Rows deleted by the cleanup job |
| `ridm_audit_events_total` | counter | | Audit rows written |
| `ridm_audit_sink_rows_total` | counter | | Audit rows shipped to the sink |
| `ridm_audit_sink_failures_total` | counter | | Sink batches that failed after their retries |
| `ridm_audit_sink_dropped_total` | counter | | Audit rows dropped because the sink queue was full |

Every `_seconds` histogram uses buckets from 1 ms to 10 s (0.001, 0.0025, 0.005, 0.01,
0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10). A metric appears only after its first
observation, so a fresh node does not list, say, `ridm_ip_rule_rejections_total` until
something is refused.

Notes for alerting:

- A job that runs on a single node per pass still counts on whichever node took the
  lock, so sum `ridm_job_runs_total` across nodes. A node that skipped a pass because
  another held the lock records an `ok` pass too; alert on `outcome="error"` rather than
  on the absence of runs.
- `ridm_messages_queued` and `ridm_webhook_deliveries_pending` are set only by the node
  that last ran the delivery job; take the maximum across nodes.

## Traces

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to an OpenTelemetry collector's base URL (for example
`http://otel-collector:4318`) and spans are exported over OTLP/HTTP with protobuf
encoding to `{endpoint}/v1/traces`, batched, under the service name `OTEL_SERVICE_NAME`
(default `ridm`) with `service.version` set. Unset, no exporter runs. If the exporter
cannot be built, the server prints `otlp: exporter not started` and carries on without
it. Pending spans are flushed on shutdown.

The exporter sees spans that pass the `RUST_LOG` filter. Each request opens one span at
`info` level, so the default `RUST_LOG=info` exports it:

| Attribute | Value |
|-----------|-------|
| span name | `METHOD /route/{template}`, e.g. `POST /t/{slug}/token`; `unmatched` for a path no route matched |
| `otel.kind` | `server` |
| `http.request.method` | The method |
| `http.route` | The matched route template |
| `http.response.status_code` | The response status, recorded when the response is ready |

The span never records the concrete path or the query string, because those can carry
invitation tokens and authorization codes. It is the only span rIDM creates today;
database and Valkey calls are not traced as child spans.

The log output is unchanged at `info`: the log layer shows the request span (as a
`span` object on JSON lines) only when `RUST_LOG` enables `debug` somewhere, and
tower-http's "started processing" and "finished processing" lines are `debug` events.

## Audit log and export

Every domain event (sign-ins, token issuance, administrative changes, ...) is written to
the `audit_events` table as part of a per-tenant SHA-256 hash chain, so a changed or
deleted row within the retained window breaks verification. Retention is a tenant
setting; the `audit_retention` job purges older rows daily. How to read, filter and
verify the log is in [Webhooks and the audit log](../admin/webhooks-audit.md), and the
event model in [Events, audit and webhooks](../concepts/events.md).

Rows are recorded asynchronously from an in-process event bus. If that bus overflows,
events are skipped with the warning above. Compare `ridm_audit_events_total` with your
expectations after incidents.

To keep a copy off the host, set `AUDIT_SINK_URL`. Each node ships the rows it records,
exactly as stored (with chain sequence and hash):

| `AUDIT_SINK_URL` | Delivery |
|------------------|----------|
| `https://...` (or `http://...`) | `POST` of a JSON array of up to 100 rows, sent when 100 have accumulated or a second after the first; `Authorization: Bearer <AUDIT_SINK_TOKEN>` when that is set; 10-second timeout; three attempts with backoff, then the batch is dropped and counted in `ridm_audit_sink_failures_total` |
| `syslog://host:514` or `syslog+udp://host:514` | One RFC 5424 message per row over UDP: `<134>1 <time> <host> ridm - <event name> - <row as JSON>` |
| `syslog+tcp://host:514` | The same over TCP |

The sink never slows the audit writer. Rows wait in a bounded queue of 10,000 per node;
when the destination falls behind, new rows are dropped and counted in
`ridm_audit_sink_dropped_total`. The database copy is unaffected, so a gap in the sink
can be filled from `audit_events`. Alert on `ridm_audit_sink_dropped_total` and
`ridm_audit_sink_failures_total` increasing.

## Background job status

Besides the metrics, each job's last pass (time, outcome, duration, error) is kept in
the Valkey hash `ridm:jobs:last_run`, one field per job. No API endpoint or console page
shows it yet; read it directly:

```bash
valkey-cli HGETALL ridm:jobs:last_run
```

A node that skipped a pass because another node held the lock also records its pass as
successful, so an `ok` entry means the scheduler is alive, not that the job did work.

The jobs themselves are described in [Scaling and performance](scaling.md#background-jobs-on-many-nodes).
