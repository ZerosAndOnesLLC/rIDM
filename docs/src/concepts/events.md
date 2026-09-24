# Events, audit and webhooks

Every change rIDM makes, and every sign-in it handles, is described by a
**domain event**: a typed record of what happened, in which tenant, caused by
whom. Events are the single source for the audit log and for webhooks, so
whatever an administrator can read in the audit log, an external system can
subscribe to, under the same name.

## Domain events

A state-changing action emits exactly one event, from one place in the code,
after the change has been committed. An event carries:

| Field | Meaning |
|-------|---------|
| `id` | unique id (a time-ordered UUID) |
| `tenant_id` | the tenant, or `null` for deployment-wide events such as master-key rotation |
| `occurred_at` | when it happened |
| `actor` | who caused it: `{"type": "user" \| "admin" \| "client", "id": ...}` or `{"type": "system"}` |
| `impersonator` | the administrator behind it, when it happened in a session they opened as the user ([impersonation](../admin/impersonation.md)) |
| `ip`, `user_agent` | the request's client address and browser, when there was a request |
| `kind` | what happened, with its details, tagged by `type` |

Every event also has a stable dotted **name**, such as `user.created`,
`role.assigned` or `login.failed`. Names are part of the public contract: once
shipped, they do not change. The main families:

| Family | Examples |
|--------|----------|
| `tenant.*` | `tenant.created`, `tenant.updated`, `tenant.moved`, `tenant.profile_schema_updated` |
| `user.*` | `user.created`, `user.registered`, `user.password_changed`, `user.email_verified`, `user.locked` |
| `login.*` | `login.succeeded`, `login.failed`, `login.new_device`, `login.brokered`, `login.passwordless_sent` |
| `logout.*` | `logout.upstream` ([SAML identity providers](../admin/saml-upstream.md#single-logout)) |
| `directory.*` | `directory.synced` ([LDAP and Active Directory](../admin/ldap.md#sync)) |
| `session.*`, `device.*` | `session.created`, `session.revoked`, `device.trusted`, `device.revoked` |
| `token.*` | `token.revoked`, `token.refresh_reuse_detected` |
| `mfa.*` | `mfa.changed` |
| `risk.*` | `risk.step_up`, `risk.blocked` ([adaptive authentication](../admin/adaptive-auth.md)) |
| `audit.*` | `audit.chain_broken` ([the scheduled check](../admin/webhooks-audit.md#the-scheduled-check)) |
| `impersonation.*` | `impersonation.requested`, `impersonation.started`, `impersonation.ended` ([impersonation](../admin/impersonation.md)) |
| `client.*`, `consent.*`, `authorization.*` | `client.created`, `client.secret_rotated`, `consent.granted`, `authorization.granted` |
| `backchannel.*` | `backchannel.requested`, `backchannel.denied` ([backchannel sign-in](../admin/ciba-fapi.md)) |
| `group.*`, `role.*`, `permission.*` | `group.member_added`, `role.assigned`, `role.composite_added`, `permission.granted` |
| `resource_server.*`, `scope.*`, `claim_mapper.*` | configuration changes |
| `signing_key.*`, `master_key.*` | `signing_key.created`, `signing_key.status_changed`, `master_key.rotated` |
| `saml_key.*` | `saml_key.created`, `saml_key.status_changed` ([SAML identity provider](../admin/saml-idp.md)) |
| `identity_provider.*`, `identity.*` | `identity.linked`, `identity.unlinked` |
| `invitation.*`, `personal_token.*`, `scim_token.*`, `dcr_token.*`, `ip_rule.*`, `webhook.*` | lifecycle of each |

The full list, with each event's fields, is in
[Webhooks and the audit log](../admin/webhooks-audit.md).

## The event bus

Events are published on an in-process bus on the node that handled the
request. Publishing never blocks or fails the action: a sign-in does not wait
for the audit log, and a slow webhook endpoint cannot slow down the token
endpoint. Two subscribers run on every node:

- the **audit writer**, which appends every event to the audit log;
- the **webhook dispatcher**, which turns every event that a tenant's webhooks
  subscribe to into queued deliveries.

Both subscribers have their own queue: a burst or a slow database delays them
rather than dropping events. The audit writer takes what has queued up and
appends each chain's share in one transaction with one insert, several chains
at a time; the dispatcher queues each tenant's deliveries with one insert, and
sends them at once in the background. A chain that cannot be written for now
(a tenant being moved between regions, a region's database down) is set aside,
in order, and retried every five seconds.

Each queue is bounded (`EVENT_QUEUE_CAPACITY`, 100,000 events by default), so
a consumer that stops keeping up cannot take the node's memory with it. Once a
queue is 80% full, `/readyz` reports the node not ready (`events: saturated`),
so the load balancer sends it no new work while it catches up; only an event
published into a full queue is dropped, and that is logged and counted
(`ridm_event_queue_dropped_total`). The depths are the `ridm_event_queue_depth`
gauges (and `ridm_audit_queue_depth`, `ridm_webhook_dispatch_queue_depth`).

Events still live in memory until written. A node that is stopped gives its
queues, and the deliveries it started, up to 15 seconds to drain after its last
request; what is left after that is lost, and an event that fails to append is
logged. Treat the audit log as a faithful record rather than a transactional
ledger, and watch those gauges.

Two other things that the event names might suggest are not driven by the bus:

- **Security notices to users** (a sign-in from a new browser, a password or
  email change, a second factor added or a recovery code used) are sent by the
  services that make those changes, through the tenant's email or SMS
  settings, in the user's language. Each can be switched off under
  `settings.notifications`.
- **Cache invalidation** has its own channel. Every write evicts the cache
  entries it affects locally and in Valkey, and publishes the evicted keys on a
  Valkey pub/sub channel so that every other node evicts its in-process copy
  too. That is why a change made through one node is visible on all of them on
  the next request.

## The audit log

The audit writer stores every event as a row of `audit_events`: its name,
actor, subject, address, browser, the event's details, and the time it was
recorded. The table is partitioned by month and protected by tenant row level
security like everything else.

Rows form a **hash chain** per tenant: each row stores the hash of the one
before it, and its own hash is `SHA-256(prev_hash || row)`. Changing or deleting
a row inside the retained window breaks every hash after it, which
`GET /admin/tenants/{slug}/audit/verify` detects and pinpoints. Exports include
the hashes, so the chain can also be checked offline. Events without a tenant
form a separate global chain, readable by global administrators.

Retention is a tenant setting, `settings.audit.retention_days` (365 days by
default, `0` to keep everything). A daily job creates upcoming partitions and
removes each tenant's expired rows from the start of its chain, so what remains
is still one contiguous, verifiable chain.

The audit log can also be streamed out as it is written: set `AUDIT_SINK_URL`
to an HTTPS endpoint (JSON batches) or a syslog receiver, and every row is
shipped with its chain sequence and hash. See
[Observability](../deploy/observability.md).

## Webhooks

A webhook sends a tenant's events to an HTTPS endpoint of yours as they happen.
It names the events it wants: exact names (`user.created`), prefixes
(`user.*`), or `*` for everything. Deployment-wide events are never delivered
to tenant webhooks.

Each delivery is a `POST` with the JSON body `{delivery_id, attempt, event}`
and these headers:

| Header | Meaning |
|--------|---------|
| `X-RIDM-Event` | the event name |
| `X-RIDM-Delivery` | the delivery id, the same across retries |
| `X-RIDM-Webhook` | the webhook's id |
| `X-RIDM-Timestamp` | when this attempt was signed |
| `X-RIDM-Signature` | `t=<unix time>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>` |

A receiver should verify the signature with the webhook's secret (shown once,
when the webhook is created or its secret rotated), refuse stale timestamps,
and ignore delivery ids it has already processed, because a delivery can
arrive more than once.

Deliveries are queued in Postgres when the event occurs and sent at once. A
`2xx` answer counts as delivered. A `5xx`, `408`, `425`, `429` or network error
is retried with backoff (30 seconds, 2 minutes, 10 minutes, 30 minutes,
2 hours, 6 hours) up to the webhook's `max_attempts`; any other `4xx` fails the
delivery immediately, since retrying would get the same answer. A delivery that
runs out of attempts is marked dead, raises `webhook.delivery_dead` (audited,
but never itself delivered, so a broken endpoint cannot breed deliveries), and
stays in the delivery log with its last status and response snippet until an
administrator redelivers it.

Webhook targets must be `https` (plain `http` only to loopback, for
development) and must be reachable at a public address. The check is made when
each delivery connects, not only when the URL is saved: the host name is
resolved by rIDM and private, loopback, link-local, carrier-grade NAT,
unique-local and reserved addresses are dropped, so a name that resolves (or
later re-resolves) to an internal address is refused. Redirects are not
followed and proxy environment variables are ignored. For development, the host
`localhost` and loopback IP literals remain allowed. See
[Outbound requests](tenants.md#outbound-requests).
Signing secrets are encrypted under the [master key](keys.md#the-master-key).

Setting up and operating webhooks is covered in
[Webhooks and the audit log](../admin/webhooks-audit.md).
