# Webhooks and the audit log

Every state-changing action in rIDM raises a domain event with a stable dotted name
such as `user.created`. Two consumers matter to an administrator: **webhooks**, which
POST selected events to your endpoints, signed, with retries; and the **audit log**,
which appends every event to a per-tenant hash chain that can be listed, exported,
verified and shipped to an external system. For the event model itself see
[Events, audit and webhooks](../concepts/events.md).

## Event catalogue

These are the names webhooks subscribe to and the audit log records. The names are part
of the public contract and do not change once shipped. The payload fields listed are
those of the event's `kind` document (next to `type`).

| Event | Payload fields |
|-------|----------------|
| `tenant.created`, `tenant.updated`, `tenant.deleted` | `tenant_id` |
| `tenant.moved` | `tenant_id`, `from_region`, `to_region` (`null`: the home database) |
| `tenant.profile_schema_updated` | `tenant_id` |
| `system.bootstrapped` | `admin_user_id` |
| `user.created`, `user.updated`, `user.deleted` | `user_id` |
| `user.password_changed` | `user_id`, `by_user` |
| `user.password_hash_upgraded` | `user_id`, `from_algo` |
| `user.registered` | `user_id`, `verified` |
| `user.email_verified` | `user_id` |
| `user.email_changed` | `user_id`, `old_email`, `new_email` |
| `user.password_reset_requested`, `user.password_reset_completed` | `user_id` |
| `user.locked` | `user_id`, `until_secs` |
| `user.terms_accepted` | `user_id` |
| `login.succeeded` | `user_id`, `method` |
| `login.failed` | `identifier`, `reason` |
| `login.passwordless_sent` | `user_id`, `method` |
| `login.new_device` | `user_id`, `session_id` |
| `login.brokered` | `user_id`, `idp_id`, `provider` |
| `logout.upstream` | `idp_id`, `provider` |
| `directory.synced` | `idp_id`, `provider`, `full`, `created`, `updated`, `disabled`, `enabled` |
| `mfa.changed` | `user_id`, `change` |
| `risk.step_up` | `user_id`, `score`, `signals`, `country` |
| `risk.blocked` | `user_id`, `score`, `signals`, `country` |
| `impersonation.requested` | `user_id`, `reason` |
| `impersonation.started` | `user_id`, `session_id`, `impersonator_id`, `impersonator_tenant_id`, `reason` |
| `impersonation.ended` | `user_id`, `session_id`, `impersonator_id` |
| `audit.chain_broken` | `seq`, `reason` (the [scheduled check](#the-scheduled-check) found this tenant's chain broken) |
| `device.trusted`, `device.revoked` | `user_id`, `device_id` |
| `session.created`, `session.revoked` | `session_id`, `user_id` |
| `authorization.granted` | `user_id`, `client_id`, `scopes` (also raised when the user approves a backchannel request) |
| `backchannel.requested` | `request_id`, `client_id`, `user_id`, `scopes`, `binding_message` (actor: the client) |
| `backchannel.denied` | `request_id`, `client_id`, `user_id` |
| `consent.granted` | `user_id`, `client_id`, `scopes` |
| `consent.revoked` | `user_id`, `client_id` |
| `token.refresh_reuse_detected` | `family_id`, `client_id`, `user_id` |
| `token.revoked` | `user_id`, `session_id`, `count` |
| `personal_token.created` | `user_id`, `token_id`, `scopes` |
| `personal_token.revoked` | `user_id`, `token_id` |
| `client.created` | `client_id`, `public_id` |
| `client.updated`, `client.deleted`, `client.secret_rotated` | `client_id` |
| `dcr_token.created`, `dcr_token.revoked` | `token_id` (a dynamic registration [initial access token](clients.md#initial-access-tokens)) |
| `group.created`, `group.updated`, `group.deleted` | `group_id` |
| `group.member_added`, `group.member_removed` | `group_id`, `user_id` |
| `organization.created`, `organization.updated`, `organization.deleted` | `org_id` |
| `organization.member_added`, `organization.member_removed` | `org_id`, `user_id` |
| `organization.domain_added`, `organization.domain_verified`, `organization.domain_removed` | `org_id`, `domain_id` |
| `role.created`, `role.updated`, `role.deleted` | `role_id` |
| `role.assigned`, `role.unassigned` | `role_id`, `user_id` or `group_id` |
| `role.composite_added`, `role.composite_removed` | `parent_role_id`, `child_role_id` |
| `invitation.created` | `invitation_id`, `email` |
| `invitation.accepted` | `invitation_id`, `user_id` |
| `invitation.revoked` | `invitation_id` |
| `scope.created`, `scope.updated`, `scope.deleted` | `scope_id` |
| `claim_mapper.created`, `claim_mapper.updated`, `claim_mapper.deleted` | `mapper_id` |
| `resource_server.created`, `resource_server.updated`, `resource_server.deleted` | `resource_server_id` |
| `permission.created`, `permission.deleted` | `resource_server_id`, `permission_id` |
| `permission.granted`, `permission.revoked` | `role_id`, `permission_id` |
| `signing_key.created` | `key_id`, `kid`, `alg` |
| `signing_key.status_changed` | `key_id`, `kid`, `status` |
| `master_key.rotated` | `new_version` |
| `master_key.generation_created` | `version`, `backend` |
| `saml_key.created` | `key_id` |
| `saml_key.status_changed` | `key_id`, `status` (`active` or `deleted`) |
| `webhook.created`, `webhook.updated`, `webhook.deleted`, `webhook.secret_rotated` | `webhook_id` |
| `webhook.test` | `webhook_id` |
| `webhook.delivery_dead` | `webhook_id`, `delivery_id`, `event_name` |
| `scim_token.created`, `scim_token.revoked` | `token_id` |
| `ip_rule.created`, `ip_rule.updated`, `ip_rule.deleted` | `rule_id` |
| `mtls_trust_anchor.created` | `anchor_id`, `fingerprint` |
| `mtls_trust_anchor.deleted` | `anchor_id` |
| `identity_provider.created`, `identity_provider.updated`, `identity_provider.deleted` | `idp_id` |
| `identity.linked` | `user_id`, `idp_id`, `external_subject` |
| `identity.unlinked` | `user_id`, `idp_id` |

Three of them never reach a webhook: `master_key.rotated` and
`master_key.generation_created` are global events (they belong to no tenant and are
recorded in the global audit chain), and `webhook.delivery_dead` is
kept out of deliveries so that a failing endpoint cannot breed a new delivery for every
dead one. All three are in the audit log.

## Webhooks

### Creating a webhook

In the console: **Webhooks** (`/console/webhooks/`). Through the admin API, under
`ridm:webhooks:read` and `ridm:webhooks:write` (owners and administrators):

```bash
curl -X POST https://id.example.com/admin/tenants/acme/webhooks \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
        "name": "HR sync",
        "url": "https://hooks.acme.example/ridm",
        "events": ["user.*", "group.member_added", "group.member_removed"],
        "headers": {"X-Api-Key": "…"},
        "max_attempts": 8
      }'
```

The answer is the webhook plus `secret` (`whsec_…`), shown this once. Store it with the
receiver.

| Field | Default | Rules |
|-------|---------|-------|
| `name` | required | 1–255 characters |
| `url` | required | see [Target restrictions](#target-restrictions) |
| `events` | required | exact names (`user.created`), prefixes ending in `*` (`user.*`), or `*` for everything; lower case, at most 64 characters each |
| `enabled` | `true` | a disabled webhook receives nothing, and its pending deliveries die |
| `headers` | `{}` | static string headers sent with every delivery; `Host` and anything starting `X-RIDM-` are reserved |
| `max_attempts` | `8` | 1–20 |

| Route | Does |
|-------|------|
| `GET /admin/tenants/{slug}/webhooks` | list |
| `GET`, `PATCH`, `DELETE …/webhooks/{webhook}` | read, change any field above, delete (its deliveries go with it) |
| `POST …/webhooks/{webhook}/secret` | new secret, returned once; later deliveries use it |
| `POST …/webhooks/{webhook}/test` | send a `webhook.test` event now, whatever the event filter; returns the delivery |
| `GET …/webhooks/{webhook}/deliveries?status=&limit=` | delivery log, newest first (`limit` 100 by default, at most 500) |
| `GET …/webhooks/{webhook}/deliveries/{delivery}` | one delivery with its payload, last status and the first 512 bytes of the last response |
| `POST …/deliveries/{delivery}/redeliver` | send one delivered, failed or dead delivery again now |
| `POST …/deliveries/redeliver-dead` | requeue every dead delivery of the webhook; answers `{"requeued": n}` |

Webhooks are part of the [tenant configuration document](../reference/tenant-document.md);
a webhook created by an import gets a fresh secret, reported once.

### What a delivery looks like

```http
POST /ridm HTTP/1.1
Host: hooks.acme.example
Content-Type: application/json
User-Agent: rIDM-Webhooks/1
X-RIDM-Event: user.created
X-RIDM-Timestamp: 1789722764
X-RIDM-Delivery: 0192f5d0-6a1e-7c3b-9d2a-4b8e1f0c7a55
X-RIDM-Webhook: 0192f5c4-1b2c-7d3e-8f40-5a6b7c8d9e0f
X-RIDM-Signature: t=1789722764,v1=5f2b9c…
X-Api-Key: …

{
  "delivery_id": "0192f5d0-6a1e-7c3b-9d2a-4b8e1f0c7a55",
  "attempt": 1,
  "event": {
    "id": "0192f5d0-69f0-7a11-b3c4-2d5e6f708192",
    "tenant_id": "0192f0a1-…",
    "occurred_at": "2026-09-18T09:12:44.512Z",
    "actor": {"type": "admin", "id": "0192f0a2-…"},
    "kind": {"type": "user_created", "user_id": "0192f5d0-69e8-…"}
  }
}
```

| Header | Content |
|--------|---------|
| `X-RIDM-Event` | the dotted event name, which the body does not repeat. The body's `kind.type` is the event's internal variant name (`user_created` for `user.created`, but `password_changed` for `user.password_changed`), so route on this header |
| `X-RIDM-Timestamp` | Unix seconds when this attempt was signed |
| `X-RIDM-Delivery` | the delivery id; the same on every retry and redelivery of this delivery |
| `X-RIDM-Webhook` | the webhook id |
| `X-RIDM-Signature` | `t=<timestamp>,v1=<hex HMAC-SHA256>` |

`event.actor.type` is `user`, `client`, `admin` or `system` (the last without an `id`).
`event.impersonator` names the administrator when the event happened in a session they
opened as the user ([impersonation](impersonation.md)).
`event.ip` and `event.user_agent` appear when the event was raised by a request that
recorded them, such as sign-in attempts. `attempt` counts from 1 and restarts at 1 after
a manual redelivery. Payloads carry ids, not full records: fetch the current state from
the admin API when you need it.

### Verifying a delivery

The signature is an HMAC-SHA256, keyed with the whole secret string (including the
`whsec_` prefix) as UTF-8 bytes, over the timestamp, a full stop, and the raw request
body exactly as received: `"<t>.<body>"`. A receiver should:

1. recompute the HMAC over the raw body before parsing it, and compare in constant time;
2. reject a timestamp more than a few minutes from its own clock, so a captured request
   cannot be replayed later (every retry is signed afresh, so an honest delivery is
   always recent);
3. remember the `X-RIDM-Delivery` ids it has processed and acknowledge a repeat
   without acting on it again. Delivery is at least once: a timeout after your endpoint
   did the work, or an administrator's redelivery, sends the same delivery again.

```python
import hashlib, hmac, time

TOLERANCE = 300  # seconds

def verify(secret: str, headers, body: bytes, seen: set) -> bool:
    parts = dict(p.split("=", 1) for p in headers["X-RIDM-Signature"].split(","))
    t, sig = parts.get("t", ""), parts.get("v1", "")
    if not t.isdigit() or abs(time.time() - int(t)) > TOLERANCE:
        return False                                   # stale or malformed
    mac = hmac.new(secret.encode(), t.encode() + b"." + body, hashlib.sha256)
    if not hmac.compare_digest(mac.hexdigest(), sig):
        return False                                   # not from rIDM
    delivery = headers["X-RIDM-Delivery"]
    if delivery in seen:
        return True                                    # duplicate: acknowledge, do nothing
    seen.add(delivery)                                 # use a durable store in production
    return True
```

The same in Rust with the `hmac`, `sha2`, `hex` and `subtle` crates:

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

fn signature_ok(secret: &str, header: &str, body: &[u8], now: i64) -> bool {
    let (mut t, mut v1) = (None, None);
    for part in header.split(',') {
        match part.split_once('=') {
            Some(("t", v)) => t = v.parse::<i64>().ok(),
            Some(("v1", v)) => v1 = hex::decode(v).ok(),
            _ => {}
        }
    }
    let (Some(t), Some(v1)) = (t, v1) else { return false };
    if (now - t).abs() > 300 {
        return false;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.finalize().into_bytes().as_slice().ct_eq(&v1).into()
}
```

Rotating the secret (`POST …/secret`) switches signing at once; there is no period in
which both secrets sign. Have the receiver accept either secret while you roll the new
one out, then drop the old one.

### Retries and dead deliveries

A matching event is queued as a delivery for every enabled webhook that wants it and
sent straight away; up to eight deliveries of a tenant are attempted at a time. Each
attempt has a 10-second timeout and does not follow redirects.

| Outcome | Result |
|---------|--------|
| `2xx` | `delivered` |
| connection error, timeout, `5xx`, `408`, `425`, `429` | `failed`, retried after a backoff |
| any other status (including `3xx` and other `4xx`) | `dead` at once |
| attempts reach `max_attempts` | `dead` |

The backoff after the first failure is 30 seconds, then 2 minutes, 10 minutes,
30 minutes, 2 hours, and 6 hours for every attempt after that. With the default of
eight attempts a delivery is given up about 15 hours after the first try. Retries are
sent by the `webhook_delivery` job, which runs every 30 seconds on one node at a time;
a delivery stuck in `sending` for ten minutes (a node died mid-attempt) is picked up
again.

A delivery that dies raises `webhook.delivery_dead` (audited, not delivered) and is
logged as a warning. Fix the endpoint, then redeliver from the console's delivery log
or with `redeliver-dead`. Redelivery resets the attempt count and keeps the delivery
id.

Deliveries are not ordered: concurrent attempts and retries mean `user.updated` can
arrive before the `user.created` it follows. Use `event.occurred_at` or fetch the
current state when order matters.

Delivered and dead deliveries are deleted by the hourly cleanup job once they are older
than `RETENTION_DAYS` (default 30). The counter `ridm_webhook_deliveries_total{outcome}`
(`delivered`, `retry`, `dead`) tracks the outcomes.

### Target restrictions

- The URL must be `https`. Plain `http` is allowed only for `localhost`, `127.0.0.1`
  and `[::1]`, for development.
- A literal private address is refused when the webhook is saved (`400`): RFC 1918
  ranges, link-local (including `169.254.169.254`), `100.64.0.0/10`, `0.0.0.0/8`,
  IPv6 unique-local (`fc00::/7`) and link-local (`fe80::/10`), and IPv6 forms that
  embed one of those.
- A hostname is checked at delivery time, on every attempt: it is resolved to public
  addresses only, so a name that resolves (or later rebinds) to an internal address
  fails the attempt instead of reaching it.
- Redirects are never followed and `HTTP(S)_PROXY` is ignored, so an endpoint cannot
  bounce a delivery elsewhere.

These are the rules of the [outbound request policy](security-controls.md#outbound-request-policy),
which applies to every URL tenant administrators choose.

## The audit log

### What is recorded

Every event in the catalogue is appended to its tenant's chain as a row with:

| Field | Content |
|-------|---------|
| `id` | the event id |
| `tenant_id` | the tenant, or `null` in the global chain |
| `seq` | position in the chain, from 1 |
| `occurred_at`, `recorded_at` | when it happened, when it was written |
| `name` | the dotted event name |
| `actor_type`, `actor_id` | `user`, `client`, `admin` or `system`; a SCIM token acts as `client` |
| `subject_id` | the main entity: the first of `user_id`, `client_id`, `role_id`, `group_id`, `invitation_id`, `key_id`, `mapper_id`, `resource_server_id`, `scope_id`, `session_id` in the payload |
| `impersonator_id` | the administrator behind the event, when it happened in a session they opened as the user ([impersonation](impersonation.md)) |
| `ip`, `user_agent` | when the event came from a request that recorded them |
| `payload` | the event's `kind` document |
| `prev_hash`, `hash` | the chain links, lowercase hex |

Global events, today only `master_key.rotated` and `master_key.generation_created`, form a chain of their own.

### Querying

In the console: **Audit log** (`/console/audit/`), with filters, paging, expandable
rows, JSON and CSV export and a verify button; global administrators can switch to the
global chain. Every built-in administrator role holds `ridm:audit:read`.

```bash
# Newest first; name ending in "." or "*" is a prefix
curl -G https://id.example.com/admin/tenants/acme/audit \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode 'name=login.' \
  --data-urlencode 'from=2026-09-01T00:00:00Z' \
  --data-urlencode 'limit=100'
```

| Parameter | Meaning |
|-----------|---------|
| `from`, `to` | RFC 3339 bounds on `occurred_at` |
| `name` | exact event name, or a prefix when it ends with `.` or `*` |
| `actor_id`, `subject_id`, `impersonator_id` | exact match |
| `user_id` | rows where the user is the actor, the subject or the impersonator |
| `limit` | page size, 50 by default, at most 500 |
| `cursor` | the previous page's `next_cursor` |

The answer is `{"items": [...], "next_cursor": "..."}`; `next_cursor` is absent on the
last page. Tenant listings are served from `DATABASE_READ_URL` when one is configured.

`GET /admin/tenants/{slug}/audit/export?format=json|csv` (same filters, no paging)
streams the chain oldest first as a download, with the hashes included.
`GET /admin/audit`, `/admin/audit/export` and `/admin/audit/verify` do the same for the
global chain and require a global administrator.

### The hash chain

Each row's hash is `SHA-256(prev_hash || canonical row)`, where the canonical row is the
UTF-8 string

```text
id|chain|seq|occurred_at|name|actor_type|actor_id|subject_id|ip|user_agent|payload
```

with `chain` the tenant id (the nil UUID for the global chain), `occurred_at` in RFC 3339
UTC with exactly six fractional digits and a `Z`, absent values as empty strings, and
`payload` as compact JSON with its keys sorted. A row with an `impersonator_id` has
`|impersonator:<uuid>` appended; rows without one hash as they always did. The first row of a chain has no
`prev_hash`. Writers of one chain are serialised with a Postgres advisory lock, so `seq`
has no gaps.

`GET /admin/tenants/{slug}/audit/verify` walks the retained chain from its oldest row
and recomputes every hash:

```json
{
  "checked": 48211, "valid": true, "first_seq": 1, "last_seq": 48211,
  "last_hash": "9f2c…",
  "scheduled": { "verified_seq": 48190, "verified_at": "2026-09-21T03:10:44Z" }
}
```

A row that was altered, removed from the middle or reordered makes it answer
`"valid": false` with `broken_at_seq` and a `reason` (`gap in chain after seq …`,
`prev_hash does not link to the previous row`, `row hash does not match its contents`).
`scheduled` is what the daily check (below) last established.

The chain proves that retained history was not edited in place. On its own it can't
prove that the newest rows were not cut off, or that the whole log was not rewritten
by someone holding the database. Two things close that gap: keep `last_hash`
somewhere else, and keep a copy outside rIDM
([Shipping to an external system](#shipping-to-an-external-system)).

### Checking an export yourself

`ridm audit verify --file` checks a JSON export with nothing but the file. It never
contacts the server, so a server that rewrote its own log can't vouch for itself. The
algorithm is the one above, and it lives in the `ridm-core` crate, so you can also
check exports with your own tooling.

```bash
ridm audit export -o acme-2026-09.json         # the whole chain, oldest first
ridm audit verify -f acme-2026-09.json --head 9f2c…
# Intact: 48211 rows (seq 1–48211), ending on 9f2c….
```

| Flag | Proves |
|------|--------|
| `--head <hex>` | The chain ends on a hash you kept earlier (the `last_hash` of a previous check), so nothing was cut off or rewritten after that point. |
| `--after <hex>` | The file's first row follows that hash, so consecutive exports (`--from`/`--to` windows) form one unbroken chain. |

It fails, exiting non-zero, at the first row that does not hash or link, and names its
`seq`. An export filtered by event name or user has gaps by design, and verification
says so. Export the whole chain, or a time window, to check it. `ridm audit verify`
without `--file` asks the server to walk its copy, and `--global` does the same for the
global chain. The file is read as a stream, so an export of millions of rows is fine.

### The scheduled check

The daily `audit_verify` job checks every chain that grew since it was last found
intact. It starts from that checkpoint rather than from the oldest row, which keeps it
cheap on a large log. It rehashes the checkpoint row itself, so a rewrite that reaches
the checkpoint is caught; the verify endpoint and `ridm audit verify` always walk
everything. When a chain does not verify, the job:

- stores where and why on the chain, which the verify endpoint shows as
  `scheduled.broken_at_seq`, and checks that chain from the start on every run until
  it verifies again;
- logs an error and counts it in `ridm_audit_chain_breaks_total`, and sets
  `ridm_audit_chains_broken` to the number of broken chains (alert on anything above
  0);
- records `audit.chain_broken` (`seq`, `reason`) in that tenant's chain, once per
  break, so the tenant's webhooks hear of it.

### Retention

`settings.audit.retention_days` (default `365`; `0` keeps everything) sets how long a
tenant's rows are kept. The global chain follows the `master` tenant's setting. The
daily `audit_retention` job removes each chain's expired *prefix*: every row up to the
newest one older than the cutoff, in batches of 5,000. Removing a prefix rather than
scattered rows keeps what remains verifiable; the oldest retained row's `prev_hash`
then points at a row that no longer exists, which verification accepts. The same job
creates the monthly partitions of the audit table two months ahead.

The setting is in the console under Settings → Keys, discovery & audit, or:

```bash
curl -X PATCH https://id.example.com/admin/tenants/acme \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"settings": {"audit": {"retention_days": 730}}}'
```

### Shipping to an external system

Set `AUDIT_SINK_URL` to copy every recorded row, from every tenant, to a SIEM or log
store:

| `AUDIT_SINK_URL` | Transport |
|------------------|-----------|
| `https://…` or `http://…` | POST of a JSON array of up to 100 rows of one chain, in chain order. `Authorization: Bearer $AUDIT_SINK_TOKEN` when that is set. `X-RIDM-Signature: t=<unix>,v1=<hex>` (HMAC-SHA256 of `"<t>.<body>"` under `AUDIT_SINK_SECRET`, the [webhook scheme](#verifying-a-delivery)) when that is set. |
| `syslog://host:port` (or `syslog+udp://`) | One RFC 5424 message per row over UDP, facility local0, severity informational, with the row as JSON in the message. Port 514 by default. |
| `syslog+tcp://host:port` | The same over TCP, newline-delimited. |
| `syslog+tls://host:port` | The same over TLS (RFC 5425): each message is prefixed with its length. Port 6514 by default. The collector's certificate is checked against the system's roots, or against `AUDIT_SINK_CA_FILE` (PEM) for a private CA. |

The sink ships **from the database**, not from memory. A worker on one node at a time
(a leader lock) reads each chain's rows after the last one it delivered, sends them,
and records how far it got only once the receiver accepted them. When a delivery fails,
nothing moves: the worker backs off, doubling up to a minute, and tries the same rows
again. A receiver that is down for an hour, or a rolling restart of rIDM, delays rows
but never loses them.

- **At least once.** A row can arrive twice, for example when a node dies between a
  delivery and recording it. Deduplicate on the row's `id`, not on `seq`: after a
  database restore, a chain reuses the `seq` numbers written after the backup.
- **A new destination starts now.** The first time rIDM sees an `AUDIT_SINK_URL`
  (compared without credentials or query), it starts every chain at its current head
  rather than replaying history. Backfill older rows with `ridm audit export`.
- **Rows the retention job removed before they were shipped are skipped.**

Watch `ridm_audit_sink_rows_total`, `ridm_audit_sink_failures_total` and
`ridm_audit_sink_lag_rows` (rows recorded but not yet shipped, over every chain). A lag
that keeps growing means the receiver is refusing rows or can't keep up.

## Caveats

- Events travel on an in-process bus, and the audit writer and the webhook dispatcher
  record them after the action has committed. Each has its own queue, so a burst
  delays events rather than skipping them (watch `ridm_audit_queue_depth` and
  `ridm_webhook_dispatch_queue_depth`), but a node that stops before its queues drain
  loses what was still waiting.
- An event is dispatched only on the node where it happened; webhooks and audit rows
  are not duplicated across nodes.
- Webhook payloads contain identifiers, email addresses (in `invitation.created`,
  `user.email_changed`) and login identifiers (in `login.failed`). Treat the endpoint
  as holding personal data.
