# Email, SMS and templates

rIDM sends email and text messages for verification links, password resets, magic
links, one-time codes, invitations and security notices. Each tenant chooses where its
messages go, may override the wording of every message per language, and can watch the
outbound queue. This page covers the delivery settings, templates, the queue and its
log, and the security notices.

Everything here is per tenant and lives under `/admin/tenants/{slug}/messaging` in the
admin API, guarded by `ridm:messaging:read` and `ridm:messaging:write` (owners and
administrators hold both; viewers hold the read permission). In the admin console it is
**Messaging** (`/console/messaging/`).

## Where email goes

Email for a tenant is resolved in this order:

1. The tenant's own configuration: SMTP, or an HTTP endpoint that receives each message
   as JSON.
2. The deployment's SMTP defaults, from the `SMTP_*` environment variables.
3. Nothing: email is not sent, and every queued email fails at once (see
   [The outbound queue](#the-outbound-queue)).

`GET /admin/tenants/{slug}/messaging/email` reports which one applies in `source`:
`tenant`, `server_default` or `none`.

### Deployment defaults

| Variable | Default | Meaning |
|----------|---------|---------|
| `SMTP_HOST` | unset | SMTP server. Unset means there are no deployment defaults |
| `SMTP_PORT` | `587` | Port |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | unset | Credentials; both must be set for authentication to be used |
| `SMTP_FROM` | required when `SMTP_HOST` is set | Sender, e.g. `rIDM <no-reply@example.com>` |
| `SMTP_SECURITY` | `starttls` | `starttls`, `tls` (implicit TLS, usually port 465) or `none` |

### Tenant SMTP

```bash
curl -X PUT https://id.example.com/admin/tenants/acme/messaging/email \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
        "type": "smtp",
        "host": "smtp.example.com",
        "port": 587,
        "username": "acme-mailer",
        "password": "…",
        "from": "Acme <no-reply@acme.example>",
        "security": "starttls"
      }'
```

`security` defaults to `starttls`. `host`, `port` and `from` are required, and `from`
must parse as a mailbox. The password is stored encrypted under the master key and is
never returned: reads show `password_set: true` instead. A `PUT` that omits the
password, or sends it empty, keeps the stored one, so a form can be saved without
re-entering it.

A tenant's SMTP host is chosen by a tenant administrator, so it is held to the
[outbound request policy](security-controls.md#outbound-request-policy): a private IP
literal is refused when saved (`400`), and a host name is resolved just before each
connection to public addresses only. rIDM connects to the first allowed address and
TLS still verifies the certificate against the configured host name. The deployment's
own `SMTP_HOST` is the operator's choice and is not filtered.

### Tenant HTTP endpoint

For a mail service with an HTTP API, or a relay of your own, rIDM can POST every message
as JSON:

```json
{ "type": "http", "url": "https://mail-relay.example.com/send",
  "auth_header": "Bearer …", "from": "no-reply@acme.example" }
```

The URL must be `https`; plain `http` is accepted only for `localhost`, `127.0.0.1` and
`[::1]`. Requests follow the
[outbound request policy](security-controls.md#outbound-request-policy): public
addresses only, no redirects, no proxy from the environment. `auth_header`, when set, is sent verbatim as the `Authorization` header and,
like the SMTP password, is write-only (`auth_header_set` on read; omitted on `PUT`
keeps the stored value). Each message arrives as:

```json
{
  "from": "no-reply@acme.example",
  "to": ["alice@example.com"],
  "subject": "Sign in to Acme",
  "text": "Hi alice, …",
  "html": "<p>Hi alice, …</p>",
  "reply_to": null,
  "headers": []
}
```

A `2xx` answer means sent. A `4xx` is a permanent rejection and the message is
dead-lettered; a `5xx`, a timeout (15 seconds) or a connection failure is retried.

`DELETE /admin/tenants/{slug}/messaging/email` removes the tenant configuration, which
falls back to the deployment defaults.

## SMS

SMS always goes through an HTTP gateway of your choosing; there is no built-in carrier
integration, and no deployment-wide default.

```bash
curl -X PUT https://id.example.com/admin/tenants/acme/messaging/sms \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"url": "https://sms-gateway.example.com/send", "auth_header": "Bearer …", "from": "Acme"}'
```

The same URL rules and write-only `auth_header` apply. Each text is posted as
`{"to": "+15551234567", "body": "…", "from": "Acme"}` (`from` is `null` when unset),
with the same status handling as the email endpoint. Phone numbers are E.164.
`GET` answers `{"configured": false, …}` when nothing is set.

## Test sends

`POST /admin/tenants/{slug}/messaging/email/test` and `…/sms/test` with
`{"to": "alice@example.com"}` (or a phone number) send a fixed test message straight
through the configured sender, bypassing the queue, so a misconfiguration comes back as
an error in the response (`503` with the sender's reason) instead of a dead message in
the log. The answer names the backend that took it: `{"sender": "smtp", "to": "…"}`.
The console has a test button beside each form.

## Templates

rIDM sends messages for ten events:

| Event | Sent when | Email | SMS |
|-------|-----------|:-----:|:---:|
| `verify_email` | self-registration needs the address confirmed | yes | |
| `password_reset` | a user asks for a reset link | yes | |
| `magic_link` | passwordless sign-in by link | yes | yes |
| `otp` | a one-time code (sign-in, second factor, contact change) | yes | yes |
| `invitation` | an administrator invites someone | yes | |
| `new_device` | security notice: sign-in from a new browser | yes | yes |
| `password_changed` | security notice | yes | |
| `mfa_changed` | security notice | yes | |
| `email_changed` | security notice, sent to the previous address | yes | |
| `backchannel_request` | an application asks, over the back channel, to sign the user in ([CIBA](ciba-fapi.md)); sent whatever `settings.notifications` says | yes | yes |

Every email event has a built-in English template; the four marked for SMS have
built-in SMS templates too. An event with no template for the channel cannot be sent on
that channel.

### Overrides and language fallback

A tenant override is stored per channel, event and locale:

```bash
# The template an editor starts from: the override, or the built-in text
curl https://id.example.com/admin/tenants/acme/messaging/templates/email/magic_link/de \
  -H "Authorization: Bearer $TOKEN"

curl -X PUT https://id.example.com/admin/tenants/acme/messaging/templates/email/magic_link/de \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
        "subject": "Bei {{tenant.display_name}} anmelden",
        "body_text": "Hallo {{user.username}},\n\n{{link}}\n\nGültig für {{expires_minutes}} Minuten.",
        "body_html": "<p>Hallo {{user.username}},</p><p><a href=\"{{link}}\">Anmelden</a></p>"
      }'
```

Email templates need `subject` and `body_text`; `body_html` is optional and, when
present, the message is sent as `multipart/alternative`. SMS templates take `body_text`
only. The locale is a BCP 47 tag such as `de` or `pt-BR`. `DELETE` on the same path
removes the override; `GET …/messaging/templates` lists every event, the channels and
all stored overrides.

When a message is sent, rIDM picks the user's locale (the flow's negotiated locale, or
the locale stored on the user) and looks for an override in this order:

1. the exact tag, lower-cased (`de-ch`);
2. its language (`de`);
3. the tenant's default locale (`settings.locale.default`);
4. `en`;
5. the built-in English template.

So a single `de` override serves `de-DE`, `de-AT` and `de-CH` users.

### Syntax and variables

Templates are [Handlebars](https://handlebarsjs.com/guide/). Values are HTML-escaped in
`body_html` only; the subject and `body_text` are rendered as plain text. A template is
validated by rendering it with sample data when it is saved, so a syntax error is
refused with `400`.

| Variable | Available in |
|----------|--------------|
| `tenant.display_name`, `tenant.slug` | every event |
| `user.username` | every event except `invitation` |
| `link` | `verify_email`, `password_reset`, `magic_link`, `invitation`, `backchannel_request` (the account console's approvals page) |
| `code` | `otp` |
| `expires_minutes` | `verify_email`, `password_reset`, `magic_link`, `otp`, `backchannel_request` |
| `expires_days`, `inviter` | `invitation` |
| `when` | the four security notices and `backchannel_request` (`YYYY-MM-DD HH:MM UTC`) |
| `ip`, `user_agent` | `new_device` |
| `change` | `mfa_changed` (for example "TOTP enrolled") |
| `new_email` | `email_changed` |
| `client_name`, `binding_message` | `backchannel_request` (`binding_message` is empty when the application sent none) |

### Preview

`POST /admin/tenants/{slug}/messaging/templates/preview` renders a template without
sending anything:

```json
{ "channel": "email", "event": "otp", "locale": "de",
  "draft": { "subject": "Ihr Code", "body_text": "Code: {{code}}" },
  "vars": { "code": "000000" } }
```

Without `draft` it renders what would be sent for that locale; `vars` is merged over
the sample data, and the answer returns the variables it used. The sample data has
exactly the variables of the table above for each event, from the same definition the
real sends use, so a template that previews cleanly renders the same variables when it
is sent. The console's editor calls this on every change and shows the text, the HTML
rendering and the variables.

## The outbound queue

Every message is rendered, written to the `outbound_messages` table as `queued`, and
delivered immediately in the request that caused it. Anything that fails waits for the
`message_delivery` job, which runs every 30 seconds on one node at a time and sends
whatever is due.

| Status | Meaning |
|--------|---------|
| `queued` | waiting for its first attempt or its next retry |
| `sending` | claimed by a delivery pass; a message stuck here for 10 minutes (a node died mid-send) is queued again |
| `sent` | the provider accepted it |
| `dead` | gave up; kept for inspection and redelivery |

A message gets six attempts. After each failure it waits 1 minute, then 5 minutes,
30 minutes, 2 hours and 6 hours (12 hours for any attempt beyond). A permanent failure
dies at once without using its remaining attempts: an SMTP permanent (5xx) reply, a
`4xx` from an HTTP endpoint, or no sender configured for the channel. Transient
failures (timeouts, connection errors, `5xx` from an HTTP endpoint, SMTP temporary
replies) are retried.

Because a missing sender is permanent, a tenant that has neither its own settings nor
deployment defaults dead-letters every email the moment it is queued. Configure a
sender, then redeliver.

The Prometheus gauge `ridm_messages_queued` reports the backlog across all tenants.
Sent and dead messages are deleted by the hourly `cleanup` job once they are older than
`RETENTION_DAYS` (default 30).

## The delivery log

`GET /admin/tenants/{slug}/messaging/log?status=dead&limit=100` lists recent messages,
newest first: channel, event, recipient, subject, status, attempts, next attempt,
last error and timestamps. `limit` defaults to 100 and is capped at 500; `status` is
`queued`, `sending`, `sent` or `dead`. Message bodies are deliberately left out: they
carry sign-in links and codes that must not be readable after the fact.

`POST /admin/tenants/{slug}/messaging/log/{message}/redeliver` puts a dead message back
in the queue with its attempts reset (`202`); the next delivery pass sends it. Only dead
messages can be redelivered. Remember that a redelivered link or code may have expired
in the meantime.

## Security notices

Users are told about security-relevant changes to their account, in their own locale,
through the tenant's messaging settings:

| Setting (`settings.notifications`) | Default | Sent when |
|------------------------------------|---------|-----------|
| `new_device` | `true` | a sign-in from a browser the user has not used before |
| `password_changed` | `true` | the password changes through recovery, a forced change, the account console, or an administrator's reset with `notify` set (never the initial password) |
| `mfa_changed` | `true` | a second factor is added or removed, or a recovery code is used |
| `email_changed` | `true` | the email address changes; sent to the previous address, which is the one that can still object |

A notice goes to the account's email address. An account with no email but a verified
phone gets the `new_device` notice (and a `backchannel_request`) by SMS; the other
notices have no SMS template and are skipped. Sending a notice never fails the action that triggered it: a failure is
logged and the notice is dropped. Switch notices off in the console under Settings →
Locale & notices, or with a merge patch:

```bash
curl -X PATCH https://id.example.com/admin/tenants/acme \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"settings": {"notifications": {"new_device": false}}}'
```

## Development with Mailpit

The `dev` profile of the bundled compose file starts [Mailpit](https://mailpit.axllent.org/),
which accepts all mail and shows it in a web UI, and points the API's deployment
defaults at it (`SMTP_HOST=mailpit`, `SMTP_PORT=1025`, `SMTP_SECURITY=none`):

```bash
docker compose -f deploy/docker-compose.yml --profile dev up -d
# Mailpit web UI: http://localhost:8025   (RIDM_MAILPIT_UI_PORT)
# Mailpit SMTP:   localhost:1025          (RIDM_MAILPIT_SMTP_PORT), for an API run outside compose
```

An API started with `cargo run` can use the same Mailpit by setting `SMTP_HOST=localhost`,
`SMTP_PORT=1025`, `SMTP_SECURITY=none` and an `SMTP_FROM`. See
[docker-compose](../deploy/docker-compose.md).

## Caveats

- Provider settings are cached in each node's memory for up to 60 seconds; a change is
  evicted everywhere at once, but a node that misses the eviction catches up within a
  minute.
- Delivery settings (SMTP, SMS, CAPTCHA) are credentials, not configuration, and are
  not part of the [tenant configuration document](../reference/tenant-document.md).
  Template overrides are.
- `SMTP_SECURITY=none` sends credentials and mail in clear text. Use it only against a
  local catcher.
