# Impersonation

Impersonation lets an administrator sign in as one of a tenant's users, to see what
they see: the apps they reach, the pages the account console shows them, what a
relying party makes of their token. Tokens from the session name the administrator,
the audit log records every step, and the user's credentials, consent and account are
kept out of reach.

It is off until an administrator turns it on for the tenant.

## Turning it on

Settings → Impersonation in the console, or with `ridm:tenants:write`:

```bash
curl -X PATCH https://id.example.com/admin/tenants/acme \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"settings": {"impersonation": {"enabled": true, "max_minutes": 60}}}'
```

| Field | Default | Meaning |
|-------|---------|---------|
| `enabled` | `false` | Whether anyone may impersonate this tenant's users |
| `max_minutes` | `60` | How long an impersonated session lives (1–480). It never outlives the tenant's absolute session timeout either |

## Who may, and whom

- The caller needs **`ridm:users:impersonate`** for the tenant. Among the built-in
  roles only `ridm:owner` holds it, and `ridm:admin` deliberately does not. A custom
  role can be given it, so a support team can impersonate without owning the tenant.
  A global administrator whose role in `master` holds it reaches every tenant that
  allows impersonation.
- The user must be **active**, and must **hold no admin permission at all**, whether
  tenant-wide or inside an organization. Taking on someone's identity can never widen
  what the administrator may do.
- Nobody impersonates themselves.
- A **reason** is required (1–500 characters). It is stored with the session and
  recorded in the audit log, so a support ticket number is a good choice.

All of this is checked when the link is asked for, and again when it is opened.

## Starting

In the console, open the user and choose **Impersonate**. The button appears only
when you hold the permission, the tenant allows impersonation, and the user is
active. Give a reason and you get a link that opens a session as the user in a new
tab. Or through the API:

```bash
curl -X POST https://id.example.com/admin/tenants/acme/users/$USER_ID/impersonate \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"reason": "Ticket 4711: the user cannot see the billing app"}'
```

```json
{
  "url": "https://id.example.com/t/acme/impersonate?ticket=…",
  "expires_at": "2026-09-21T15:02:10Z"
}
```

The link works **once**, and only for **60 seconds**. Opening it in a browser sets the
tenant's session cookie for a new session as the user and lands on the account
console, which signs in through it. From there, any client the user has already
consented to signs in silently as the user, the same way it would for them.

In the browser that opens it, the link replaces whatever session that browser had in
the tenant. The browser's own session is remembered, and it comes back when the
impersonation ends. This matters when a tenant's own administrator impersonates a user
of that same tenant. A global administrator's session lives in `master` and is never
touched.

## What the session is

It is an ordinary SSO session of the user, with these differences:

- **It carries no authentication method.** The user proved nothing, so `amr` is empty
  and there is no `acr`.
- **It owes none of the user's steps.** The MFA policy, a forced password change and
  risk scoring judge the user's own sign-ins. The administrator couldn't pass them,
  and opening the session was checked and audited instead. A client that demands an
  MFA class in `acr_values` still asks for the second step, which the administrator
  can't give.
- **It never counts against the user's concurrent-session cap**, so opening it never
  signs the user out anywhere.
- **It ends after `max_minutes`**, and so does everything minted from it.

## What its tokens carry

Every access token and ID token minted from the session, including those from its
refresh tokens and from a device-flow approval, carries an `act` claim naming the
administrator ([RFC 8693 §4.1](https://www.rfc-editor.org/rfc/rfc8693#section-4.1)):

```json
{
  "sub": "5b0c…",
  "act": {
    "sub": "0192…",
    "iss": "https://id.example.com/t/master"
  }
}
```

`act.sub` is the administrator's user id and `act.iss` their tenant's issuer, which
is often `master`. A relying party that must not act on an impersonation, such as a
payments service, can refuse any token carrying `act`. No token outlives the session:
access tokens expire by its end and refresh-token families end with it, even ones
granted `offline_access`.

The admin API refuses every token carrying `act`, and every token from an
impersonated session. Administration is done as oneself.

## What it may not do

The account API answers `403` with `urn:ridm:error:impersonation-forbidden` to
anything only the user may do:

- everything that needs a [recent sign-in](../reference/errors.md#reauthentication-required):
  the password, second factors and passkeys, email and phone changes, linked
  identities, trusted devices, ending sessions, personal access tokens, the data
  export, deleting the account;
- withdrawing an app's consent.

Consent can't be given either. A client the user hasn't consented to sends the
browser back with `access_denied` instead of showing a consent page. Looking at
everything, and editing ordinary profile attributes, works.

The same refusals apply to any account-API token that names an actor, such as one
obtained by token exchange.

## Ending

The account console shows a banner on every page while it's impersonating, with an
**End impersonation** button. The button posts to `POST /t/{slug}/impersonation/end`,
which:

1. ends the session, its tokens with it, and tells its relying parties
   (back-channel and front-channel logout, as for any sign-out);
2. puts back the browser's own session in the tenant, if it had one and it is still
   live;
3. returns to the administrator's console.

Revoking the session anywhere else also ends it: from the user's page in the console
(Sessions), through `DELETE /admin/tenants/{slug}/users/{user}/sessions/{id}`, or by
the user in their own account console, where it's listed as opened by the
administrator (with the administrator's address and browser withheld). A session that
runs out its time simply expires.

## The audit trail

| Event | Actor | Payload |
|-------|-------|---------|
| `impersonation.requested` | the administrator | `user_id`, `reason` |
| `impersonation.started` | the administrator | `user_id`, `session_id`, `impersonator_id`, `impersonator_tenant_id`, `reason` |
| `impersonation.ended` | the administrator when they ended it from the session, otherwise `system` | `user_id`, `session_id`, `impersonator_id` |

Everything else recorded while the session is in use, such as the authorizations it
grants, the tokens it refreshes and the profile changes it makes, keeps the user as its
actor and **names the administrator in `impersonator_id`**. That field is part of the
audit row, is covered by the hash chain, appears in webhook payloads as
`impersonator`, and can be filtered on:

```bash
# Everything one administrator did while impersonating
curl -G https://id.example.com/admin/tenants/acme/audit \
  -H "Authorization: Bearer $TOKEN" --data-urlencode "impersonator_id=$ADMIN_ID"
```

`user_id=` matches rows where the user is the actor, the subject or the impersonator,
so an administrator's own audit trail includes what they did as someone else.
