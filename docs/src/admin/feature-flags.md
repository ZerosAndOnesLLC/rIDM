# Feature flags

Feature flags are switches your applications read: a new checkout for everyone, a beta
report for one customer organization, a kill switch you can throw without a deploy.
rIDM stores them per tenant, and tells an application which ones are on for the person
signed in. rIDM itself doesn't act on them.

## Managing flags

In the console: **Feature flags** (`/console/features/`, or `g` then `f`). It needs
`ridm:tenants:read` to look and `ridm:tenants:write` to change anything. Each flag has:

| Field | Meaning |
|-------|---------|
| name | 1–64 characters: lowercase letters, digits, `.`, `_` and `-`, starting with a letter or digit. Up to 200 flags per tenant. |
| `enabled` | The tenant-wide value. A new flag starts off. |
| `description` | What turning it on changes, for the people who toggle it (up to 500 characters). |
| `organizations` | Values for particular [organizations](organizations.md), by organization slug. They win over `enabled` for anyone signed in to that organization. |

Flags live in the tenant's settings (`settings.features`), so they're also edited
through the admin API and travel with [configuration as
code](../concepts/config-as-code.md):

```bash
curl -X PATCH https://id.example.com/admin/tenants/acme \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"settings": {"features": {
        "checkout.v2":  {"enabled": true, "description": "The rebuilt checkout"},
        "beta.reports": {"enabled": false, "organizations": {"globex": true}}
      }}}'
```

The body is a merge patch: `{"beta.reports": {"organizations": {"globex": null}}}`
removes one override, and `{"beta.reports": null}` removes the flag. A bare
`true`/`false` is still accepted for a flag, which is how flags were written before they
had descriptions, and is stored as `{"enabled": …}`.

## Reading flags from an application

Only flags that are **on** are listed, so a flag that doesn't exist reads as off.

**In tokens.** Ask for the `features` scope, which every tenant has alongside the
standard OIDC scopes. The access token and the ID token then carry the flags that were
on at sign-in:

```json
{ "sub": "…", "org_id": "…", "features": ["beta.reports", "checkout.v2"] }
```

They are worked out for the organization the sign-in acts in (`org_id`), or tenant-wide
without one. A refreshed token is worked out again, so a change reaches the
application at the next refresh at the latest. No claim mapper may write `features`.

**Live.** `GET /t/{slug}/features` with any access token the tenant issued (as
`Authorization: Bearer`, or `DPoP` for a sender-constrained token) answers with the
current values for that token's organization:

```json
{ "features": ["beta.reports", "checkout.v2"], "org_id": "…" }
```

A token of another tenant gets `403`, and no token or an invalid one gets `401`.
