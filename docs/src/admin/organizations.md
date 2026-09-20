# Organizations

Organizations group a tenant's users into customers, business units or teams;
[the concept page](../concepts/organizations.md) explains what they are and how
they differ from tenants. This page is how to run them.

Everything here needs `ridm:orgs:read` to look and `ridm:orgs:write` to change.
Owners, administrators and user managers hold both; viewers only read. Those
permissions can also be granted *inside* one organization, which makes their
holder [that organization's administrator](#organization-administrators) and
nobody else's.

## In the console

**Identity → Organizations** (or `g` then `z`). The list searches by name and
slug. Choosing one opens its detail, which saves as you type:

| Field | Notes |
|-------|-------|
| Name | shown to members on the login page's picker |
| Slug | lowercase letters, digits and hyphens. Clients may name it in an `organization` request parameter, so treat it as an identifier, not a label |
| Status | `disabled` takes no new members and cannot be signed in to; its members keep their accounts |
| Description | for administrators |

Below the fields: **Members** (add with the user picker, remove, the primary
organization marked), **Invitations** (invite an email address into the
organization, revoke an open one), **Email domains** (add, verify, turn auto-join
on or off), and **Roles inside this organization**.

An organization's own administrator sees the same page opened on their
organization, without the list, the *New organization* button, the delete button,
the slug and status fields, and the *Add member* picker.

## The admin API

```
GET    /admin/tenants/{slug}/organizations           # ?search= &status= &cursor= &limit=
POST   /admin/tenants/{slug}/organizations           # {slug, display_name, description?, attributes?}
GET    /admin/tenants/{slug}/organizations/{org}     # with member_count and domains
PATCH  /admin/tenants/{slug}/organizations/{org}
DELETE /admin/tenants/{slug}/organizations/{org}

GET    /admin/tenants/{slug}/organizations/{org}/members
PUT    /admin/tenants/{slug}/organizations/{org}/members/{user_id}
DELETE /admin/tenants/{slug}/organizations/{org}/members/{user_id}

GET    /admin/tenants/{slug}/organizations/{org}/roles
GET    /admin/tenants/{slug}/organizations/{org}/grantable-roles   # with `grantable` per role
PUT    /admin/tenants/{slug}/organizations/{org}/members/{user_id}/roles/{role_id}
DELETE /admin/tenants/{slug}/organizations/{org}/members/{user_id}/roles/{role_id}
PUT    /admin/tenants/{slug}/organizations/{org}/groups/{group_id}/roles/{role_id}
DELETE /admin/tenants/{slug}/organizations/{org}/groups/{group_id}/roles/{role_id}

GET    /admin/tenants/{slug}/organizations/{org}/invitations    # ?open_only= &cursor= &limit=
POST   /admin/tenants/{slug}/organizations/{org}/invitations    # {email, expires_days?}
DELETE /admin/tenants/{slug}/organizations/{org}/invitations/{invitation}

GET    /admin/tenants/{slug}/organizations/{org}/domains
POST   /admin/tenants/{slug}/organizations/{org}/domains        # {domain, auto_join}
PATCH  /admin/tenants/{slug}/organizations/{org}/domains/{id}   # {auto_join}
POST   /admin/tenants/{slug}/organizations/{org}/domains/{id}/verify
DELETE /admin/tenants/{slug}/organizations/{org}/domains/{id}
```

The [API reference](../reference/admin-api/index.html) has the bodies.

```bash
ORG=$(curl -fsS -X POST "$API/admin/tenants/acme/organizations" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"slug": "northwind", "display_name": "Northwind Traders"}' | jq -r .id)

curl -fsS -X PUT "$API/admin/tenants/acme/organizations/$ORG/members/$USER_ID" \
  -H "authorization: Bearer $TOKEN"
```

## Verifying a domain

Adding a domain returns a `verification` value. Publish it as a TXT record at
`_ridm-challenge.<domain>`, then ask rIDM to look:

```bash
curl -fsS -X POST "$API/admin/tenants/acme/organizations/$ORG/domains" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"domain": "northwind.example", "auto_join": true}'
# → {"id": "…", "verification": "ridm-domain-verification=0192f…", "verified_at": null, …}

# after the record is published and has propagated
curl -fsS -X POST "$API/admin/tenants/acme/organizations/$ORG/domains/$DOMAIN_ID/verify" \
  -H "authorization: Bearer $TOKEN"
```

The check is one DNS TXT lookup from the rIDM server, so its host needs a
resolver that can reach public DNS:

| Answer | Meaning |
|--------|---------|
| 200 | the record was found; the domain is verified from now on |
| 400 | no matching record yet (also what a wrong value looks like) |
| 503 | the server has no usable resolver configuration; an operator problem, worth retrying |

Once verified, auto-join adds every user with a **verified** address at that
domain as they sign in, including users who already existed. Turning auto-join
off stops new joins and leaves existing members alone; so does removing the
domain.

## Roles inside an organization

A grant scoped to an organization applies only while a session acts there:

```bash
curl -fsS -X PUT \
  "$API/admin/tenants/acme/organizations/$ORG/members/$USER_ID/roles/$ROLE_ID" \
  -H "authorization: Bearer $TOKEN"
```

The user must already be a member (400 otherwise), and you must hold every
permission the role carries (403 otherwise). Removing the membership removes the
grants that hung off it.

`GET …/organizations/{org}/roles` lists the organization's grants; each row names
a `role_id` and either a `user_id` or a `group_id`. A group grant reaches every
member of the group and of its descendants, while they act in this organization.

## Organization administrators

Granting a role **inside** an organization makes its holder an administrator of
that organization alone. `ridm:org-admin` is the built-in role for it
(`ridm:orgs:read`, `ridm:orgs:write`, `ridm:invitations:read`,
`ridm:invitations:write`, `ridm:roles:read`), but any role works: the reach comes
from the grant, not the role.

```bash
ROLE=$(curl -fsS "$API/admin/tenants/acme/organizations/$ORG/grantable-roles" \
  -H "authorization: Bearer $TOKEN" | jq -r '.[] | select(.name=="ridm:org-admin") | .id')
curl -fsS -X PUT \
  "$API/admin/tenants/acme/organizations/$ORG/members/$USER_ID/roles/$ROLE" \
  -H "authorization: Bearer $TOKEN"
```

What they may do is everything on this page **for that organization**: read and
rename it, manage members, domains, invitations and the roles granted inside it.
What they may not do:

| Refused | Why |
|---------|-----|
| `GET /organizations`, `POST /organizations`, `DELETE /organizations/{org}` | an organization's existence is the tenant's business |
| `PATCH` with `slug` or `status` | the identity others may have stored, and the lifecycle |
| `PUT /organizations/{org}/members/{user_id}` | they add people by invitation, or through a verified auto-join domain |
| an invitation carrying `roles` or `groups` | those are granted tenant-wide on acceptance |
| any route outside `/organizations/{org}` | users, groups, clients, settings, audit — all tenant-wide |
| granting a role that carries an admin permission they do not hold here | the same no-escalation rule as everywhere else |

Their permissions come from the session's organization, so the token must carry
the `org_id` claim: they sign in normally (one membership is chosen silently) and
`GET /admin/me` reports `organization` and `organization_permissions`. A personal
access token belongs to the user rather than to a sign-in, carries no
organization, and therefore holds none of this.

## What members see

Members with more than one organization choose one on the login page; with one,
it is chosen for them. The choice becomes the `org_id` claim in their tokens and
decides which org-scoped roles they hold. The account console's
**Organizations** tab lists what a user belongs to, marking their primary one; it
is read-only, since membership is granted, not chosen.

## Events

`organization.created`, `organization.updated`, `organization.deleted`,
`organization.member_added`, `organization.member_removed`,
`organization.domain_added`, `organization.domain_verified` and
`organization.domain_removed` all reach the audit log and webhooks
([Webhooks and the audit log](webhooks-audit.md)). An auto-join arrives as
`organization.member_added` by the `system` actor.
