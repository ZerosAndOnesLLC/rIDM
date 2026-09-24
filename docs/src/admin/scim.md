# SCIM provisioning

Every tenant exposes a SCIM 2.0 server (RFC 7643 and RFC 7644), so an HR system or a
workforce identity provider can create, update, disable and remove the tenant's users
and groups on its own schedule. rIDM is the SCIM *service provider*: the other system
pushes, rIDM stores. rIDM does not push to other SCIM servers.

## Endpoints

The base URL is `{PUBLIC_URL}/scim/v2/{slug}`, for example
`https://id.example.com/scim/v2/acme`. It is not under `/t/{slug}` and has no
custom-domain form.

| Path | Methods |
|------|---------|
| `/ServiceProviderConfig` | `GET` |
| `/ResourceTypes` | `GET` |
| `/Schemas` | `GET` |
| `/Users` | `GET` (list, filter), `POST` |
| `/Users/{id}` | `GET`, `PUT`, `PATCH`, `DELETE` |
| `/Groups` | `GET` (list, filter), `POST` |
| `/Groups/{id}` | `GET`, `PUT`, `PATCH`, `DELETE` |

Requests and responses use `application/scim+json`. Errors are SCIM error documents
(`urn:ietf:params:scim:api:messages:2.0:Error`) with `status`, `detail` and, where it
applies, `scimType`: `invalidFilter`, `invalidSyntax`, `invalidValue`, `invalidPath`,
`noTarget`, `uniqueness` (a `409`, for example a username or `externalId` already taken)
or `tooMany`. `POST` answers `201` with a `Location` header; `DELETE` answers `204`.

`ServiceProviderConfig` advertises what is supported: PATCH and filtering (up to 200
results per page) yes; bulk operations, sorting, ETags and the password-change
operation no.

## Provisioning tokens

A provisioning system authenticates with a bearer token minted for one tenant. Tokens
start with `rscim_`, carry 256 random bits, are shown once, stored only as a SHA-256
hash, may expire, and can be revoked. A token only works against its own tenant's base
URL; any other tenant answers `401`.

In the console: **Provisioning** (`/console/provisioning/`), which also shows the base
URL to paste into the other system. Through the admin API, under `ridm:scim:read` and
`ridm:scim:write` (held by owners, administrators and user managers):

```bash
# Mint a token (expires_in_days is optional, 1..3650; omit it for no expiry)
curl -X POST https://id.example.com/admin/tenants/acme/scim/tokens \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "Okta", "expires_in_days": 365}'
```

```json
{
  "id": "0192f5c4-…",
  "tenant_id": "0192f0a1-…",
  "name": "Okta",
  "expires_at": "2027-09-18T09:12:44Z",
  "last_used_at": null,
  "revoked_at": null,
  "created_at": "2026-09-18T09:12:44Z",
  "token": "rscim_Qm9i…"
}
```

`GET /admin/tenants/{slug}/scim/tokens` lists the tokens (never their values) with the
`base_url`: every live one (a tenant may have 100), then the most recent revoked ones,
200 rows at most; `DELETE /admin/tenants/{slug}/scim/tokens/{token}` revokes one at once.
`last_used_at` is updated at most once a minute per token. Creating and revoking a token
are audited as `scim_token.created` and `scim_token.revoked`, and every change made
with a token is recorded in the audit log with actor type `client` and the token's id
as actor, so provisioning changes can be told apart from administrators' changes.

Revoked and expired tokens are deleted by the hourly cleanup job after
`RETENTION_DAYS`.

## How a SCIM User maps onto a user

| SCIM attribute | rIDM user |
|----------------|-----------|
| `id` | the user's id (read-only) |
| `userName` (required) | username |
| `externalId` | `external_id`, unique per tenant |
| `emails` | email: the entry marked `primary`, else the first; one address is kept |
| `phoneNumbers` | phone: the `primary` entry, else the first |
| `active` | `true` = active, `false` = disabled (default `true`) |
| `locale` | locale |
| `name.givenName` | profile attribute `given_name` |
| `name.familyName` | profile attribute `family_name` |
| `displayName` | profile attribute `display_name` |
| `groups` | direct group memberships, read-only |
| `meta` | `created`, `lastModified`, `location` |

The three name attributes are stored only when the tenant's profile schema declares
`given_name`, `family_name` and `display_name`, or allows undeclared attributes;
otherwise they are dropped silently. `name.formatted` is produced on read and ignored
on write. Other profile attributes are left alone by every SCIM write. SCIM writes
count as an import, so they may set attributes the schema marks `editable_by: none`.

A user created through SCIM:

- has its email marked verified (the provisioning system is trusted for it) and its
  phone unverified;
- has no password. It signs in by whatever the tenant offers that needs none (a magic
  link, an email code, a brokered identity provider) or sets a password through
  recovery;
- is not held back by required profile attributes: they are asked for at the next
  sign-in instead.

Setting `active: false` disables the user and `DELETE /Users/{id}` soft-deletes it,
exactly as the admin API does: every session ends at once and the user's clients get
back-channel logout. A deleted account is gone from SCIM and sign-in at once, and the purge job removes it for good after the
tenant's `account.deletion_retention_days` (default 30). A deleted user answers `404`.

`PUT` replaces the document: an attribute left out is cleared. A `PUT` without
`emails` removes the user's email address, one without `externalId` clears it. Most
provisioning systems send the full document, but check before pointing a hand-written
integration at `PUT`.

## How a SCIM Group maps onto a group

| SCIM attribute | rIDM group |
|----------------|------------|
| `id` | the group's id |
| `displayName` (required) | name |
| `externalId` | `attributes.externalId` |
| `members` | member users, by user id (`value`) |

Groups created through SCIM are top-level. Members must be users of the same tenant;
a nested group as a member is refused with `invalidValue`. A `POST` whose member list
names a user that does not exist creates nothing. The group list covers every group of
the tenant, including groups created in the console. Roles attached to a group apply
to its SCIM-provisioned members like to any other member, which is the usual way to
turn an upstream group into permissions: attach roles to the group in rIDM once, let
SCIM keep the membership current.

That route stops at administrator access. Adding members to a group whose roles
(directly, through its parent groups or through composite roles) grant any `ridm:*`
admin permission is refused with `403` and changes nothing, whether by `POST`, `PUT` or
`PATCH`. A provisioning token carries no administrator whose own permissions could bound
what it hands out, so admin rights are granted in rIDM, not provisioned. Removing
members, and requests that add nobody new, are unaffected.

## Listing and filters

`GET /Users` and `GET /Groups` accept `filter`, `startIndex` (1-based) and `count`.
`count` defaults to and is capped at 200; a `startIndex` beyond 2,000 is refused with
`tooMany`. An unfiltered user list reads only the requested page, and its
`totalResults` may lag writes by up to 30 seconds.

`GET /Groups` and `GET /Groups/{id}` accept `excludedAttributes=members` (RFC 7644
§3.9), which leaves the member list out: for a large group it is most of the document,
and Microsoft Entra ID asks for groups this way. Without it, a group lists its members
only for the groups on the requested page, unless the filter itself tests `members`.

Filters follow the RFC 7644 grammar: the operators `eq ne co sw ew gt ge lt le pr`,
`and`, `or`, `not`, parentheses, dotted paths (`name.givenName`), value filters
(`emails[type eq "work"].value`), schema-URN prefixes, and case-insensitive attribute
names and string comparisons.

A user filter that is a single equality on `userName`, `externalId`, `emails`
(or `emails.value`) or `id` is answered from an index, even when it is `and`-ed with
further conditions. Any other user filter is evaluated over the tenant's users and only
works while the tenant has at most 2,000 of them; beyond that it is refused with
`tooMany`. Provisioning systems look users up by `userName` or `externalId` before
creating them, which is the indexed path. Group filters are evaluated over all groups;
an equality on `displayName` skips the others before anything else is read.

## PATCH

PATCH takes an RFC 7644 `PatchOp` with `add`, `replace` and `remove` operations,
case-insensitive op names, with or without `path`:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    { "op": "replace", "path": "active", "value": false },
    { "op": "replace", "path": "emails[type eq \"work\"].value", "value": "alice@acme.example" },
    { "op": "add", "value": { "name.familyName": "Liddell" } }
  ]
}
```

Simple, dotted and filtered paths work, including `members[value eq "<user id>"]` to
remove one member. Booleans may be sent as the strings `"True"` and `"False"`, which
some clients do. `remove` needs a path (`noTarget` otherwise) and `add`/`replace` need
a value. The operations are applied to the current SCIM document and the result is
stored as a full replace, so PATCH and PUT share one code path and one set of rules.

## Example with curl

```bash
BASE=https://id.example.com/scim/v2/acme
SCIM=rscim_Qm9i…

# Create
curl -X POST "$BASE/Users" \
  -H "Authorization: Bearer $SCIM" -H "Content-Type: application/scim+json" \
  -d '{
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "alice",
        "externalId": "00u1a2b3c4",
        "name": {"givenName": "Alice", "familyName": "Liddell"},
        "emails": [{"value": "alice@acme.example", "type": "work", "primary": true}],
        "active": true
      }'

# Look up by externalId (indexed)
curl -G "$BASE/Users" -H "Authorization: Bearer $SCIM" \
  --data-urlencode 'filter=externalId eq "00u1a2b3c4"'

# Deactivate
curl -X PATCH "$BASE/Users/<id>" \
  -H "Authorization: Bearer $SCIM" -H "Content-Type: application/scim+json" \
  -d '{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
       "Operations": [{"op": "replace", "path": "active", "value": false}]}'
```

## Configuring a provisioning system

Okta, Microsoft Entra ID and similar systems need the same few things; the field names
differ by product:

- **SCIM base URL / tenant URL**: `https://id.example.com/scim/v2/acme`.
- **Authentication**: HTTP header / bearer token, the `rscim_` token. There is no
  OAuth or basic-auth mode.
- **Unique identifier for users**: `userName`. Map it to whatever the source uses as a
  login name, and keep it stable; changing it upstream renames the user in rIDM.
- **Attribute mappings**: `userName`, `externalId`, `emails[type eq "work"].value`,
  `name.givenName`, `name.familyName`, `displayName`, `phoneNumbers`, `active`,
  `locale`. Anything else the source sends is ignored.
- **Supported operations**: create, update (PATCH or PUT), deactivate (`active: false`),
  delete, group push. Turn off password synchronisation; rIDM does not accept passwords
  over SCIM.

Run the product's connection test first: it reads `ServiceProviderConfig` and filters
`/Users` by `userName`, which exercises both the token and the base URL.

## Caveats

- The SCIM endpoints are not behind the tenant's request ceilings or IP rules, which
  cover the sign-in and OAuth endpoint families only (see
  [Rate limits, IP rules and CAPTCHA](security-controls.md)). Treat a provisioning
  token as an administrator credential: give it an expiry, one per upstream system,
  and revoke it when the integration goes away.
- A disabled tenant answers every SCIM request with `403`.
- Bulk requests (`/Bulk`) are not supported; provisioning systems fall back to one
  request per change when `ServiceProviderConfig` says so.
