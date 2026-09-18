# Users, invitations and bulk import

Users belong to one tenant. This page covers managing them from the admin console,
the `ridm` CLI and the admin API: creating, editing, disabling and deleting accounts,
their credentials and sessions, invitations, self-registration, the profile schema,
and bulk import and export. For how users relate to groups and roles, see
[Users, groups and roles](../concepts/users-groups-roles.md).

All routes below are under `/admin/tenants/{slug}/users` and need `ridm:users:read`
to read and `ridm:users:write` to change, unless noted. `{user}` is the user's id.

## Finding users

Console: Users (`/console/users/`) is a table with prefix search on username and email,
a status filter and, on request, deleted users; further pages load as you scroll.

```http
GET /admin/tenants/acme/users?search=ali&status=active&limit=50
```

| Parameter | Meaning |
|-----------|---------|
| `search` | Case-insensitive prefix of the username or email |
| `status` | `active`, `disabled`, `locked`, `pending` or `deleted` |
| `include_deleted` | Include soft-deleted users (default `false`) |
| `cursor`, `limit` | Paging: `limit` defaults to 50, at most 500; pass `next_cursor` back as `cursor` |

`GET …/users/{user}` returns the user with a `password` summary (set, algorithm,
changed and expiry dates, must-change flag), direct and effective roles, and groups.

## Creating a user

| Where | How |
|-------|-----|
| Console | Users → New user: a temporary password revealed once, a chosen password, or none |
| CLI | `ridm --tenant acme user create alice --email alice@example.com --temporary-password` |
| API | `POST /admin/tenants/{slug}/users` |

```http
POST /admin/tenants/acme/users
Content-Type: application/json

{
  "username": "alice",
  "email": "alice@example.com",
  "email_verified": true,
  "locale": "en",
  "attributes": { "department": "finance" },
  "temporary_password": true
}
```

| Field | Default | Notes |
|-------|---------|-------|
| `username` | required | Trimmed and lower-cased; 1–255 characters, no whitespace; unique in the tenant |
| `email` | `null` | Lower-cased; unique in the tenant |
| `email_verified` | `false` | |
| `phone` | `null` | E.164, such as `+14155550100` |
| `phone_verified` | `false` | |
| `status` | `active` | `active`, `disabled` or `pending`; `locked` and `deleted` are refused with `400` |
| `attributes` | `{}` | Profile attributes, validated against the [profile schema](#profile-schema) |
| `locale` | `null` | The user's language, used when the request names none |
| `external_id` | `null` | The identifier in the system the user came from (SCIM `externalId`); unique in the tenant |
| `password` | — | An initial password, checked against the tenant's password policy |
| `temporary_password` | `false` | Generate a password, return it once as `temporary_password`, and force a change at first sign-in |

Send either `password` or `temporary_password`, not both. With neither, the account has
no password until the user sets one through recovery or signs in another way the
tenant offers.

To bring someone in without handling a password at all, send an
[invitation](#invitations) instead.

## Editing, disabling, unlocking and deleting

`PATCH …/users/{user}` is a partial update: absent fields are unchanged, `null` clears
an optional field, and unknown fields are refused. It accepts `username`, `email`,
`email_verified`, `phone`, `phone_verified`, `status`, `attributes`, `locale`,
`must_change_password` and `external_id`. `attributes` replaces the whole attribute
object, subject to the profile schema. In the console, the user page's Profile tab
saves as you go.

| Task | Console (user page header) | API |
|------|---------------------------|-----|
| Disable | Disable | `PATCH …/users/{user}` with `{"status": "disabled"}`; every session ends at once, with back-channel logout |
| Re-enable | Enable | `PATCH` with `{"status": "active"}` |
| Clear a lockout | Unlock | `POST …/users/{user}/unlock`: resets the failure counter and the `locked` status |
| Delete | Delete | `DELETE …/users/{user}` |

`status` can only be set to `active` or `disabled`: `locked` is set by the lockout
policy and `deleted` by deletion.

Disabling or deleting a user by any path (the admin API, SCIM, a user deleting their
own account) signs them out everywhere at once and sends back-channel logout to the
clients of each session. A session of a disabled or deleted user that somehow survives
gets no further authorization codes.

Deletion is a soft delete. Sessions and trusted devices end at once, the username and
email are freed, and the record is purged by a daily job after
`settings.account.deletion_retention_days` (default 30). Users may also delete their own
account from the account console, unless `settings.account.self_deletion` is off, but an
administrator must be removed by another administrator.

## Passwords and credentials

The console's "Password & credentials" tab shows the password summary, the enrolled
factors, linked upstream identities and personal access tokens.

**Set or reset a password**: `PUT …/users/{user}/password`, or
`ridm user reset alice`.

```json
{ "password": "a-new-long-passphrase", "must_change": true, "notify": true, "revoke_sessions": true }
```

| Field | Default | Meaning |
|-------|---------|---------|
| `password` | absent | Absent: generate a temporary password, returned once as `temporary_password` |
| `must_change` | `false` | Force a change at the next sign-in (always on for a temporary password) |
| `skip_policy` | `false` | Accept a password the policy and history would refuse |
| `notify` | `false` | Tell the user their password changed |
| `revoke_sessions` | `false` | End every session, with back-channel logout, so the new password is needed everywhere |

Note that the CLI flips the `must_change` default: `ridm user reset` forces a change
unless `--no-must-change` is given.

**Force a change** without setting a password: `POST …/users/{user}/force-password-change`.

**Second factors**: `GET …/users/{user}/credentials` lists the password summary and
factor rows (type, label, timestamps, never the secret material);
`DELETE …/credentials/{credential_id}` removes one; removing the last second factor
removes the recovery codes with it. See
[MFA policy](mfa-policy.md#resetting-a-users-mfa).

**Linked identities**: `GET …/users/{user}/identities` and
`DELETE …/identities/{idp_id}` list and unlink upstream accounts (see
[Identity brokering](../concepts/brokering.md)).

**Personal access tokens**: `GET …/users/{user}/pats` and `DELETE …/pats/{token_id}` list
and revoke the user's tokens (see
[Administrator access](access.md#personal-access-tokens)).

## Sessions, devices and consents

The "Sessions & devices" and "Consents" tabs of the user page, or:

| Route | Does |
|-------|------|
| `GET …/users/{user}/sessions` | Live SSO sessions |
| `DELETE …/users/{user}/sessions` | End every session (answers `{"revoked": n}`) |
| `DELETE …/users/{user}/sessions/{session_id}` | End one |
| `GET …/users/{user}/devices` | Trusted devices ("remember this device") |
| `DELETE …/users/{user}/devices[/{device_id}]` | Revoke all, or one: the second factor is asked again |
| `GET …/users/{user}/consents` | Scopes the user granted, per client |
| `DELETE …/users/{user}/consents/{client_id}` | Withdraw consent; the next sign-in to that client asks again |

Ending a session revokes the refresh tokens issued in it, `offline_access` ones
included, sends back-channel logout to the clients that took part in it, and makes any
authorization code issued in it unredeemable. Admin tokens issued in a browser session
stop working with it.

## Roles and groups

The Roles and Groups tabs show direct and effective memberships, with assign and
remove. Through the API: `GET …/users/{user}/roles`, `PUT` or `DELETE
…/roles/{role_id}`, and likewise `…/groups/{group_id}`. Granting a role or group that
carries admin permissions the caller does not hold is refused (see
[Administrator access](access.md#no-escalation-through-role-management)).

## Invitations

An invitation emails a link; the invitee opens it on `/invite/`, sets a password (when
the tenant offers password sign-in) and optionally a username (the email address
otherwise), and gets an account whose email is already verified, with the roles and
groups the invitation named. Roles and groups are granted on acceptance.

| Where | How |
|-------|-----|
| Console | Users → Invite; open invitations under Users → `?view=invitations`, with resend and revoke |
| API | `POST /admin/tenants/{slug}/invitations` (`ridm:invitations:write`) |

```json
{ "email": "bob@example.com", "roles": ["<role id>"], "groups": ["<group id>"], "expires_days": 14 }
```

- `expires_days` defaults to 7 and is clamped to 1–90.
- An email that already belongs to a user is refused with `409`.
- The token only travels in the email. `POST …/invitations/{id}/resend` issues a new
  token and expiry and emails it again; the previous link stops working.
  `DELETE …/invitations/{id}` revokes it.
- `GET …/invitations?open_only=true` lists the ones not yet accepted.

Invitations need an email provider (see [Email, SMS and templates](messaging.md)).
They work whether or not self-registration is enabled.

## Self-registration

Self-registration is off by default. Turn it on under Settings → Sign-in, or:

```json
{ "settings": { "registration": { "enabled": true, "require_email_verification": true, "allowed_email_domains": ["acme.example"] } } }
```

With `require_email_verification` (the default), a new account is `pending` until the
emailed link is followed. The registration form asks for the attributes the profile
schema declares as editable by the user. All registration settings are listed in
[Tenants and tenant settings](tenants.md#registration).

## Profile schema

The profile schema declares the custom attributes users carry in `attributes`: their
type, validation, who may edit them and which tokens they appear in. Edit it under
Settings → Profile attributes, or with `GET` and `PUT
/admin/tenants/{slug}/profile-schema` (`ridm:tenants:read` / `write`). `PUT` replaces
the whole schema; existing values are not rewritten.

```json
{
  "allow_undeclared": false,
  "attributes": [
    {
      "name": "department",
      "type": "enum",
      "label": "Department",
      "required": true,
      "editable_by": "admin",
      "visible_in": ["id_token", "userinfo"],
      "validation": { "values": ["finance", "engineering", "sales"] },
      "order": 1
    }
  ]
}
```

| Field | Default | Meaning |
|-------|---------|---------|
| `name` | required | `^[a-zA-Z][a-zA-Z0-9_]{0,63}$`, unique |
| `type` | `string` | `string`, `number`, `boolean`, `email`, `url` (http or https), `phone`, `date` (`YYYY-MM-DD`), `enum`, `json` |
| `label`, `description` | `null` | Shown in forms |
| `required` | `false` | Must be present and non-empty |
| `multivalued` | `false` | An array of values of the type |
| `editable_by` | `user` | `user` (the user and administrators), `admin` (administrators and the admin API only), `none` (only [bulk import](#bulk-import) and SCIM provisioning; the admin API's create and `PATCH` cannot set it) |
| `visible_in` | `[]` | Which of `id_token`, `userinfo`, `access_token` carry the attribute, under its own name |
| `validation` | `{}` | `min_length`, `max_length`, `pattern` (an anchored regular expression), `min`, `max`, `values` (for `enum`) |
| `order` | `0` | Position in forms |

At most 200 attributes. An `enum` needs at least one value, and a required attribute
cannot be `editable_by: none`.

An attribute listed in `visible_in` appears in those tokens as a claim named after the
attribute, when the user has a value for it. It never overwrites a claim a granted scope
released or a protected claim (`sub`, `iss`, `aud` and the like), but a claim mapper
may override it. See [Token claims](../reference/token-claims.md). With `allow_undeclared` (default `false`), attributes
the schema does not declare are stored as given, writable by administrators but not by
users.

## Bulk import

`POST /admin/tenants/{slug}/users/import` creates users in bulk. It needs both
`ridm:users:write` and `ridm:invitations:write`. In the console: Users → Import, paste
or pick a file, run the dry run, then import.

- `Content-Type: application/json` or `text/csv`; anything else is refused.
- At most 10 000 rows and 32 MiB per request.
- `?dry_run=true` validates every row, and checks usernames and emails against existing
  users (not against each other), without writing anything.
- Rows are independent: a bad row is reported and skipped, good rows are created.
- A row that grants a role or group carrying admin permissions the importing
  administrator does not hold fails with "cannot grant permissions you do not hold",
  in a dry run too. The same rule protects role assignment in the admin API.
- Imports may set attributes marked `editable_by: none`.

The response reports every failure by its 1-based row number:

```json
{ "dry_run": false, "total": 3, "created": 2, "failed": 1,
  "errors": [ { "row": 2, "username": "bob", "error": "unknown role `billing`" } ] }
```

### JSON

An array of users, or an object `{"users": [...]}`. Unknown fields are refused.

```json
[
  {
    "username": "alice",
    "email": "alice@example.com",
    "email_verified": true,
    "attributes": { "department": "finance" },
    "roles": ["accountant"],
    "groups": ["finance"],
    "password_hash": "$2b$12$KIXQJ2zLx0R3pNN4mQJb6eBu3b9a3m1FJqPq3r2t9t8kJ0bK1dQ6a"
  },
  { "username": "bob", "email": "bob@example.com", "password": "correct horse battery staple" }
]
```

| Field | Default | Meaning |
|-------|---------|---------|
| `username` | required | As for a created user |
| `email`, `email_verified`, `phone`, `phone_verified`, `locale`, `attributes` | as for a created user | |
| `status` | `active` | `active`, `disabled` or `pending` |
| `roles` | `[]` | Tenant-wide role names (not client roles) |
| `groups` | `[]` | Group names |
| `password` | — | Plaintext, checked against the password policy |
| `password_hash` | — | A hash from another system, in a [supported format](#legacy-password-hashes) |
| `must_change_password` | `false` | Force a change at first sign-in |

Send `password` or `password_hash`, not both; with neither, the user has no password.

### CSV

A header row, then one user per row. Known columns: `username` (required), `email`,
`email_verified`, `phone`, `phone_verified`, `locale`, `status`, `roles`, `groups`,
`password`, `password_hash`, `must_change_password`. Any other column must be named
`attr.<name>` and becomes the profile attribute `<name>`; any other header is refused.

- Booleans are true for `1`, `true`, `yes` or `y` (any case), false otherwise.
- `roles` and `groups` are lists separated by `;` or `|`.
- Empty cells mean "not given".
- An `attr.` cell that parses as JSON (a number, `true`, an array, an object, a quoted
  string) is stored as that value; anything else is stored as a string.

```text
username,email,email_verified,roles,groups,password_hash,attr.department,attr.employee_no
alice,alice@example.com,true,accountant;auditor,finance,$2b$12$KIXQJ2zLx0R3pNN4mQJb6eBu3b9a3m1FJqPq3r2t9t8kJ0bK1dQ6a,finance,1042
bob,bob@example.com,yes,,,,sales,1043
```

```bash
curl -s -X POST "https://id.example.com/admin/tenants/acme/users/import?dry_run=true" \
  -H "Authorization: Bearer $RIDM_TOKEN" -H "Content-Type: text/csv" \
  --data-binary @users.csv
```

### Legacy password hashes

An imported `password_hash` is stored as it is and verified in its own format at the
user's first sign-in, then replaced with a fresh argon2id hash. The accepted formats,
recognised by prefix:

| Format | Example | Notes |
|--------|---------|-------|
| argon2 (PHC) | `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>` | `$argon2i$` and `$argon2d$` too; rehashed when weaker than the server's parameters |
| bcrypt | `$2b$12$<22-char salt><31-char hash>` | `$2a$` and `$2y$` too |
| PBKDF2 (passlib PHC) | `$pbkdf2-sha256$29000$<salt b64>$<hash b64>` | `$pbkdf2-sha512$` too; passlib's `.`-for-`+` base64 is accepted |
| PBKDF2 (Django) | `pbkdf2_sha256$600000$<salt>$<hash b64>` | `pbkdf2_sha512$` too; the salt is used as raw text |
| Salted SHA-2 | `$sha256$<salt>$<hex of sha256(salt ‖ password)>` | `$sha512$` too |
| Unsalted SHA-2 | `$sha256$<hex of sha256(password)>` | `$sha512$` too |
| MD5 | `$md5$<hex>` or `$md5$<salt>$<hex of md5(salt ‖ password)>` | For migration only |

PBKDF2 iteration counts above 10 000 000 are refused. A hash in any other format fails
its row with "unsupported hash format". Systems that store SHA or MD5 digests in
another layout (hash then salt, base64 instead of hex) need their values rewritten
into the layout above before import. See [Migrating to rIDM](../migrate/overview.md).

## Export

`GET /admin/tenants/{slug}/users/export?format=json` (the default) or `?format=csv`
streams every live user, page by page, without credentials. In the console: Users →
Export.

JSON is an array of objects; CSV has the header:

```text
id,username,email,email_verified,phone,phone_verified,status,locale,attributes,must_change_password,last_login_at,created_at
```

In CSV, `attributes` is one column holding the JSON object, and timestamps are RFC
3339. The export's columns differ from the import's (no roles, groups or password), so
a round trip between tenants needs the file reshaped.
