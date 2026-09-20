# Users, groups and roles

Users are the people (and service accounts) who sign in to a tenant. Groups
organise them, roles say what they may do, and permissions attach meaning to
roles for a particular API. All four belong to one tenant and are invisible to
every other. A tenant can also group its users into
[organizations](organizations.md), which carry membership, their own role grants
and email domains.

## Users

A user has a `username` and an optional `email` and `phone`, each unique within
the tenant, each with a verified flag. Everything else about a person lives in
**profile attributes**, which the tenant declares in its profile schema: name,
type (`string`, `number`, `boolean`, `email`, `url`, `phone`, `date`, `enum`,
`json`), validation, whether it is required, and who may edit it
(`editable_by`: `user`, `admin`, or `none` for values only bulk import and
SCIM provisioning set; the interactive admin console and API cannot). The registration page, the account console and the admin
console all build their forms from that schema, and every write is validated
against it. A schema can also allow undeclared attributes, which are then
stored as they are and editable by administrators only.

Attributes reach tokens in three ways. An attribute's schema entry can list
where it appears in `visible_in` (`id_token`, `userinfo`, `access_token`); it
is then emitted under the attribute's name there, whenever the user has a
value. A scope can name the attribute in its `claims` list, releasing it when
that scope is granted (see
[Scopes](resource-servers.md#scopes-what-the-user-agreed-to)). And a
[claim mapper](#claims-from-users-groups-and-roles) can emit it under any name,
shape or type. `visible_in` never overwrites a claim a scope released or one the
token service owns (`sub`, `roles`, `permissions` and the like); mappers run
last and may override what `visible_in` added.

A user's `status` is one of:

| Status | Meaning |
|--------|---------|
| `active` | may sign in |
| `pending` | created but not yet complete (for example, awaiting email verification) |
| `locked` | temporarily locked after too many failed sign-ins (`settings.lockout`) |
| `disabled` | switched off by an administrator; disabling ends the user's sessions |
| `deleted` | soft-deleted; purged after the tenant's retention period |

Deleting a user is a soft delete: every session, token and trusted device ends
at once and the username and email are freed immediately, and a daily job
removes the row for good after `settings.account.deletion_retention_days`
(30 by default). Tokens are only issued to `active` users, and a refresh fails
once the user is no longer active.

Passwords are hashed with argon2id. Users imported from another system keep
their existing hashes (bcrypt, PBKDF2, salted SHA-2, MD5) and are upgraded to
argon2id the first time they sign in; see [Migrating to rIDM](../migrate/overview.md).
A user may also have no password at all and sign in with a passkey, a magic
link, a one-time code or an upstream identity provider.

Users arrive by self-registration (when `settings.registration.enabled` is on),
by invitation, through the admin API or console, by bulk import, through SCIM
provisioning, or on their first sign-in through an
[upstream identity provider](brokering.md). See
[Users, invitations and bulk import](../admin/users.md).

## Groups

A group is a named set of users. Groups nest: each has an optional parent, and a
member of a group is treated as a member of every group above it. A user in
`engineering/platform` is also in `engineering`.

Groups exist to hold roles. Assign a role to a group and every member,
including the members of its subgroups, holds that role. This is usually the
better way to grant access: add a person to the right group rather than
granting them five roles one by one, and remove them from it when they move on.

Groups also carry free-form JSON `attributes`, and can be emitted in tokens by
name or as full paths.

## Roles

A role is a named capability, such as `orders-admin` or `support`. rIDM
does not interpret custom roles itself; it hands them to your applications in
tokens and maps them to permissions on your APIs.

A role is either **realm-wide** (usable by every client in the tenant) or
**client-scoped** (it belongs to one client, which is deleted with it). Roles
are assigned to users directly or to groups.

**Composite roles** contain other roles. Holding a composite means holding
every role inside it, recursively: grant `manager`, which contains `viewer` and
`approver`, and the user holds all three. Cycles are refused when a composite
is added.

## Effective roles

A user's **effective roles** are everything they hold by any route:

1. roles assigned to the user directly;
2. roles assigned to any group the user belongs to, or to any ancestor of those
   groups;
3. every role contained in any of the above, through composites, to any depth.

Effective roles are what tokens carry, what permissions are computed from, and
what the admin API checks. They are resolved once and cached under a
per-tenant version token. Any change that could alter the result (a role,
composite, assignment, group, membership or permission grant) replaces the
token, which makes every cached resolution in the tenant unreachable at once on
every node. The next request resolves afresh, so a revoked role stops counting
immediately, not after a cache expiry.

## Permissions

A permission is a string such as `orders:read`, defined on a
[resource server](resource-servers.md) (an API) and granted to roles. When a
token is issued for that API, rIDM collects the permissions that the user's
effective roles hold on it and puts them in the token's `permissions` claim.
The API then checks `permissions`, not role names, so the mapping from roles to
what they allow is managed in one place.

## Administrators are users with roles

rIDM's own administration uses the same model. Every tenant carries a built-in
resource server, `urn:ridm:admin`, whose permissions are the admin API's
(`ridm:users:read`, `ridm:clients:write`, and so on), and five built-in roles
that hold them:

| Role | Grants |
|------|--------|
| `ridm:owner` | everything, including creating, deleting and importing tenants |
| `ridm:admin` | everything except creating, deleting and importing tenants |
| `ridm:user-manager` | users, invitations and groups; read roles, tenant settings and audit |
| `ridm:client-manager` | clients, scopes, claim mappers and resource servers; read roles, tenant settings and audit |
| `ridm:viewer` | every read permission |

Built-in roles cannot be renamed, deleted or given different permissions, but
they can be assigned, put in groups and used inside composites. Custom roles
may be granted any admin permission, or a wildcard such as `ridm:users:*`.
Roles held in `master` apply to every tenant; roles held anywhere else apply to
that tenant only.

Two rules keep this safe:

- **No escalation.** An administrator cannot grant a role, add a user to a
  group, add a composite or send an invitation that would give someone admin
  permissions the administrator does not hold themselves. The rule covers the
  bulk paths too: a bulk-import row, or an item of a tenant configuration
  import, that would grant such a role or group fails on its own with "cannot
  grant permissions you do not hold" (in a dry run as well), and a SCIM client
  adding members to a group that grants `ridm:*` permissions is refused with
  `403`.
- **Checked on every request.** The admin API reads the caller's permissions
  from their effective roles on each call rather than trusting a list inside the
  token, so removing a role takes effect on the caller's very next request.

See [Administrator access](../admin/access.md).

## Claims from users, groups and roles

Every user access token carries `roles` (effective role names) and `groups`
(effective group names). Anything more, and anything in ID tokens and userinfo
beyond the scope claims and `visible_in` attributes, comes from **claim
mappers**, configured per tenant or per client:

| Mapper `type` | Adds |
|---------------|------|
| `user_attribute` | a user value, as a string, number, boolean or JSON: `attributes.department` is that profile attribute; any other name is a top-level user field (`username`, `email`, ...) or, failing that, the profile attribute of that name |
| `groups` | effective group names, or `parent/child` paths |
| `roles` | effective role names: realm-wide ones, or only those belonging to one named client |
| `hardcoded` | a fixed value |
| `template` | a Handlebars template over `user`, `tenant`, `client`, `roles` and `groups` |
| `audience` | an extra audience on access tokens |

Each mapper names where its claim goes (`include_in`: `access`, `id`,
`userinfo`). Some claims are off limits, and a mapper targeting one is refused
when it is saved:

- the claims the token service owns: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`,
  `jti`, `azp`, `at_hash`, `c_hash`, `nonce`, `auth_time`, `amr`, `acr`,
  `sid`, `tid`, `client_id`, `scope`, `typ`, and `cnf` and `act`, which would
  otherwise let a mapper bind a token to a key or name an actor that never took
  part;
- `permissions`, which is always computed from the audience's grants;
- `roles` and `groups`, except by a mapper of that type: a `roles` mapper
  targeting `roles` (or a `groups` mapper targeting `groups`) replaces the
  built-in claim, for example to emit only one client's roles or group paths.

The complete claim list is in [Token claims](../reference/token-claims.md).
