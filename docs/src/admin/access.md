# Administrator access

Administration in rIDM is not a separate account system. An administrator is an
ordinary user of some tenant whose roles grant permissions on a built-in resource
server, `urn:ridm:admin`, and the admin API accepts an access token issued for that
audience. This page covers the permissions, the built-in roles, how far a grant
reaches, how an organization's own administrator fits in, and the tokens automation
uses.

## Permissions

Admin permissions are named `ridm:<resource>:<action>`. Every tenant carries the same
catalogue, seeded on the `urn:ridm:admin` resource server when the tenant is created;
it cannot be extended or trimmed. `GET /admin/permissions` returns the catalogue and
the built-in roles.

| Permission | Allows |
|------------|--------|
| `ridm:tenants:read` | View tenant settings, branding, feature flags, IP rules, CAPTCHA configuration, profile schema, dashboard statistics |
| `ridm:tenants:write` | Change tenant settings, branding, feature flags, IP rules, CAPTCHA configuration, profile schema |
| `ridm:tenants:create` | Create tenants (global administrators only) |
| `ridm:tenants:delete` | Delete tenants (global administrators only) |
| `ridm:tenants:export` | Export tenant configuration |
| `ridm:tenants:import` | Import tenant configuration |
| `ridm:users:read` | View users, their sessions, credentials, devices, tokens, consents, linked identities |
| `ridm:users:write` | Create, change, disable and delete users; manage their sessions, credentials, devices, tokens, consents, roles and groups |
| `ridm:users:impersonate` | Sign in as a user where the tenant allows it ([impersonation](impersonation.md)) |
| `ridm:invitations:read` | View invitations |
| `ridm:invitations:write` | Create, resend and revoke invitations; bulk import users |
| `ridm:groups:read` / `write` | View groups and members / create, change, delete groups and manage membership |
| `ridm:roles:read` / `write` | View roles, composites and assignments / create, change, delete roles and composites |
| `ridm:clients:read` / `write` | View OAuth clients / create, change, delete them; generate and rotate secrets |
| `ridm:scopes:read` / `write` | View / manage scopes |
| `ridm:mappers:read` / `write` | View / manage claim mappers |
| `ridm:resource-servers:read` / `write` | View / manage resource servers and their permissions; grant permissions to roles |
| `ridm:idps:read` / `write` | View / manage identity providers |
| `ridm:keys:read` | View signing keys and master-key rotation status |
| `ridm:keys:write` | Create, rotate, activate, retire and revoke signing keys; re-encrypt under the master key |
| `ridm:messaging:read` / `write` | View / change messaging settings and templates; send test messages |
| `ridm:audit:read` | View and export the audit log |
| `ridm:webhooks:read` / `write` | View / manage webhooks; redeliver events |
| `ridm:scim:read` / `write` | View / create and revoke SCIM provisioning tokens |

The permission each admin route needs is listed in the
[admin API reference](../reference/admin-api/index.html).

A custom role may also be granted a wildcard: a granted name ending in `:*` covers
every permission that shares the preceding segments, so `ridm:users:*` covers
`ridm:users:read` and `ridm:users:write`, and `ridm:*` covers the whole catalogue.
Wildcards only work on the granted side.

## Built-in roles

Six roles are seeded in every tenant. They can be assigned, used as composites of
other roles and attached to groups, but not renamed, deleted or given different
permissions.

| Role | Holds |
|------|-------|
| `ridm:owner` | Every permission, including tenant lifecycle |
| `ridm:admin` | Every permission except `ridm:tenants:create`, `ridm:tenants:delete`, `ridm:tenants:import` and `ridm:users:impersonate` |
| `ridm:user-manager` | `ridm:tenants:read`, `ridm:users:read`, `ridm:users:write`, `ridm:invitations:read`, `ridm:invitations:write`, `ridm:groups:read`, `ridm:groups:write`, `ridm:roles:read`, `ridm:audit:read`, `ridm:scim:read`, `ridm:scim:write` |
| `ridm:org-admin` | `ridm:orgs:read`, `ridm:orgs:write`, `ridm:invitations:read`, `ridm:invitations:write`, `ridm:roles:read` — meant to be granted [inside one organization](#organization-administrators) |
| `ridm:client-manager` | `ridm:tenants:read`, `ridm:clients:read`, `ridm:clients:write`, `ridm:scopes:read`, `ridm:scopes:write`, `ridm:mappers:read`, `ridm:mappers:write`, `ridm:resource-servers:read`, `ridm:resource-servers:write`, `ridm:roles:read`, `ridm:audit:read` |
| `ridm:viewer` | Every `*:read` permission (not `ridm:tenants:export`) |

Permissions reach a user through their effective roles: direct assignments, roles of
the groups they belong to (and of those groups' ancestors), and composites of either.
They are resolved on every request (cached, and invalidated by any role, group,
assignment or grant change), so removing a role takes effect on the next request, not
when the token expires.

## Global and tenant scope

Where a role is held decides how far it reaches:

- A user of the **`master`** tenant is a **global** administrator. Their permissions
  apply to every tenant.
- A user of **any other tenant** is a **tenant** administrator. Their permissions apply
  to that tenant only; a request naming another tenant is refused with `403` ("this
  token is scoped to another tenant").

A few operations need a global administrator whatever the permissions say: creating
and deleting tenants, the master-key routes (`GET /admin/master-key`,
`POST /admin/master-key/rotate`) and the global audit chain (`/admin/audit`). A tenant
administrator listing `GET /admin/tenants` sees only their own tenant.

`GET /admin/me` reports the caller's user, tenant, `scope` (`global` or `tenant`),
roles and permissions; `ridm whoami` prints it.

To make someone the administrator of `acme` only, assign a built-in role to their
`acme` user:

```bash
ROLE_ID=$(curl -s -H "Authorization: Bearer $RIDM_TOKEN" \
  "https://id.example.com/admin/tenants/acme/roles?realm_only=true" |
  jq -r '.[] | select(.name == "ridm:admin") | .id')
curl -s -X PUT -H "Authorization: Bearer $RIDM_TOKEN" \
  "https://id.example.com/admin/tenants/acme/users/$USER_ID/roles/$ROLE_ID"
```

In the console: Users → the user → Roles → assign `ridm:admin`. They then sign in to
the console through `acme`.

## Organization administrators

A role assignment may carry an organization (`role_assignments.org_id`, see
[Organizations](../concepts/organizations.md)). Such a grant applies only to a session
acting in that organization — the `org_id` claim the sign-in put on the token — and
only to the admin routes of that one organization:

- everything under `/admin/tenants/{slug}/organizations/{org}`: the organization
  record, its members, its domains, the roles granted inside it, its invitations;
- nothing else. An org-scoped grant never satisfies a tenant-wide check, so the users,
  groups, clients, settings and audit routes stay closed, and so does the list of the
  tenant's organizations.

Three operations on the organization itself stay with the tenant's administrators,
because they are the tenant's business rather than the organization's: creating an
organization, deleting one, and changing an existing one's `slug` or `status`. Adding
an existing user as a member is theirs too — an organization's own administrator adds
people by inviting an email address
(`POST /admin/tenants/{slug}/organizations/{org}/invitations`, which creates the
membership when the invitation is accepted) or through a verified auto-join domain.
Such an invitation may not carry tenant roles or groups; roles are granted inside the
organization afterwards, and `GET …/{org}/grantable-roles` lists what the caller may
grant there.

To appoint one, grant `ridm:org-admin` (or any role) to a member within the
organization:

```bash
curl -s -X PUT -H "Authorization: Bearer $RIDM_TOKEN" \
  "https://id.example.com/admin/tenants/acme/organizations/$ORG_ID/members/$USER_ID/roles/$ROLE_ID"
```

In the console: Organizations → the organization → *Roles inside this organization*.
They sign in to the console as usual; with one membership the organization is chosen
silently, and the console then opens their organization instead of the tenant's pages.
`GET /admin/me` reports it as `organization`, with `organization_permissions` beside
the tenant-wide `permissions`.

Two limits are worth knowing. A **personal access token** belongs to a user rather
than to a sign-in, so it carries no organization and no org-scoped permission; org
administrators work through the console or a browser-issued token. And the
**MFA-for-administrators** policy counts them: a user who administers any organization
is an administrator for `mfa.policy = required_for_admins`.

### No escalation through role management

An administrator cannot hand out more than they hold. Assigning a role to a user or
group, adding a user to a group, adding a composite, granting an admin permission to a
role, and inviting someone into roles or groups are all refused with `403` ("cannot
grant permissions you do not hold") when the grant would carry an admin permission the
caller lacks. A user manager can therefore manage users but cannot make anyone an
owner. Inside an organization the same rule is measured against what the caller holds
*there*: an organization's administrator can appoint a peer, but cannot grant a role
that carries a tenant-wide admin permission.

## The admin token

Admin endpoints take a bearer token in the `Authorization` header only, never in a
query or form parameter. `Authorization: DPoP <token>` with a proof is accepted too,
and a DPoP-bound token must come with one. The token is either an access token or a
personal access token.

An **access token**, a JWT or an opaque `at_…` token of a client registered for opaque
tokens, may be issued by any tenant, and must:

- carry `urn:ridm:admin` in `aud`. The token endpoint only puts it there for clients
  that list it in `allowed_audiences`; it is never implied, even for clients with no
  audience restriction;
- belong to an active, unlocked user, or to a machine client's service-account user,
  whose effective roles grant at least one `ridm:*` permission;
- if it was issued in a browser session, come from a session that is still alive, so
  signing out ends admin access before the token expires;
- come from a tenant that is not disabled.

A missing or invalid token gets `401` with `WWW-Authenticate: Bearer realm="ridm-admin"`;
a valid token without the permission a route needs gets `403` with an
`application/problem+json` body naming it (see [Errors](../reference/errors.md)).

Every tenant carries a built-in public client, `ridm-admin-console`, that the admin
console signs in with: authorization code with PKCE, no consent step, and
`urn:ridm:admin` as its only audience. It cannot be deleted and is left out of tenant
exports. See [The admin and account consoles](consoles.md).

## Automation

Three ways to give a script or pipeline admin access, in order of how little they need:

### Personal access tokens

A user mints a personal access token (`rpat_…`) in the account console, under
Security, or through `POST /t/{slug}/account/tokens` with an account-console token:

```json
{ "name": "ci-config-sync", "scopes": ["ridm:tenants:export", "ridm:tenants:import", "ridm:tenants:read"], "expires_in_days": 90 }
```

- Scopes are `account` (the self-service API as the user) and any admin permission the
  user holds when the token is minted. At every use they are narrowed again to what
  the user still holds, so removing a role narrows every token at once, and a
  disabled or locked user's tokens stop working.
- The token is shown once and stored as a SHA-256 hash. It inherits the scope of its
  user: a `master` user's token is global.
- A token acts without a browser session, so nothing that needs a recent sign-in
  works with it, and a token can never mint another token.
- `settings.account.personal_tokens` (default `true`) switches minting off for a
  tenant; `settings.account.personal_token_max_days` (default `365`, `0` for no limit)
  caps the lifetime and is the default when none is asked for.
- `last_used_at` is recorded at most once a minute. Administrators list and revoke a
  user's tokens with `GET /admin/tenants/{slug}/users/{user}/pats` and
  `DELETE …/pats/{token_id}`, or on the user's "Password & credentials" tab; the
  tokens themselves are never readable again.

A personal access token is the simplest credential for CI: put it in `RIDM_TOKEN`
and the [`ridm` CLI](cli.md) needs no login.

### A machine client with a service account

For a credential that is not tied to a person:

1. Register a `machine` client (client credentials) with `urn:ridm:admin` in
   `allowed_audiences`.
2. Create its service account:
   `PUT /admin/tenants/{slug}/clients/{client}/service-account`. This makes a user
   named `svc-<client_id>` that `client_credentials` tokens are issued for.
3. Assign that user the roles it needs, such as `ridm:viewer` or a custom role.
4. Request tokens with `grant_type=client_credentials` and
   `resource=urn:ridm:admin`, or run
   `ridm login --client-id <id> --client-secret-stdin`.

Register the client in `master` for a global credential, or in the tenant it should
manage. See [Machine-to-machine access](../quickstarts/machine-to-machine.md) for the
client side.

### The device grant

A `device` client that lists `urn:ridm:admin` in its audiences lets an operator
approve a CLI session in a browser: `ridm login --client-id <id> --device`. The
approving user's permissions apply, and the CLI keeps a refresh token.
