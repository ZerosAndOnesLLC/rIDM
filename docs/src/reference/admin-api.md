# Admin API (OpenAPI)

Everything the admin console does, it does through the admin API under `/admin`, and the same API is there for your own automation. This page describes how the API is organised and the conventions every operation shares. The operation-by-operation reference is rendered from the OpenAPI document:

- **[Rendered reference](admin-api/index.html)**: every path, parameter, request body, response schema and required permission.
- **[`openapi.json`](admin-api/openapi.json)**: the raw OpenAPI 3.1 document, the same one the server serves at `GET /openapi.json`.

The document also covers the self-service account API (`/t/{slug}/account/...`, tag `account`), which follows the same conventions but authenticates differently; see [HTTP endpoints](endpoints.md#account-api).

## Where the document comes from

The document is derived from the admin routers themselves with utoipa ([`api/src/openapi.rs`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/api/src/openapi.rs)), so an undocumented route fails the build, and a test keeps the committed [`api/openapi.json`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/api/openapi.json) equal to what the binary produces. Three ways to get it:

```bash
curl -s https://id.example.com/openapi.json          # from a running server, no auth
cargo run -p ridm-api -- openapi > openapi.json      # from source, no database needed
docker run --rm <image> openapi > openapi.json       # from the container image
```

`info.version` is the server's crate version (`0.1.0-dev` today). Swagger UI is served at `/docs` when `DOCS_ENABLED=true`.

## Organisation

Operations are grouped by tag. Operation ids are the handler names prefixed with their tag (`users_list`, `clients_create`), unique across the document as client generators require.

| Tag | Covers |
|-----|--------|
| `auth` | the caller's identity (`GET /admin/me`) and the permission catalogue with the built-in roles (`GET /admin/permissions`) |
| `tenants` | tenants and their settings, CAPTCHA provider, profile schema, statistics |
| `tenant_config` | [configuration as code](tenant-document.md): `GET .../export`, `POST .../import` |
| `clients` | OAuth / OIDC clients, secrets, service accounts, registration access tokens, and the initial access tokens of dynamic registration (`/admin/tenants/{slug}/dcr/initial-access-tokens`) |
| `users` | users and everything attached to them: password, sessions, credentials, trusted devices, roles, groups, consents, linked identities, personal access tokens, bulk import and export |
| `groups` | groups, membership and group roles |
| `roles` | roles, composites, permission grants and holders |
| `resource_servers` | resource servers (audiences) and their permissions |
| `scopes` | OAuth scopes |
| `mappers` | claim mappers |
| `keys` | signing keys, and master-key rotation |
| `invitations` | invitations |
| `messaging` | email and SMS delivery settings, templates, the delivery log |
| `audit` | the audit log, export and chain verification |
| `webhooks` | webhooks and their deliveries |
| `scim` | SCIM provisioning tokens |
| `ip_rules` | IP allow and deny rules |
| `identity_providers` | upstream OpenID Connect and OAuth 2.0 providers |
| `account` | the self-service account API |

Almost everything is tenant-scoped under `/admin/tenants/{slug}/...`. The exceptions are `/admin/me`, `/admin/permissions`, `/admin/tenants` (list and create), `/admin/master-key` and the global audit chain at `/admin/audit`.

## Authentication

Every admin operation takes a token in the `Authorization` header only (never a query or form parameter):

- **An access token** whose `aud` includes `urn:ridm:admin`: a JWT (`typ: at+jwt`), or an opaque `at_...` token of a client registered with `access_token_format: opaque`. The token endpoint grants that audience only to clients that list it in `allowed_audiences` explicitly; it is never implied, even for clients whose audiences are otherwise unrestricted. The subject must be an active user, or the service-account user of a machine client. When the token was issued in a browser session, the session must still be alive, so signing out ends admin access before the token expires. A DPoP-bound token must be presented as `Authorization: DPoP` with a valid proof.
- **A personal access token** (`rpat_...`) minted by the user in the account console, carrying admin permissions as its scopes. Its reach is the intersection of those scopes and what the user still holds.

The token may come from any tenant. A token issued by `master` is **global**: it may act on every tenant. A token from any other tenant reaches only that tenant; a request for another tenant is `403`. Tenant lifecycle operations (creating and deleting tenants, master-key rotation, the global audit chain) need a global token.

Permissions are resolved from the user's effective roles on every request (cached, and evicted whenever a role, group or grant changes), so revoking a role takes effect at once regardless of the `permissions` claim in the token. See [Administrator access](../admin/access.md).

### Permissions

Each operation requires one permission named `ridm:<resource>:<action>`; the rendered reference and `GET /admin/permissions` list which. The catalogue:

| Resource | Permissions |
|----------|-------------|
| tenants | `ridm:tenants:read`, `write`, `create`, `delete`, `export`, `import` |
| users | `ridm:users:read`, `write` |
| invitations | `ridm:invitations:read`, `write` (also bulk user import) |
| groups | `ridm:groups:read`, `write` |
| roles | `ridm:roles:read`, `write` |
| clients | `ridm:clients:read`, `write` |
| scopes | `ridm:scopes:read`, `write` |
| claim mappers | `ridm:mappers:read`, `write` |
| resource servers | `ridm:resource-servers:read`, `write` |
| identity providers | `ridm:idps:read`, `write` |
| keys | `ridm:keys:read`, `write` |
| messaging | `ridm:messaging:read`, `write` |
| audit | `ridm:audit:read` |
| webhooks | `ridm:webhooks:read`, `write` |
| SCIM tokens | `ridm:scim:read`, `write` |

IP rules and the CAPTCHA provider fall under `ridm:tenants:read` / `write`. Custom roles may be granted wildcards (`ridm:users:*`, `ridm:*`). Every tenant is seeded with five immutable built-in roles:

| Role | Grants |
|------|--------|
| `ridm:owner` | every permission |
| `ridm:admin` | everything except `ridm:tenants:create`, `ridm:tenants:delete`, `ridm:tenants:import` |
| `ridm:user-manager` | users, invitations, groups and SCIM tokens; read tenant settings, roles and audit |
| `ridm:client-manager` | clients, scopes, claim mappers, resource servers; read tenant settings, roles and audit |
| `ridm:viewer` | every `*:read` permission |

An administrator can never grant a permission they do not hold themselves, whether through a role assignment, a composite, a group membership or an invitation.

## Request and response conventions

| Convention | Detail |
|------------|--------|
| Bodies | `application/json`, except user import, which also takes `text/csv`. Create and update bodies reject unknown fields, so a typo fails loudly instead of being ignored. |
| Identifiers | Path parameters take the resource's UUID; clients also accept the public `client_id`, identity providers their `alias`. |
| Create | `POST` to the collection, usually `201` with the created resource. A generated secret (client secret, webhook secret, SCIM token, DCR initial access token, temporary password) appears in that response only. |
| Update | `PATCH` with the changed fields only. For tenant settings and client metadata the body is a JSON merge patch (RFC 7396): absent means unchanged, `null` clears a field or resets it to its default. |
| Replace, link | `PUT` on a sub-resource (`.../roles/{role_id}`, `.../members/{user_id}`) creates the link; `DELETE` removes it. Whole documents such as the profile schema and messaging settings are replaced with `PUT`. |
| Delete | `DELETE`, usually `204`. Users are soft-deleted and purged after the tenant's retention. |
| Secrets on read | Never returned. Reads report `secret_set`, `password_set` or `client_secret_set` instead; omitting a secret on update keeps the stored one. |
| Caching | Responses that carry secrets or exports are `Cache-Control: no-store`. |

### Pagination and filtering

Large collections (tenants, users, clients, invitations, the audit log) use keyset pagination:

```http
GET /admin/tenants/acme/users?limit=100&cursor=eyJ0IjoiMjAyNi0wOS0xOFQwOTowMDowMFoiLCJpIjoi...
```

```json
{
  "items": [ ... ],
  "next_cursor": "eyJ0IjoiMjAyNi0wOS0xOFQwOTowMToxMloiLCJpIjoi..."
}
```

| Parameter | Meaning |
|-----------|---------|
| `limit` | page size, default 50, clamped to 1–500 |
| `cursor` | the previous page's `next_cursor`, passed back unchanged. It is opaque; a malformed one is `400` |

`next_cursor` is absent on the last page. Pages are stable while rows are inserted, because the cursor encodes the position (creation time and id) rather than an offset. Smaller collections (groups, roles, resource servers, scopes, claim mappers, keys, webhooks, IP rules, identity providers) return every item as one JSON array. The webhook delivery log and the message log take `?status=` and `?limit=` (default 100) and return the most recent entries.

Filters are query parameters on the collection:

| Collection | Filters |
|------------|---------|
| `users` | `search` (username or email prefix), `status`, `org_id`, `include_deleted` |
| `clients` | `search` (prefix of `client_id` or name) |
| `invitations` | `open_only` |
| `roles` | `client_id`, `realm_only` |
| `claim-mappers`, `ip-rules` | `client_id`, `tenant_wide` |
| `keys` | `status` (`pending`, `active`, `retiring`, `revoked`) |
| `audit` | `from`, `to`, `name` (exact, or a prefix when it ends in `.` or `*`), `actor_id`, `subject_id`, `user_id` |
| `stats` | `days` (1–365, default 30) |
| `users/export`, `audit/export` | `format` (`json` or `csv`) |

### Errors

Errors are RFC 9457 problem documents (`application/problem+json`) with a stable `type` URN such as `urn:ridm:error:forbidden`; see [Errors](errors.md#problem-documents-rfc-9457). A missing or invalid token is `401` with `WWW-Authenticate: Bearer realm="ridm-admin"`; a valid token without the needed permission is `403` with `detail` naming it. The admin API is not rate limited by the request guard.

## Example

A machine client for automation: create it with the `client_credentials` grant and `urn:ridm:admin` in `allowed_audiences`, give it a service account (`PUT /admin/tenants/{slug}/clients/{client}/service-account`), and assign that account a role such as `ridm:user-manager`. Then:

```bash
ISSUER=https://id.example.com/t/acme

TOKEN=$(curl -s "$ISSUER/token" \
  -u "provisioner:$CLIENT_SECRET" \
  -d grant_type=client_credentials \
  -d resource=urn:ridm:admin | jq -r .access_token)

curl -s "https://id.example.com/admin/tenants/acme/users?search=alice&limit=20" \
  -H "Authorization: Bearer $TOKEN" | jq '.items[] | {id, username, email}'
```

For scripts run by a person, a personal access token is simpler: mint one in the account console with the admin permissions it needs and send it the same way (`Authorization: Bearer rpat_...`). The [`ridm` command line](../admin/cli.md) wraps the common operations and accepts either kind of token.

## Generating a client

Any OpenAPI 3.1 generator works against the document. The bundled UI generates its TypeScript types with `openapi-typescript` and calls the API through `openapi-fetch`:

```bash
cargo run -p ridm-api -- openapi > api/openapi.json
cd ui && npm run gen:api          # writes lib/api/openapi.d.ts
```

For another language, point your generator at the same file, for example:

```bash
npx @openapitools/openapi-generator-cli generate \
  -i api/openapi.json -g python -o ridm-admin-client
```

The document declares one security scheme, `bearer` (HTTP bearer, JWT format), and every operation requires it. A personal access token is sent under the same scheme.
