# Tenant configuration document

A tenant's configuration can be exported as one JSON document and applied back, to the same tenant or another one. The document is deterministic (sorted keys and sorted collections), keyed by natural identifiers rather than database ids, and free of secrets, so it can live in version control and be reviewed like code. The idea and the workflow are in [Configuration as code](../concepts/config-as-code.md); this page is the format reference. The implementation is [`api/src/services/tenant_config.rs`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/api/src/services/tenant_config.rs).

| Operation | API | CLI | Permission |
|-----------|-----|-----|------------|
| Export | `GET /admin/tenants/{slug}/export` | `ridm tenant export [slug] [-o FILE]` | `ridm:tenants:export` |
| Plan (dry run) | `POST /admin/tenants/{slug}/import?dry_run=true[&prune=true]` | `ridm tenant diff [slug] -f FILE [--prune] [--exit-code]` | `ridm:tenants:import` |
| Apply | `POST /admin/tenants/{slug}/import[?prune=true]` | `ridm tenant import [slug] -f FILE [--prune] [--yes]` | `ridm:tenants:import` |

Of the built-in roles only `ridm:owner` holds `ridm:tenants:import`; `ridm:admin` may export but not import.

## Top level

```json
{
  "format": "ridm.tenant/1",
  "tenant": { "slug": "acme", "display_name": "Acme", "settings": { } },
  "profile_schema": { "attributes": [], "allow_undeclared": false },
  "resource_servers": [],
  "scopes": [],
  "clients": [],
  "roles": [],
  "groups": [],
  "claim_mappers": [],
  "message_templates": [],
  "webhooks": [],
  "ip_rules": [],
  "identity_providers": []
}
```

| Field | Required | Meaning |
|-------|----------|---------|
| `format` | yes | must be `ridm.tenant/1`; anything else is refused |
| `tenant` | yes | name and settings ([below](#tenant)) |
| `profile_schema` | no | the user profile schema; defaults to an empty schema |
| `resource_servers` … `identity_providers` | no | collections, each defaulting to empty |

Unknown fields are refused at the top level and in every section, so a misspelt key fails the import rather than being dropped. The one exception is inside `tenant.settings`, which, like settings everywhere, ignores keys it does not know (they are not stored).

## What the document leaves out

The document is configuration, not data or credentials. It never contains:

- **Secrets**: client secrets, webhook signing secrets, identity providers' client secrets, registration access tokens.
- **Users** and everything attached to them: credentials, sessions, trusted devices, consents, personal access tokens, linked identities, role assignments to users and group memberships. Move users with the bulk user [import and export](../admin/users.md).
- **Provider credentials**: the email and SMS delivery settings and the CAPTCHA provider, which hold secrets.
- **Signing keys** (each tenant has its own), SCIM provisioning tokens, dynamic registration initial access tokens, invitations and the audit log.
- **Built-in objects**: the `ridm-admin-console` and `ridm-account-console` clients, the built-in `ridm:*` roles, and the built-in resource servers `urn:ridm:admin` and `urn:ridm:account`. Exports leave them out, an import naming a built-in client is refused, and pruning never deletes them. The standard scopes (`openid`, `profile`, `email`, `phone`, `address`, `offline_access`) are exported so their descriptions can be tuned, but pruning never deletes them either.

## Sections

### `tenant`

| Field | Meaning |
|-------|---------|
| `slug` | informational only: an import applies to the tenant named in the URL, so one document can configure several tenants |
| `display_name` | the tenant's name |
| `settings` | the complete tenant settings document |

The tenant's status (active or disabled) is not part of the document.

`settings` is applied as a whole, not merged: a section or field the document omits takes its **default**, not the tenant's current value. An export always writes every field, so round-tripping is safe; a hand-written document that omits `settings` resets the tenant's settings to defaults, and the plan shows it. `custom_domain` is part of the settings and must be unique across tenants, so clear it before applying a production export to another tenant.

| Settings section | Fields (default) |
|------------------|------------------|
| `password` | `min_length` (12), `max_length` (128), `require_uppercase`, `require_lowercase`, `require_digit`, `require_symbol` (all `false`), `history` (5), `max_age_days` (`null`, never), `check_breached` (`false`) |
| `session` | `idle_timeout_secs` (1800), `absolute_timeout_secs` (43200), `max_concurrent` (0, unlimited), `remember_device_days` (30), `access_token_ttl_secs` (300), `refresh_token_ttl_secs` (2592000), `id_token_ttl_secs` (300) |
| `mfa` | `{"mode": "off"}`; also `optional`, `required`, `required_for_admins`, `{"mode": "required_for_roles", "roles": [...]}` |
| `mfa_methods` | `totp` (`true`), `email_otp` (`false`), `sms_otp` (`false`) |
| `risk` | `enabled` (`false`), `weights` (`new_device` 20, `new_country` 50, `impossible_travel` 60, `velocity` 40), `step_up_at` (50), `block_at` (100), `impossible_travel_kmh` (900), `velocity_window_minutes` (15), `velocity_max_failures` (10) |
| `auth` | first-factor methods: `password` (`true`), `magic_link`, `email_otp`, `sms_otp`, `passkey` (all `false`) |
| `registration` | `enabled` (`false`), `require_email_verification` (`true`), `require_terms` (`false`), `terms_url`, `privacy_url` (`null`), `allowed_email_domains` (`[]`, any). A leftover `captcha` key from older exports is ignored; the setting is `captcha.on_registration` |
| `locale` | `default` (`"en"`), `supported` (`["en"]`) |
| `branding` | `logo_url`, `favicon_url`, `primary_color`, `background_color`, `support_url`, `custom_css` (all `null`), `links` (`[]` of `{label, url}`) |
| `keys` | `default_alg` (`"RS256"`; also `RS384`, `RS512`, `ES256`, `EdDSA`), `rsa_bits` (`"B2048"`; also `B3072`, `B4096`), `rotation_interval_days` (90, 0 = never), `retire_overlap_hours` (24) |
| `discovery` | `email_domains` (`[]`): WebFinger `acct:` domains that resolve to this tenant |
| `dcr` | `mode` (`"disabled"`; also `open`, `initial_access_token`), `allowed_grants` (`[]`), `require_pkce` (`true`) |
| `lockout` | `max_failures` (10), `lock_minutes` (15), `ip_max_failures` (100), `ip_window_minutes` (15) |
| `captcha` | `after_failures` (3, 0 = never), `on_registration` (`true`) |
| `notifications` | `new_device`, `password_changed`, `mfa_changed`, `email_changed` (all `true`) |
| `audit` | `retention_days` (365, 0 = forever) |
| `account` | `self_deletion` (`true`), `deletion_retention_days` (30), `personal_tokens` (`true`), `personal_token_max_days` (365, 0 = no limit) |
| `rate_limits` | `enabled` (`true`), `window_secs` (60), `token_per_ip` (600), `token_per_client` (1200), `authorize_per_ip` (300), `flows_per_ip` (600), `tenant_total` (0, off) |
| `custom_domain` | `null`, or a host name |
| `features` | `{}`: free-form boolean flags |

What each setting does is described in [Tenants and tenant settings](../admin/tenants.md).

### `profile_schema`

`{"attributes": [...], "allow_undeclared": false}`. Each attribute:

| Field | Meaning |
|-------|---------|
| `name` | attribute name, stored under the user's `attributes` |
| `type` | `string`, `number`, `boolean`, `email`, `url`, `phone`, `date` (`YYYY-MM-DD`), `enum`, `json` |
| `label`, `description` | shown in forms |
| `required`, `multivalued` | booleans, default `false` |
| `editable_by` | `user` (default), `admin`, `none` |
| `visible_in` | any of `id_token`, `userinfo`, `access_token`: the attribute appears there as a claim of its name (see [Token claims](token-claims.md#profile-attributes)) |
| `validation` | `min_length`, `max_length`, `pattern` (anchored regular expression), `min`, `max`, `values` (for `enum`) |
| `order` | position in forms |

The schema is replaced as a whole when it differs.

### `resource_servers`

Keyed by `identifier`.

| Field | Default | Meaning |
|-------|---------|---------|
| `identifier` | | the audience URI; immutable |
| `name` | | display name |
| `token_ttl_secs` | `null` | caps the lifetime of access tokens for this audience |
| `signing_alg` | `null` | `RS256`, `RS384`, `RS512`, `ES256` or `EdDSA`: access tokens for this audience are signed with the tenant's key of that algorithm (created on save if missing); `null` uses the tenant's `keys.default_alg` |
| `allow_offline_access` | `true` | `false` drops `offline_access` from any grant whose audience includes this server |
| `permissions` | `[]` | `[{name, description?}]` |

`permissions` is authoritative: when a resource server is created or updated, permissions missing from its list are deleted, with or without `prune`.

### `scopes`

Keyed by `name`: `name`, `description`, `claims` (`[]`: the claims the scope releases at `/userinfo`, and in ID tokens of clients with `id_token_scope_claims`), `is_default` (`false`: granted when a request names no scope), and `resource_server` (the identifier of the resource server the scope is bound to, or `null`; requesting a bound scope targets that server). See [Token claims](token-claims.md#scopes-in-the-token).

### `clients`

Keyed by `client_id`. Besides `client_id`, a client document carries:

| Field | Default | Meaning |
|-------|---------|---------|
| `status` | `active` | or `disabled` |
| `service_account` | `false` | whether the client has a service-account user for `client_credentials` (created or removed to match) |

and every metadata field `POST /admin/tenants/{slug}/clients` accepts: `name` (required), `client_type` (`spa`, `web`, `native`, `machine`, `device`), `description`, `logo_uri`, `client_uri`, `tos_uri`, `policy_uri`, `token_endpoint_auth_method`, `jwks`, `jwks_uri`, `redirect_uris`, `post_logout_redirect_uris`, `allowed_grants`, `allowed_scopes`, `allowed_audiences`, `access_token_ttl_secs`, `refresh_token_ttl_secs`, `id_token_ttl_secs`, `access_token_format`, `id_token_encryption` (`{alg, enc}`), `subject_type`, `sector_identifier_uri`, `require_pkce`, `require_consent`, `id_token_scope_claims`, `cors_origins`, `initiate_login_uri`, `backchannel_logout_uri`, `frontchannel_logout_uri`, `dpop_bound_access_tokens`. See [Registering clients](../admin/clients.md).

Before comparing, rIDM fills omitted fields with the defaults the client type implies, exactly as creating the client would, so a minimal document does not read as a change against the export of the client it created.

### `roles`

Keyed by `name`, or `client_id/name` for a client role.

| Field | Meaning |
|-------|---------|
| `name` | role name |
| `client` | `client_id` of the client the role belongs to; absent for a realm role |
| `description` | |
| `composites` | role references: `name` for a realm role, `client_id/name` for a client role |
| `permissions` | `resource-server-identifier#permission-name`, e.g. `https://orders.example#orders:read` |

`composites` and `permissions` are authoritative for each role in the document: links not listed are removed.

### `groups`

Keyed by path.

| Field | Meaning |
|-------|---------|
| `path` | names from the root down, e.g. `["staff", "engineering"]`; the last is the group's own name |
| `description` | |
| `attributes` | a JSON object (`{}` by default) |
| `roles` | role references the group grants its members; authoritative |

Parents are applied before children, and a group whose path changed is a delete (with `prune`) plus a create. Members are not part of the document.

### `claim_mappers`

Keyed by `name`, or `client_id/name` for a client's mapper: `name`, `client` (`client_id`, or absent for a tenant-wide mapper) and `config`, the mapper document (`{"type": ..., "include_in": [...]}`) described in [Token claims](token-claims.md#claim-mappers).

### `message_templates`

Keyed by `channel/event/locale`. Only tenant overrides are exported; the built-in templates are not.

| Field | Meaning |
|-------|---------|
| `channel` | `email` or `sms` |
| `event` | the message event, e.g. `password_reset` |
| `locale` | e.g. `en` |
| `subject` | email subject (email only) |
| `body_text` | required |
| `body_html` | optional HTML body (email only) |

The events and their variables are listed in [Email, SMS and templates](../admin/messaging.md).

### `webhooks`

Keyed by `name`: `name`, `url`, `events` (exact names, prefixes such as `user.*`, or `*`), `enabled` (`true`), `headers` (an object of extra request headers, `{}`), `max_attempts` (8). The signing secret is not in the document; a webhook created by an import gets a fresh one, reported once. See [Events, audit and webhooks](../concepts/events.md).

### `ip_rules`

Keyed by `cidr`, or `client_id/cidr` for a client's rule: `cidr` (normalised, so `10.0.0.1/8` compares equal to `10.0.0.0/8`), `action` (`allow` or `deny`, default `deny`), `client` (a `client_id`, or absent for a tenant-wide rule), `description`.

### `identity_providers`

Keyed by `alias` (lower-cased).

| Field | Default | Meaning |
|-------|---------|---------|
| `alias` | | the provider's name in `/broker/{alias}/...` |
| `kind` | `oidc` | or `oauth2` |
| `display_name` | | button label |
| `preset` | `null` | `google`, `microsoft`, `github`, `apple`, `gitlab` |
| `enabled`, `hidden` | `true`, `false` | |
| `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri` | `null` | upstream endpoints |
| `client_id` | | rIDM's client id at the provider |
| `token_endpoint_auth_method` | `client_secret_basic` | or `client_secret_post`, `none` |
| `scopes` | `[]` | scopes requested upstream |
| `pkce` | `true` | |
| `link_policy` | `verified_email` | or `explicit`, `always_new` |
| `trust_email` | `false` | |
| `mappers` | `{}` | `subject`, `username`, `email`, `email_verified` (claim names) and `attributes` (profile attribute → claim) |
| `sort_order` | 0 | |

The client secret is never part of the document. An update keeps the stored secret; a provider created by an import has none, and the report lists its alias under `secrets.identity_providers` so you can set it (`PATCH .../identity-providers/{alias}` with `client_secret`). See [Identity brokering](../concepts/brokering.md).

## How an import works

1. **Parse and normalise.** The document is checked (`format`, unknown fields, duplicate keys within a collection) and brought into the shape an export would have: client defaults filled in, CIDRs normalised, reference lists sorted and de-duplicated, empty `attributes` and `headers` made `{}`.
2. **Plan.** The tenant is exported and compared with the document, collection by collection, on the natural keys above. An item only in the document is a `create`; an item in both that differs is an `update`, with the changed fields; an item only in the tenant is a `delete`, but only with `prune`. Without `prune` an import only adds and changes.
3. **Apply** (skipped for a dry run). Changes are applied in dependency order: tenant settings, profile schema, resource servers, scopes, clients, roles (rows first, then composites and permissions), groups (parents first), claim mappers, message templates, webhooks, IP rules, identity providers. Deletions run afterwards in reverse order.

Each change is applied independently: a change that fails is reported in `errors` and the others still go ahead, so an import is not a single transaction. Fix the reported problems and apply again. Applying the same document twice gives an empty plan the second time.

An import cannot hand out admin permissions the importing administrator does not hold. A role or group whose new composites, permissions or roles would grant `ridm:*` permissions beyond the importer's own is refused and left unchanged, reported in `errors` as `cannot grant permissions you do not hold: …`. A role the same document defines counts with the permissions it will have once imported. A dry run finds these refusals without changing anything and lists them in its `errors` too, so a plan shows what the apply would refuse; `ridm tenant diff` fails on them and `ridm tenant import` prints them before asking.

### Report

A dry run and an apply both answer `200` with the same shape:

```json
{
  "dry_run": false,
  "prune": false,
  "changes": [
    {
      "resource": "client",
      "key": "orders-web",
      "op": "create"
    },
    {
      "resource": "webhook",
      "key": "audit-feed",
      "op": "update",
      "fields": [
        { "field": "max_attempts", "from": 8, "to": 12 }
      ]
    }
  ],
  "summary": { "create": 1, "update": 1, "delete": 0, "unchanged": 11 },
  "applied": 2,
  "errors": [],
  "secrets": {
    "clients": { "orders-web": "k3Jd..." },
    "webhooks": {},
    "identity_providers": []
  }
}
```

| Field | Meaning |
|-------|---------|
| `changes[].resource` | `tenant`, `profile_schema`, `resource_server`, `scope`, `client`, `role`, `group`, `claim_mapper`, `message_template`, `webhook`, `ip_rule`, `identity_provider` |
| `changes[].key` | the natural key |
| `changes[].op` | `create`, `update`, `delete` |
| `changes[].fields` | for updates: `{field, from, to}` for each top-level field that differs |
| `summary` | counts; `unchanged` counts items present on both sides and equal |
| `applied` | changes applied successfully (0 for a dry run) |
| `errors` | `[{resource, key, error}]` for changes that failed; in a dry run, the changes the apply would refuse under the rule above |
| `secrets` | present only when the import created something with a secret: `clients` (`client_id` → secret) and `webhooks` (name → secret), shown this once; `identity_providers` lists providers that still need their client secret |

The `tenant` change is the exception to field-level diffs: it compares the name and the settings as one pair, so its single entry has an empty `field` and carries `[display_name, settings]` before and after in full; compare the two to see what moved.

`ridm tenant diff --exit-code` exits `3` when the plan is not empty, so a pipeline can detect drift; `ridm tenant import` shows the plan and asks before applying unless `--yes` is given (required when standard input is not a terminal).

## Annotated example

[`examples/demo-tenant.json`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/examples/demo-tenant.json) is the document behind the [example relying parties](https://github.com/ZerosAndOnesLLC/rIDM/tree/main/examples). Abridged:

```json
{
  "format": "ridm.tenant/1",
  "tenant": {
    "slug": "demo",
    "display_name": "Example Orders Co."
  },
  "resource_servers": [
    {
      "identifier": "https://orders.example",
      "name": "Orders API",
      "allow_offline_access": true,
      "permissions": [
        { "name": "orders:read", "description": "See orders" },
        { "name": "orders:write", "description": "Place orders" }
      ]
    }
  ],
  "scopes": [
    { "name": "orders:read", "description": "See your orders", "resource_server": "https://orders.example" },
    { "name": "orders:write", "description": "Place orders on your behalf", "resource_server": "https://orders.example" }
  ],
  "roles": [
    {
      "name": "orders-manager",
      "description": "May see and place orders",
      "permissions": ["https://orders.example#orders:read", "https://orders.example#orders:write"]
    }
  ],
  "clients": [
    {
      "client_id": "orders-web",
      "name": "Orders (server-side web app)",
      "client_type": "web",
      "token_endpoint_auth_method": "client_secret_basic",
      "redirect_uris": ["http://localhost:3200/callback"],
      "post_logout_redirect_uris": ["http://localhost:3200/"],
      "backchannel_logout_uri": "http://localhost:3200/backchannel-logout",
      "allowed_grants": ["authorization_code", "refresh_token"],
      "allowed_scopes": ["openid", "profile", "email", "offline_access", "orders:read", "orders:write"],
      "allowed_audiences": ["https://orders.example"],
      "require_pkce": true,
      "require_consent": false
    }
  ]
}
```

Reading it top to bottom:

- `tenant` has no `settings`, so applying this document to an existing tenant plans to reset its settings to the defaults. It is meant for a fresh tenant, where that is no change.
- The resource server `https://orders.example` is the audience of the Orders API and declares two permissions. Tokens requested for it (the client lists it in `allowed_audiences`, so it is the default audience) carry the permissions the user's roles hold on it in the `permissions` claim.
- The two custom scopes belong to that resource server. `profile`, `email` and the other standard scopes are not listed: they exist in every tenant, and without `prune` an import never deletes anything.
- The role `orders-manager` grants both permissions, referenced as `identifier#name`. Users are not in the document; assign the role to users or groups afterwards.
- `orders-web` is a confidential client (`client_secret_basic`). The document carries no secret: the first import creates the client and returns its secret once under `secrets.clients`. Omitted fields (token lifetimes, `subject_type`, and so on) take the `web` type's defaults.

Applying it to a new tenant called `demo`:

```bash
ridm tenant create demo --name "Example Orders Co."
ridm tenant diff demo -f examples/demo-tenant.json      # review the plan
ridm tenant import demo -f examples/demo-tenant.json    # apply; prints the client secret once
```

or with the API:

```bash
curl -s -X POST "https://id.example.com/admin/tenants/demo/import?dry_run=true" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @examples/demo-tenant.json | jq .summary
```
