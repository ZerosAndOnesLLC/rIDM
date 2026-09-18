# From Auth0

An Auth0 tenant maps onto an rIDM tenant. This page gives the concept mapping, how to
get users (with password hashes) and configuration out of Auth0, and `jq` scripts that
turn them into rIDM's [bulk user import](../admin/users.md#bulk-import) rows and a first
draft of a [tenant document](../reference/tenant-document.md). Read
[Migrating to rIDM](overview.md) first for what carries over in general.

## Concept mapping

| Auth0 | rIDM | Notes |
|-------|------|-------|
| Tenant | [Tenant](../concepts/tenants.md) | Issuer changes from `https://acme.us.auth0.com/` (trailing slash) to `https://id.example.com/t/acme`, or `https://login.acme.example` with a [custom domain](../admin/custom-domains.md) (no trailing slash) |
| Application: Single Page | Client `spa` | |
| Application: Regular Web | Client `web` | |
| Application: Native | Client `native` | Custom URL schemes and any loopback port allowed |
| Application: Machine to Machine | Client `machine` | See [Machine-to-machine applications](#machine-to-machine-applications) |
| Device authorization flow on an application | Client `device`, or the device grant on another type | |
| API | [Resource server](../concepts/resource-servers.md) | The API identifier becomes the resource server identifier, so `aud` stays the same |
| API permissions (scopes) | Permissions on the resource server, and scopes linked to it | |
| RBAC "Add Permissions in the Access Token" | Always on: a token for a resource server carries the user's `permissions` | |
| Roles, role permissions | Roles with `permissions` (`<API identifier>#<permission>`) | |
| User role assignments | `roles` on each import row | Not in the user export; see [Role assignments](#role-assignments) |
| `user_metadata`, `app_metadata` | User `attributes`, declared in the [profile schema](../admin/users.md#profile-schema) with `editable_by: user`, `admin` or `none` | `none` values are set only by bulk import and SCIM |
| API setting "Allow Offline Access" | Resource server `allow_offline_access` | Without it, `offline_access` is dropped from grants for that API and refresh tokens end with the user's session |
| Database connection | Local users with passwords | |
| Social connections | [Identity providers](../concepts/brokering.md): presets for Google, Microsoft, GitHub, Apple and GitLab; any other OpenID Connect or OAuth 2.0 provider configured by hand | |
| Enterprise: OpenID Connect, Microsoft Entra ID (Azure AD) | Identity provider (`oidc`, or the `microsoft` preset with your directory id in the issuer) | |
| Enterprise: SAML, AD/LDAP, ADFS | Not supported | SAML and LDAP are planned (Phase 13), not present |
| Passwordless connections (email, SMS) | `settings.auth.magic_link`, `email_otp`, `sms_otp` | |
| Custom database connection with "Import users to Auth0" (lazy migration) | No equivalent | rIDM cannot check a password against another system at sign-in |
| Organizations | Not yet | Organizations are planned (Phase 12), not present |
| Rules, Actions | Claim mappers, where they only add claims | See [Rules and Actions](#rules-and-actions) |
| MFA (Guardian): one-time password, SMS, email, WebAuthn | [Second factors](../concepts/mfa.md): TOTP, SMS and email codes, passkeys; policy in `settings.mfa` | Push notifications are not supported. Enrolments do not carry over |
| Adaptive MFA | Not yet | Planned (Phase 12) |
| Attack protection: brute-force, suspicious IP throttling | `settings.lockout` (per user and per IP) | |
| Attack protection: breached password detection | `settings.password.check_breached` | Checks passwords as they are set, against a Have I Been Pwned compatible range API |
| Bot detection | `settings.captcha` (Turnstile or hCaptcha) | |
| Universal Login branding, email templates | `settings.branding`, message templates | Templates are rewritten, not converted |
| Log streams | [Webhooks and the audit log](../admin/webhooks-audit.md) | |
| Custom domain | [Custom domain](../admin/custom-domains.md) | |

Auth0's SDKs (`auth0-spa-js`, `nextjs-auth0` and the rest) are written for Auth0's own
endpoint layout and features. Replace them with a generic OpenID Connect library that
reads discovery from the new issuer. rIDM's endpoints are all under the issuer:
`/authorize`, `/token`, `/userinfo`, `/end_session` (instead of `/oauth/token` and
`/v2/logout`); see [HTTP endpoints](../reference/endpoints.md).

## Exporting users

Auth0 exports users with a bulk export job on the Management API
([Bulk User Exports](https://auth0.com/docs/manage-users/user-migration/bulk-user-exports)).
The token needs the `read:users` scope. Omit `connection_id` to export every connection,
which includes social users; the `json` format produces newline-delimited JSON.

```bash
A0=https://acme.us.auth0.com
curl -s -X POST "$A0/api/v2/jobs/users-exports" \
  -H "Authorization: Bearer $A0_TOKEN" -H "Content-Type: application/json" \
  -d '{
        "format": "json",
        "fields": [
          {"name": "user_id"}, {"name": "email"}, {"name": "email_verified"},
          {"name": "username"}, {"name": "name"}, {"name": "given_name"},
          {"name": "family_name"}, {"name": "blocked"},
          {"name": "user_metadata"}, {"name": "app_metadata"}
        ]
      }'
# -> {"id": "job_…", "status": "pending", …}

curl -s "$A0/api/v2/jobs/job_…" -H "Authorization: Bearer $A0_TOKEN" | jq '{status, location}'
# when status is "completed", fetch location promptly (the link is short-lived)
curl -s -o users.json.gz "<location>" && gunzip users.json.gz
```

Each line is one user:

```json
{"user_id":"auth0|60425dc43519d90068f82973","email":"ada@example.com","email_verified":true,"given_name":"Ada","family_name":"Lovelace","name":"Ada Lovelace"}
```

### Password hashes

The export job never includes password hashes. Auth0 releases them only through a
support request, on paid plans, after an eligibility review; the file arrives
PGP-encrypted
([Export Password Hashes and MFA Secrets](https://auth0.com/docs/manage-users/user-migration/export-password-hashes-and-mfa-secrets)).
Once decrypted it is newline-delimited JSON, one line per database-connection user,
with bcrypt hashes:

```json
{"_id":{"$oid":"60425dc43519d90068f82973"},"email_verified":true,"email":"ada@example.com","passwordHash":"$2b$10$194fndLu5YaiEbZPc24zcuRddSGBuQj/45xU7hVf9AZsmHCxxIocS","password_set_date":{"$date":"2021-03-05T16:40:36.528Z"},"tenant":"acme","connection":"Username-Password-Authentication","_tmp_is_unique":true}
```

Auth0's own documentation does not publish this layout; the example follows what
Auth0 support has delivered and what other migration guides describe (for example
[ZITADEL's](https://zitadel.com/docs/guides/migrate/sources/auth0)). Check your file
against it. The `$oid` is the part of `user_id` after `auth0|`, which is how the two
files join. bcrypt (`$2a$`, `$2b$`, `$2y$`, any cost) is accepted by rIDM as it is, and
upgraded to argon2id at the first sign-in; no conversion is needed.

The same request can include MFA secrets. rIDM cannot import them; users enrol again
(see [Second factors](overview.md#second-factors)).

Without the hash export, import users without passwords and let them recover their
accounts, or use the gradual brokering route in [the overview](overview.md#big-bang-or-gradual).

### Role assignments

Neither export says which roles a user holds. Fetch the members of each role from the
Management API ([Get a role's users](https://auth0.com/docs/api/management/v2/roles/get-role-user))
into lines of `{"role": …, "user_id": …}`:

```bash
curl -s "$A0/api/v2/roles?per_page=100" -H "Authorization: Bearer $A0_TOKEN" \
  | jq -r '.[] | "\(.id)\t\(.name)"' |
while IFS=$'\t' read -r id name; do
  from=""
  while :; do
    page=$(curl -s "$A0/api/v2/roles/$id/users?take=100${from:+&from=$from}" \
             -H "Authorization: Bearer $A0_TOKEN")
    echo "$page" | jq -c --arg role "$name" '.users[] | {role: $role, user_id}'
    from=$(echo "$page" | jq -r '.next // empty')
    [ -n "$from" ] || break
  done
done > role-members.json
```

This uses checkpoint pagination (`take` and `from`, answered with `users` and `next`).
It was not run against a live Auth0 tenant; check the parameters against the
Management API reference for your tenant, and `per_page` if you have more than 100
roles.

## Converting users

```jq
# auth0-users.jq: Auth0 user export + password hash export -> rIDM bulk import rows.
# Usage:
#   jq -n --slurpfile pw passwords.json --slurpfile rm role-members.json \
#      -f auth0-users.jq users.json > import.json
# passwords.json: the NDJSON file from Auth0 support (use /dev/null if you have none)
# role-members.json: NDJSON lines {"role": "<name>", "user_id": "<Auth0 user_id>"}
#                    (use /dev/null if you do not use Auth0 roles)
($pw | map({ key: ._id["$oid"], value: .passwordHash }) | from_entries) as $hashes
| ($rm | group_by(.user_id) | map({ key: .[0].user_id, value: map(.role) }) | from_entries) as $roles
| [ inputs
    | {
        username: (.username // .email),
        email,
        email_verified: (.email_verified // false),
        status: (if .blocked == true then "disabled" else "active" end),
        attributes: ({ auth0_user_id: .user_id, given_name, family_name, name }
                     | with_entries(select(.value != null))),
        roles: ($roles[.user_id] // []),
        password_hash: $hashes[.user_id | sub("^auth0\\|"; "")]
      }
  ]
```

A database user with a hash comes out as:

```json
{
  "username": "ada@example.com",
  "email": "ada@example.com",
  "email_verified": true,
  "status": "active",
  "attributes": {
    "auth0_user_id": "auth0|60425dc43519d90068f82973",
    "given_name": "Ada",
    "family_name": "Lovelace",
    "name": "Ada Lovelace"
  },
  "roles": ["Support"],
  "password_hash": "$2b$10$194fndLu5YaiEbZPc24zcuRddSGBuQj/45xU7hVf9AZsmHCxxIocS"
}
```

Notes on the conversion:

- **Usernames.** Auth0 database connections usually have no username, so the email is
  used. rIDM lower-cases usernames.
- **Attributes.** Declare `auth0_user_id`, `given_name`, `family_name` and `name` in the
  profile schema (or turn on `allow_undeclared`), otherwise every row fails with
  "unknown attribute". `given_name`, `family_name` and `name` are among the claims the
  `profile` scope releases. `auth0_user_id` keeps the old `sub` (Auth0's `sub` is the
  `user_id`) for applications that need to map it; declare it `editable_by: none` so
  that nobody can change it after the import. See
  [Subject identifiers](overview.md#subject-identifiers).
- **Metadata.** The script leaves `user_metadata` and `app_metadata` out. To carry a
  field, add it to `attributes` in the script (for example
  `department: .app_metadata.department`) and declare it in the schema: `editable_by:
  user` for what was user metadata, `admin` (or `none`, when only imports and SCIM
  should ever set it) for what was app metadata. An attribute that should appear in
  tokens under its own name can list `id_token`, `userinfo` or `access_token` in its
  `visible_in`, with no claim mapper needed.
- **Social and enterprise users** (a `user_id` such as `google-oauth2|…`) are imported
  without a password. Configure the provider in rIDM with `link_policy:
  verified_email`, and the first sign-in through it links the upstream account to the
  imported user (see [Brokered users](overview.md#brokered-users)). A user whose email
  Auth0 did not verify will not be linked this way.
- **Duplicate emails.** Auth0 allows one address in several connections; rIDM allows it
  once per tenant. The second row fails as a conflict; decide which account survives
  before importing.
- **Roles** must exist in the tenant before the users are imported (apply the tenant
  document first).

The conversion was tested with bcrypt `$2b$10$` hashes generated for a password with
non-ASCII characters, joined and converted by the script above, then parsed by rIDM's
bulk-import parser and checked by rIDM's password verifier: the right password was
accepted and flagged for upgrade, a wrong one refused.

Split, dry-run and import as described in the [checklist](overview.md#checklist).

## Exporting applications and APIs

The Auth0 Deploy CLI exports a tenant's configuration as files
([Using as a CLI](https://github.com/auth0/auth0-deploy-cli/blob/master/docs/using-as-cli.md)).
Use the directory format, which writes one JSON file per resource in the Management
API's shapes, and `--export_ids` so client ids are included:

```bash
a0deploy export -c config.json --format directory --output_folder auth0-export --export_ids
```

`config.json` holds `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID` and `AUTH0_CLIENT_SECRET` of a
machine-to-machine application authorised for the Management API
([Authenticating with your tenant](https://github.com/auth0/auth0-deploy-cli/blob/master/docs/authenticating-with-tenant.md)).

This script drafts a tenant document from the `clients/`, `resource-servers/` and
`roles/` folders:

```jq
# auth0-tenant.jq: Auth0 Deploy CLI export (directory format) -> draft rIDM tenant document.
# Usage (from the export folder):
#   jq -n --arg slug acme --arg name "Acme" -f auth0-tenant.jq \
#      clients/*.json resource-servers/*.json roles/*.json > acme.json
def kind: input_filename | split("/") | .[-2];
def standard: ["openid", "profile", "email", "phone", "address", "offline_access"];
def ridm_grants: ["authorization_code", "refresh_token", "client_credentials",
                  "urn:ietf:params:oauth:grant-type:device_code"];
reduce inputs as $o ({}; .[$o | kind] += [$o])
| (.["resource-servers"] // [] | map(select(.identifier | endswith("/api/v2/") | not))) as $apis
| ([ $apis[] | (.scopes // [])[].value ] | unique) as $api_scopes
| {
    format: "ridm.tenant/1",
    tenant: { slug: $slug, display_name: $name },
    resource_servers: [ $apis[] | {
      identifier, name,
      token_ttl_secs: .token_lifetime,
      allow_offline_access: (.allow_offline_access // false),
      permissions: [ (.scopes // [])[] | { name: .value, description } ] } ],
    scopes: [ $apis[] | .identifier as $rs | (.scopes // [])[]
              | { name: .value, description, resource_server: $rs } ],
    roles: [ (.roles // [])[] | {
      name, description,
      permissions: [ (.permissions // [])[]
                     | "\(.resource_server_identifier)#\(.permission_name)" ] } ],
    clients: [ (.clients // [])[] | ({
        spa: "spa", regular_web: "web", native: "native", non_interactive: "machine"
      }[.app_type // "regular_web"]) as $type | select($type != null) | {
      client_id: (.client_id // (.name | ascii_downcase | gsub("[^a-z0-9._:-]+"; "-"))),
      name,
      client_type: $type,
      token_endpoint_auth_method: (.token_endpoint_auth_method // "client_secret_basic"),
      redirect_uris: (.callbacks // []),
      post_logout_redirect_uris: (.allowed_logout_urls // []),
      backchannel_logout_uri: (.oidc_backchannel_logout.backchannel_logout_urls // [] | first),
      cors_origins: ((.web_origins // []) + (.allowed_origins // []) | unique),
      allowed_grants: [ (.grant_types // [])[] | select(IN(ridm_grants[])) ],
      allowed_scopes: (if $type == "machine" then $api_scopes else standard + $api_scopes end)
    } | with_entries(select(.value != null)) ]
  }
```

Each Auth0 permission becomes both a permission on the resource server (what roles
grant, and what the `permissions` claim carries) and a scope linked to it (what a client
may request in `scope`, as it did with Auth0). The script was run on hand-written files
in the Deploy CLI's directory layout, and every generated client passed rIDM's client
validation; it has not been run on a real tenant's export, so review the draft:

- **Grants** other than the authorization code, refresh token, client credentials and
  device grants are dropped. rIDM does not support the implicit flow or the password
  grant (including Auth0's `password-realm`); applications using them move to the
  authorization code flow with PKCE.
- **Wildcards** in callback URLs (`https://*.acme.example/callback`) are copied as they
  are but never match, because rIDM compares redirect URIs exactly; list the real ones.
- **Applications without `--export_ids`** get a `client_id` made from their name, and
  their users' configuration must change to it. Other application types (the SSO
  integrations) are skipped.
- **The Management API** (identifier ending in `/api/v2/`) is left out; rIDM's own admin
  API is `urn:ridm:admin` and is never imported.
- **Secrets** are not in the document. Each confidential client gets a new secret in
  the import report, shown once.
- **Offline access.** The script copies each API's `allow_offline_access`, defaulting to
  `false` as Auth0 does. In rIDM that setting decides whether refresh tokens for the API
  may outlive the user's sign-in session (`offline_access`), so check it for every API
  whose clients keep users signed in for days.
- **Signing algorithm.** Auth0 APIs set to `RS256` need nothing: that is rIDM's default.
  rIDM does not sign with `HS256`; an API that used it must move to an asymmetric
  algorithm (`RS256`, `RS384`, `RS512`, `ES256` or `EdDSA`, settable per resource server
  as `signing_alg`).
- **Settings** are not converted; add `tenant.settings` (password policy, MFA,
  lockout, registration, branding) before applying, because an import replaces the
  tenant's settings as a whole. See [Tenants and tenant settings](../admin/tenants.md).

```bash
cd auth0-export
jq -n --arg slug acme --arg name "Acme" -f ../auth0-tenant.jq \
   clients/*.json resource-servers/*.json roles/*.json > ../acme.json
cd ..
ridm --tenant acme tenant diff   -f acme.json
ridm --tenant acme tenant import -f acme.json
```

### Machine-to-machine applications

Auth0 authorises a machine-to-machine application for an API with a client grant
(the Deploy CLI's `grants/` folder: `client_id`, `audience`, `scope`). In rIDM the
client's `allowed_audiences` lists the APIs it may get tokens for, and the permissions
in its tokens come from roles held by its
[service account](../admin/clients.md#service-accounts). For each grant, set
`service_account: true` and `allowed_audiences` on the client in the document, create a
role holding the granted permissions, and assign the role to the service account user
(`svc-<client_id>`) in the console or through the admin API. See
[Machine-to-machine access](../quickstarts/machine-to-machine.md).

## Rules and Actions

Rules and Actions are code; rIDM runs no customer code during sign-in. What they
commonly do, and where it goes:

| Rule or Action that… | In rIDM |
|----------------------|---------|
| adds a namespaced claim from user or app metadata (`api.idToken.setCustomClaim("https://acme.example/plan", …)`) | A `user_attribute` claim mapper with the same claim name, so APIs keep reading it: `{"type": "user_attribute", "attribute": "attributes.plan", "claim": "https://acme.example/plan", "include_in": ["id", "access"]}` |
| adds the user's roles to the token | A `roles` mapper: `{"type": "roles", "claim": "https://acme.example/roles", "include_in": ["access"]}`. Access tokens also carry `roles` by default |
| adds a fixed value | A `hardcoded` mapper |
| builds a string from user fields | A `template` mapper (Handlebars over `user`, `tenant`, `client`, `roles`, `groups`) |
| requires MFA for some users | `settings.mfa`: `required_for_roles` or `required_for_admins` |
| blocks sign-in by email domain, IP or country | `registration.allowed_email_domains` for sign-up; [IP rules](../admin/security-controls.md) for addresses; no country rules |
| notifies another system after sign-in or sign-up | [Webhooks](../admin/webhooks-audit.md) on `login.*` and `user.*` events (after the fact, not in the flow) |
| calls an external API to decide, enriches the profile from one, or redirects mid-flow | Not supported |

Claim names are free, except the protected claims (`iss`, `sub`, `aud`, `exp`, `scope`,
`acr`, `amr`, `cnf`, `act` and the rest) and `permissions`, which no mapper may set, and
`roles` and `groups`, which only a mapper of that type may set (replacing the built-in
claim). A mapper that breaks these rules is refused when it is saved.
