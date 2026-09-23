# From Keycloak

Keycloak and rIDM share most of their vocabulary, so a realm maps onto a tenant
closely. This page gives the concept mapping, how to export a realm, and two `jq`
scripts: one that drafts a [tenant document](../reference/tenant-document.md) from the
realm export, and one that turns the exported users, including their password hashes,
into [bulk import](../admin/users.md#bulk-import) rows. Read
[Migrating to rIDM](overview.md) first for what carries over in general.

## Concept mapping

| Keycloak | rIDM | Notes |
|----------|------|-------|
| Realm | [Tenant](../concepts/tenants.md) | Issuer changes from `https://kc.example.com/realms/acme` to `https://id.example.com/t/acme` (or a custom domain) |
| Client (OpenID Connect) | [Client](../concepts/clients.md) | `client_id` and redirect URIs carry over; secrets do not |
| Bearer-only client, or a client that only represents an API | [Resource server](../concepts/resource-servers.md) | Its `clientId` becomes the resource server identifier, so the `aud` your API checks can stay the same |
| Client scope | [Scope](../concepts/resource-servers.md#scopes-what-the-user-agreed-to) | A scope's `claims` list names the user claims it releases at userinfo (and in the ID token for clients with `id_token_scope_claims`); `is_default` corresponds to a default client scope. Protocol mappers do not hang off scopes; they become tenant-wide or per-client claim mappers |
| Realm role | Role (no `client`) | |
| Client role | Role with `client` set to the client's `client_id` | Referenced as `client_id/name` in composites and group roles |
| Client role on an API client | Permission on that resource server, granted to roles | rIDM separates "what the user may do in this API" (permissions, in the `permissions` claim) from role names |
| Composite role | Role `composites` | |
| Group, subgroups, group attributes | Group with `path`, `attributes` | Sibling names are unique; the same name may appear under different parents |
| Group role mappings | Group `roles` | |
| User attributes, user profile (declarative) | [Profile schema](../admin/users.md#profile-schema) and user `attributes` | Undeclared attributes are refused unless `allow_undeclared` is on |
| Protocol mapper | [Claim mapper](../concepts/users-groups-roles.md#claims-from-users-groups-and-roles) | See [Protocol mappers](#protocol-mappers) |
| Identity provider (OpenID Connect, social) | [Identity provider](../concepts/brokering.md) (`oidc` or `oauth2`, presets for Google, Microsoft, GitHub, Apple, GitLab) | First-broker-login flow becomes `link_policy` |
| Identity provider (SAML) | [SAML identity provider](../admin/saml-upstream.md) (`saml`) | |
| User federation (LDAP) | [LDAP directory](../admin/ldap.md) (`ldap`): bind authentication, periodic and on-sign-in sync, group mapping, `edit_mode` `read_only` or `writable` | Keycloak's `UNSYNCED` mode has no equivalent; users are always linked to the directory |
| User federation (Kerberos), Kerberos authenticator | [Kerberos provider](../admin/kerberos.md) (`kerberos`): SPNEGO with the service's keytab, users matched by name or looked up in an LDAP provider | AES tickets only (no RC4, no RFC 8009 types); no credential delegation |
| Required actions | See [Required actions](#required-actions) | |
| Authentication flows | Tenant settings: `auth`, `mfa`, `mfa_methods`, `lockout`, `captcha`, `registration` | rIDM's flow is fixed; its steps are switched on and off, not rearranged |
| Password policy | `settings.password` | See [Realm settings](#realm-settings) |
| Brute-force detection | `settings.lockout` | |
| Events, admin events | [Audit log and webhooks](../admin/webhooks-audit.md) | |
| Themes, email templates | `settings.branding`, message templates | Templates are rewritten, not converted |
| Service account of a client | `service_account: true` on the client | |
| Token exchange | Token exchange (RFC 8693), per-client `allowed_audiences` | |
| Offline access, offline sessions | The `offline_access` scope | A refresh token granted `offline_access` outlives the SSO session's timeouts (not an explicit sign-out); without it, it ends with the session. Each resource server can refuse it with `allow_offline_access: false` |
| Authorization services (resources, policies, permissions, UMA) | Not supported | rIDM's authorization model is roles granting permissions on resource servers; there is no policy engine or UMA |
| Custom SPIs (authenticators, mappers, storage) | Not supported | Rebuild the behaviour with claim mappers, webhooks or in the application |
| SAML clients | [SAML service providers](../admin/saml-idp.md) | Registered by hand or from metadata; signing keys are rIDM's own, not the realm's |

## Exporting a realm

Use the command-line export. The admin console's partial export (Realm settings →
Action → Partial export) leaves users out and replaces secrets with `*`; it is enough
for drafting the tenant document but not for users. See Keycloak's
[Importing and exporting realms](https://www.keycloak.org/server/importExport).

```bash
# Keycloak 17 and later (Quarkus distribution). The server must not be running;
# give the export the same database options the server uses.
bin/kc.sh export --dir /tmp/kc-export --realm acme --users different_files --users-per-file 1000
```

This writes `acme-realm.json` and `acme-users-0.json`, `acme-users-1.json`, and so on.
`--users realm_file` puts the users into the realm file instead; `skip` leaves them
out. Users from a user-federation provider are written to
`acme-federated-users-<n>.json` and have no password credential.

The export contains every user's password hash and TOTP secret. Treat the files as
secrets, and delete them when the migration is done.

## Drafting the tenant document

This script turns `acme-realm.json` into a first draft of a `ridm.tenant/1` document.
It keeps OpenID Connect clients (skipping Keycloak's built-in `account`,
`account-console`, `admin-cli`, `broker`, `realm-management` and
`security-admin-console`), turns bearer-only clients into resource servers and their
roles into permissions, and carries realm roles, client roles, composites, groups and
a few realm settings.

```jq
# keycloak-tenant.jq: Keycloak realm export -> draft rIDM tenant document.
# Usage: jq -f keycloak-tenant.jq acme-realm.json > acme.json
def builtin_clients: ["account", "account-console", "admin-cli", "broker",
                      "realm-management", "security-admin-console"];
def builtin_role: startswith("default-roles-") or . == "offline_access"
                  or . == "uma_authorization";
def uris: if . == null then [] else split("##") | map(select(. != "")) end;
def single: map_values(if type == "array" and length == 1 then .[0] else . end);

. as $realm
| (.clients // [] | map(select((.protocol // "openid-connect") == "openid-connect"
                              and ((.clientId | IN(builtin_clients[])) | not)))) as $all
| ($all | map(select(.bearerOnly != true))) as $clients
| ($all | map(select(.bearerOnly == true)) | map(.clientId)) as $apis
| ($clients | map(.clientId)) as $cids
# A role reference in rIDM's notation: "name" (realm) or "client_id/name".
| def refs: [ ((.realm // [])[] | select(builtin_role | not)),
              ((.client // {}) | to_entries[] | select(.key | IN($cids[]))
               | .key as $c | .value[] | "\($c)/\(.)") ];
# Keycloak roles on a bearer-only client become permissions on a resource server.
  def perms: [ (.client // {}) | to_entries[] | select(.key | IN($apis[]))
               | .key as $c | .value[] | "\($c)#\(.)" ];
  def role(client): { name, client: client, description,
                      composites: (.composites // {} | refs),
                      permissions: (.composites // {} | perms) };
  def groups(parent): .[] | (parent + [.name]) as $p
      | { path: $p, attributes: (.attributes // {} | single),
          roles: ({ realm: .realmRoles, client: .clientRoles } | refs) },
        (.subGroups // [] | groups($p));
{
  format: "ridm.tenant/1",
  tenant: {
    slug: .realm,
    display_name: (.displayName // .realm),
    settings: {
      session: ({ idle_timeout_secs: .ssoSessionIdleTimeout,
                  absolute_timeout_secs: .ssoSessionMaxLifespan,
                  access_token_ttl_secs: .accessTokenLifespan }
                | with_entries(select(.value != null))),
      registration: ({ enabled: .registrationAllowed,
                       require_email_verification: .verifyEmail }
                     | with_entries(select(.value != null)))
    }
  },
  resource_servers: [ $apis[] as $a | {
    identifier: $a, name: $a,
    permissions: [ $realm.roles.client[$a] // [] | .[] | { name, description } ] } ],
  clients: [ $clients[] | . as $c | {
    client_id: .clientId,
    name: (.name // .clientId | if startswith("${") then $c.clientId else . end),
    status: (if .enabled == false then "disabled" else "active" end),
    service_account: (.serviceAccountsEnabled // false),
    client_type: (if .publicClient then "spa"
                  elif .serviceAccountsEnabled and (.standardFlowEnabled == false) then "machine"
                  else "web" end),
    token_endpoint_auth_method: (if .publicClient then "none"
                                 elif .clientAuthenticatorType == "client-jwt" then "private_key_jwt"
                                 else "client_secret_basic" end),
    redirect_uris: [ (.redirectUris // [])[]
                     | if startswith("/") then ($c.rootUrl // "") + . else . end ],
    post_logout_redirect_uris: (.attributes["post.logout.redirect.uris"] | uris),
    allowed_grants: ([ if .standardFlowEnabled != false then "authorization_code", "refresh_token" else empty end,
                       if .serviceAccountsEnabled then "client_credentials" else empty end,
                       if .attributes["oauth2.device.authorization.grant.enabled"] == "true"
                       then "urn:ietf:params:oauth:grant-type:device_code" else empty end ]),
    require_consent: (.consentRequired // false),
    cors_origins: [ (.webOrigins // [])[] | select(. != "+" and . != "*") ],
    jwks_uri: (if .clientAuthenticatorType == "client-jwt" then .attributes["jwks.url"] else null end),
    backchannel_logout_uri: .attributes["backchannel.logout.url"]
  } | with_entries(select(.value != null)) ],
  roles: [ (.roles.realm // [])[] | select(.name | builtin_role | not) | role(null) ],
  groups: [ .groups // [] | groups([]) ]
}
| .roles += [ $all[] | select(.clientId | IN($cids[])) | .clientId as $c
              | ($realm.roles.client[$c] // [])[] | role($c) ]
```

Then review the draft, dry-run it, and apply it:

```bash
jq -f keycloak-tenant.jq /tmp/kc-export/acme-realm.json > acme.json
ridm --tenant acme tenant diff   -f acme.json      # the plan; nothing changes
ridm --tenant acme tenant import -f acme.json      # plan, confirm, apply
```

The script was checked against Keycloak's own sample realm exports from its test suite
and a synthetic realm; each generated client was run through rIDM's client validation.
What it does not do, and what to review by hand:

- **Wildcard redirect URIs** (`https://app.example.com/*`) are copied as they are. rIDM
  accepts them as URLs but compares redirect URIs exactly, so a wildcard never matches.
  Replace each with the real callback URLs.
- **Relative redirect URIs** are prefixed with the client's `rootUrl`; a client without
  one fails its import with "is not a valid URL".
- **Public clients** become `spa`. Change mobile and desktop apps to `native`, which
  allows custom URL schemes and any loopback port.
- **`webOrigins`** of `+` ("the origins of the redirect URIs") and `*` are dropped;
  list the origins a browser client calls the token endpoint from in `cors_origins`.
- **Clients that only used the direct access grant** (resource owner password) fail with
  "authorization_code clients need at least one redirect_uri", or import without the
  grant. rIDM does not support the password grant or the implicit flow; such
  applications have to move to the authorization code flow with PKCE.
- **`client-secret-jwt`** authentication has no equivalent; the script maps it to
  `client_secret_basic`. `client-jwt` becomes `private_key_jwt` with the client's
  `jwks.url`; a client with an inline key needs its `jwks` added by hand.
- **Group role mappings on bearer-only clients** are dropped, because a group holds roles,
  not permissions. Grant those permissions through a role and give the group the role.
- **Keycloak display names** such as `${client_account}` are replaced by the client id.
- **Client scopes, protocol mappers and identity providers** are not converted; add them
  as shown below.
- **Settings** in the document replace the tenant's settings as a whole; add the
  password policy and the rest before applying (next section).

## Realm settings

| Keycloak | rIDM (`tenant.settings`) |
|----------|--------------------------|
| Password policy `length(n)`, `maxLength(n)` | `password.min_length`, `password.max_length` |
| `upperCase`, `lowerCase`, `digits`, `specialChars` | `password.require_uppercase`, `require_lowercase`, `require_digit`, `require_symbol` (booleans: rIDM requires at least one, not a count) |
| `passwordHistory(n)` | `password.history` |
| `forceExpiredPasswordChange(days)` | `password.max_age_days` |
| `notUsername`, `notEmail` | Always on: a password may not contain the username or the email's local part (when four characters or longer) |
| `hashAlgorithm`, `hashIterations` | Deployment-wide argon2id parameters, `ARGON2_M_COST_KIB`, `ARGON2_T_COST`, `ARGON2_P_COST` ([Server configuration](../reference/configuration.md)) |
| SSO Session Idle / Max | `session.idle_timeout_secs`, `session.absolute_timeout_secs` |
| Access Token Lifespan | `session.access_token_ttl_secs` (clients and resource servers can override) |
| User registration, Verify email | `registration.enabled`, `registration.require_email_verification` |
| Terms and conditions (required action) | `registration.require_terms`, `registration.terms_url` |
| Brute force detection: max login failures, wait increment | `lockout.max_failures`, `lockout.lock_minutes` (a fixed lock, not an increasing one) |
| Internationalization, supported locales | `locale` |
| OTP policy | Fixed: TOTP, SHA-1, six digits, 30-second steps |

See [Tenants and tenant settings](../admin/tenants.md) for every setting.

## Required actions

| Keycloak required action | rIDM |
|--------------------------|------|
| `UPDATE_PASSWORD` | `must_change_password: true` on the import row (the user script below sets it) |
| `CONFIGURE_TOTP` | MFA policy `required` (tenant-wide) or `required_for_roles`; there is no per-user flag |
| `UPDATE_PROFILE` | Mark profile attributes `required`: a user missing one is asked for it at sign-in |
| `TERMS_AND_CONDITIONS` | `registration.require_terms`: every user who has not accepted, imported users included, is asked at sign-in |
| `VERIFY_EMAIL` | No equivalent at sign-in. Imported users keep the `email_verified` they had |
| `webauthn-register` | Passkey enrolment at the MFA step (`auth.passkey`) |

Do not mark an attribute `required` before importing users that lack it: user creation
checks required attributes and the row fails.

## Protocol mappers

Claim mappers cover the common Keycloak mapper types. Keycloak's "Add to ID token",
"Add to access token" and "Add to userinfo" switches become `include_in` (`id`,
`access`, `userinfo`).

| Keycloak mapper | rIDM mapper `config` |
|-----------------|----------------------|
| User Attribute, User Property | `{"type": "user_attribute", "attribute": "attributes.department", "claim": "department"}` (user fields: `username`, `email`, `email_verified`, `phone`, `locale`, `id`, …; a bare name that is not a user field is read as the profile attribute of that name) |
| Group Membership (Full group path on/off) | `{"type": "groups", "claim": "groups", "full_path": true}` |
| User Realm Role | `{"type": "roles", "claim": "realm_roles"}` |
| User Client Role | `{"type": "roles", "claim": "portal_roles", "client_id": "portal"}` (only that client's roles) |
| Hardcoded claim | `{"type": "hardcoded", "claim": "tier", "value": "gold"}` |
| Audience | `{"type": "audience", "audience": "orders-api"}` |
| Script mapper | `{"type": "template", "claim": "...", "template": "{{user.username}}@{{tenant.slug}}"}` where a Handlebars template can express it; otherwise not supported |

A claim name is used literally: rIDM does not build nested objects from dotted names,
so Keycloak's `realm_access.roles` and `resource_access.<client>.roles` cannot be
reproduced. Every access token already carries the effective role names in `roles`,
the groups in `groups`, and, for a resource server, the granted `permissions`. Point
APIs at those claims (checking `permissions` is the better design; see
[Resource servers, scopes and permissions](../concepts/resource-servers.md)).
Protected claims (`iss`, `sub`, `aud`, `exp`, `acr`, `amr`, `scope`, `cnf`, `act` and
the rest) and `permissions` cannot be set by a mapper, and `roles` and `groups` only by
a mapper of that type, which then replaces the built-in claim; a mapper that breaks
these rules is refused when it is saved.

Keycloak's "User Attribute" mappers that only copy an attribute under its own name
need no mapper at all: list `id_token`, `userinfo` and `access_token` as needed in the
attribute's `visible_in` in the profile schema.

In the tenant document a mapper is `{"name": ..., "client": <client_id or absent>, "config": {...}}`:

```json
"claim_mappers": [
  { "name": "department",
    "config": { "type": "user_attribute", "attribute": "attributes.department",
                "claim": "department", "include_in": ["id", "userinfo"] } },
  { "name": "portal-roles", "client": "portal",
    "config": { "type": "roles", "client_id": "portal", "claim": "portal_roles",
                "include_in": ["access", "id"] } }
]
```

## Identity providers

A Keycloak OpenID Connect or social identity provider becomes an entry in
`identity_providers`, without its client secret (set it after the import). Keycloak's
first-broker-login behaviour maps onto `link_policy`:

| Keycloak first broker login | rIDM `link_policy` |
|-----------------------------|--------------------|
| Automatically link an existing account with a verified, matching email | `verified_email` |
| Review profile / confirm link, then link after re-authentication | `explicit` (the user links from the account console) |
| Always create a new account | `always_new` |

Register rIDM's callback, `https://id.example.com/t/acme/broker/<alias>/callback`, with
the upstream provider; it replaces Keycloak's `/realms/acme/broker/<alias>/endpoint`.
Keycloak stores the links between users and upstream accounts (`federatedIdentities`),
but rIDM has no import for them; with `verified_email` they are re-created at each
user's next brokered sign-in.

## Converting users and password hashes

Keycloak stores a password credential as two JSON strings. `credentialData` names the
algorithm and its parameters; `secretData` holds the salt and hash, both standard base64
(see Keycloak's
[`Pbkdf2PasswordHashProvider`](https://github.com/keycloak/keycloak/blob/main/server-spi-private/src/main/java/org/keycloak/credential/hash/Pbkdf2PasswordHashProvider.java)
and
[`Argon2PasswordHashProvider`](https://github.com/keycloak/keycloak/blob/main/crypto/default/src/main/java/org/keycloak/crypto/hash/Argon2PasswordHashProvider.java)):

```json
{
  "type": "password",
  "secretData": "{\"value\":\"gD0eGu4V…Vym0=\",\"salt\":\"oYHN6Zdt8/w/gqBDTSSwyQ==\",\"additionalParameters\":{}}",
  "credentialData": "{\"hashIterations\":600000,\"algorithm\":\"pbkdf2-sha256\",\"additionalParameters\":{}}"
}
```

How each algorithm converts:

| Keycloak `algorithm` | Keycloak default | rIDM format | Conversion |
|----------------------|------------------|-------------|------------|
| `pbkdf2-sha256` | 600 000 iterations, 256-bit key (older versions: 27 500 iterations, 512-bit key) | `$pbkdf2-sha256$<iterations>$<salt>$<hash>` | Copy: rIDM decodes standard base64 with padding, and verifies with the key length it finds |
| `pbkdf2-sha512` | 210 000 iterations, 512-bit key | `$pbkdf2-sha512$<iterations>$<salt>$<hash>` | Copy |
| `argon2` | argon2id, version 1.3, m=7168 KiB, t=5, p=1, 32-byte hash | `$argon2<type>$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<hash>` | PHC string; strip the base64 `=` padding. Version `1.0` becomes `v=16`; types `i` and `d` become `$argon2i$` and `$argon2d$` |
| `pbkdf2` (HMAC-SHA1) | 1 300 000 iterations (older versions: 27 500) | none | Not supported; those users need a password reset |
| a custom hash provider | | | Not supported unless it produces one of the formats rIDM accepts |

Every one of these is upgraded to argon2id under the server's parameters at the first
successful sign-in. PBKDF2 iteration counts above 10 000 000 are refused.

The user script:

```jq
# keycloak-users.jq: Keycloak realm export (users) -> rIDM bulk user import rows.
# Usage: jq -s -f keycloak-users.jq acme-users-*.json > users.json
def nopad: gsub("="; "");
def phc:
  (.credentialData | fromjson) as $d
  | (.secretData | fromjson) as $s
  | ($d.additionalParameters // {}) as $p
  | if $d.algorithm == "pbkdf2-sha256" or $d.algorithm == "pbkdf2-sha512" then
      "$\($d.algorithm)$\($d.hashIterations)$\($s.salt)$\($s.value)"
    elif $d.algorithm == "argon2" then
      "$argon2\($p.type[0])$v=\(if $p.version[0] == "1.0" then 16 else 19 end)"
      + "$m=\($p.memory[0]),t=\($d.hashIterations),p=\($p.parallelism[0])"
      + "$\($s.salt | nopad)$\($s.value | nopad)"
    else null end;       # "pbkdf2" (HMAC-SHA1) and custom providers: no rIDM equivalent
[ .[] | (.users // [])[]
  | select(.serviceAccountClientId == null)          # service-account users stay behind
  | {
      username,
      email,
      email_verified: (.emailVerified // false),
      status: (if .enabled == false then "disabled" else "active" end),
      attributes: (
        { keycloak_id: .id, given_name: .firstName, family_name: .lastName }
        + ((.attributes // {}) | map_values(if length == 1 then .[0] else . end))
        | with_entries(select(.value != null))
      ),
      roles: [ (.realmRoles // [])[]
               | select(startswith("default-roles-") or . == "offline_access"
                        or . == "uma_authorization" | not) ],
      groups: [ (.groups // [])[] | split("/") | last ],
      password_hash: ([ (.credentials // [])[] | select(.type == "password") | phc ] | first),
      must_change_password: ((.requiredActions // []) | index("UPDATE_PASSWORD") != null)
    }
]
```

`-s` slurps every user file into one array, so the same command works for one file or
many, and for a realm file exported with `--users realm_file`. A pbkdf2-sha256 user comes
out as:

```json
{
  "username": "alice",
  "email": "alice@example.com",
  "email_verified": true,
  "status": "active",
  "attributes": {
    "keycloak_id": "550d2e8a-06f3-40ac-b4a7-5f4a32cf4ae4",
    "given_name": "Alice",
    "family_name": "Example",
    "department": "Sales"
  },
  "roles": ["editor"],
  "groups": ["sales"],
  "password_hash": "$pbkdf2-sha256$600000$oYHN6Zdt8/w/gqBDTSSwyQ==$gD0eGu4VA0woP+PLJI6jA/O6NAvmLMxE3ioVRL0Vym0=",
  "must_change_password": false
}
```

Before importing:

- **Declare the attributes** the rows carry (`given_name`, `family_name`, `keycloak_id`
  and every custom attribute) in the tenant's profile schema, or turn on
  `allow_undeclared`; an undeclared attribute fails its row. `given_name` and
  `family_name` are among the claims the `profile` scope releases. `keycloak_id` is
  there to map the old `sub` (Keycloak's `sub` is the user's `id`); declare it
  `editable_by: none` so that nobody can change it after the import; see
  [Subject identifiers](overview.md#subject-identifiers).
- **Roles and groups must exist** (import the tenant document first). The import assigns
  realm roles only; client roles in `clientRoles` are not carried by the script, because
  a user row cannot name a client role. Grant them through a group, or afterwards
  through the admin API. Groups are matched by name, not path: where two groups share a
  name under different parents, the row lands in one of them, so rename one or fix the
  membership afterwards.
- **Second factors** (`otp` and `webauthn` credentials in the export) are not imported;
  see [Second factors](overview.md#second-factors).

Then dry-run and import as described in the [checklist](overview.md#checklist).

The conversion was tested end to end: credentials generated by a Java program that
calls the same JDK `PBKDF2WithHmacSHA256`/`SHA512` and BouncyCastle
`Argon2BytesGenerator` code paths Keycloak does (pbkdf2-sha256 at 600 000 and at
27 500 iterations with the older 512-bit key, pbkdf2-sha512, argon2id with Keycloak's
defaults, and argon2i with other parameters, for a password with non-ASCII
characters), converted with the script above, parsed by rIDM's bulk-import parser, and
verified by rIDM's password verifier, which accepted the right password, refused a
wrong one, and asked for each hash to be upgraded.
