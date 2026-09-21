# Tenants and tenant settings

A tenant is an isolated identity realm with its own issuer
(`https://id.example.com/t/acme`), users, clients, keys and settings. This page covers
creating and managing tenants and every key of the tenant settings document. For what
a tenant is, see [Tenants and issuers](../concepts/tenants.md).

## The master tenant

Every deployment has a `master` tenant, created by the first migration. Its users are
global administrators (see [Administrator access](access.md)). It cannot be disabled or
deleted. Keep ordinary users and applications in their own tenants; `master` is for
the people who run the deployment.

## Creating a tenant

Creating tenants needs `ridm:tenants:create`, which only a global owner holds.

| Where | How |
|-------|-----|
| Console | Tenants (`/console/tenants/`) → New tenant; you land on the new tenant's settings |
| CLI | `ridm tenant create acme --name "Acme Corp"` |
| API | `POST /admin/tenants` |

```http
POST /admin/tenants
Authorization: Bearer rpat_…
Content-Type: application/json

{ "slug": "acme", "display_name": "Acme Corp", "settings": { "registration": { "enabled": true } } }
```

- `slug` is 1–63 lowercase letters, digits or hyphens, not starting or ending with a
  hyphen. It is part of every URL of the tenant (`/t/acme/…`) and cannot change.
- `display_name` is 1–255 characters; it is shown on the login pages and in the console.
- `settings` is optional: anything left out takes the defaults below.

A new tenant is seeded with the standard scopes (`openid`, `profile`, `email`,
`phone`, `address`, `offline_access`), the `urn:ridm:admin` and `urn:ridm:account`
resource servers, the six built-in admin roles, and the two built-in console clients
(`ridm-admin-console`, `ridm-account-console`). Its first signing key is made on first
use. It has no users: invite or create an administrator for it next (see
[Users, invitations and bulk import](users.md)).

## Managing a tenant

| Task | Console | API | Permission |
|------|---------|-----|------------|
| List tenants | Tenants | `GET /admin/tenants?cursor=&limit=` | `ridm:tenants:read`; tenant administrators see only their own |
| Read a tenant | Settings | `GET /admin/tenants/{slug}` | `ridm:tenants:read` |
| Rename, disable, change settings | Settings | `PATCH /admin/tenants/{slug}` | `ridm:tenants:write` |
| Delete | Settings → delete zone (global owners) | `DELETE /admin/tenants/{slug}` | `ridm:tenants:delete`, global |
| Export / import configuration | Export & import | `GET …/export`, `POST …/import` | `ridm:tenants:export` / `ridm:tenants:import` |

`PATCH` takes `display_name`, `status` (`active` or `disabled`) and `settings`. The
settings are a JSON merge patch (RFC 7396) over the stored document: send only what
changes, and `null` resets a key to its default. A field name the settings document
does not have is refused with `400` ("unknown settings fields: …") rather than silently
dropped, because it is almost certainly a typo; that includes the removed
`registration.captcha`. Tagged settings switch variant cleanly: `{"mfa": {"mode":
"optional"}}` replaces a `required_for_roles` policy without clearing `roles` by hand.

```bash
curl -s -X PATCH "https://id.example.com/admin/tenants/acme" \
  -H "Authorization: Bearer $RIDM_TOKEN" -H "Content-Type: application/json" \
  -d '{"settings": {"password": {"min_length": 14}, "mfa": {"mode": "required_for_admins"}}}'
```

A **disabled** tenant refuses every sign-in and token request, and its tokens stop
working at the admin API; administrators can still read it through the admin API and
re-enable it. **Deleting** a tenant permanently removes it and everything in it, with no
soft-delete period.

The console's Settings page (`/console/settings/`) shows every setting on one page and
saves as you go: changes are joined into one merge patch sent once typing pauses. The
header shows "Unsaved changes", "Saving…", "Saved", or the API's reason for refusing,
after which the stored settings are reloaded.

To keep settings in version control, export the tenant with
`ridm tenant export acme -o acme.json` and apply edits with `ridm tenant import`; see
[Configuration as code](../concepts/config-as-code.md).

## The settings document

Every key has a default, and a stored document written by an older version keeps
loading. The top-level keys:

| Key | Governs | Details |
|-----|---------|---------|
| `password` | Password rules and history | [below](#password) |
| `session` | Browser sessions, trusted devices, default token lifetimes | [below](#session) |
| `mfa` | When a second factor is demanded | [MFA policy](mfa-policy.md) |
| `mfa_methods` | Which second factors users may enrol | [MFA policy](mfa-policy.md) |
| `risk` | Scoring sign-ins, and what an unusual one costs | [Adaptive authentication](adaptive-auth.md) |
| `impersonation` | Whether administrators may sign in as users, and for how long | [Impersonation](impersonation.md) |
| `auth` | Which first-factor sign-in methods are offered | [below](#auth) |
| `registration` | Self-registration | [below](#registration) |
| `lockout` | Brute-force lockout | [below](#lockout) |
| `captcha` | When a CAPTCHA is demanded | [Rate limits, IP rules and CAPTCHA](security-controls.md) |
| `rate_limits` | Request ceilings on the OAuth and sign-in endpoints | [Rate limits, IP rules and CAPTCHA](security-controls.md) |
| `notifications` | Security notices to users | [below](#notifications) |
| `account` | What users may do in the account console | [below](#account) |
| `locale` | Languages of the login pages | [below](#locale) |
| `branding` | Look of the login pages | [below](#branding) |
| `keys` | Signing key algorithm and rotation | [below](#keys) |
| `discovery` | WebFinger issuer discovery | [below](#discovery) |
| `dcr` | Dynamic client registration: `disabled`, `open` or `initial_access_token` | [Registering clients](clients.md#dynamic-client-registration) |
| `audit` | Audit log retention | [below](#audit) |
| `custom_domain` | The tenant's own issuer host | [Custom domains](custom-domains.md) |
| `features` | Free-form feature flags | [below](#features) |

### password

| Key | Default | Meaning |
|-----|---------|---------|
| `min_length` | `12` | Minimum characters |
| `max_length` | `128` | Maximum characters |
| `require_uppercase` | `false` | Needs an uppercase letter |
| `require_lowercase` | `false` | Needs a lowercase letter |
| `require_digit` | `false` | Needs a digit |
| `require_symbol` | `false` | Needs a character that is neither alphanumeric nor whitespace |
| `history` | `5` | A new password must differ from this many previous ones, the current one included (`0` off) |
| `max_age_days` | `null` | Days until a password expires and must be changed (`null` never) |
| `check_breached` | `false` | Refuse passwords found in breach corpora |

The policy applies to users' own changes, registration, invitations, admin-set
passwords (unless `skip_policy` is sent) and imported plaintext passwords. Imported
hashes are not checked, since the plaintext is unknown.

### session

| Key | Default | Meaning |
|-----|---------|---------|
| `idle_timeout_secs` | `1800` (30 min) | A browser session ends after this long without use |
| `absolute_timeout_secs` | `43200` (12 h) | A session ends this long after sign-in, whatever its use |
| `max_concurrent` | `0` | Live sessions per user; the oldest is signed out first, with back-channel logout to its clients (`0` unlimited) |
| `remember_device_days` | `30` | How long a "remember this device" cookie skips the second factor |
| `access_token_ttl_secs` | `300` | Default access token lifetime |
| `refresh_token_ttl_secs` | `2592000` (30 days) | Default refresh token lifetime |
| `id_token_ttl_secs` | `300` | Default ID token lifetime |

A client may set its own token lifetimes, which take precedence over these defaults
(see [Registering clients](clients.md#token-lifetimes-and-format)).

The session timeouts bound refresh tokens too. A refresh token issued without the
`offline_access` scope belongs to the browser session it came from: it stops working
once that session ends, whether by sign-out, `idle_timeout_secs` or
`absolute_timeout_secs`, and each refresh counts as activity that extends the idle
window. A refresh token issued with `offline_access` outlives the session's timeouts
and lasts its own `refresh_token_ttl_secs`, though an explicit sign-out still revokes
it. Clients that need long-lived access without a browser, device-flow clients among
them, should request `offline_access`. See [Tokens](../concepts/tokens.md).

### auth

First-factor methods shown on the login page.

| Key | Default | Meaning |
|-----|---------|---------|
| `password` | `true` | Username or email and password |
| `magic_link` | `false` | A sign-in link by email |
| `email_otp` | `false` | A one-time code by email |
| `sms_otp` | `false` | A one-time code by text message (needs an SMS gateway, see [Email, SMS and templates](messaging.md)) |
| `passkey` | `false` | Passwordless sign-in with a passkey; also enables passkeys as a second factor |

### registration

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | `false` | Show "create an account" and accept self-registration |
| `require_email_verification` | `true` | New accounts stay `pending` until the emailed link is followed |
| `require_terms` | `false` | Registrants must accept the terms |
| `terms_url` | `null` | Terms of service link, shown to registrants and on the terms step |
| `privacy_url` | `null` | Privacy policy link |
| `allowed_email_domains` | `[]` | Only these email domains may register (empty: any) |

Whether registration demands a CAPTCHA is `captcha.on_registration` (see
[Rate limits, IP rules and CAPTCHA](security-controls.md#captcha)); in the console it sits
under Settings → Passwords & lockout. The earlier `registration.captcha` key is gone:
a migration carried any `true` value over to `captcha.on_registration`, a `PATCH` naming
it is refused, and a tenant import ignores it.

The fields a registrant fills in beyond username, email and password come from the
tenant's profile schema (see [Users](users.md#profile-schema)).

### lockout

| Key | Default | Meaning |
|-----|---------|---------|
| `max_failures` | `10` | Consecutive failed sign-ins before the account is locked temporarily (`0` off) |
| `lock_minutes` | `15` | How long that lock lasts |
| `ip_max_failures` | `100` | Failures from one address within the window before it is throttled (`0` off) |
| `ip_window_minutes` | `15` | That window |

An administrator clears a lock with `POST /admin/tenants/{slug}/users/{user}/unlock`
or the Unlock button on the user page.

### notifications

Security notices sent to the user by email, or by text message when they have no
email address. All default to `true`.

| Key | Sent when |
|-----|-----------|
| `new_device` | Someone signs in from a device not seen before |
| `password_changed` | The password changes |
| `mfa_changed` | A second factor is added or removed |
| `email_changed` | The email address changes (sent to the previous address) |

### account

What users may do to their own account in the account console. These keys are not on
the console's Settings page; change them with `PATCH /admin/tenants/{slug}` or a tenant
import.

| Key | Default | Meaning |
|-----|---------|---------|
| `self_deletion` | `true` | Users may delete their own account |
| `deletion_retention_days` | `30` | Days a deleted account (by the user or an administrator) is kept before the daily purge removes it |
| `personal_tokens` | `true` | Users may mint personal access tokens |
| `personal_token_max_days` | `365` | Longest, and default, personal access token lifetime (`0` no limit) |

### locale

| Key | Default | Meaning |
|-----|---------|---------|
| `default` | `"en"` | Language used when neither the request nor the user names a supported one |
| `supported` | `["en"]` | BCP 47 tags the login pages and messages may use |

Tags are normalised on save (`pt_BR` becomes `pt-BR`); a malformed tag, or a `default`
outside `supported`, is refused. An empty `supported` list becomes `[default]`. The
language of a page or message is negotiated from the OIDC `ui_locales` parameter, then
the user's stored `locale`, then `default`; a tag matches exactly or by language
(`de-CH` matches a supported `de`). Right-to-left languages (Arabic, Hebrew, Persian,
Urdu and others) set `dir="rtl"`.

The bundled UI ships English strings only, and falls back to English for other
languages. Message templates can be overridden per locale; see
[Email, SMS and templates](messaging.md).

### branding

| Key | Default | Meaning |
|-----|---------|---------|
| `logo_url` | `null` | Logo on the login pages |
| `favicon_url` | `null` | Browser tab icon |
| `primary_color` | `null` | Accent colour (buttons, links) |
| `background_color` | `null` | Page background |
| `support_url` | `null` | "Need help?" link |
| `custom_css` | `null` | Stylesheet applied to the login pages after the theme |
| `links` | `[]` | Extra footer links, each `{"label": "…", "url": "…"}` |

Branding, the display name, locales and the offered sign-in methods are published at
`GET /t/{slug}/branding`, a public, cacheable document every end-user page loads. The
console's branding editor (Settings → Branding) frames the real login page in preview
mode and applies each draft change as you type. Images are loaded from their URLs
over https; the pages' Content-Security-Policy allows images and fonts from any https
origin, so host them anywhere.

### keys

| Key | Default | Meaning |
|-----|---------|---------|
| `default_alg` | `"RS256"` | Algorithm for keys made by rotation: `RS256`, `RS384`, `RS512`, `ES256`, `EdDSA` |
| `rsa_bits` | `"B2048"` | RSA key size: `B2048`, `B3072`, `B4096` |
| `rotation_interval_days` | `90` | Rotate the active key automatically after this many days (`0` only on demand) |
| `retire_overlap_hours` | `24` | How long a retired key stays published so tokens it signed still verify |

See [Rotating keys](key-rotation.md).

### discovery

| Key | Default | Meaning |
|-----|---------|---------|
| `email_domains` | `[]` | WebFinger `acct:user@<domain>` lookups for these domains resolve to this tenant's issuer |

### audit

| Key | Default | Meaning |
|-----|---------|---------|
| `retention_days` | `365` | Days to keep audit rows (`0` forever) |

See [Webhooks and the audit log](webhooks-audit.md).

### features

A map of flag name to boolean, default `{}`. rIDM itself does not read these flags;
they are for the deployment or its applications to consult. Edit them under
Settings → General.

```json
{ "features": { "beta_dashboard": true } }
```

### custom_domain

A hostname such as `login.acme.example` (optionally with a port), lower-cased on save.
It must not be the deployment's own host and must not be used by another tenant.
Default `null`, meaning the issuer is `{PUBLIC_URL}/t/{slug}`. See
[Custom domains](custom-domains.md).

## Settings kept outside the document

Some tenant configuration holds secrets and so lives behind its own endpoints, stored
encrypted and never returned:

| Configuration | Endpoints | Page |
|---------------|-----------|------|
| CAPTCHA provider (site key, secret) | `GET/PUT/DELETE /admin/tenants/{slug}/captcha` | [Rate limits, IP rules and CAPTCHA](security-controls.md) |
| Email and SMS providers, templates | `/admin/tenants/{slug}/messaging/…` | [Email, SMS and templates](messaging.md) |
| User profile schema | `GET/PUT /admin/tenants/{slug}/profile-schema` | [Users](users.md#profile-schema) |
| IP allow and deny rules | `/admin/tenants/{slug}/ip-rules` | [Rate limits, IP rules and CAPTCHA](security-controls.md) |
