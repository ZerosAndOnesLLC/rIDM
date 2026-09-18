# The admin and account consoles

rIDM ships two browser consoles in its Next.js UI (`ui/`):

- the **admin console** at `/console/`, where administrators manage tenants, users,
  clients and everything else the admin API offers;
- the **account console** at `/account/`, where end users manage their own profile,
  security and connected applications.

Both are static pages served from wherever the UI is hosted, the same host as the
login pages. `UI_URL` tells the server where that is (it defaults to `PUBLIC_URL`),
because the consoles' built-in clients redirect there. Today the UI is served by
`next dev` or by any static host serving the `ui/out` export; serving it from the
API binary itself is planned, not present. See
[Deployment overview](../deploy/overview.md).

Neither console has privileges of its own. Each is an ordinary OIDC public client of
the tenant you sign in through, and every action it takes is an API call made with
your token, checked like any other.

## The admin console

Open `https://id.example.com/console/` (or wherever `UI_URL` points).

### Signing in

Signed out, every console page shows a card asking which tenant to sign in through.
Global administrators use `master`; the administrator of `acme` alone uses `acme`. The
last tenant used is remembered. The browser then goes through that tenant's normal
login page, including a forced password change or a second factor if one is due, and
comes back to `/console/callback/` with an authorization code that the page exchanges
with PKCE.

The client it signs in with is `ridm-admin-console`, built into every tenant: public,
PKCE only, no consent step, and `urn:ridm:admin` as its only audience. It is created
at start-up and with every new tenant, and its redirect URIs are kept in line with
`UI_URL`. It cannot be deleted. See [Administrator access](access.md) for what makes a
user an administrator.

Tokens live in the tab's `sessionStorage`, not in cookies or `localStorage`, so each
tab signs in on its own and closing it forgets them. The access token is refreshed
shortly before it expires, with refresh-token rotation. Because admin tokens are bound
to the browser session, **Sign out** (RP-initiated logout) ends both the console and
the tenant session at once. If the API starts refusing the token (a revoked session, a
removed role), the console drops back to the sign-in card with a notice.

A user who signs in but holds no admin permission gets `403` from the API, and the
console says "This account has no administrator permissions".

### Finding your way

- **Sidebar**: grouped as Identity, Applications, Security, Integrations and Tenant,
  and filtered by your permissions from `GET /admin/me`, so it only lists pages you can
  open. Below the tablet breakpoint it becomes a drawer.
- **Tenant switcher** (global administrators): pick the tenant every page acts on.
  The choice travels in the URL as `?tenant=acme`, so links deep-link into a tenant.
  Tenant administrators always act on their own tenant.
- **Search** (`Ctrl K` / `⌘ K`, or `/`): console pages you may open, plus users and
  clients of the current tenant whose username, email, client ID or name starts with
  what you type (two characters or more).
- **Theme**: system, light or dark, kept per browser.

### Keyboard shortcuts

Single keys work when no text field has focus; `?` lists them.

| Keys | Does |
|------|------|
| `Ctrl K` / `⌘ K`, `/` | Search |
| `t` | Tenant switcher (global administrators) |
| `?` | The shortcut list |
| `g` then `o` | Overview |
| `g` then `u` / `g` / `r` | Users / Groups / Roles |
| `g` then `c` / `a` / `p` / `m` | Clients / Resource servers / Scopes / Claim mappers |
| `g` then `k` / `l` / `i` | Signing keys / Audit log / IP rules |
| `g` then `w` / `e` / `d` / `v` | Webhooks / Messaging / Identity providers / Provisioning |
| `g` then `t` / `s` / `x` | Tenants / Settings / Export & import |

The `g` sequence waits one second for its second key.

### Pages

| Page | Path | Needs | Covered in |
|------|------|-------|-----------|
| Overview | `/console/` | any admin permission | Sign-ins, failures, live sessions, second-factor adoption and top clients over 7, 30 or 90 days (`GET /admin/tenants/{slug}/stats`, `ridm:tenants:read`) |
| Users | `/console/users/` | `ridm:users:read` | [Users, invitations and bulk import](users.md) |
| Groups, Roles | `/console/groups/`, `/console/roles/` | `ridm:groups:read`, `ridm:roles:read` | [Users, groups and roles](../concepts/users-groups-roles.md) |
| Clients | `/console/clients/` | `ridm:clients:read` | [Registering clients](clients.md) |
| Playground | `/console/playground/?client=<id>` | reached from a client's detail page | Runs the client's flow for real (authorization code with PKCE, or client credentials with a pasted secret) and shows the token response, the decoded tokens and userinfo |
| Resource servers, Scopes, Claim mappers | `/console/resource-servers/`, `/console/scopes/`, `/console/claim-mappers/` | the matching `read` permission | [Resource servers, scopes and permissions](../concepts/resource-servers.md) |
| Signing keys | `/console/keys/` | `ridm:keys:read` | [Rotating keys](key-rotation.md) |
| Audit log | `/console/audit/` | `ridm:audit:read` | [Webhooks and the audit log](webhooks-audit.md) |
| IP rules | `/console/ip-rules/` | `ridm:tenants:read` | [Rate limits, IP rules and CAPTCHA](security-controls.md) |
| Webhooks | `/console/webhooks/` | `ridm:webhooks:read` | [Webhooks and the audit log](webhooks-audit.md) |
| Messaging | `/console/messaging/` | `ridm:messaging:read` | [Email, SMS and templates](messaging.md) |
| Identity providers | `/console/identity-providers/` | `ridm:idps:read` | [Identity brokering](../concepts/brokering.md) |
| Provisioning | `/console/provisioning/` | `ridm:scim:read` | [SCIM provisioning](scim.md) |
| Tenants | `/console/tenants/` | `ridm:tenants:read` | [Tenants and tenant settings](tenants.md) |
| Settings | `/console/settings/` | `ridm:tenants:read` | [Tenants and tenant settings](tenants.md) |
| Export & import | `/console/config/` | `ridm:tenants:export` | [Configuration as code](../concepts/config-as-code.md) |

With only a `read` permission, a page shows its data but disables or hides the
controls that would change it.

### Saving as you go

Detail pages and Settings have no Save button. Each change is applied on the page at
once and sent as a merge patch when typing pauses (600 ms, and at most 2.5 s into
continuous editing; also when the tab is hidden or closed). The header shows
"Unsaved changes", "Saving…", "Saved", or the API's reason for refusing, after which
the stored values are reloaded. Actions such as assigning a role or adding a group
member apply at once.

Secrets the API returns once (a client secret, a temporary password, a webhook signing
secret, a personal access token, a dynamic registration initial access token) are shown
in a dialog that says so. Copy them before
closing it.

## The account console

Open `https://id.example.com/account/`. Signed out, each page asks which organisation
(tenant) to sign in through; `?tenant=acme` fills it in and the last one is remembered.
After signing in, the user comes back to the page they asked for.

The account console signs in with the built-in `ridm-account-console` client, whose
tokens carry the `urn:ridm:account` audience and reach only the self-service API under
`/t/{slug}/account/`. A token acts only on its own user, only in the tenant that issued
it, and only while its browser session is alive.

| Page | What the user can do |
|------|----------------------|
| **Profile** | Edit the attributes the tenant's [profile schema](users.md#profile-schema) lets users edit (others are shown read-only), choose a language, change their email address or phone number (proven by a code sent to the new one), remove the phone number |
| **Security** | Change the password (the current one is required while one is set, with an option to sign out everywhere else); enrol and remove second factors and regenerate recovery codes; link and unlink upstream accounts; list and revoke trusted devices; list sessions and end one or all but this one; mint and revoke personal access tokens |
| **Applications** | See the applications they consented to, with scopes and the applications' privacy and terms links, and remove access, which also revokes the application's refresh tokens |
| **Your data** | Download everything held about them as JSON (no secrets), and delete the account after typing the username |

Every security change (a factor, a device, a session, the password, a contact detail,
the export, deletion) needs a sign-in from the last fifteen minutes, including the
second step once the user has one. If it is older, the console sends the user through
sign-in again and back to where they were.

Administrators govern what the account console allows with `settings.account`:

| Setting | Default | Effect |
|---------|---------|--------|
| `self_deletion` | `true` | Whether users may delete their own account |
| `deletion_retention_days` | `30` | How long a deleted account is kept before it is purged |
| `personal_tokens` | `true` | Whether users may mint personal access tokens |
| `personal_token_max_days` | `365` | Longest token lifetime (`0` no limit) |

`settings.mfa_methods` and `settings.auth.passkey` decide which second factors the
Security page offers (see [MFA policy](mfa-policy.md)), and the identity providers
configured for the tenant decide which upstream accounts can be linked.

Administrators cannot delete themselves from the account console; another
administrator has to.
