# MFA policy

This page covers the settings that decide when rIDM asks for a second factor, which
factors users may enrol, passkeys, trusted devices, recovery codes, step-up requests
from clients, and what an administrator does when a user loses a device. For how the
second step fits into sign-in, see [MFA and passkeys](../concepts/mfa.md).

All of it is tenant configuration: Settings → Sign-in in the console, or
`PATCH /admin/tenants/{slug}` with `ridm:tenants:write` (see
[Tenants and tenant settings](tenants.md)).

## When a second factor is asked: settings.mfa

`settings.mfa` is an object tagged by `mode`. The default is `{"mode": "off"}`.

| Mode | Who is asked for a second factor |
|------|----------------------------------|
| `off` | Nobody, unless the client asks for it with `acr_values` |
| `optional` | Users who have enrolled a second factor |
| `required` | Everyone. A user with no factor enrols one during sign-in before continuing |
| `required_for_admins` | Users holding any admin permission in the tenant, as for `required`; everyone else as for `optional` |
| `required_for_roles` | Holders of any of the listed roles, as for `required`; everyone else as for `optional` |

```json
{ "settings": { "mfa": { "mode": "required_for_roles", "roles": ["finance", "ridm:admin"] } } }
```

- `required_for_roles` takes `roles`, a list of role names. A role counts however it is
  held: directly, through a group, or as a composite of another role.
- `required_for_admins` looks at the user's permissions on `urn:ridm:admin` in their
  own tenant. In `master` that is every global administrator. Setting it on `master`
  is the usual way to make console access need two factors.
- Under `off`, a user who has enrolled a factor anyway (the account console allows it)
  is not asked for it at sign-in; `optional` is the mode that honours voluntary
  enrolment.

Switching mode needs only the new `mode`: a patch such as
`{"settings": {"mfa": {"mode": "required"}}}` leaves nothing of a previous
`required_for_roles` behind.

Policy is evaluated at sign-in, and again whenever an existing session is used. Every
`/authorize` request that would reuse a live session, and every device-code approval,
checks the session against the policy as it stands now: a session that never passed a
second factor, held by a user the current policy asks for one (a policy tightened
after sign-in, or a role granted since, counts), is sent to the second step before any
code is issued, unless the browser is a trusted device. A pending forced password
change is owed the same way and comes first. With `prompt=none` such a request fails
with `login_required`. Sessions of users who have since been disabled or deleted get no
codes at all; they sign in again. Changing the policy does not end sessions by itself.

## Which factors: settings.mfa_methods

| Key | Default | Factor |
|-----|---------|--------|
| `totp` | `true` | An authenticator app: six-digit codes, 30-second period |
| `email_otp` | `false` | A one-time code to the account's email address (offered only to users with one) |
| `sms_otp` | `false` | A one-time code by text message to a verified phone number |

Passkeys are not in this list: they follow `settings.auth.passkey` (below). Email and
SMS codes need a working provider (see [Email, SMS and templates](messaging.md)).

A method switched off is no longer offered for enrolment. Factors already enrolled
with it are left in place.

Keep at least one method on whenever `mfa.mode` requires a second factor, so users
who have none have something to enrol.

## Passkeys: settings.auth.passkey

`settings.auth.passkey` (default `false`) turns on WebAuthn passkeys in two roles at
once:

- **as a first factor**: the login page offers "sign in with a passkey", with no
  username or password. When the authenticator verifies the user (a PIN or biometric),
  the sign-in already counts as two factors and no second step follows;
- **as a second factor**: users may enrol a passkey on the second step or in the
  account console, and use it after a password.

The relying party ID is the tenant's custom domain when it has one, else the host of
`UI_URL`. Passkeys are bound to that host, so changing a tenant's custom domain (or
moving the UI to another host) strands the passkeys registered before; users have to
enrol again. See [Custom domains](custom-domains.md).

## Trusted devices

On the second step, a user may tick "remember this device". The browser then gets a
long-lived cookie, and later sign-ins from it skip the policy-driven second factor.

| Setting | Default | Meaning |
|---------|---------|---------|
| `settings.session.remember_device_days` | `30` | How long a trusted device lasts (minimum 1) |

- The cookie holds a random secret; only its hash is stored. It is `HttpOnly`, host-only
  with `Path=/`, and named per tenant (`__Host-ridm_device_acme`, or `ridm_device_acme`
  with `COOKIE_SECURE=false`).
- A step-up request from a client (below) is honoured even on a trusted device.
- Users list and revoke their trusted devices in the account console (Security);
  administrators do so on the user page (Sessions & devices) or with
  `GET` and `DELETE /admin/tenants/{slug}/users/{user}/devices[/{device_id}]`.
  Deleting a user revokes them all.

## Recovery codes

A user's first second factor comes with ten single-use recovery codes, shown once.
Each is ten characters from a lower-case base-32 alphabet; case, spaces and dashes are
ignored when typed. On the second step, "use a recovery code" is offered while unused
codes remain.

- Users generate a new set in the account console (Security), or with
  `POST /t/{slug}/account/mfa/recovery-codes`; the old set stops working.
- Removing the user's last second factor removes the codes with it, whether the user
  does it in the account console or an administrator does it through the admin API.
- The codes are stored encrypted as one `recovery_code` credential row per user.

## Step-up with acr_values

A client that needs a second factor for a particular request, whatever the tenant
policy, asks for it in the authorization request:

```text
https://id.example.com/t/acme/authorize?client_id=acme-portal&response_type=code
  &scope=openid&redirect_uri=https%3A%2F%2Fportal.acme.example%2Fcb
  &code_challenge=…&code_challenge_method=S256
  &acr_values=urn:ridm:acr:mfa
```

- `acr_values` is a preference list, most preferred first. rIDM honours the first
  class it recognises: a class ending in `:mfa` is a step-up request, and a weaker
  class ahead of it (`urn:ridm:acr:single`) means the client will settle for that.
  Classes rIDM cannot assert are skipped.
- A step-up is honoured even on a trusted device and even under `mode: off`. A user
  with no factor enrols one first.
- A live session whose `acr` is not one of the requested values goes straight to the
  second step, without the password again; one that already carries the class does
  not ask again. With `prompt=none` the request fails with `login_required` instead.
  Add `max_age=0` or `prompt=login` to force a fresh sign-in as well.

The session, and the ID and access tokens from it, report `acr`
`urn:ridm:acr:mfa` (or the `:mfa` class the client named) with `mfa` in `amr` once a
second factor has passed, and `urn:ridm:acr:single` otherwise. Discovery advertises
`acr_values_supported: ["urn:ridm:acr:single", "urn:ridm:acr:mfa"]`. A relying party
should check `acr` in the ID token rather than assume its request was met; see
[Token claims](../reference/token-claims.md).

The account console uses the same mechanism: a security change there needs a sign-in
from the last fifteen minutes, with the second step once the user has a factor, and the
console sends the user through sign-in with `max_age=0` and `acr_values` when it is
missing.

## Failed attempts

Five wrong second-factor codes in one sign-in discard the flow; the user starts again
from the first step. Codes sent by email or SMS are single-use and expire after ten
minutes. First-factor failures count towards the account lockout in
`settings.lockout` (see [Tenants and tenant settings](tenants.md#lockout)).

## Resetting a user's MFA

When a user has lost their authenticator and their recovery codes:

1. **Remove the factors.** Console: Users → the user → Password & credentials → remove
   each factor. API: list them, then delete each one:

   ```bash
   curl -s -H "Authorization: Bearer $RIDM_TOKEN" \
     "https://id.example.com/admin/tenants/acme/users/$USER_ID/credentials"
   curl -s -X DELETE -H "Authorization: Bearer $RIDM_TOKEN" \
     "https://id.example.com/admin/tenants/acme/users/$USER_ID/credentials/$CREDENTIAL_ID"
   ```

   Removing the last second factor removes the `recovery_code` row with it, as in the
   account console. The user is notified when `settings.notifications.mfa_changed` is
   on.
2. **Revoke trusted devices**, so no remembered browser skips the new enrolment:
   `DELETE /admin/tenants/{slug}/users/{user}/devices`.
3. **End sessions** if the device may be in someone else's hands:
   `DELETE /admin/tenants/{slug}/users/{user}/sessions`.

At the next sign-in, a user under a `required` policy enrols a new factor (and gets new
recovery codes); under `optional` they sign in with one factor and may enrol again from
the account console.

Verify the person's identity out of band before removing their factors: this is the
step an attacker who has taken over an email account would ask a help desk for.
