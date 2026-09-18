# MFA and passkeys

rIDM separates two questions: *how may a user prove who they are first*, and
*when must they prove it a second way*. The first is the tenant's choice of
sign-in methods; the second is its MFA policy, plus whatever an individual
application demands for a sensitive action.

## First factors

`settings.auth` decides what the login page offers:

| Setting | Default | Method |
|---------|---------|--------|
| `password` | on | username or email, and password |
| `magic_link` | off | a one-time link sent by email |
| `email_otp` | off | a six-digit code sent by email |
| `sms_otp` | off | a six-digit code sent by text message |
| `passkey` | off | a passkey (WebAuthn discoverable credential), no username needed |

A user can also sign in through an [upstream identity provider](brokering.md),
which counts as a first factor of its own.

## Second factors

`settings.mfa_methods` decides which second-step methods users may enrol:

| Setting | Default | Method |
|---------|---------|--------|
| `totp` | on | an authenticator app (RFC 6238: SHA-1, six digits, 30-second steps, one step of drift either way; each code accepted once) |
| `email_otp` | off | a six-digit code to the account's verified email address |
| `sms_otp` | off | a six-digit code to the account's verified phone number |

Passkeys are offered as a second step whenever `settings.auth.passkey` is on.

Enrolling proves the channel: an email or SMS factor is only saved once a code
sent to it has been entered, and the address or number is then marked
verified. Emailed and texted codes are stored hashed, bound to the flow, and
good for ten minutes and five attempts; sends are limited to three per ten
minutes per user.

The first second factor a user enrols also issues **ten single-use recovery
codes**, shown once. Any one of them replaces the second factor for one
sign-in, and the user is told how many remain. Codes are hashed, then
encrypted; authenticator seeds and passkeys are encrypted per row under the
[master key](keys.md#the-master-key).

## MFA policy

`settings.mfa` decides who is asked for a second step at sign-in. It is a
tagged object, for example `{"mode": "required"}` or
`{"mode": "required_for_roles", "roles": ["finance"]}`:

| `mode` | Who is asked |
|--------|--------------|
| `off` (default) | nobody, unless the application asks for it |
| `optional` | users who have enrolled a second factor |
| `required` | everyone; a user without a factor enrols one during this sign-in |
| `required_for_roles` | holders of any listed role (directly, through a group, or through a composite); everyone else as `optional` |
| `required_for_admins` | anyone holding any admin-console (`ridm:*`) permission; everyone else as `optional` |

`required_for_admins` is the least disruptive way to protect a tenant: the
accounts that can change other accounts must use a second factor, and nobody
else is forced to.

The policy is enforced on live sessions too, not only at sign-in. Whenever
`/authorize` or a device-flow approval is about to use an existing SSO session,
rIDM checks it against the policy as it stands at that moment. Tightening the
policy, or granting a user a role that `required_for_roles` names, therefore
takes effect at their next authorization request: a session without a second
factor is sent to the second step before any code is issued (or answered with
`login_required` under `prompt=none`). The same check stops a browser that
closed the sign-in page after the password from using its half-finished
session. See [The SSO session](flows-and-sessions.md#the-sso-session).

A **trusted device** (a browser the user asked rIDM to remember, after a
complete sign-in including any second step) skips the policy-driven second
step for `settings.session.remember_device_days`. See
[Sign-in flows and sessions](flows-and-sessions.md#session-policy).

## Step-up: acr and amr

Applications learn how a user signed in from two claims, carried in ID tokens
and access tokens:

- **`amr`** (authentication methods references, RFC 8176) lists the methods
  used:

  | Value | Meaning |
  |-------|---------|
  | `pwd` | password |
  | `otp` | a one-time code or link (authenticator app, email, SMS, magic link) |
  | `sms` | the code came by text message (alongside `otp`) |
  | `hwk` | a passkey (hardware- or platform-bound key) |
  | `user` | the passkey verified the user (PIN or biometric) |
  | `fed` | an upstream identity provider |
  | `mfa` | more than one factor was used |

- **`acr`** (authentication context class) is `urn:ridm:acr:single` for a
  one-factor session and `urn:ridm:acr:mfa` once a second factor has passed.
  Both are advertised in discovery as `acr_values_supported`.

An application that needs a second factor for a particular action (approving a
payment, opening an admin page) does not have to rely on the tenant policy. It
sends the user back through `/authorize` with `acr_values=urn:ridm:acr:mfa`.
Any requested class ending in `:mfa` is treated as a demand for a second
factor, so an application may use its own class name (`urn:example:mfa`), and
the token then reports that class. This step-up:

- is always honoured, even on a trusted device and even with the tenant policy
  `off`;
- skips the password when the browser's session is otherwise fresh, sending the
  user straight to the second step;
- answers `login_required` under `prompt=none`, because a second step needs the
  user.

`acr_values` is a preference list: rIDM honours the first class it recognises,
so a request that lists `urn:ridm:acr:single` before `urn:ridm:acr:mfa` does not
demand a second factor. Classes rIDM does not recognise are ignored, and the
token reports the class the session actually holds. An application must check
the `acr` it receives rather than assume its request was met.

## Passkeys

A passkey is a WebAuthn credential kept by the user's device or password
manager. rIDM uses passkeys in two ways:

- **As a sign-in on their own.** With `settings.auth.passkey` on, the login
  page offers "Sign in with a passkey". The browser offers the user's
  discoverable credentials for the site; rIDM finds the account from the
  credential the authenticator presents, checks that the user handle names the
  same account, and opens the session. User verification is required, so a
  passkey sign-in is already two factors (`amr`: `hwk`, `user`, `mfa`) and no
  second step follows.
- **As a second step** after a password or code, for users who enrolled one.

The relying party id that passkeys are bound to is the host of the login pages
(`UI_URL`), or the tenant's custom domain when it has one. A passkey created
for one host will not work on another, so settle on the login host before
users start enrolling passkeys. Each passkey's signature counter and backup
flags are stored and the counter is checked on every use. Challenges live in
Valkey for five minutes, bound to the flow, and are spent by the first answer.

## Managing factors

Users enrol and remove factors and regenerate recovery codes in the account
console; the recovery codes go with the last factor removed. Every
change of factors (and every other security change in the account console)
requires a sign-in from the last fifteen minutes, including the second step
when the account has one; otherwise the console sends the user through sign-in
again first. Users are notified (by email, or by text message when they have
only a verified phone) when a factor is added or a recovery code is used, unless the tenant has switched that notice off
(`settings.notifications.mfa_changed`).

Administrators can list a user's factors (never the secrets) and remove one,
for a user who has lost their device. As in the account console, removing a
user's last second factor removes their recovery codes with it, so no orphaned
codes are left to stand in for a factor the user no longer has. See [MFA policy](../admin/mfa-policy.md).
