# Sign-in flows and sessions

Signing a user in involves three parties: the application (the client), the
rIDM API, and the login pages the user actually sees. rIDM keeps the pages and
the API apart. The pages are a static site that holds no secrets and makes no
decisions; the API holds all the state and all the rules; and the two are
connected by a short-lived **login flow**.

## The flow-handoff pattern

```text
 client              rIDM API                          login pages (UI_URL)
   |  /authorize ------> validate the request
   |                     create flow {id} (Valkey, 10 min)
   |  <------------------ 302 to /login/?tenant=acme&flow={id}
   |                                                   GET  /t/acme/flows/{id}
   |                                                   POST /t/acme/flows/{id}/password
   |                                                   POST /t/acme/flows/{id}/mfa/verify
   |                                                   ... until stage = done
   |                     GET /t/acme/flows/{id}/finish  <-- browser follows finish_url
   |  <------------------ code (or error) to redirect_uri
```

1. The client sends the browser to `/t/{slug}/authorize`. rIDM validates
   everything it can up front: the client, the exact redirect URI, the
   response type, scopes, PKCE, resource indicators. A bad client or redirect
   URI is shown as an error page and never redirected, so rIDM never sends
   users to an address it has not verified.
2. If the browser already has a live session that satisfies the request, and
   that session owes no step (see [The SSO session](#the-sso-session)), rIDM
   issues the authorization code at once. Otherwise it stores the validated
   request as a login flow in Valkey (ten minutes to live) and redirects the
   browser to the login pages with nothing but the tenant and the flow id:
   `{UI_URL}/login/?tenant=acme&flow=<id>` (or `/register/`, `/consent/`, `/mfa/`
   when that is where the flow starts).
3. The page reads the flow's public state from `GET /t/{slug}/flows/{id}`,
   which says what stage the flow is at and what to show: the client's name
   and logo, the sign-in methods offered, a CAPTCHA if one is due, the scopes
   awaiting consent, the attributes still missing, the negotiated language.
4. The page posts each step to the flow API (`/flows/{id}/password`,
   `/flows/{id}/mfa/verify`, `/flows/{id}/consent`, ...). Every step carries
   the flow's CSRF token, and the API answers with the new state.
5. When the stage is `done`, the state includes a `finish_url`. The browser
   follows it; rIDM issues the code and redirects to the client's
   `redirect_uri` in the requested response mode.

A flow passes through the stages that apply to it: `authenticate` (or
`register`), `verify_email`, `password_change`, `mfa`, `profile`, `terms`,
`organization` (only when the user belongs to more than one and the request
named none — see [Organizations](organizations.md)), `consent`, and finally
`done`. The API decides the next stage; the page only renders it.

A tenant with [adaptive authentication](../admin/adaptive-auth.md) on scores
each sign-in as its first factor passes. A score past the step-up threshold
adds the `mfa` stage even where the MFA policy would not; a score past the
block threshold ends the flow there and then — no session is opened, the flow
is discarded, and the browser goes back to the client with `access_denied`.

### Why it works this way

- **The UI can be any static host.** The pages are a static export with no
  dynamic routes and no server code, so they can sit on a CDN, on any web
  server, or behind the same host as the API. Only `UI_URL` has to point at
  them.
- **The pages hold nothing worth stealing.** The authorization code is minted
  by the API at `finish` and goes straight to the client; tokens never pass
  through the login pages. A compromised page can show the wrong thing but
  cannot mint a token.
- **Every rule is enforced in one place.** Password policy, lockout, CAPTCHA,
  MFA policy, required attributes, terms and consent are decided by the API.
  A custom login page cannot skip a step, because the flow will not reach
  `done` without it.
- **One mechanism for every entry point.** The device flow, invitations,
  identity brokering and step-up authentication all create or resume a login
  flow; the same pages and the same rules serve all of them.

Flows are rate-limited per address, count failed attempts (a CAPTCHA is
demanded after `settings.captcha.after_failures` failures, three by default,
and five wrong second-factor codes discard the flow), and expire after ten
minutes, after which the user starts again from the application.

Endpoint details are in [HTTP endpoints](../reference/endpoints.md).

## The SSO session

Once a user has authenticated, rIDM opens a **single sign-on session**: the
record that this browser is signed in to this tenant, as this user, since this
time, by these methods (`auth_time`, `amr`, `acr`). The next application that
sends the browser to `/authorize` finds the session and gets its code without
the user typing anything.

- The session lives in Valkey, where every node can read it on the hot path,
  and is mirrored to Postgres so that it can be listed, ended from the
  consoles, and audited.
- The browser holds only a reference, in an HttpOnly, `SameSite=Lax` cookie
  with `Path=/`, named per tenant: `__Host-ridm_session_{slug}` (for example
  `__Host-ridm_session_acme`), or `ridm_session_{slug}` when
  `COOKIE_SECURE=false`, for plain-http development. The `__Host-` prefix makes
  browsers insist on `Secure`, `Path=/` and no `Domain`, so no other host can
  set or overwrite the cookie; the slug in the name keeps tenants on one host
  apart, and `Path=/` lets the same cookie work on a tenant's
  [custom domain](tenants.md#custom-domains), where the tenant's pages are not
  under `/t/{slug}`. One browser has at most one session per tenant, and
  sessions of different tenants never share a cookie.
- The session opens when the first factor succeeds and is upgraded in place
  when a second factor passes, so its `amr` and `acr` always describe what
  actually happened.
- A session that has not finished its sign-in is not good for anything. Every
  time `/authorize` (or a device-flow approval) is about to use a live session,
  rIDM checks it against the tenant's MFA policy *as it stands now* and against
  a pending forced password change. A browser that abandoned the flow after the
  password, a policy tightened after the user signed in, or a role granted
  since that falls under `required_for_roles`, all send the user back to the
  owed step (the second factor or the password change) before any code is
  issued; under `prompt=none` the answer is `login_required`. A trusted device
  waives a policy-driven second factor here exactly as it does in the flow. A
  session whose user has since been disabled or deleted gets no code at all:
  the user is asked to sign in afresh.
- An administrator may open a session as a user ([impersonation](../admin/impersonation.md)).
  It owes none of the user's steps, carries no `amr`, names the administrator in
  every token's `act` claim, and ends after the tenant's `impersonation.max_minutes`.

The request parameters that interact with the session behave as OIDC
specifies: `prompt=login` and `max_age` force a fresh sign-in, `prompt=none`
never shows a page (it answers `login_required` or `consent_required` instead,
which is how single-page apps renew silently), `prompt=consent` asks for
consent again, and `prompt=create` starts at registration.

## Session policy

`settings.session` governs how long sessions last:

| Setting | Default | Meaning |
|---------|---------|---------|
| `idle_timeout_secs` | 1800 (30 minutes) | the session ends after this long without use; each use restarts the clock |
| `absolute_timeout_secs` | 43200 (12 hours) | the session ends this long after it opened, however active |
| `max_concurrent` | 0 (unlimited) | sessions one user may hold; opening one more revokes the oldest |
| `remember_device_days` | 30 | lifetime of a trusted device |

The same section holds the default token lifetimes; see [Tokens](tokens.md).

A session ends when either timeout passes, when the user signs out, when the
user or an administrator ends it from a console (one session or all of them),
when the user changes their password and chooses to sign out elsewhere, when an
administrator sets a password with `revoke_sessions`, when the user resets a
forgotten password (which signs them out everywhere), when the account is
disabled or deleted (including through SCIM), or when opening a new session
pushes the user over `max_concurrent` and the oldest is evicted.

Signing a session out revokes every refresh token issued in it, including
those granted `offline_access`, and sends back-channel logout to the clients
that took part (see [Signing out](#signing-out)); an authorization code issued
in the session can no longer be exchanged. A session that merely times out
leaves `offline_access` refresh tokens working, while refresh tokens without
it stop at the next refresh (see [Tokens](tokens.md#refresh-tokens)).

**Trusted devices.** On the sign-in page a user can ask rIDM to remember the
browser. The device is registered, and its own cookie
(`__Host-ridm_device_{slug}`, or `ridm_device_{slug}` over plain http, also
`Path=/`) set, only once the whole flow has completed, including any second
step, so an attacker who knows only the password cannot make their browser
trusted. A trusted device skips the tenant's MFA policy on later sign-ins (a
client's explicit step-up request is still honoured) and suppresses the
new-device notice. Users see and revoke their trusted devices in the account
console.

## Signing out

rIDM supports all three OpenID Connect logout mechanisms:

- **RP-initiated logout.** The client sends the browser to
  `/t/{slug}/end_session`. With an `id_token_hint` that matches the browser's
  session, the session ends at once and the browser goes to the client's
  registered `post_logout_redirect_uri`. Without one, the login pages ask the
  user to confirm first, so a third-party page cannot sign users out behind
  their backs.
- **Back-channel logout.** Every client registered with a
  `backchannel_logout_uri` that took part in the session receives a signed
  logout token, server to server, so it can end its own session for the user.
  This happens on every path that signs a session out, not only
  `end_session`: the user signing out one or all sessions from the account
  console, an administrator revoking one or all of a user's sessions, a
  password change that signs out other sessions, an administrator password
  reset with `revoke_sessions`, a recovery password reset, the user being
  disabled or deleted (by an administrator or through SCIM), and eviction under
  `max_concurrent`. The logout URI must resolve to a public address (see
  [Outbound requests](tenants.md#outbound-requests)).
- **Front-channel logout.** Clients registered with a
  `frontchannel_logout_uri` are loaded in the logout page, for applications that
  can only clear their state in the browser. It only works where the browser
  still sends the application's cookies to a frame embedded in another site:
  Safari (Intelligent Tracking Prevention), Firefox (Total Cookie Protection),
  private windows in every browser and Android WebView do not, so the frame
  loads without the application's session and the user stays signed in there.
  Nothing on the identity provider's side can change that; register a
  back-channel logout URI instead wherever the application can receive one.

Signing out ends the SSO session and revokes its refresh tokens. Access tokens
already issued remain valid until they expire, as with any JWT; rIDM's account
and admin APIs additionally refuse tokens whose session has ended.
