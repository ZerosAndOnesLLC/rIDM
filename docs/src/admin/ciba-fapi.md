# Backchannel sign-in and FAPI 2.0

Two things for clients with stricter needs than a browser redirect:

- **Backchannel sign-in (CIBA).** An application that already knows who the user is (a
  call centre, a point-of-sale terminal, a device with no browser) asks rIDM to have
  that user sign in on their own device. It never sees a browser; it collects the tokens
  once the user approves. This is OpenID Client-Initiated Backchannel Authentication
  (CIBA) Core 1.0.
- **The FAPI 2.0 Security Profile.** A client can be held to the profile open-banking
  and other high-assurance APIs ask for: pushed requests, PKCE, sender-constrained
  tokens, strong signatures, and nothing weaker accepted from it.

Both are per client. Neither changes how any other client works.

## Backchannel sign-in (CIBA)

### Registering a client for it

The client needs the grant `urn:openid:params:grant-type:ciba` in `allowed_grants`,
and it must be confidential: CIBA requests are always authenticated. In the console,
tick **Backchannel (CIBA)** under Grants & authentication and choose the delivery.

| Field | Default | Notes |
|-------|---------|-------|
| `backchannel_token_delivery_mode` | `poll` when the grant is allowed | `poll`: the client asks the token endpoint until the user answers. `ping`: rIDM calls the client's notification endpoint once the user answers, and the client then collects the tokens. `push` is not offered: it would put the tokens themselves on an outbound call |
| `backchannel_client_notification_endpoint` | `null` | Required in `ping` mode, refused in `poll` mode. HTTPS (plain HTTP only for loopback addresses) |

Both fields are refused on a client without the grant; remove them in the same
change that removes the grant. Signed authentication requests and user codes are not
supported, and a dynamic registration that asks for either
(`backchannel_authentication_request_signing_alg`,
`backchannel_user_code_parameter: true`) is refused.

### The request

```bash
curl https://id.example.com/t/acme/bc-authorize \
  -u "bank:$SECRET" \
  -d scope="openid profile" \
  -d login_hint=alice@example.com \
  -d binding_message="K7 R2"
```

```json
{ "auth_req_id": "Vh2…", "expires_in": 600, "interval": 5 }
```

| Parameter | Required | Meaning |
|-----------|----------|---------|
| `scope` | yes | Must include `openid`; the client's default scopes are not used |
| `login_hint` | one hint | The user's username or email address, as they sign in with |
| `id_token_hint` | one hint | An ID token this tenant issued to this client (expired is fine) |
| `login_hint_token` | — | Refused: it has no standard format |
| `binding_message` | no | Up to 64 letters, digits, spaces and `-_.:#`, shown to the user and in their notice. The client shows the same text on its own screen so the user can check they match. Anything else (a link, markup, a line break) is `invalid_binding_message` |
| `client_notification_token` | `ping` mode | The bearer token rIDM sends to the notification endpoint (up to 1024 characters) |
| `requested_expiry` | no | Seconds the request stays open, 30–1800; 600 by default |
| `acr_values` | no | Recorded with the request |
| `resource` | no | Audiences, as at the token endpoint (RFC 8707) |

Exactly one hint must be present. A hint that names no active, unlocked user is
`unknown_user_id`. At most five requests may wait on one user at a time; a sixth is
`access_denied`, so no client can flood someone's inbox.

### What the user sees

rIDM emails the user (or texts them, if they have a verified phone and no email) the
`backchannel_request` message: who is asking, the binding message, and a link to
**Requests** in the [account console](consoles.md), `/account/approvals/`. The link
carries the request's own id, never the `auth_req_id`. The notice is sent whatever
`settings.notifications` says, because without it nobody learns there is anything to
approve. Its template can be overridden like any other; see
[Email, SMS and templates](messaging.md).

The page lists what waits on the user: the application, its binding message, the
scopes, and when the request expires. The user signs in to the account console if they
are not already, then approves or denies. An approval:

- gives the client tokens as if the user had signed in to it from the session they
  approved in: the ID token's `sid`, `auth_time`, `amr` and `acr` are that session's,
  and a refresh token without `offline_access` ends with it;
- is remembered as consent, so the application appears under **Applications** and can
  be removed there like any other.

A request is answered once. Approving needs a signed-in session: a personal access
token cannot approve (`403`), or a leaked one could turn itself into the user's tokens
at any CIBA client. A session opened by [impersonation](impersonation.md) cannot answer
at all (`403`), and one user can never see or answer another's request.

### Collecting the tokens

```bash
curl https://id.example.com/t/acme/token \
  -u "bank:$SECRET" \
  -d grant_type=urn:openid:params:grant-type:ciba \
  -d auth_req_id=Vh2…
```

Until the user answers, the token endpoint says `authorization_pending`; asking again
within the interval says `slow_down` and adds five seconds to it. A denial is
`access_denied` and an expired request `expired_token`, each once. An approval is
handed over at once, whatever the interval, and only once: after that the
`auth_req_id` is `invalid_grant`. Only the client that asked can collect.

In `ping` mode rIDM POSTs, as soon as the user answers:

```http
POST /cb HTTP/1.1
Authorization: Bearer <client_notification_token>
Content-Type: application/json

{"auth_req_id": "Vh2…"}
```

It tries three times over about five seconds through the same outbound guard as
back-channel logout (no private addresses unless the operator opened them with
`OUTBOUND_ALLOW_NETWORKS`). A ping client that never hears can still poll.

### Audit

`backchannel.requested` (actor: the client) when a request opens, `authorization.granted`
when the user approves, `backchannel.denied` when they refuse. The `ciba_requests`
table keeps every request's outcome for the tenant's retention period.

## The FAPI 2.0 Security Profile

Set `security_profile: "fapi2"` on a client (in the console: **Security profile → FAPI
2.0 Security Profile**). Registration then refuses anything outside the profile, and
every request from the client is held to it.

| Rule | Where it is enforced |
|------|----------------------|
| Confidential client (`web` or `machine`) authenticating with `private_key_jwt` | registration |
| Grants limited to `authorization_code`, `refresh_token`, `client_credentials` and CIBA | registration |
| HTTPS redirect URIs, exact match | registration, `/authorize` |
| PKCE and DPoP-bound tokens, which cannot be switched off | registration; `/authorize`, `/par`, `/token` |
| Authorization requests only through PAR | `/authorize` refuses anything else with `invalid_request` to the redirect URI |
| Client assertions signed with PS256, ES256 or EdDSA, with the issuer identifier as `aud`, as a string | every endpoint that authenticates the client |
| Request objects and DPoP proofs signed with PS256, ES256 or EdDSA | `/par`, `/token` |
| ID tokens, access tokens and JARM responses signed with ES256 or EdDSA | the tenant's default algorithm when it is one of these, otherwise ES256; a key is created on demand |
| Refresh tokens are not rotated | `/token` answers with the same refresh token, which stays valid |
| Authorization codes live 60 seconds; PAR request URIs 60 seconds | always so in rIDM |

A resource server that asks for RS256 access tokens cannot be a FAPI client's
audience: such a request is `invalid_target`.

Mutual-TLS client authentication and certificate-bound tokens (RFC 8705) are not
offered yet, so DPoP is the only sender constraint and `private_key_jwt` the only
client authentication a FAPI client can use.

### Requiring PAR without the profile

`require_pushed_authorization_requests: true` (RFC 9126 §6) makes `/authorize` refuse
any request of that client that did not come through `/par`, with none of the
profile's other rules. A FAPI 2.0 client always requires PAR. Dynamic registration
accepts the field and stores it.
