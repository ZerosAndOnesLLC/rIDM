# SAML identity provider

rIDM is a SAML 2.0 identity provider for applications that sign users in with SAML
rather than OpenID Connect: older enterprise software and SaaS tools whose "single
sign-on" setting asks for an IdP's metadata. It implements the Web Browser SSO
profile, service-provider-initiated over HTTP-Redirect or HTTP-POST (and
IdP-initiated for applications that opt in), and front-channel Single Logout.

A SAML application is registered as a **service provider** (SP). Under the hood it is a
client of type `saml`, so the things clients have work the same way for it: the sign-in
page, second factors and step-up, risk policy, consent, organizations, client roles,
IP rules, the audit log and the dashboard's sign-in counts. It has no redirect URIs,
grants or secret, so no OAuth endpoint will serve it, and the client routes refuse to
edit its settings; the SAML routes and the console's **SAML** page do.

## What to give the service provider

Every tenant is an IdP. Most SPs take the metadata URL, or an upload of the document:

| | Value |
|---|---|
| Metadata | `{issuer}/saml/metadata` |
| Entity ID | `{issuer}` (the tenant's OIDC issuer) |
| Single sign-on | `{issuer}/saml/sso` (HTTP-Redirect and HTTP-POST) |
| Single logout | `{issuer}/saml/slo` (HTTP-Redirect and HTTP-POST) |
| Signing certificate | in the metadata; also on the console's SAML page |

On a [custom domain](custom-domains.md) the issuer is the custom host, and these URLs
follow it.

The console's SAML page shows all of these with copy buttons, and so does
`GET /admin/tenants/{slug}/saml`.

## Registering a service provider

In the console, **SAML → New service provider**. Paste or upload the SP's metadata to
fill in its entity ID, consumer URLs, logout URL and certificates, review, and create; or
enter the entity ID and assertion consumer service URL by hand. Every other setting is
then edited on the SP's page and saves as you go.

Through the API, `POST /admin/tenants/{slug}/saml/service-providers` takes the
registration below (`POST …/service-providers/metadata` with `{"metadata": "<xml>"}`
turns a metadata document into one without saving anything), `PUT …/{sp}` replaces it,
and `DELETE …/{sp}` removes the SP. They need `ridm:clients:read` / `ridm:clients:write`.
Disabling an SP is the client's `status`: `PATCH /admin/tenants/{slug}/clients/{sp}`
with `{"status": "disabled"}`, or the switch on its page.

| Field | Default | Notes |
|-------|---------|-------|
| `name` | required | Shown on the sign-in and consent pages |
| `entity_id` | required | The SP's entity ID, unique in the tenant |
| `acs_urls` | required | HTTP-POST assertion consumer services, 1–32. The first is the default; a request may name another by URL or index, never an unregistered one |
| `slo_url`, `slo_binding` | none, `redirect` | Where rIDM sends logout requests, and how (`redirect` or `post`) |
| `name_id_format` | `persistent` | `persistent` (opaque, stable, different for every SP), `transient` (new on every sign-in), `email`, or `unspecified` (the user's id) |
| `allowed_scopes` | `openid`, `profile`, `email` | Whose claims may be released as attributes |
| `attributes` | `[]` | See [Attributes](#attributes) |
| `require_consent` | `false` | Ask the user before releasing attributes the first time. Off by default: an SP is an application an administrator connected |
| `signing_certificates` | `[]` | PEM or base64 certificates the SP signs requests with (up to four, for its own key rollover) |
| `require_signed_requests` | `false` | Refuse requests not signed with one of them |
| `sign_response`, `sign_assertion` | `true`, `true` | At least one stays on |
| `encrypt_assertion`, `encryption_certificate` | `false`, none | Encrypt the assertion to the SP's RSA certificate |
| `data_encryption` | `aes256-gcm` | Also `aes128-gcm`, and `aes256-cbc` / `aes128-cbc` for SPs that cannot read GCM |
| `key_transport` | `rsa-oaep-mgf1p` | RSA-OAEP with SHA-1 (every SAML stack reads it; SHA-1 is sound inside OAEP), or `rsa-oaep-sha256` (XML Encryption 1.1; SPs built on xmlsec 1.2 cannot read it) |
| `allow_idp_initiated`, `default_relay_state` | `false`, none | See [IdP-initiated sign-in](#idp-initiated-sign-in) |
| `assertion_ttl_secs` | `300` | How long the SP may accept the assertion (30–3600) |
| `client_id` | generated | rIDM's own id for the SP: roles, audit, consent |

## Sign-in

An `AuthnRequest` is checked before the browser is shown anything: its issuer must be a
registered, enabled SP; a signature, if present, must verify against the SP's registered
certificates (in the query string for HTTP-Redirect, enveloped in the XML for HTTP-POST);
`Destination` must be rIDM's SSO URL (and is required when the request is signed);
`IssueInstant` must be within the last ten minutes, three minutes' clock skew allowed; the
consumer URL must be registered; and a request ID is accepted once. A failure there is
shown to the user as an error page, never sent anywhere. What the SP may hear is sent to
it as a signed status response: `UnsupportedBinding` (anything but HTTP-POST for the
response), `InvalidNameIDPolicy` (a NameID format other than the configured one, or an
email NameID for a user without an address), `NoAuthnContext`, and `NoPassive` when
`IsPassive` would need a sign-in page.

The request then runs through the same sign-in machinery as an OpenID Connect
authorization. `ForceAuthn` is `prompt=login`. A `RequestedAuthnContext` naming
`https://refeds.org/profile/mfa` or `http://schemas.microsoft.com/claims/multipleauthn`
asks for a second factor, as `acr_values` would; `PasswordProtectedTransport`,
`Password` and `unspecified` take any sign-in. The assertion's
`AuthnContextClassRef` says what happened: the MFA class after a second factor,
`PasswordProtectedTransport` after a password, `unspecified` otherwise.

The answer is a `Response` posted to the consumer URL, with the assertion's subject
confirmation, audience restriction and conditions set to the SP and its URL, the
session's `SessionIndex`, and the `RelayState` the SP sent. If the user cancels, refuses
consent, or the risk policy refuses the sign-in, the SP gets a signed `RequestDenied` or
`AuthnFailed` response instead.

An HTTP-POST request from the SP arrives without the user's session cookie (it is
`SameSite=Lax`, and the post is cross-site), so rIDM checks it, keeps it for ten minutes
and sends the browser to `{issuer}/saml/sso?continue=…`, where the cookie is present.

An administrator [impersonating](impersonation.md) a user gets no SAML assertion: SAML has
no `act` claim, so the SP could not tell who it was really dealing with.

### Attributes

With no attribute list, every claim the SP's allowed scopes release (and profile
attributes shown in ID tokens, and what claim mappers add) goes out under its own name,
`NameFormat` basic. With a list, only the listed claims go out, under the names the SP
expects:

```json
"attributes": [
  { "claim": "email", "name": "urn:oid:0.9.2342.19200300.100.1.3", "name_format": "uri", "friendly_name": "mail" },
  { "claim": "groups", "name": "memberOf" }
]
```

`roles` and `groups` (the user's effective role and group names) are available to a list,
as they are in access tokens. Arrays become one `AttributeValue` each; objects are sent
as JSON.

### IdP-initiated sign-in

Some applications expect to be launched from the IdP (an app launcher) rather than to
send a request. With `allow_idp_initiated` on, `{issuer}/saml/init?sp=<entity ID or
client id>` signs the user in and posts an unsolicited response (no `InResponseTo`) to
the SP's default consumer URL, with `RelayState` from the link or else
`default_relay_state`. It is off by default: an unsolicited response is the easier kind
to replay or to push a user into an application with, so leave it off unless the SP needs
it.

## Single Logout

Logout is front-channel only: the user's browser carries each message.

- **The SP starts it.** Its `LogoutRequest` (either binding; signed if the SP has a
  signing certificate, and it must be when `require_signed_requests` is on) names the
  NameID and `SessionIndex` rIDM gave it. rIDM ends that session, sends the browser
  through every other SAML SP that took part with a signed `LogoutRequest` of its own,
  waits for each `LogoutResponse`, and finally answers the SP that asked, with
  `PartialLogout` under `Success` if any did not confirm. OpenID Connect clients hear
  through back-channel logout, and front-channel ones in hidden frames on the way.
- **rIDM starts it.** An RP-initiated logout (`/end_session`, and the sign-out
  confirmation page) walks the browser through the session's SAML SPs the same way
  before going on to where it was going.

An SP that never answers its logout request leaves the user on its page; that is the
nature of front-channel logout. Sessions ended with no browser in hand — an
administrator's revocation, a password change, a user disabled — end at rIDM, and SAML
SPs keep their own sessions until those expire. There is no SOAP back-channel logout.

## Signing keys

The SAML signing keys are not the JWT signing keys. SPs pin the certificate from the
metadata, often by hand, so these keys never rotate on a timer. The first key (RSA, the
tenant's key size, a self-signed certificate valid for ten years) is made on first use.
A rollover is three steps, in the console's SAML page or through the API
(`ridm:keys:write`):

1. **Start a rollover** — `POST /admin/tenants/{slug}/saml/keys`. A pending key is listed
   in the metadata at once, signing nothing.
2. When every SP has the new metadata (or certificate), **activate** it —
   `POST …/saml/keys/{key}/activate`. It signs from then on; the previous key stays in
   the metadata as `retiring`.
3. **Delete** the retiring key — `DELETE …/saml/keys/{key}`.

The keys are encrypted under the master key like every other secret, and a master-key
rotation rewrites them. The metadata lists every key, the active one first.

## In the tenant document

SAML SPs are in the [tenant document](../reference/tenant-document.md) under
`saml_service_providers`, keyed by `client_id`, each with the registration fields above and
`status`; the `clients` section leaves them out, and a `saml` client there is refused.
Certificates are exported, keys are not.

## Keycloak as the service provider

Every build is tested against Keycloak 26 in this role (a realm brokering to rIDM through
a SAML identity provider): sign-in with signed and with encrypted assertions, attribute
import, Keycloak's signed requests, and Single Logout started from either side. The
settings that test uses:

| Keycloak (identity provider, SAML) | Value |
|---|---|
| Identity provider entity ID | `{issuer}` |
| Single Sign-On service URL | `{issuer}/saml/sso` |
| Single logout service URL | `{issuer}/saml/slo` |
| NameID policy format | Persistent |
| Principal type | Subject NameID |
| HTTP-POST binding response | On (rIDM answers by HTTP-POST only) |
| Want AuthnRequests signed | On, RSA_SHA256 |
| Validate signatures | On, with the certificate from rIDM's metadata |
| Want assertions signed | On |
| Want assertions encrypted | Either; rIDM encrypts when the SP's metadata carries an encryption key and `encrypt_assertion` is set |

Register Keycloak in rIDM from `{keycloak}/realms/{realm}/broker/{alias}/endpoint/descriptor`:
its metadata says it signs requests, so rIDM requires that. With attributes named for
their LDAP OIDs (`urn:oid:0.9.2342.19200300.100.1.3` for `email`, `urn:oid:2.5.4.42` for
`given_name`, `urn:oid:2.5.4.4` for `family_name`, name format URI), Keycloak's
"Attribute Importer" mappers fill in the user's email, first and last name, and its
first-broker-login flow creates the user without asking anything.

## Events

A SAML sign-in raises `authorization.granted`, as an OpenID Connect one does; registering,
changing and deleting an SP raise the `client.*` events. The keys raise
`saml_key.created` and `saml_key.status_changed` (`active`, or `deleted`).

## Limits

- No HTTP-Artifact binding, no SOAP (back-channel logout, attribute queries), no ECP.
- Responses go by HTTP-POST only.
- `EncryptedID` in logout requests is not accepted, and rIDM publishes no encryption key.
- SHA-1 signatures and digests are refused, and signatures must use exclusive
  canonicalization.
- One consumer URL list per SP; no per-request consumer URLs outside it.
