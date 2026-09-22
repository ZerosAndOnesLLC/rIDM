# SAML identity providers (upstream)

A SAML identity provider can be an upstream of a tenant: users press "Continue with
Corp SSO" on the login page, sign in at the company's Entra ID, ADFS, Okta, Shibboleth or
another SAML 2.0 IdP, and come back signed in to rIDM. rIDM is then the **service
provider** (SP). It is an [identity provider](../concepts/brokering.md) of kind `saml`,
so everything brokering does applies unchanged: the login-page button, account linking
and its `link_policy`, claim mappers, the account console's linked identities, MFA,
terms, consent and the risk policy after the upstream sign-in. Your applications keep
speaking OpenID Connect (or SAML, to rIDM as their [IdP](saml-idp.md)); only rIDM talks
to the upstream IdP.

rIDM implements the Web Browser SSO profile over HTTP-Redirect or HTTP-POST (requests),
answers over HTTP-POST, IdP-initiated sign-in for providers that opt in, and front-channel
Single Logout in both directions.

## Adding a provider

In the console, **Identity providers → New provider**, choose **SAML 2.0**, give an alias
and a display name, and the IdP's **metadata URL** (or paste or upload the metadata
document). rIDM reads the entity ID, the single sign-on and logout services, the signing
certificates and the NameID formats from it; everything is then editable on the
provider's page and saves as you go.

Through the API:

```http
POST /admin/tenants/{slug}/identity-providers/saml-metadata
{"url": "https://login.example.com/federationmetadata.xml"}
```

answers the provider's settings, read from the metadata, without saving anything
(`{"metadata": "<xml>"}` takes the document itself). Create the provider with them:

```http
POST /admin/tenants/{slug}/identity-providers
{"alias": "corp", "kind": "saml", "display_name": "Corp SSO", "saml": { …the settings… }}
```

`PATCH …/identity-providers/{alias}` with `{"saml": {…}}` replaces the SAML settings as a
whole (the console sends the whole object on every change). A provider cannot change
between SAML and another kind; create another one. The routes need `ridm:idps:read` and
`ridm:idps:write`.

## What to give the identity provider

Each SAML provider gets its own SP identity in rIDM, so two IdPs never share an entity ID:

| | Value |
|---|---|
| Metadata | `{issuer}/broker/{alias}/saml/metadata` |
| Entity ID | the metadata URL |
| Assertion consumer service | `{issuer}/broker/{alias}/saml/acs` (HTTP-POST) |
| Single logout service | `{issuer}/broker/{alias}/saml/slo` (HTTP-Redirect and HTTP-POST) |
| Certificates | in the metadata, for signing and for encryption |

Most IdPs take the metadata URL. The console's provider page shows every value with a
copy button, and the admin API returns them as `saml_sp` (and the consumer URL as
`callback_url`) on the provider.

rIDM signs with the tenant's **SAML key**, the same one it signs with as an
[IdP](saml-idp.md#signing-keys). It never rotates on a timer. An IdP that pins
rIDM's certificate follows the rollover described there: add a pending key (the SP
metadata lists it at once), let the IdP re-read the metadata, activate it. Assertions
may be encrypted to any published certificate, so an IdP that has not caught up yet
still works.

## Settings

| Field | Default | Notes |
|-------|---------|-------|
| `entity_id` | required | The IdP's entity ID, the `Issuer` of its messages; unique in the tenant |
| `sso_url`, `sso_binding` | required, `redirect` | Where `AuthnRequest`s go, and how (`redirect` or `post`) |
| `slo_url`, `slo_binding` | none, `redirect` | The IdP's logout service; without one, sign-out stays local to rIDM |
| `signing_certificates` | required | PEM or base64 certificates the IdP signs with, one to ten (two during its key rollover). Nothing unsigned is ever accepted |
| `name_id_format` | none | Asked for in `NameIDPolicy`: `persistent`, `email`, `transient`, `unspecified`, or none to leave it to the IdP. Import picks `persistent` when the IdP offers it |
| `sign_requests` | `true` | Sign `AuthnRequest`s. Logout messages are always signed |
| `want_assertions_signed` | `true` | The assertion itself must carry a signature; a signed `Response` around an unsigned assertion is refused |
| `require_encrypted_assertions` | `false` | Refuse plaintext assertions |
| `force_authn` | `false` | Ask the IdP to authenticate the user again every time (`ForceAuthn`) |
| `authn_context_class_refs` | `[]` | Authentication context classes to ask for (Comparison `exact`), e.g. `https://refeds.org/profile/mfa` |
| `allow_unsolicited` | `false` | Accept IdP-initiated sign-in (below) |
| `unsolicited_client_id` | none | Where an IdP-initiated sign-in lands: this client's `initiate_login_uri`; the account console when unset |
| `metadata_url` | none | Re-read daily (below) |

The provider also carries the usual `link_policy`, `trust_email` and `mappers`. SAML has
no "email verified" attribute, so `trust_email` is what lets `verified_email` linking
work with most IdPs. Set it only for an IdP that really does vouch for its addresses,
such as your own corporate directory.

## What rIDM checks

A response is accepted only when all of the following hold:

- it is signed by one of the registered certificates. The key never comes from the
  message's `KeyInfo`. The signature covers the assertion that is read: either the
  `Response` around it, or the assertion itself (required when `want_assertions_signed`).
  The shapes behind signature wrapping are refused (two assertions, a reference to another
  element, a duplicated ID), and so are SHA-1 and comments in the canonicalization;
- the assertion's `Issuer` is the IdP's entity ID, its audience is this provider's SP
  entity ID, and its bearer confirmation names this assertion consumer service;
- it answers the `AuthnRequest` rIDM sent (`InResponseTo`), within its validity window,
  allowing three minutes of clock skew. The `Response` itself may be at most ten minutes
  old;
- its assertion has not been seen before. Assertion IDs are remembered for as long as the
  assertion could be presented;
- an encrypted assertion decrypts with one of the tenant's SAML keys (AES-GCM or
  AES-CBC, RSA-OAEP).

A failure `Status` from the IdP (the user cancelled, `NoPassive`, …) brings the user back
to the login page with `broker_error=access_denied` or `upstream_error`. The reason for
any refusal is logged, not shown.

The response arrives as a cross-site POST, which carries no `SameSite=Lax` cookie. rIDM
therefore checks it at once, parks the proven identity for five minutes, and continues at
a same-site `…/saml/acs?continue=` link, where the session and trusted-device cookies are
sent. That link works only in the browser that started the sign-in: a cookie set at
`/broker/{alias}/start` binds them, so a link handed to someone else signs nobody in.

## Who the user is

The subject is the **NameID**, unless the `subject` mapper names an attribute. A
`transient` NameID changes on every sign-in and cannot identify anyone: with one, map the
subject to a stable attribute (an employee number, `eduPersonUniqueId`), or rIDM refuses
the sign-in.

Attributes are available to the mappers under their `Name`, and under their
`FriendlyName` too. One value is a string, several are an array. The well-known names
also count as the claims the broker reads by default, so most IdPs need no mappers:

| Claim | Attributes that count |
|-------|-----------------------|
| `email` | `mail`, `emailAddress`, `urn:oid:0.9.2342.19200300.100.1.3`, `urn:oid:1.2.840.113549.1.9.1`, `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`; else an `emailAddress` NameID |
| `preferred_username` | `uid`, `username`, `urn:oid:0.9.2342.19200300.100.1.1`, `eduPersonPrincipalName`, `urn:oid:1.3.6.1.4.1.5923.1.1.1.6`, `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn` |
| `given_name` | `givenName`, `urn:oid:2.5.4.42`, `…/claims/givenname` |
| `family_name` | `sn`, `surname`, `urn:oid:2.5.4.4`, `…/claims/surname` |
| `name` | `displayName`, `cn`, `urn:oid:2.16.840.1.113730.3.1.241`, `urn:oid:2.5.4.3`, `http://schemas.microsoft.com/identity/claims/displayname` |

The NameID itself is `nameid` (and its format `nameid_format`), for a mapper that wants
it.

## IdP-initiated sign-in

Responses rIDM did not ask for are refused unless `allow_unsolicited` is on. It is off by
default for a reason: anyone able to post a response to the consumer URL, such as a page
the victim visits, could sign the victim in to the attacker's account. A response that
answers some request (it carries `InResponseTo`) is never accepted as unsolicited.

When it is on, an unsolicited response runs through the same checks, link policy and risk
scoring as a solicited one, then lands on the `initiate_login_uri` of
`unsolicited_client_id` (with `iss`, as in OpenID Connect third-party-initiated login) or
on the account console. The session is set. Whatever it still owes (a second factor,
terms) is asked when an application resumes it at `/authorize`.

## Single Logout

rIDM keeps the NameID and `SessionIndex` of every session brokered through a SAML IdP.

- **The IdP signs the user out** (a `LogoutRequest` at `…/saml/slo`): it must be signed
  with a registered certificate (forged logout requests are refused), name rIDM's logout
  URL and be fresh and new. rIDM ends every session of that NameID through this IdP (only
  those with a named `SessionIndex`, when it names any), takes the browser through the
  SAML applications of those sessions (as when an SP signs out, see
  [SAML identity provider](saml-idp.md#single-logout)), and answers with a signed
  `LogoutResponse`. OpenID Connect applications hear of it by back-channel logout.
- **The user signs out at rIDM** (an application's RP-initiated logout, or the logout
  page): once the session's own SAML applications have had their turn, rIDM sends the IdP
  a signed `LogoutRequest` for the session, and the IdP's answer takes the browser on to
  where the sign-out was going.

Both are front-channel: they need the user's browser. A session that ends without one
(expiry, an administrator revoking it, a password change) does not reach the IdP, and a
sign-out that a downstream SAML application starts ends rIDM's session without reaching
the upstream IdP either.

## Keeping the metadata current

With a `metadata_url`, rIDM re-reads the IdP's metadata every day (the
`saml_metadata_refresh` job, hourly, picks up providers last read more than a day ago)
and takes the endpoints and signing certificates from it, so the IdP's own key rollover
needs nobody on rIDM's side. The entity ID in the metadata must stay the same. A
document naming another entity is refused. **Refresh now** on the provider's page, or
`POST /admin/tenants/{slug}/identity-providers/{alias}/saml/refresh`, does it at once.

A failed refresh keeps the settings as they were and shows the error on the provider
(`saml.metadata_error`) until one succeeds; failed providers are retried every hour.
The metadata is fetched like every upstream endpoint: `https` (plain `http` for loopback
only), public addresses only, no redirects, at most 256 KiB.

## Monitoring

| Metric | Labels | Meaning |
|--------|--------|---------|
| `ridm_saml_sp_responses_total` | `outcome`: `accepted`, `status`, `invalid`, `replay`, `no_request`, `no_subject` | Responses at the assertion consumer services |
| `ridm_saml_metadata_refresh_total` | `outcome`: `changed`, `unchanged`, `failed` | Metadata refreshes |

Events: the brokering ones (`login.brokered`, `identity.linked`, …), `logout.upstream`
when an IdP's `LogoutRequest` ended sessions, and `identity_provider.updated` when a
refresh changed the settings.
