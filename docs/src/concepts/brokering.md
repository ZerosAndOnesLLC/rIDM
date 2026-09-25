# Identity brokering

Identity brokering lets users sign in to a tenant with an account they already
have elsewhere: Google, Microsoft, GitHub, Apple, GitLab, a partner's OpenID
Connect provider, or any OAuth 2.0 service with a userinfo endpoint. rIDM
stands between that **upstream provider** and your applications.

Your applications never talk to the upstream provider. They send users to
rIDM as always and receive rIDM tokens, with rIDM's subject identifiers, roles
and permissions. Adding or removing a provider changes the login page, not the
applications, and the tenant's own policies (MFA, terms, required profile
attributes, consent) still apply to brokered sign-ins.

## Providers

Identity providers are configured per tenant (admin console: Identity
providers; admin API: `/admin/tenants/{slug}/identity-providers`). Each has an
`alias`, used in its URLs, and one of three kinds:

| Kind | How the identity is proved |
|------|----------------------------|
| `oidc` | an ID token, verified against the provider's published keys |
| `oauth2` | the provider's userinfo endpoint, read with the access token |
| `saml` | a signed SAML assertion posted to rIDM's assertion consumer service; see [SAML identity providers (upstream)](../admin/saml-upstream.md) |

A **preset** (`google`, `microsoft`, `github`, `apple`, `gitlab`) fills in the
kind, endpoints, scopes and claim mappings the provider needs; for any other
OpenID Connect provider, giving its `issuer` is enough, and the endpoints are
discovered from it. You register rIDM with the provider as a client, using the
callback URL rIDM reports for the provider
(`{issuer}/broker/{alias}/callback`), and give rIDM the client id and secret.
The secret is stored encrypted under the [master key](keys.md#the-master-key)
and never returned.

Upstream endpoints must use `https`; plain `http` is accepted only for loopback
hosts, for development and tests. Because a tenant administrator chooses these
URLs, rIDM only connects to them at public addresses, follows no redirects and
ignores proxy settings (see [Outbound requests](tenants.md#outbound-requests)):
a provider on a private network cannot be used.

Providers that are enabled and not `hidden` appear on the login page as
"Continue with ..." buttons, in `sort_order`. A hidden provider still works
through a direct link, which suits a partner's employees who arrive from a
link on the partner's intranet.

## What happens at sign-in

1. The user presses "Continue with Google". The browser goes to
   `/t/{slug}/broker/{alias}/start?flow={id}`, carrying the current
   [login flow](flows-and-sessions.md).
2. rIDM redirects to the provider's authorization endpoint with a fresh
   `state` (whose record in Valkey remembers the flow), a `nonce` and a PKCE
   challenge, and sets a short-lived `SameSite=Lax` cookie binding the sign-in
   to this browser.
3. The provider returns the browser to `/t/{slug}/broker/{alias}/callback`
   (GET, or POST for providers using `form_post`, such as Apple; a posted
   answer is kept for a moment and continued by a same-site GET to
   `…/callback?continue=`, since a cross-site POST carries no `Lax` cookie).
   The callback signs in only the browser holding the binding cookie: a
   callback URL someone else obtained, opened in another browser, is refused
   with `broker_error=invalid_state` (login CSRF).
4. rIDM redeems the code, authenticating as the provider's
   `token_endpoint_auth_method` says (`client_secret_basic`,
   `client_secret_post`, or `none` for PKCE alone). For `oidc` providers it verifies the ID token's
   signature against the provider's JWKS (cached for an hour, refetched once
   for an unknown `kid`), its issuer (a Microsoft provider configured with the
   `common`, `organizations` or `consumers` issuer accepts any directory's), audience, expiry and nonce. For `oauth2`
   providers it reads the userinfo endpoint (for GitHub, the primary verified
   address comes from `/user/emails`).
5. rIDM resolves the upstream identity to a local user (below), then the login
   flow carries on as after any first factor: second step if the policy asks
   for one, required profile attributes, terms, consent.

A brokered sign-in records `amr: ["fed"]`. rIDM does not import the upstream
provider's own authentication methods: if a second factor is required, the
user passes rIDM's.

## Linking upstream identities to users

An upstream identity is the pair *(provider, subject)*. Once linked to a local
user, that user signs in with it from then on, whatever the email address
says.

The first time an identity arrives, the provider's `link_policy` decides what
to do when the tenant already has an account with the same email address:

| `link_policy` | Existing account with that email | No such account |
|---------------|----------------------------------|-----------------|
| `verified_email` | linked, if both the upstream provider and the local account have verified the address; otherwise refused | a new account is created |
| `explicit` | refused; the user signs in the usual way and links the provider from the account console | a new account is created |
| `always_new` | a new account is created, without the email address | a new account is created |

A refused sign-in returns to the login page with `broker_error=email_in_use`.

The default choice, `verified_email`, is the one that is safe to automate:
linking on an unverified address would let anyone who can register that address
at the upstream provider take over the local account. `trust_email` tells rIDM
to treat the provider's addresses as verified even when it does not say so;
set it only for providers that really do verify every address, such as your
own corporate directory.

A new account takes its username from the mapped username claim, else the
email address, else `{alias}-{subject}`, with a random suffix if the name is
taken. Mapped profile attributes are written on every sign-in, so changes
upstream flow through.

Users see their linked identities in the account console, can link further
providers there (which sends them through the provider once) and unlink them.
Administrators can list and unlink a user's identities from the user's detail
page.

## Claim mapping

Each provider's `mappers` name the upstream claims to read, looked up in the ID
token first and then in userinfo, with a dot descending into objects:

| Mapper | Default |
|--------|---------|
| `subject` | `sub` (`id` for GitHub) |
| `username` | `preferred_username` |
| `email` | `email` |
| `email_verified` | `email_verified` |
| `attributes` | profile attribute name → upstream claim |

Mapped attributes are validated against the tenant's profile schema like any
other write. Values the schema refuses are dropped and logged rather than
failing the sign-in.

## Configuration as code

Identity providers are part of the [tenant configuration document](config-as-code.md),
without their client secrets, so a tenant can be reproduced in another
environment and the secrets set there afterwards.

Events: `identity_provider.created`, `.updated` and `.deleted`,
`identity.linked`, `identity.unlinked` and `login.brokered` (and
`logout.upstream` when a SAML IdP's logout request ends sessions). An LDAP or
Active Directory directory is a provider of kind `ldap` whose users sign in with the
password form; see [LDAP and Active Directory](../admin/ldap.md). A Kerberos realm is
a provider of kind `kerberos`: the login page asks the browser for a ticket (HTTP
Negotiate), with no redirect; see [Kerberos desktop sign-in](../admin/kerberos.md).
