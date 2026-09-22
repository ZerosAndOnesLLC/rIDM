# Threat model

rIDM is an OpenID Connect provider: it holds the credentials of every user of every
application that trusts it, and it mints the tokens those applications accept. A single
authentication bypass here is a bypass of every application behind it. This document
records what rIDM protects, who it protects it from, what stops each attack today, and
what it deliberately leaves to the deployment.

It is written against the code in this repository. Every mitigation names where it lives
so the claim can be checked, and the regression tests that hold it in place. Findings
from reviews, fuzzing, conformance runs and external reports become named tests in
[`api/tests/security/`](api/tests/security/main.rs).

## 1. What is being protected

| Asset | Why it matters | Where it lives |
|---|---|---|
| User credentials | Password reuse makes a leak everyone's problem | `users.password_hash` (argon2id), never logged or returned |
| Signing keys | Anyone holding one mints tokens for any user | `signing_keys.private_key_enc`, envelope-encrypted |
| Client secrets, registration and provisioning tokens | Impersonate a relying party | Hashed; shown once on create or rotate |
| Second-factor secrets | Defeat step-up authentication | `credentials.data_enc`, envelope-encrypted |
| Upstream provider secrets, SMTP and webhook credentials | Pivot into the tenant's other systems | `*_enc` columns, excluded from tenant export |
| Live sessions and refresh tokens | Sign in as a user without their credentials | Postgres, revocable |
| Audit log | The record of what happened, and the first thing an intruder edits | Per-tenant SHA-256 hash chain |
| Personal data | Regulatory and reputational exposure | Tenant-scoped rows under row-level security |

## 2. Trust boundaries

1. **Internet to API.** Every public endpoint. Untrusted input, unauthenticated by
   default. The largest boundary and the one most of this document concerns.
2. **Tenant to tenant.** One deployment serves many tenants who must never see each
   other's data. Enforced in the database by row-level security, not only in code: every
   query runs inside a transaction bound to one tenant (`db::tenant_tx`).
3. **User to administrator.** Admin API permissions decide who may read and change what,
   and `AdminCtx::require_can_grant` stops an administrator granting more than they hold.
4. **Application to identity provider.** A relying party is not trusted to tell the truth
   about itself: redirect URIs, scopes, audiences and grant types are all checked against
   what was registered.
5. **Process to datastore.** Postgres and Valkey are trusted to store what they are
   given, not to authenticate callers. Secrets are encrypted before they are written, so
   a database copy alone does not yield keys.
6. **Deployment to rIDM.** The master key, TLS termination, network reachability of
   Postgres and Valkey, and the container's runtime are the operator's responsibility.
   Section 6 lists these explicitly.

## 3. Adversaries

- **An anonymous internet attacker.** Probing endpoints, guessing passwords, replaying
  codes and tokens, hunting for open redirects.
- **A registered end user.** Authenticated, but should reach only their own data. The
  self-service account API is the interesting surface.
- **A relying party.** Holds a client id and perhaps a secret. Should not be able to read
  another client's tokens, widen its own scopes, or have rIDM call arbitrary hosts.
- **A tenant administrator.** Legitimately powerful inside one tenant, and must stay
  inside it. Should not reach another tenant, nor escalate to the deployment.
- **A network observer or an active middlebox.** Reads or rewrites traffic that is not
  protected end to end.
- **Someone holding a database copy.** A backup, a snapshot, or a compromised replica.
- **A compromised dependency.** A malicious or vulnerable crate or npm package.

Out of scope: an attacker with root on the host running rIDM, or with the master key.
Both are game over by construction, and the mitigation is operational.

## 4. Threats and what answers them

### Authentication

| Threat | Mitigation |
|---|---|
| Password guessing, credential stuffing | argon2id hashing; per-user and per-IP flow rate limits; a CAPTCHA demanded after repeated failures; optional breached-password check against a configured service |
| Weak or reused passwords | Per-tenant password policy; the breach check refuses known-leaked passwords at set time |
| Phishing of a second factor | Passkeys are origin-bound by WebAuthn; TOTP and one-time codes are not, and the tenant chooses which to offer |
| Second factor skipped | `flows::mfa_required` decides from tenant policy, the user's roles, and the `acr_values` the client asked for; a trusted device never skips a client-requested step-up |
| A session that predates a stricter policy | `/authorize` and device approval re-check a live session against the tenant's MFA policy as it stands now and against a pending forced password change, and send an unfinished session back to that stage (`prompt=none` answers `login_required`); sessions of disabled or deleted users get no code |
| Session fixation | A session identifier is issued only after the whole flow completes, including any second factor |
| Stolen session cookie | `HttpOnly`, `SameSite=Lax`, and with `COOKIE_SECURE` the `__Host-` prefix (so `Secure`, `Path=/`, no `Domain`); named per tenant (`__Host-ridm_session_{slug}`) so tenants never share one; idle and absolute timeouts; a cap on concurrent sessions |
| Cross-site request forgery on the flow API | Every flow carries a CSRF token checked on each step (`flows::check_csrf`) |
| Enumerating which accounts exist | Password reset and passwordless start answer identically for known and unknown identifiers |

### OAuth and OpenID Connect

| Threat | Mitigation |
|---|---|
| Authorization code interception | PKCE S256; required for public clients and by default for dynamically registered ones (`dcr.require_pkce`) |
| Code replay | Codes are single use; replaying one revokes everything the first exchange produced, refresh family and access token alike (RFC 6749 §4.1.2) |
| Open redirect | Redirect and post-logout URIs must match a registered value exactly; no wildcards, no fragments |
| Token substitution across clients or tenants | Audience, issuer and `azp` are checked on every token; `id_token_hint` from another tenant is refused |
| Replayed ID token | `nonce` is bound to the authorization request and checked on return |
| Refresh token theft | Rotation with reuse detection: replaying a consumed token revokes the whole family; public clients' tokens are DPoP-bound |
| Bearer token theft in transit or at rest | Optional DPoP sender-constraining (RFC 9449), per-client enforcement, with a `jti` replay guard |
| Token lifetime abuse after logout or revoke | A `jti` denylist in Valkey stops JWT access tokens before expiry; opaque access tokens live in Valkey and are deleted on revocation. Ending a session revokes its refresh tokens (offline ones included), refresh tokens without `offline_access` die with their session, a code whose session was signed out is refused, and every sign-out path sends back-channel logout |
| Widening a grant on refresh | `resource` may only narrow to the original grant's audiences (`invalid_target`); an ungranted `scope` is `invalid_scope`, answered before the refresh token is spent |
| A client widening its own reach | Scopes, audiences and grant types are checked against registration; token exchange may only narrow, and only into audiences the client explicitly lists |
| Trading a sender-constrained token for a looser one | Exchanging a subject token that carries `cnf.jkt` requires a proof of the same key |
| Forged request objects | Request objects must be signed; `none` is not offered |
| Mix-up between providers when brokering | The upstream's issuer and audience are verified, and its state is bound to the local flow |
| A client pushing unwanted backchannel (CIBA) sign-in requests at a user | Only confidential clients with the CIBA grant may ask; at most five requests wait on one user; the user must approve on their own, signed-in account console, never from the notice alone; an impersonated session cannot answer |
| Phishing through the CIBA notice | The binding message is limited to 64 letters, digits, spaces and `-_.:#` (no links, markup or line breaks); the notice links to the tenant's own account console, never carries the `auth_req_id`, and the request is answerable only by the user it names |
| Collecting someone else's CIBA grant | The `auth_req_id` is 256 random bits, stored hashed, bound to the requesting client, and handed over once; ping callbacks go through the outbound SSRF guard |
| Forged or wrapped SAML signatures | rIDM's own XML-DSig accepts one shape only: an enveloped signature with one `Reference` to the verified element's `ID`, that `ID` unique in the document, exclusive C14N without comments, no SHA-1; keys come from the SP's registered certificates, never from `KeyInfo`; and the verified element itself is what is read, so a signature over another part of the document proves nothing. Checked against xmlsec1 in both directions and fuzzed |
| XML entity attacks (XXE, billion laughs) | The XML parser refuses DTDs outright; documents are capped at 256 KiB after DEFLATE (which is itself read with a limit), 20,000 nodes and 64 levels |
| A SAML response sent somewhere it should not go | The consumer URL is only ever one the SP registered; unregistered URLs are an error page, not a redirect |
| Replayed or stale SAML requests | Request IDs are remembered for 15 minutes and accepted once; `IssueInstant` must be within ten minutes (three of skew); a signed request must name rIDM as its `Destination` |
| Unsolicited SAML responses pushing a user into an application | IdP-initiated sign-in is off unless the SP opts in |
| A forged, wrapped or misdirected assertion from an upstream SAML IdP | Only the IdP's registered certificates count (never `KeyInfo`); the element read is the one the verified signature covers, and a `Response` must carry exactly one assertion; the assertion must be signed itself by default; issuer, audience, recipient, `InResponseTo` and validity window must be rIDM's; assertion IDs are remembered until they expire |
| Login CSRF through the SAML assertion consumer service or a broker callback | Responses are accepted only for a request rIDM sent (unsolicited ones are a per-provider opt-in), and the step that signs the browser in (the OIDC/OAuth callback, or SAML's same-site continue) requires the binding cookie set in the browser that started the sign-in; posted answers are parked and continued same-site so the cookie is always checked |
| A forged upstream `LogoutRequest` signing users out everywhere | It must be signed with the IdP's registered certificate, name rIDM's logout URL, be fresh and seen once |
| An upstream IdP's metadata URL used to reach internal hosts, or a substituted IdP | Fetched through the SSRF-guarded outbound client (public addresses, https, no redirects, 256 KiB); a refresh naming another entity ID is refused |
| LDAP filter injection through the sign-in identifier (`*`, `x)(uid=*`) | Every value put into a filter is escaped (RFC 4515), so an identifier matches only an entry with exactly that value; filters and attribute names an administrator writes are parsed when saved. Regression test `tests/security/ldap.rs` |
| An LDAP unauthenticated bind (a DN with an empty password) accepted as a sign-in | An empty password is never sent to the directory |
| A local password outliving the directory (changed or disabled there) | Directory users keep no local hash: linking clears it, password writes go to the directory or are refused, a bulk hash import is refused for them; an unreachable directory is a 503, never a local fallback |
| A tenant administrator using an LDAP URL to reach internal hosts, or LDAP credentials sent in the clear | The host is resolved through the SSRF-checked resolver and the socket opened to the vetted address (private networks only when the operator opens them); LDAPS or StartTLS with certificate verification (an optional pinned CA) is required except for loopback |
| A hostile directory crashing sign-in with a malformed entry, or a misconfigured one locking everyone out | Entries are parsed without panicking; a full sync that reads no entries disables nobody |
| SAML signing key rotation breaking SPs, or a stolen key | The SAML keys are separate from the JWT keys and never rotate on a timer; a rollover publishes the new certificate before it signs; keys are encrypted under the master key |
| Downgrade of a high-assurance client | A client under the FAPI 2.0 profile is refused, at registration and on every request, anything weaker than the profile: no request outside PAR, no missing PKCE or DPoP, no RSA-PKCS1 or HMAC signatures, no client assertion addressed to anything but the issuer |

### Multi-tenancy and authorization

| Threat | Mitigation |
|---|---|
| Reading another tenant's data | Row-level security in Postgres plus a tenant-bound transaction per request; cross-tenant confinement has a test in every admin suite |
| Privilege escalation by an administrator | `AdminCtx::require_can_grant`; built-in roles, resource servers and permissions are immutable |
| Escalation through bulk paths | The same no-escalation rule holds where grants arrive in bulk: a user-import row, or a tenant-import item, that grants roles or groups carrying admin permissions the importer lacks fails on its own (dry runs report it too); a SCIM provisioning token cannot add members to a group that grants admin (`ridm:*`) permissions (`403`) |
| Host header confusion between tenants | Custom domains resolve through a unique index, and only trusted proxies' forwarded headers are honoured |
| A custom domain reaching beyond its tenant | `middleware::host` passes through only the health probes, host-wide well-known documents and the tenant's own `/t/{slug}/…` and `/scim/v2/{slug}/…` paths, and rewrites everything else under `/t/{slug}`: the admin API, `/metrics`, `/docs`, `/openapi.json` and other tenants answer `404` there |
| Claim mappers forging token semantics | Mappers cannot target protected claims (including `cnf` and `act`) or `permissions`; only a `roles` or `groups` mapper writes those claims |
| A tenant reaching the deployment's own clients | The admin and account console clients are built in and rejected for modification |
| Guard and handler disagreeing about which tenant a request is for | The request guard refuses any `/t/{slug}` path whose raw segment is not already a valid slug, so an escaped slug cannot route past the tenant's IP rules |

### Injection and server-side request forgery

| Threat | Mitigation |
|---|---|
| SQL injection | Every query is parameterised through sqlx; the only interpolated identifiers are compile-time constants |
| Cross-site scripting in the hosted pages | React escaping; a hash-based CSP on every exported page; server-rendered pages escape and carry their own policy |
| Clickjacking | `X-Frame-Options: DENY` and `frame-ancestors 'none'` on every API response and UI page, except the login page, which only its own origin may frame (`SAMEORIGIN`, `frame-ancestors 'self'`) for the console's branding preview |
| SSRF through URLs tenant administrators or client registrations choose | Webhooks, back-channel logout URIs, client `jwks_uri`s, identity provider endpoints, tenant HTTP email/SMS gateways, the CAPTCHA `verify_url` and a tenant SMTP host go through `util::outbound`: a resolver that keeps only public addresses (private, loopback, link-local, CGNAT, unique-local, documentation and mapped forms refused) at connection time, so DNS rebinding does not help; IP literals checked before sending; no redirects; no environment proxy. Loopback named as such stays allowed for development. The tenant SMTP connection goes to the vetted address with TLS verifying the configured name. Operator-set URLs (audit sink, breach check) are not filtered |
| Header injection through forwarded headers | The forwarded chain is read from the right past `TRUSTED_PROXIES`, so an appending proxy cannot let a caller choose its own address |

### Availability

| Threat | Mitigation |
|---|---|
| Brute force and flooding | Fixed-window rate limits per IP, per client and per tenant on the token, authorize and flow families, with `RateLimit-*` headers |
| Expensive operations as a lever | argon2id parameters are bounded; signing keys are cached; the token path avoids per-request database work |
| Queue and job pile-up | Background jobs hold a leader lock, retry with backoff, and dead-letter |
| Unbounded growth | Retention-based cleanup of spent rows |

Denial of service by volume is a deployment concern: rIDM limits what one caller can do,
but an edge proxy or WAF is what absorbs a flood.

### Confidentiality at rest

| Threat | Mitigation |
|---|---|
| Database copy yields keys and secrets | Envelope encryption with per-row AAD for signing keys, credentials, identity provider secrets, provider settings (SMTP, SMS, CAPTCHA) and webhook secrets |
| Master key compromise | Versioned keys with an online rotation path that re-encrypts every table |
| Secrets leaking through exports or APIs | Tenant export omits secrets and says so in its report; secrets are reveal-once and never re-readable |
| Secrets in logs | Secret-bearing fields are excluded from serialisation; tokens are never logged |

### Integrity of the record

| Threat | Mitigation |
|---|---|
| An intruder editing the audit log | Per-tenant SHA-256 hash chain: a changed or deleted row breaks verification |
| Losing the record with the host | Audit rows ship to an external sink over HTTP or syslog |

### Supply chain

| Threat | Mitigation |
|---|---|
| Vulnerable or unmaintained crate | `cargo audit` and `cargo deny` on every pull request, with exceptions documented in `deny.toml` |
| Vulnerable npm package | `npm audit --omit=dev` on every pull request |
| Unexpected licence or source | `cargo deny` licence allow-list and source restrictions |
| Dependency drift | Exact-pinned versions, lockfiles committed, Renovate updates |

## 5. Verification

- **Named negative tests.** `api/tests/security/main.rs` holds the cases that must keep
  failing: nonce binding, cross-tenant `id_token_hint`, PKCE and redirect downgrade,
  open redirect and injection attempts, an escaped tenant slug dodging the request
  guard, and a forged forwarded entry choosing the client address. Findings that need a
  suite's own machinery live with it, each named for the review that raised it.
- **Per-feature suites.** Rate limits, IP rules, DPoP, token exchange, SCIM, custom
  domains and the browser policy each have their own suite.
- **Conformance.** The OpenID Foundation suite runs per pull request and weekly; see
  [`conformance/`](conformance/README.md).
- **Static analysis.** clippy with warnings denied, ESLint, and no `unsafe` in this
  codebase.
- **Review.** Every phase ends with a security review pass over the branch.

## 6. What rIDM does not do for you

These are assumptions, not oversights. A deployment that breaks one of them loses the
guarantees above.

1. **TLS is terminated, by rIDM or in front of it.** rIDM terminates TLS itself when
   `TLS_CERT` and `TLS_KEY` are set; otherwise a reverse proxy must. It sets HSTS when
   its public URL is https and marks cookies `Secure` with `COOKIE_SECURE`, but it
   cannot tell whether the path between a proxy and itself is protected.
2. **`MASTER_KEY` is supplied by the environment and kept out of the repository.** Its
   confidentiality is the whole basis of encryption at rest. Rotate it with the
   documented procedure.
3. **Postgres and Valkey are not reachable from the internet.** rIDM authenticates to
   them; it cannot stop anyone else who can reach them.
4. **`TRUSTED_PROXIES` matches reality.** Set it too wide and a caller can forge their
   own address, defeating IP rules and per-IP rate limits.
5. **Backups are encrypted and access-controlled.** They contain the same data as the
   database.
6. **Volume-based denial of service is absorbed at the edge.**
7. **Clocks are synchronised.** Token expiry, TOTP and DPoP proofs depend on it.
8. **Administrators are trusted inside their tenant.** A hostile tenant administrator can
   read that tenant's users and mint tokens for them. Impersonation with an explicit
   permission and a full audit trail is Phase 12.

## 7. Known gaps

Recorded rather than hidden; each is either scheduled or a deliberate trade-off.

- **No DPoP server nonces, and no `dpop_jkt` at the authorization endpoint.** Both are
  optional in RFC 9449 and would tighten binding further.
- **The `claims` request parameter is not implemented.** Discovery says so. Scopes cover
  the same claims.
- **No mutual-TLS client authentication or certificate-bound tokens (RFC 8705).** DPoP is
  the only sender constraint, including for FAPI 2.0 clients; mTLS is Phase 13.
- **CIBA requests cannot be signed and take no user code.** Both are optional in CIBA
  Core; a client asking for either at registration is refused.
- **SAML logout is front-channel only.** SPs are logged out through the user's browser;
  a session ended without one (an administrator's revocation, a password change) does
  not reach them, and there is no SOAP back-channel logout. An SP that never answers
  its logout request stops the walk at its page. The same holds for upstream SAML IdPs.
- **No hardware security module or cloud key management backend.** The
  `KeyEncryptor` interface exists for it; backends are Phase 13.

## 8. Reporting

See [SECURITY.md](SECURITY.md) for private reporting, response times and disclosure.
