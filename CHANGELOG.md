# Changelog

Every release of rIDM, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); until 1.0.0 a minor
version may break compatibility, and its notes say how, under **Upgrade notes**. That
heading also marks any release whose migrations do not keep the release before it
working, which makes its upgrade stop-the-world (see the docs' *Upgrading*).

A release's section becomes the body of its GitHub release
(`scripts/release/notes.sh`), and the release workflow refuses a tag whose version
has no section here. Changes land under **Unreleased** as they merge; cutting a
release renames that heading to the version and date.

## [Unreleased]

### Added

- SAML 2.0 identity provider. Every tenant publishes IdP metadata at
  `{issuer}/saml/metadata` (entity ID: the issuer) and answers `AuthnRequest`s
  over HTTP-Redirect and HTTP-POST at `/saml/sso` with a signed, optionally
  encrypted (AES-GCM or AES-CBC, RSA-OAEP) `Response`. A SAML application is
  registered as a service provider — a client of the new type `saml`, with
  `saml_service_providers` holding its entity ID, consumer URLs, logout URL,
  NameID format (pairwise persistent, transient, email or user id), attribute
  names, certificates and signing options — from its metadata or by hand, in
  the console's new SAML page or at `/admin/tenants/{slug}/saml/...`.
  Requests are admitted only from registered SPs, to registered consumer URLs,
  once, within ten minutes, with signatures checked against the SP's
  certificates (`require_signed_requests` to insist). The sign-in itself is
  the OIDC one: second factors (REFEDS MFA and Microsoft `multipleauthn`
  context classes are step-up requests), risk policy, consent and
  organizations apply unchanged. IdP-initiated sign-in (`/saml/init?sp=`) for
  SPs that opt in. Front-channel Single Logout: an SP's `LogoutRequest` ends
  the session and walks the browser through the session's other SAML SPs
  before answering, and RP-initiated logouts walk them too. The SAML signing
  keys are separate from the JWT keys and rotate only by hand (pending,
  published first → active → delete). SPs travel in the tenant document under
  `saml_service_providers`. New events `saml_key.created` and
  `saml_key.status_changed`. The XML signature, canonicalization and
  encryption code is rIDM's own (new dependencies `roxmltree`, `rcgen`,
  `x509-parser`, `flate2`; no C XML library); the parser refuses DTDs,
  signatures are accepted only over the element read, and it is checked
  against xmlsec1 in both directions (CI installs it) and fuzzed
  (`saml_message`).
- Organizations within a tenant: membership (a user may belong to several, one
  of them primary), role grants scoped to an organization, email domains
  verified by DNS TXT record with auto-join, an organization step in the login
  flow, and an `org_id` claim in access and ID tokens taken from the session, so
  one user can act in different organizations in different sessions. New
  `ridm:orgs:read` and `ridm:orgs:write` permissions (user managers hold both),
  a console page, and a read-only list in the account console. A tenant with no
  organizations is unaffected, and no token gains a claim.
- Organization administrators: a role granted *inside* an organization now
  reaches the admin API for that organization alone — its record, members,
  domains, invitations and internal role grants — and never satisfies a
  tenant-wide permission check. A sixth built-in role, `ridm:org-admin`, is
  seeded in every tenant for it. Creating, deleting and listing organizations,
  changing a slug or status, and adding an existing user as a member stay
  tenant-wide; an organization's own administrator adds people through new
  org-scoped invitation routes, and `GET …/{org}/grantable-roles` says which
  roles they may grant there. `GET /admin/me` gained `organization` and
  `organization_permissions`, the console opens such an administrator on their
  own organization, and the MFA-for-administrators policy counts them.
- Risk-based adaptive authentication (`settings.risk`, off by default): four
  signals — new device, new country, impossible travel and failure velocity —
  each with a tenant-set weight, scored against two thresholds. `step_up_at`
  demands a second factor for that sign-in whatever the MFA policy says, and
  not even a trusted device waives it; `block_at` refuses the sign-in, opening
  no session, discarding the flow, denying a waiting device code and returning
  `access_denied` to the client. Either threshold at `0` switches that outcome
  off. Sign-ins are scored when a first factor passes and when a live session
  is reused at `/authorize` or a device approval; an allowed one records the
  country it came from as history. New `risk.step_up` and `risk.blocked` audit
  events (with the score, the signals and the country), a
  `ridm_risk_decisions_total` counter, and an Adaptive auth section in the
  console. Location comes from trusted-proxy headers
  (`GEOIP_COUNTRY_HEADERS`, `GEOIP_LATITUDE_HEADERS`,
  `GEOIP_LONGITUDE_HEADERS`) or a MaxMind DB file the deployment supplies
  (`GEOIP_DB`); with neither, the device and velocity signals still work.
- Admin impersonation (`settings.impersonation`, off by default): an
  administrator holding the new `ridm:users:impersonate` permission (built-in
  `ridm:owner` only) asks `POST /admin/tenants/{slug}/users/{user}/impersonate`
  with a reason for a one-time, 60-second link. Opening it gives that browser an
  SSO session as the user that lasts at most `max_minutes`. Every access and ID token
  minted from the session names the administrator in `act` (`{sub, iss}`) and
  expires with it, and the admin API refuses any token carrying `act`. The
  session owes none of the user's MFA, password-change or risk steps. The
  account API refuses everything that needs a recent sign-in, plus consent
  withdrawal, with the new `urn:ridm:error:impersonation-forbidden`, and no consent
  can be given. Users holding any admin permission can't be impersonated.
  The account console shows a banner with **End impersonation**, which ends
  the session and puts back the browser's own. New `impersonation.requested`,
  `impersonation.started` and `impersonation.ended` events. Every other event
  raised during the session carries the administrator as `impersonator`,
  stored in a new audit column `impersonator_id`. The column is covered by the hash
  chain only when set, so existing rows still verify. The audit API can filter on
  it, and the CSV export has it as a new last column.
- Audit chain verification you can run yourself: `ridm audit verify --file`
  checks a JSON export offline with the chain algorithm (now in `ridm-core`),
  streaming it. `--head` pins the hash the export must end on, and `--after`
  the hash it must follow, so consecutive exports prove one chain. `ridm audit
  verify` asks the server and `ridm audit export` streams a chain to disk. The
  verify endpoint gained `last_hash` and `scheduled`.
- A daily `audit_verify` job checks every chain that grew, from its last
  verified checkpoint. A break is stored, logged, counted
  (`ridm_audit_chain_breaks_total`, `ridm_audit_chains_broken`) and recorded
  once as the new `audit.chain_broken` event in that tenant's chain.
- Feature flags have their own console page (key, description, on/off, and
  per-organization values by slug), and applications can read them: the new
  standard `features` scope adds a `features` claim (the flags on for the
  sign-in's organization) to access and ID tokens, and `GET /t/{slug}/features`
  answers live for any access token of the tenant. `settings.features` values
  are now `{enabled, description, organizations}`; a bare boolean still loads
  and is still accepted.
- Backchannel sign-in (OpenID CIBA Core 1.0): `POST /t/{slug}/bc-authorize`
  takes a `login_hint` (username or email) or an `id_token_hint`, an optional
  `binding_message` and `requested_expiry`, and answers an `auth_req_id`; the
  client collects the tokens with the new `urn:openid:params:grant-type:ciba`
  grant, polling or after rIDM pings its notification endpoint
  (`backchannel_token_delivery_mode` `poll` or `ping`, per client; push is not
  offered). The user is emailed or texted a link to the account console's new
  **Requests** page, where they approve or deny; an approval is remembered as
  consent. At most five requests wait on one user. New
  `backchannel_request` message template, `backchannel.requested` and
  `backchannel.denied` events, `unknown_user_id` and `invalid_binding_message`
  errors, and the CIBA discovery metadata.
- The FAPI 2.0 Security Profile per client (`security_profile: fapi2`):
  registration refuses anything outside the profile, `/authorize` accepts only
  pushed requests, PKCE and DPoP-bound tokens are compulsory, client
  assertions must be PS256/ES256/EdDSA with the issuer as a string `aud`,
  request objects and DPoP proofs PS256/ES256/EdDSA, tokens and JARM responses
  are signed with ES256 or EdDSA even when the tenant defaults to RSA, and
  refresh tokens are not rotated. mTLS is not offered yet, so DPoP is the only
  sender constraint.
- `require_pushed_authorization_requests` per client, for PAR without the rest
  of the profile.

### Changed

- The audit export sink (`AUDIT_SINK_URL`) ships from the database instead
  of an in-memory queue. It keeps a cursor per chain and advances it only
  once the receiver accepts the rows, backing off up to a minute on failure,
  so a receiver outage or a restart no longer loses rows. Delivery is at
  least once, so deduplicate on the row's `id`. A newly configured
  destination starts at the chains' current heads. HTTP batches are one chain
  each, in order, and are signed with `X-RIDM-Signature` when
  `AUDIT_SINK_SECRET` is set. `syslog+tls://` (RFC 5425) and
  `AUDIT_SINK_CA_FILE` are new. `ridm_audit_sink_dropped_total` is gone;
  watch `ridm_audit_sink_lag_rows` instead.

### Fixed

- Dynamic registration accepted `require_pushed_authorization_requests` and
  dropped it; it is now stored and enforced.
- The legacy password verifier took its iteration count from the stored hash
  and allowed up to ten million rounds, which is about 25 seconds of CPU for
  PBKDF2-SHA512: an imported or crafted hash turned every sign-in attempt
  against that account into a worker held hostage. The ceiling is now a
  million, above every corpus rIDM imports from, and a hash beyond it is
  refused rather than computed. Found by the `jwt_decode` fuzz target.

## [0.1.0] - 2026-09-19

The first release.

### Added

- Multi-tenant OpenID Connect provider: authorization code with PKCE, PAR, JAR,
  JARM, DPoP, device authorization, client credentials, token exchange, refresh
  rotation, introspection, revocation, RP-initiated, front- and back-channel logout,
  dynamic client registration.
- Users, groups, roles, resource servers and permissions; passwords, magic links,
  TOTP, WebAuthn passkeys, recovery codes; social and OIDC brokering; SCIM 2.0;
  bulk import from Keycloak and Auth0 exports.
- Admin and account consoles, embedded in the server binary.
- Webhooks, a tamper-evident audit log with export sinks, rate limits, IP rules
  and CAPTCHA.
- The `ridm` admin CLI and the `ridm-auth` crate for Rust resource servers.
- Container image, Helm chart, production docker-compose stack with nginx, Caddy
  and Traefik configurations, and a documentation site.
- Release workflow: signed multi-arch images with SBOMs, static Linux binaries,
  the Helm chart as an OCI artifact, checksums signed with Sigstore.
- Backup and restore, and upgrade, guides; a start-up check that refuses a master key
  that does not decrypt the database's signing keys, and a warning when the database was
  migrated by a newer release.
- `/.well-known/security.txt` is the operator's: `SECURITY_CONTACT`,
  `SECURITY_POLICY_URL` or a whole `SECURITY_TXT_FILE`, and 404 until one is set.

[Unreleased]: https://github.com/ZerosAndOnesLLC/rIDM/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ZerosAndOnesLLC/rIDM/releases/tag/v0.1.0
