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
- SAML 2.0 identity providers upstream: an identity provider of the new kind
  `saml` (settings in `saml_identity_providers`) makes rIDM the service provider
  of a SAML IdP. It is set up from the IdP's metadata URL or document
  (`POST /admin/tenants/{slug}/identity-providers/saml-metadata`), and publishes
  its own SP metadata at `{issuer}/broker/{alias}/saml/metadata` (the SP entity
  ID), with signing and encryption certificates from the tenant's SAML keys.
  `AuthnRequest`s are signed and sent by HTTP-Redirect or HTTP-POST; the
  assertion consumer service accepts only responses signed with a registered
  certificate (the assertion itself unless `want_assertions_signed` is off),
  answering rIDM's request, for this SP and consumer URL, within their window,
  once, and decrypts encrypted assertions (`require_encrypted_assertions` to
  insist). The continue step after it is bound to the starting browser by a
  cookie (login CSRF). The NameID is the subject unless a mapper names an
  attribute (a transient NameID needs one); well-known attribute names (`mail`,
  the eduPerson and Microsoft claim URIs, …) feed the default claims. IdP-initiated
  sign-in is a per-provider opt-in landing on a client's `initiate_login_uri` or
  the account console. Single Logout both ways: the IdP's signed `LogoutRequest`
  ends the sessions it brokered and walks their SAML SPs (event
  `logout.upstream`); a sign-out at rIDM sends the IdP a `LogoutRequest` after the
  downstream SPs. The new hourly `saml_metadata_refresh` job re-reads metadata URLs
  daily (`…/{alias}/saml/refresh` does it now); metrics
  `ridm_saml_sp_responses_total`, `ridm_saml_metadata_refresh_total`. Console:
  a SAML choice under Identity providers and its settings page.
- LDAP / Active Directory upstream: an identity provider of the new kind `ldap`
  (settings in `ldap_identity_providers`; the service account's bind password
  encrypted where every provider keeps its secret). Directory users sign in with
  the password form: rIDM binds as their entry (found by `entryUUID` or
  `objectGUID`) and keeps no local password, so a password changed or an account
  disabled in the directory counts at once; an identifier no account has is looked
  up in the tenant's directories and imported through the link policy on a
  successful bind. The new `ldap_sync` job runs each directory's incremental
  sync (`modifyTimestamp` / `whenChanged`) on its interval and a full one daily,
  which also disables users who left the directory (or are disabled in AD) and
  enables them when they return; a full pass that reads nothing disables nobody.
  Directory groups become rIDM groups the directory owns (AD ranged `member`
  values read in full). `edit_mode: writable` writes password changes and resets
  (Password Modify, or `unicodePwd` on AD), email and mapped attributes to the
  directory first; `read_only` refuses them. Connections go over LDAPS or
  StartTLS (plain LDAP for loopback only) with an optional pinned CA, through the
  SSRF-checked resolver (private networks need `OUTBOUND_ALLOW_NETWORKS`).
  Admin API `POST …/identity-providers/{idp}/ldap/test` and `…/ldap/sync`;
  event `directory.synced`; metrics `ridm_ldap_syncs_total`,
  `ridm_ldap_sync_seconds`. Console: an LDAP / Active Directory choice under
  Identity providers with a connection test, sync status and Sync now. New
  dependency `ldap3` 0.12.1 (MIT/Apache-2.0, rustls).
- Kerberos / SPNEGO desktop sign-in: an identity provider of the new kind
  `kerberos` (settings in `kerberos_identity_providers`; the service's keytab
  encrypted where every provider keeps its secret, only its entries shown). The
  login page posts to the flow's new `/kerberos` step, on its own from the
  provider's `trusted_networks` (unless `prompt=login` or `max_age=0`) or from a
  "Continue with …" button; rIDM answers with an HTTP Negotiate challenge, and a
  browser holding a ticket for `HTTP/<host>` signs in without typing. Tickets are
  validated by rIDM itself (no system GSSAPI): the service principal and keytab,
  validity, allowed realms, the authenticator's client and clock, a replay cache
  in Valkey; AES encryption types only; the mutual-authentication answer is sent
  back. A principal finds its account through an LDAP provider
  (`ldap_idp_id`, looked up by `sAMAccountName`/`uid` or the principal
  attribute, and imported as a password sign-in would), or else its link, a
  local username (`match_username`) or a new account (`create_users`). The
  session's `amr` is `kerberos`, and SAML assertions state the Kerberos context
  class. Admin API `POST …/identity-providers/kerberos-keytab` reads a keytab
  without storing it; the tenant document carries the settings with the
  directory named by alias. Metric `ridm_kerberos_negotiations_total`. The
  acceptor is the new `kerberos` cargo feature (new dependency `picky-krb`
  0.12.4, MIT/Apache-2.0, pure Rust, for the RFC 3962 AES encryption), on in
  the released image and binaries; without it a provider can be configured but
  not used. Tested against MIT Kerberos (a KDC and GSSAPI initiator in a
  container, and headless Chromium negotiating in the browser suite).
- Mutual-TLS client authentication and certificate-bound access tokens
  (RFC 8705). Client certificates reach rIDM on a second listener that asks
  for them (`MTLS_BIND`, with `MTLS_CERT`/`MTLS_KEY` or the main TLS
  certificate) or in a header from a TLS-terminating proxy
  (`CLIENT_CERT_HEADER`, believed only from `TRUSTED_PROXIES`; PEM,
  URL-encoded PEM or base64 DER). Two new client authentication methods:
  `tls_client_auth`, a certificate chaining to one of the tenant's trusted
  authorities (new console page Security → Client certificates,
  `/admin/tenants/{slug}/mtls/trust-anchors`, `mtls_trust_anchors` in the
  tenant document, events `mtls_trust_anchor.created`/`.deleted`) and
  carrying the subject DN or SAN registered for the client; and
  `self_signed_tls_client_auth`, a certificate in the client's JWK Set.
  `tls_client_certificate_bound_access_tokens` binds a client's access
  tokens (and a public client's refresh tokens) to its certificate
  (`cnf.x5t#S256`); userinfo and the account and admin APIs check it, and
  token exchange will not loosen it. With `MTLS_PUBLIC_URL`, discovery
  publishes `mtls_endpoint_aliases` so browsers never meet a certificate
  prompt. Dynamic registration takes the RFC 8705 metadata, and a FAPI 2.0
  client may use mutual TLS for authentication and sender constraint in
  place of `private_key_jwt` and DPoP. `ridm-auth` gains
  `Validator::validate_with_certificate`, `Claims::x5t_s256` and
  `certificate_thumbprint`. New fuzz target `client_cert`.
- Key custody: an HSM or a key-management service can hold the master key
  instead of the environment. `KEY_WRAPPER` names the backend — `pkcs11` (any
  PKCS#11 HSM, AES-GCM on the token), `aws-kms`, `vault` (Vault or OpenBao
  Transit, with a token or the Kubernetes auth method), `gcp-kms` or
  `azure-key-vault` (Key Vault or Managed HSM) — and makes `MASTER_KEY`
  optional. Each master-key generation is then a random data key the backend
  wrapped, stored wrapped in the new `master_key_generations` table and
  unwrapped by every node at start-up, so no request calls the backend and a
  backend outage stops only the start of new nodes. Generations from the
  environment and from backends coexist (`KEY_WRAPPER_PREVIOUS` for a backend
  being left), so a deployment moves onto one, off it, or between two online
  with the existing re-encryption. Workload identity everywhere it exists:
  IRSA / EKS Pod Identity, GKE and Azure Workload Identity, workload identity
  federation files, Vault's Kubernetes auth (OpenShift too). New
  `ridm-api rotate-master-key --new-generation`, `ridm master-key
  new-generation`, `POST /admin/master-key/generations` and a **New
  generation** button in the console, whose master-key card now shows the
  backend and every generation; `GET /admin/master-key` gains `generations`
  and `key_wrapper`. New global event `master_key.generation_created`. Each
  backend is a cargo feature (`hsm-pkcs11`, `kms-aws`, `kms-vault`, `kms-gcp`,
  `kms-azure`), off in a plain build and on in the image; the static release
  binaries carry every one but PKCS#11. New dependencies `cryptoki` 0.12.1,
  `aws-config` 1.12.0 and `aws-sdk-kms` 1.121.0 (Apache-2.0), optional. The
  Helm chart gains `keyCustody`, and `masterKey` becomes optional with it.

### Changed

- `ridm-api migrate` no longer reads the master key, and the Helm chart's
  migration Job no longer receives it.

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

- Brokered sign-ins through OpenID Connect and OAuth 2.0 providers are now
  bound to the browser that started them: a `SameSite=Lax` cookie set at
  `/broker/{alias}/start` must come back to the callback, so a callback URL
  opened in another browser no longer signs it in to someone else's account
  (login CSRF). Posted callbacks (`form_post`, Apple) are parked and continued
  by a same-site GET at `…/callback?continue=`.
- The SAML IdP's front-channel logout page, shown when OIDC front-channel
  logout URLs have to be framed, dropped the auto-posting form of a
  POST-binding SP's `LogoutResponse`; the form is now embedded and submitted
  after the frames.
- A sign-out started by a downstream SAML SP now reaches the upstream SAML IdP
  that brokered the session before the SP is answered.

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
