# HTTP endpoints

Every HTTP route the server mounts, apart from the admin API (`/admin/...`), which has its own [reference](admin-api.md). Paths are relative to `PUBLIC_URL`; examples use `https://id.example.com` and the tenant `acme`, whose issuer is `https://id.example.com/t/acme`.

Tenant endpoints live under `/t/{slug}`. A tenant with a [custom domain](../admin/custom-domains.md) also answers every one of them on its own host without the prefix (`https://login.acme.example/token` as well as `https://id.example.com/t/acme/token`); both forms report the same issuer. A custom host serves that tenant only: besides the tenant's routes it answers `/healthz`, `/readyz`, `/.well-known/webfinger`, `/.well-known/security.txt` and the tenant's own `/t/{slug}/…` and `/scim/v2/{slug}/…` paths, and `404` for everything else (the admin API, `/metrics`, `/docs`, `/openapi.json`, other tenants). The router lives in [`api/src/lib.rs`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/api/src/lib.rs).

The **Limit** column names the rate-limit family a route counts against (see [Rate limits, IP rules and CAPTCHA](../admin/security-controls.md)). Tenant IP rules are checked by the same guard, so routes marked `—` are subject to neither.

| Family | Tenant setting | Refusal format |
|--------|----------------|----------------|
| `token` | `rate_limits.token_per_ip`, `token_per_client` | OAuth JSON (`{"error": "slow_down"}`) |
| `authorize` | `rate_limits.authorize_per_ip` | HTML page for `/authorize`, OAuth JSON for `/par` and `/register` |
| `flows` | `rate_limits.flows_per_ip` | RFC 9457 problem document; HTML page for brokering |

## Global

| Method | Path | Auth | Limit | Purpose |
|--------|------|------|-------|---------|
| GET | `/healthz` | none | — | Liveness: `{"status": "ok", "version": "..."}`. Never touches a dependency. |
| GET | `/readyz` | none | — | Readiness: pings Postgres and Valkey; `200` with `{"status": "ok", "checks": {"database": "ok", "cache": "ok"}}`, or `503` with `"status": "degraded"` and the failing check as `"fail"`. |
| GET | `/metrics` | `Bearer <METRICS_TOKEN>` when that variable is set, otherwise none | — | Prometheus exposition (`text/plain; version=0.0.4`). See [Observability](../deploy/observability.md). |
| GET | `/openapi.json` | none | — | The admin and account API's OpenAPI 3 document. Always served. |
| GET | `/docs` | none | — | Swagger UI over `/openapi.json`; mounted only when `DOCS_ENABLED=true`. |
| GET | `/.well-known/webfinger` | none | — | Issuer discovery (OIDC Discovery 1.0 §2, RFC 7033). `resource` is `acct:user@domain` (the domain must be in a tenant's `settings.discovery.email_domains`) or an issuer URL or any URL beneath it. |
| GET | `/.well-known/security.txt` | none | — | Vulnerability disclosure policy (RFC 9116). |

The container image's `HEALTHCHECK` runs `ridm-api --healthcheck` inside the container, which probes `/healthz` at `BIND_ADDR` (loopback for a wildcard address), over HTTPS when `TLS_CERT` is set.

## Tenant OpenID Connect and OAuth 2.0

| Method | Path | Auth | Limit | Purpose | Specification |
|--------|------|------|-------|---------|---------------|
| GET | `/t/{slug}/.well-known/openid-configuration` | none | — | Provider metadata (below). `ETag`, `Cache-Control: public, max-age=300, must-revalidate`, `304` on `If-None-Match`, `Access-Control-Allow-Origin: *`. | OIDC Discovery 1.0 §3, RFC 8414 |
| GET | `/t/{slug}/.well-known/jwks.json` | none | — | The tenant's published signing keys (pending, active and retiring; revoked keys are removed at once). Same caching as discovery. | RFC 7517 |
| GET, POST | `/t/{slug}/authorize` | client identified by `client_id` | authorize | Authorization endpoint. POST takes `application/x-www-form-urlencoded`. Client and `redirect_uri` problems render an HTML error page; everything else is returned to the client's redirect URI with `state` and `iss`. | RFC 6749 §4.1, OIDC Core §3.1.2, RFC 7636, RFC 9207, RFC 9101 |
| POST | `/t/{slug}/par` | client authentication | authorize | Pushed authorization request; answers `201 {"request_uri": "urn:ietf:params:oauth:request_uri:...", "expires_in": ...}` for a single use at `/authorize`. | RFC 9126 |
| POST | `/t/{slug}/token` | client authentication | token | Token endpoint, form-encoded only. Grants below. Optional `DPoP` header. | RFC 6749 §3.2, RFC 8693, RFC 8628, RFC 9449, RFC 8707 |
| POST | `/t/{slug}/device_authorization` | client authentication | token | Starts the device authorization grant; the client must be allowed the device-code grant. | RFC 8628 §3.1 |
| GET, POST | `/t/{slug}/userinfo` | access token, JWT or opaque (`Authorization: Bearer` or `DPoP`, or an `access_token` form field on POST) | token | Claims about the token's subject; the token must carry `openid`. See [Token claims](token-claims.md#userinfo-response). | OIDC Core §5.3, RFC 6750 |
| POST | `/t/{slug}/introspect` | client authentication (confidential clients only) | token | Token introspection for refresh tokens (`rt_...`), personal access tokens (`rpat_...`) and access tokens, JWT or opaque (`at_...`); the only way a resource server learns what an opaque token stands for. Unknown, expired, foreign or inactive tokens, and ID tokens, answer `{"active": false}`. | RFC 7662 |
| POST | `/t/{slug}/revoke` | client authentication | token | Revokes a refresh token with its whole family, or an access token: its `jti` is denylisted until it expires, and an opaque token's entry is dropped. Unknown tokens still answer `200`. | RFC 7009 |
| GET, POST | `/t/{slug}/end_session` | none (`id_token_hint` recommended) | — | RP-initiated logout. With an `id_token_hint` matching the browser session the logout is immediate; otherwise the UI asks the user first. | OIDC RP-Initiated Logout 1.0 |
| GET | `/t/{slug}/end_session/{flow}` | none | — | State of a pending logout for the UI's logout page (who is being signed out of, and the CSRF token). | |
| POST | `/t/{slug}/end_session/confirm` | CSRF token of the logout flow | — | The user's confirmation from the logout page. Back-channel logout tokens are sent and front-channel logout URLs (with `iss` and `sid`) are returned for the page to load. | OIDC Back-Channel Logout 1.0, Front-Channel Logout 1.0 |
| POST | `/t/{slug}/register` | none, or an initial access token (`Bearer iat_...`, issued by an administrator; see [Registering clients](../admin/clients.md#initial-access-tokens)), per `settings.dcr.mode` | authorize | Dynamic client registration. `403 access_denied` when `dcr.mode` is `disabled`; `401 invalid_token` when an initial access token is required and missing, unknown, revoked, expired or used up. Answers `201` with the metadata, `registration_access_token` and `registration_client_uri`. | RFC 7591 |
| GET, PUT, DELETE | `/t/{slug}/register/{client_id}` | registration access token (`Bearer`) | authorize | Read, replace or delete a dynamically registered client. | RFC 7592 |
| GET | `/t/{slug}/branding` | none | — | Public description of the tenant for the sign-in pages: name, theme, links, locales and which sign-in options exist. `Cache-Control: public, max-age=60`. | |

### Client authentication

`/token`, `/par`, `/device_authorization`, `/introspect` and `/revoke` authenticate the client with the method registered for it; any other method is `invalid_client`.

| Method | How |
|--------|-----|
| `none` | public client: `client_id` in the body only (PKCE protects the code) |
| `client_secret_basic` | `Authorization: Basic base64(client_id:secret)` |
| `client_secret_post` | `client_id` and `client_secret` in the form body |
| `private_key_jwt` | `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and a `client_assertion` JWT signed with a key from the client's `jwks` or `jwks_uri` |

`client_secret_jwt` and mutual-TLS client authentication are not implemented; mTLS is planned (Phase 13), not present.

### Grant types at `/token`

| `grant_type` | Notes |
|--------------|-------|
| `authorization_code` | PKCE `S256` only; `plain` is refused. Replaying a code revokes everything the first exchange produced. A code whose browser session was signed out before the exchange is refused (`invalid_grant`). `resource` may only pick among the resources named at `/authorize` (`invalid_target` otherwise). |
| `refresh_token` | Rotation on every use with reuse detection. `scope` and `resource` may narrow the original grant, never widen it (`invalid_scope`, `invalid_target`, checked before the token is spent). Without `offline_access` the token ends with its browser session; each refresh extends the session's idle window. |
| `client_credentials` | Tokens for the client itself, or for its service-account user when one exists. `openid` and `offline_access` are refused. With no `scope`, the tenant's default scopes the client may hold. |
| `urn:ietf:params:oauth:grant-type:device_code` | Polling answers `authorization_pending`, `slow_down`, `access_denied` or `expired_token` until the user approves. |
| `urn:ietf:params:oauth:grant-type:token-exchange` | `subject_token` (type `urn:ietf:params:oauth:token-type:access_token` or `...:jwt`; an opaque `at_...` token must be sent as `access_token`), optional `actor_token` (same rule), `audience`, `resource`, `scope`. No refresh token; the result reports `issued_token_type`. A client registered for opaque tokens may not request `...:jwt`. |

A client may only use the grants in its `allowed_grants`; a known grant it is not allowed is `unauthorized_client`, an unknown one `unsupported_grant_type`. Audiences come from `resource` parameters (RFC 8707; token exchange also takes `audience`), or from the client's `allowed_audiences` when none is requested, plus the resource server of any requested scope bound to one; see [Resource servers, scopes and permissions](../concepts/resource-servers.md) and [Token claims](token-claims.md#scopes-in-the-token).

The response is `{"access_token", "token_type", "expires_in", "refresh_token"?, "id_token"?, "scope"?, "issued_token_type"?}` with `Cache-Control: no-store`. `token_type` is `DPoP` when a DPoP proof bound the tokens, otherwise `Bearer`.

### Discovery document

The discovery document advertises exactly what the build implements ([`api/src/oidc/discovery.rs`](https://github.com/ZerosAndOnesLLC/rIDM/blob/main/api/src/oidc/discovery.rs)). Endpoints are `{issuer}/authorize`, `/token`, `/.well-known/jwks.json`, `/userinfo`, `/introspect`, `/revoke`, `/end_session`, `/par` and `/device_authorization`; `registration_endpoint` (`{issuer}/register`) appears only when the tenant's `dcr.mode` is not `disabled`.

| Member | Value |
|--------|-------|
| `scopes_supported` | the tenant's scopes (standard plus custom) |
| `response_types_supported` | `code` |
| `response_modes_supported` | `query`, `fragment`, `jwt`, `query.jwt`, `fragment.jwt`, `form_post.jwt` |
| `grant_types_supported` | `authorization_code`, `refresh_token`, `client_credentials`, `urn:ietf:params:oauth:grant-type:device_code`, `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_types_supported` | `public`, `pairwise` |
| `id_token_signing_alg_values_supported` | `RS256`, `RS384`, `RS512`, `ES256`, `EdDSA` |
| `id_token_encryption_alg_values_supported` | `RSA-OAEP-256`, `RSA-OAEP` |
| `id_token_encryption_enc_values_supported` | `A256GCM`, `A128GCM` |
| `token_endpoint_auth_methods_supported` (also `introspection_...` and `revocation_...`) | `none`, `client_secret_basic`, `client_secret_post`, `private_key_jwt` |
| `token_endpoint_auth_signing_alg_values_supported` | `RS256`, `RS384`, `RS512`, `ES256`, `EdDSA` |
| `request_object_signing_alg_values_supported` | the same five |
| `authorization_signing_alg_values_supported` (JARM) | the same five |
| `dpop_signing_alg_values_supported` | `ES256`, `ES384`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `EdDSA`: the algorithms the DPoP verifier accepts |
| `code_challenge_methods_supported` | `S256` |
| `acr_values_supported` | `urn:ridm:acr:single`, `urn:ridm:acr:mfa` |
| `claims_supported` | `sub`, `iss`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `acr`, `amr`, `azp`, `sid`, `name`, `given_name`, `family_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `updated_at`, `email`, `email_verified`, `phone_number`, `phone_number_verified`, `address`, `locale` |
| `claim_types_supported` | `normal` |
| `prompt_values_supported` | `none`, `login`, `consent`, `select_account`, `create` |
| `ui_locales_supported` | the tenant's `settings.locale.supported` |
| `claims_parameter_supported` | `false` |
| `request_parameter_supported` | `true` |
| `request_uri_parameter_supported` | `true` (PAR `request_uri` values only) |
| `require_request_uri_registration` | `false` |
| `require_pushed_authorization_requests` | `false` |
| `authorization_response_iss_parameter_supported` | `true` |
| `backchannel_logout_supported`, `backchannel_logout_session_supported` | `true` |
| `frontchannel_logout_supported`, `frontchannel_logout_session_supported` | `true` |
| `op_policy_uri`, `op_tos_uri` | the tenant's `registration.privacy_url` and `registration.terms_url`, when set |
| `service_documentation` | the tenant's `branding.support_url`, when set |

`form_post` is not offered as a plain response mode, only as `form_post.jwt`. Userinfo responses are plain JSON, so `userinfo_signing_alg_values_supported` is absent. Server-provided DPoP nonces and `dpop_jkt` at `/authorize` are not implemented.

## Browser flow API

The sign-in pages drive a login flow through these routes. A flow is created by `/authorize` (or by device verification) and identified by `{id}`. Every mutating step carries the flow's `csrf` token in its JSON body; a wrong one is `403`. Responses carry the public flow state; when its stage is `done` the page navigates to `finish_url`. All are in the `flows` limit family and answer errors as RFC 9457 problems (see [Errors](errors.md#flow-api)). The flow is described in [Sign-in flows and sessions](../concepts/flows-and-sessions.md).

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/t/{slug}/flows/{id}` | Current flow state. |
| POST | `/t/{slug}/flows/{id}/password` | Identifier and password. |
| POST | `/t/{slug}/flows/{id}/password-change` | New password when one is required (expired or flagged). |
| POST | `/t/{slug}/flows/{id}/register` | Self-registration (when `settings.registration.enabled`). |
| POST | `/t/{slug}/flows/{id}/magic-link` | Send a sign-in link by email. |
| POST | `/t/{slug}/flows/{id}/magic-link/verify` | Redeem the link's token. |
| POST | `/t/{slug}/flows/{id}/email-otp` | Send a one-time sign-in code by email. |
| POST | `/t/{slug}/flows/{id}/email-otp/verify` | Check the emailed code. |
| POST | `/t/{slug}/flows/{id}/sms-otp` | Send a one-time sign-in code by SMS. |
| POST | `/t/{slug}/flows/{id}/sms-otp/verify` | Check the texted code. |
| POST | `/t/{slug}/flows/{id}/passkey/start` | Passkey sign-in: discoverable-credential challenge. |
| POST | `/t/{slug}/flows/{id}/passkey/finish` | Passkey sign-in: verify the assertion. |
| POST | `/t/{slug}/flows/{id}/mfa/totp/enroll` | Second step: start authenticator-app enrolment. |
| POST | `/t/{slug}/flows/{id}/mfa/totp/confirm` | Second step: confirm the first code. |
| POST | `/t/{slug}/flows/{id}/mfa/verify` | Second step: TOTP or recovery code. |
| POST | `/t/{slug}/flows/{id}/mfa/passkey/register` | Second step: passkey creation options. |
| POST | `/t/{slug}/flows/{id}/mfa/passkey/register/finish` | Second step: store the new passkey. |
| POST | `/t/{slug}/flows/{id}/mfa/passkey/start` | Second step: passkey challenge. |
| POST | `/t/{slug}/flows/{id}/mfa/passkey/finish` | Second step: verify the passkey. |
| POST | `/t/{slug}/flows/{id}/mfa/email/enroll`, `.../confirm` | Second step: enrol email codes. |
| POST | `/t/{slug}/flows/{id}/mfa/email/send`, `.../verify` | Second step: send and check an email code. |
| POST | `/t/{slug}/flows/{id}/mfa/sms/enroll`, `.../confirm` | Second step: enrol SMS codes (`phone` in E.164). |
| POST | `/t/{slug}/flows/{id}/mfa/sms/send`, `.../verify` | Second step: send and check an SMS code. |
| POST | `/t/{slug}/flows/{id}/profile` | Complete required profile attributes. |
| POST | `/t/{slug}/flows/{id}/terms` | Accept the terms (when `settings.registration.require_terms`). |
| POST | `/t/{slug}/flows/{id}/consent` | Grant or deny the requested scopes. |
| POST | `/t/{slug}/flows/{id}/cancel` | Abandon the flow: answers `{"stage": "cancelled", "redirect_to"}`, the client's redirect URI with `error=access_denied`. |
| GET | `/t/{slug}/flows/{id}/finish` | Browser navigation at the end: issues the authorization code (or approves the device code) and redirects to the client. |

## Registration, invitations, recovery, verification and devices

All in the `flows` limit family; errors are problem documents.

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/t/{slug}/invitations/{token}` | Look up an invitation by the token from its email. |
| POST | `/t/{slug}/invitations/{token}` | Accept it: set up the account and sign in. |
| POST | `/t/{slug}/recovery/password` | Request a password-reset message for an `identifier`. The answer does not reveal whether the account exists. |
| POST | `/t/{slug}/recovery/password/confirm` | Set a new password with the reset token. |
| POST | `/t/{slug}/verification/email/resend` | Send the email-verification message again. |
| POST | `/t/{slug}/verification/email/confirm` | Confirm an address with the token from the link; when the link belongs to a flow waiting for verification the user is signed in and the flow state returned. |
| POST | `/t/{slug}/device/verify` | The user's side of the device grant: `{user_code}` becomes a login flow for the device's client. |

## Identity brokering

| Method | Path | Auth | Limit | Purpose |
|--------|------|------|-------|---------|
| GET | `/t/{slug}/broker/{alias}/start` | none (`?flow=` a login flow, or `?ticket=` a link ticket from the account API) | flows | Sends the browser to the upstream provider named by `alias`. |
| GET, POST | `/t/{slug}/broker/{alias}/callback` | `state` of the upstream request | flows | Receives the upstream response (POST for providers that post it back), then continues the login flow or finishes linking. |

Register the callback URL with the upstream provider; the admin API reports it as `callback_url` on every identity provider. See [Identity brokering](../concepts/brokering.md).

## Account API

The self-service API for a signed-in user, under `/t/{slug}/account`. It takes a bearer (or DPoP-bound) access token, JWT or opaque, issued by that tenant with the `urn:ridm:account` audience (the built-in `ridm-account-console` client obtains one), or a personal access token with the `account` scope. It acts only on the token's own subject. Errors are RFC 9457 problems; security changes may answer `403` with type `urn:ridm:error:reauthentication-required` (see [Errors](errors.md#reauthentication-required)). These routes are in the OpenAPI document under the `account` tag and are not rate limited by the guard.

| Method | Path | Purpose |
|--------|------|---------|
| GET, DELETE | `/t/{slug}/account/me` | Identity with the session's `auth_time`, `acr` and `amr`; DELETE deletes the account (when `settings.account.self_deletion`). |
| GET, PATCH | `/t/{slug}/account/profile` | Profile attributes the schema lets the user see and edit. |
| GET, PUT | `/t/{slug}/account/password` | Password status; change it. |
| POST, DELETE | `/t/{slug}/account/email/change` | Start (or cancel) an email change. |
| POST | `/t/{slug}/account/email/confirm` | Confirm the new address with its code. |
| POST, DELETE | `/t/{slug}/account/phone/change` | Start (or cancel) a phone change. |
| POST | `/t/{slug}/account/phone/confirm` | Confirm the new number. |
| DELETE | `/t/{slug}/account/phone` | Remove the phone number. |
| GET | `/t/{slug}/account/mfa` | Enrolled second factors and remaining recovery codes. |
| POST | `/t/{slug}/account/mfa/totp/enroll`, `.../confirm` | Enrol an authenticator app. |
| POST | `/t/{slug}/account/mfa/email/enroll`, `.../confirm` | Enrol email codes. |
| POST | `/t/{slug}/account/mfa/sms/enroll`, `.../confirm` | Enrol SMS codes. |
| POST | `/t/{slug}/account/mfa/passkey/register`, `.../register/finish` | Register a passkey. |
| POST | `/t/{slug}/account/mfa/recovery-codes` | Replace the recovery codes (shown once). |
| DELETE | `/t/{slug}/account/mfa/credentials/{credential_id}` | Remove a factor; removing the last second factor removes the recovery codes too. |
| GET, DELETE | `/t/{slug}/account/devices` | Trusted devices; forget all. |
| DELETE | `/t/{slug}/account/devices/{device_id}` | Forget one trusted device. |
| GET, DELETE | `/t/{slug}/account/sessions` | Live sessions; end all of them (`?keep_current=true` spares the calling session), with back-channel logout. |
| DELETE | `/t/{slug}/account/sessions/{session_id}` | End one session, with back-channel logout. |
| GET | `/t/{slug}/account/apps` | Applications the user consented to. |
| DELETE | `/t/{slug}/account/apps/{client_id}` | Withdraw consent and the application's refresh tokens. |
| GET | `/t/{slug}/account/identities` | Linked upstream identities. |
| POST | `/t/{slug}/account/identities/link` | Start linking an upstream identity: answers `{"url"}`, a `/broker/{alias}/start?ticket=...` address to send the browser to. |
| DELETE | `/t/{slug}/account/identities/{idp_id}` | Unlink one. |
| GET, POST | `/t/{slug}/account/tokens` | Personal access tokens; mint one (shown once). |
| DELETE | `/t/{slug}/account/tokens/{token_id}` | Revoke a personal access token. |
| GET | `/t/{slug}/account/export` | Everything held about the user as one JSON document. |

Request and response bodies are in the [rendered reference](admin-api/index.html).

## SCIM 2.0

A SCIM service provider per tenant at `/scim/v2/{slug}` (RFC 7643, RFC 7644). Every request needs `Authorization: Bearer rscim_...`, a provisioning token minted for that tenant (see [SCIM provisioning](../admin/scim.md)). Bodies are `application/scim+json`; errors are SCIM error documents ([Errors](errors.md#scim-errors)). Not rate limited by the guard.

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/scim/v2/{slug}/ServiceProviderConfig` | Supported features. |
| GET | `/scim/v2/{slug}/ResourceTypes` | `User` and `Group`. |
| GET | `/scim/v2/{slug}/Schemas` | Core schemas. |
| GET, POST | `/scim/v2/{slug}/Users` | List (`filter`, `startIndex`, `count` up to 200) or create. |
| GET, PUT, PATCH, DELETE | `/scim/v2/{slug}/Users/{id}` | Read, replace, patch, soft-delete. |
| GET, POST | `/scim/v2/{slug}/Groups` | List or create. |
| GET, PUT, PATCH, DELETE | `/scim/v2/{slug}/Groups/{id}` | Read, replace, patch, delete. |

## Headers on every response

A security-headers layer adds the browser hardening headers (and `Strict-Transport-Security` when `PUBLIC_URL` is https and `HSTS_MAX_AGE` is not `0`); CORS is answered for the UI's and the API's own origins and for each client's registered `cors_origins`. Rate-limited families add `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset`.
