//! Token endpoint (RFC 6749 §3.2): `POST /t/{slug}/token`.
//!
//! Grants: `authorization_code` (+PKCE), `refresh_token` (rotation, reuse
//! detection), `client_credentials` (service-account roles). Access tokens
//! are audience-scoped to the resource servers requested via `resource`
//! (RFC 8707) or configured on the client.

use std::sync::Arc;

use std::net::{IpAddr, SocketAddr};

use axum::Router;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Method};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use redis::AsyncCommands as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::cache::keys as cache_keys;
use crate::error::{AppError, OAuthError, OAuthErrorCode};
use crate::middleware::security_headers::no_store;
use crate::middleware::{TenantCtx, client_ip_addr};
use crate::models::{ClaimMapper, Client, Group, Role, SigningAlg, Tenant, User, grants};
use crate::oidc::authorize::RawParams;
use crate::oidc::dpop;
use crate::oidc::form::FormParams;
use crate::oidc::mtls::{self, ClientCert, ClientCertificate};
use crate::oidc::{client_auth, pkce};
use crate::services::device_codes::Poll;
use crate::services::refresh_tokens::{self, IssueRequest};
use crate::services::tokens::{
    self, AccessTokenRequest, IdTokenRequest, SenderProof, TokenClient, VerifyOptions,
};
use crate::services::{auth_codes, denylist, groups, roles, scopes, users};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/t/{slug}/token", post(token))
}

/// RFC 8693 token type identifiers.
pub mod token_types {
    pub const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
    pub const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    /// RFC 8693 §2.2.1, set by the token exchange grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_token_type: Option<&'static str>,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

async fn token(
    State(state): State<AppState>,
    tenant: TenantCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    cert: ClientCertificate,
    headers: HeaderMap,
    FormParams(params): FormParams,
) -> Response {
    let ip = client_ip_addr(&state, &headers, Some(peer));
    let outcome = handle(&state, &tenant, &headers, &params, ip, cert.get()).await;
    // Counted whatever happened, refusals included (client auth, grant, DPoP).
    let grant = params
        .one("grant_type")
        .ok()
        .flatten()
        .filter(|g| grants::ALL.contains(g))
        .unwrap_or("unknown")
        .to_string();
    let label = match &outcome {
        Ok(_) => "issued".to_string(),
        Err(e) => e.error.as_str().to_string(),
    };
    metrics::counter!("ridm_token_requests_total", "grant" => grant, "outcome" => label)
        .increment(1);
    match outcome {
        Ok(res) => no_store(axum::Json(res).into_response()),
        Err(e) => no_store(e.into_response()),
    }
}

async fn handle(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    params: &RawParams,
    ip: Option<IpAddr>,
    cert: Option<&ClientCert>,
) -> Result<TokenResponse, OAuthError> {
    let one = |n: &str| params.one(n).map_err(OAuthError::invalid_request);
    let token_endpoint = tenant.token_endpoint(state);
    let (client, _method) =
        client_auth::authenticate(state, tenant, headers, params, &token_endpoint, ip, cert)
            .await?;
    // A DPoP proof binds every token of this response to the proof key; a
    // client registered for bound tokens must present one.
    let dpop_jkt = match dpop::header(headers)
        .map_err(|d| OAuthError::new(OAuthErrorCode::InvalidDpopProof, d))?
    {
        Some(proof) => {
            if client.is_fapi2()
                && !jsonwebtoken::decode_header(proof)
                    .is_ok_and(|h| crate::oidc::fapi::allows_jws(h.alg))
            {
                return Err(OAuthError::new(
                    OAuthErrorCode::InvalidDpopProof,
                    "the FAPI 2.0 profile allows PS256, ES256 or EdDSA proofs only",
                ));
            }
            let htu = dpop::htu_candidates(state, tenant.tenant.as_ref(), "/token");
            Some(
                dpop::verify_proof(
                    state,
                    tenant.tenant.as_ref(),
                    proof,
                    &Method::POST,
                    &htu,
                    None,
                )
                .await
                .map_err(|d| OAuthError::new(OAuthErrorCode::InvalidDpopProof, d))?
                .jkt,
            )
        }
        // A FAPI client may be sender-constrained by its certificate instead.
        None if client.dpop_bound_access_tokens
            || (client.is_fapi2() && !client.tls_client_certificate_bound_access_tokens) =>
        {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidDpopProof,
                "this client must present a DPoP proof",
            ));
        }
        None => None,
    };
    // RFC 8705 §3: a client registered for certificate-bound tokens gets
    // them only over a connection that carried its certificate.
    let x5t = cert.map(ClientCert::thumbprint);
    if client.tls_client_certificate_bound_access_tokens && x5t.is_none() {
        return Err(OAuthError::invalid_request(
            "this client must present its TLS client certificate",
        ));
    }
    let proof = SenderProof {
        jkt: dpop_jkt.as_deref(),
        x5t,
    };
    let grant =
        one("grant_type")?.ok_or_else(|| OAuthError::invalid_request("grant_type is required"))?;
    if !client.allows_grant(grant) {
        return Err(if grants::ALL.contains(&grant) {
            OAuthError::new(
                OAuthErrorCode::UnauthorizedClient,
                format!("client may not use grant type `{grant}`"),
            )
        } else {
            OAuthError::code(OAuthErrorCode::UnsupportedGrantType)
        });
    }
    let tenant_row = tenant.tenant.as_ref();
    match grant {
        grants::AUTHORIZATION_CODE => {
            authorization_code(state, tenant_row, &client, params, proof).await
        }
        grants::REFRESH_TOKEN => refresh_token(state, tenant_row, &client, params, proof).await,
        grants::CLIENT_CREDENTIALS => {
            client_credentials(state, tenant_row, &client, params, proof).await
        }
        grants::DEVICE_CODE => device_code(state, tenant_row, &client, params, proof).await,
        grants::CIBA => backchannel(state, tenant_row, &client, params, proof).await,
        grants::TOKEN_EXCHANGE => token_exchange(state, tenant_row, &client, params, proof).await,
        _ => Err(OAuthError::code(OAuthErrorCode::UnsupportedGrantType)),
    }
}

/// Everything about the subject needed for claims.
struct Subject {
    user: User,
    roles: Vec<Role>,
    groups: Vec<Group>,
}

/// Loads the user with the roles they hold in `org_id` (org-scoped grants
/// apply only there) plus their unscoped ones.
async fn load_subject(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    org_id: Option<Uuid>,
) -> Result<Subject, OAuthError> {
    let user = users::get(state, tenant_id, user_id)
        .await
        .map_err(|_| OAuthError::new(OAuthErrorCode::InvalidGrant, "user no longer exists"))?;
    if !matches!(user.status, crate::models::UserStatus::Active) {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "user is not active",
        ));
    }
    let roles = roles::effective_roles(state, tenant_id, user_id, org_id)
        .await?
        .to_vec();
    let groups = groups::groups_of_user(state, tenant_id, user_id, true).await?;
    Ok(Subject {
        user,
        roles,
        groups,
    })
}

/// Mappers applying to a client (tenant-wide plus its own), cached.
pub async fn effective_mappers_for(
    state: &AppState,
    tenant_id: Uuid,
    client: &Client,
) -> Result<std::sync::Arc<Vec<ClaimMapper>>, AppError> {
    effective_mappers(state, tenant_id, client)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))
}

async fn effective_mappers(
    state: &AppState,
    tenant_id: Uuid,
    client: &Client,
) -> Result<std::sync::Arc<Vec<ClaimMapper>>, OAuthError> {
    let db = state.db.clone();
    let client_id = client.id;
    let version = crate::services::claim_mappers::mappers_version(state, tenant_id).await?;
    let rows = state
        .cache
        .get_or_load(
            &cache_keys::mappers(tenant_id, &version, client_id),
            std::time::Duration::from_secs(300),
            || async move {
                let mut tx = crate::db::tenant_tx(&db, tenant_id).await?;
                let rows =
                    crate::repos::claim_mappers::list_effective(&mut *tx, tenant_id, client_id)
                        .await?;
                let mut mappers: Vec<ClaimMapper> = rows
                    .into_iter()
                    .filter_map(|r| {
                        let mut cfg = r.config;
                        cfg["name"] = serde_json::Value::String(r.name);
                        serde_json::from_value::<ClaimMapper>(cfg).ok()
                    })
                    .collect();
                // A `roles` mapper names its client by public id; roles carry
                // the client's row id. Resolve once here, so the cached
                // mapper already holds the id it is matched against (a public
                // id no client has resolves to nothing, and matches no role).
                for m in &mut mappers {
                    if let crate::models::MapperKind::Roles {
                        client_id: Some(public),
                        ..
                    } = &mut m.kind
                    {
                        let found =
                            crate::repos::clients::find_by_client_id(&mut *tx, tenant_id, public)
                                .await?;
                        *public = found.map_or_else(String::new, |c| c.id.to_string());
                    }
                }
                tx.commit().await?;
                Ok(Some(mappers))
            },
        )
        .await?;
    Ok(rows.unwrap_or_default())
}

/// Access-token audience and permissions for the requested resource servers.
struct Audience {
    audiences: Vec<String>,
    ttl_override: Option<u64>,
    permissions: Vec<String>,
    /// The resource servers behind `audiences`, for scopes bound to one.
    resource_server_ids: Vec<Uuid>,
    /// Every audience allows `offline_access` (vacuously true without any).
    offline_allowed: bool,
    /// The algorithm the audience asks access tokens to be signed with.
    signing_alg: Option<SigningAlg>,
}

/// The one signing algorithm a set of resource servers asks for.
///
/// A token has one signature, so its audiences must agree: resource servers
/// that name no algorithm accept the tenant's default and so agree with any
/// other; two that name different algorithms cannot share a token, and the
/// request is refused rather than one of them handed a token it may reject.
fn agreed_signing_alg<'a>(
    wanted: impl IntoIterator<Item = (&'a str, Option<&'a str>)>,
) -> Result<Option<SigningAlg>, OAuthError> {
    let mut agreed: Option<(SigningAlg, &str)> = None;
    for (identifier, alg) in wanted {
        let Some(alg) = alg else { continue };
        let alg: SigningAlg = alg.parse().map_err(|_| {
            OAuthError::new(
                OAuthErrorCode::ServerError,
                format!("resource `{identifier}` has an unsupported signing algorithm"),
            )
        })?;
        match agreed {
            Some((a, first)) if a != alg => {
                return Err(OAuthError::new(
                    OAuthErrorCode::InvalidTarget,
                    format!(
                        "resources `{first}` ({a}) and `{identifier}` ({alg}) need tokens signed with different algorithms; request them separately"
                    ),
                ));
            }
            Some(_) => {}
            None => agreed = Some((alg, identifier)),
        }
    }
    Ok(agreed.map(|(a, _)| a))
}

async fn resolve_audience(
    state: &AppState,
    tenant_id: Uuid,
    client: &Client,
    requested: &[String],
    role_ids: &[Uuid],
) -> Result<Audience, OAuthError> {
    let wanted: Vec<String> = if requested.is_empty() {
        client.allowed_audiences.clone()
    } else {
        requested.to_vec()
    };
    let mut audiences = vec![];
    let mut ttl_override: Option<u64> = None;
    let mut permissions = vec![];
    let mut resource_server_ids = vec![];
    let mut offline_allowed = true;
    let mut algs: Vec<(String, Option<String>)> = vec![];
    if wanted.is_empty() {
        return Ok(Audience {
            audiences,
            ttl_override,
            permissions,
            resource_server_ids,
            offline_allowed,
            signing_alg: None,
        });
    }
    for identifier in &wanted {
        let Some(rs) = crate::services::resource_servers::find_by_identifier_cached(
            state, tenant_id, identifier,
        )
        .await?
        else {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidTarget,
                format!("unknown resource `{identifier}`"),
            ));
        };
        // Built-in resource servers (the admin API) are never implied: a client
        // has to be allowed the audience explicitly, even when it is otherwise
        // unrestricted, so that a third-party client cannot mint admin tokens.
        if !client.may_target(identifier, rs.built_in) {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidTarget,
                format!("resource `{identifier}` is not allowed for this client"),
            ));
        }
        audiences.push(rs.identifier.clone());
        resource_server_ids.push(rs.id);
        offline_allowed &= rs.allow_offline_access;
        algs.push((rs.identifier.clone(), rs.signing_alg.clone()));
        if let Some(ttl) = rs.token_ttl_secs {
            let ttl = ttl.max(1) as u64;
            ttl_override = Some(ttl_override.map_or(ttl, |t| t.min(ttl)));
        }
        if !role_ids.is_empty() {
            let perms = crate::services::resource_servers::permissions_for_roles_cached(
                state, tenant_id, rs.id, role_ids,
            )
            .await?;
            for p in perms.iter() {
                if !permissions.contains(p) {
                    permissions.push(p.clone());
                }
            }
        }
    }
    let signing_alg = agreed_signing_alg(algs.iter().map(|(i, a)| (i.as_str(), a.as_deref())))?;
    Ok(Audience {
        audiences,
        ttl_override,
        permissions,
        resource_server_ids,
        offline_allowed,
        signing_alg,
    })
}

fn parse_resources(params: &RawParams) -> Result<Vec<String>, OAuthError> {
    let mut out = vec![];
    for r in params.many("resource") {
        let r = r.trim();
        if r.is_empty()
            || url::Url::parse(r)
                .map(|u| u.fragment().is_some())
                .unwrap_or(true)
        {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidTarget,
                format!("invalid resource `{r}`"),
            ));
        }
        if !out.iter().any(|x| x == r) {
            out.push(r.to_string());
        }
    }
    Ok(out)
}

struct Issue<'a> {
    tenant: &'a Tenant,
    client: &'a Client,
    subject: Option<&'a Subject>,
    scopes: &'a [String],
    audience: Audience,
    session_id: Option<Uuid>,
    auth_time: Option<chrono::DateTime<Utc>>,
    amr: Vec<String>,
    acr: Option<String>,
    /// Organization the sign-in acts in: the `org_id` claim, and the scope
    /// org-scoped roles are resolved in.
    org_id: Option<Uuid>,
    nonce: Option<String>,
    issue_refresh: bool,
    code_for_hash: Option<String>,
    /// What the request proved possession of: tokens are bound to the DPoP
    /// key, and to the certificate when the client is registered for that.
    proof: SenderProof<'a>,
    /// `act` claim of a delegated token (token exchange).
    act: Option<serde_json::Value>,
    /// Expire no later than this (token exchange: the subject token's `exp`).
    not_after: Option<chrono::DateTime<Utc>>,
}

async fn issue_tokens(state: &AppState, i: Issue<'_>) -> Result<TokenResponse, OAuthError> {
    let mappers = effective_mappers(state, i.tenant.id, i.client).await?;
    let mut tc = TokenClient::from_client(i.client, i.tenant, mappers);
    match i.audience.signing_alg {
        Some(alg) if i.client.is_fapi2() && !crate::oidc::fapi::allows_signing(alg) => {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidTarget,
                format!(
                    "the resource server asks for {} tokens, which the FAPI 2.0 profile does not allow",
                    alg.as_str()
                ),
            ));
        }
        Some(alg) => tc.access_token_alg = Some(alg),
        // A FAPI client's tokens already default to an algorithm it allows.
        None => {}
    }
    // What the grant asked for, less what this audience does not carry.
    let granted = scopes::granted_for_audience(
        state,
        i.tenant.id,
        i.scopes,
        &i.audience.resource_server_ids,
        i.audience.offline_allowed,
    )
    .await?;
    let i = Issue {
        scopes: &granted,
        ..i
    };
    if let Some(ttl) = i.audience.ttl_override {
        tc.access_token_ttl = std::time::Duration::from_secs(ttl);
    }
    tc.not_after = i.not_after;
    // The token service sets `permissions` itself; no mapper may.
    tc.permissions = i.audience.permissions.clone();
    let empty_roles: Vec<Role> = vec![];
    let empty_groups: Vec<Group> = vec![];
    let (user, roles_v, groups_v) = match i.subject {
        Some(s) => (Some(&s.user), &s.roles, &s.groups),
        None => (None, &empty_roles, &empty_groups),
    };
    let at = tokens::issue_access_token(
        state,
        AccessTokenRequest {
            tenant: i.tenant,
            client: &tc,
            user,
            scopes: i.scopes,
            audiences: &i.audience.audiences,
            roles: roles_v,
            groups: groups_v,
            session_id: i.session_id,
            org_id: i.org_id,
            auth_time: i.auth_time,
            amr: &i.amr,
            acr: i.acr.as_deref(),
            cnf_jkt: i.proof.jkt,
            cnf_x5t: i
                .proof
                .x5t
                .filter(|_| i.client.tls_client_certificate_bound_access_tokens),
            act: i.act.clone(),
        },
    )
    .await?;

    let id_token = match (user, i.scopes.iter().any(|s| s == "openid")) {
        (Some(u), true) => Some(
            tokens::issue_id_token(
                state,
                IdTokenRequest {
                    tenant: i.tenant,
                    client: &tc,
                    user: u,
                    scopes: i.scopes,
                    roles: roles_v,
                    groups: groups_v,
                    session_id: i.session_id,
                    org_id: i.org_id,
                    auth_time: i.auth_time.unwrap_or_else(Utc::now),
                    nonce: i.nonce.as_deref(),
                    amr: &i.amr,
                    acr: i.acr.as_deref(),
                    access_token: Some(&at.token),
                    code: None,
                    act: i.act.clone(),
                },
            )
            .await?
            .token,
        ),
        _ => None,
    };

    let refresh = if i.issue_refresh && i.client.allows_grant(grants::REFRESH_TOKEN) {
        let mut ttl = Duration::seconds(
            i.client
                .refresh_token_ttl_secs
                .map(|s| s.max(1) as i64)
                .unwrap_or(i.tenant.settings.session.refresh_token_ttl_secs as i64),
        );
        // A family never outlives the instant its tokens must stop by (an
        // impersonated session's end), `offline_access` or not.
        if let Some(until) = i.not_after {
            ttl = ttl.min(until - Utc::now()).max(Duration::seconds(1));
        }
        let issued = refresh_tokens::issue(
            state,
            i.tenant.id,
            IssueRequest {
                client_id: &i.client.client_id,
                user_id: user.map(|u| u.id),
                session_id: i.session_id,
                scopes: i.scopes,
                audiences: &i.audience.audiences,
                ttl,
                auth_time: i.auth_time,
                amr: &i.amr,
                acr: i.acr.as_deref(),
                org_id: i.org_id,
                act: i.act.as_ref(),
                // Public clients' refresh tokens are bound to the proof key
                // (RFC 9449 §5); confidential clients are bound by their credentials.
                dpop_jkt: if i.client.is_public() {
                    i.proof.jkt
                } else {
                    None
                },
                // The same for a public client's certificate (RFC 8705 §4).
                mtls_x5t: if i.client.is_public()
                    && i.client.tls_client_certificate_bound_access_tokens
                {
                    i.proof.x5t
                } else {
                    None
                },
            },
        )
        .await?;
        Some(issued)
    } else {
        None
    };

    // Remember what this authorization code produced, so replaying it can undo
    // all of it (RFC 6749 §4.1.2): the refresh family and the access token,
    // which stops through the `jti` denylist (JWT and opaque alike).
    if let Some(code_hash) = &i.code_for_hash {
        let grant = CodeGrant {
            family_id: refresh.as_ref().map(|r| r.record.family_id),
            access_jti: at
                .claims
                .get("jti")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            access_expires_at: at.expires_at,
        };
        let mut conn = state.redis.get().await?;
        let _: () = conn
            .set_ex(
                cache_keys::code_family(i.tenant.id, code_hash),
                serde_json::to_string(&grant).unwrap_or_default(),
                600,
            )
            .await
            .map_err(AppError::from)?;
    }
    let refresh = refresh.map(|r| r.token.to_string());

    Ok(TokenResponse {
        access_token: at.token,
        token_type: if i.proof.jkt.is_some() {
            "DPoP"
        } else {
            "Bearer"
        },
        issued_token_type: None,
        expires_in: (at.expires_at - Utc::now()).num_seconds().max(1),
        refresh_token: refresh,
        id_token,
        scope: Some(i.scopes.join(" ")),
    })
}

/// The grant being redeemed came from an impersonated session: whatever this
/// request records, it records for the administrator `act` names.
fn mark_acting(act: &serde_json::Value) {
    if let Some(id) = act
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        ridm_core::events::acting::set(id);
    }
}

/// What one authorization code produced, kept for ten minutes so a replay of
/// the code can revoke it.
#[derive(Serialize, Deserialize)]
struct CodeGrant {
    family_id: Option<Uuid>,
    access_jti: Option<String>,
    access_expires_at: DateTime<Utc>,
}

fn code_hash(code: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code.as_bytes()))
}

async fn authorization_code(
    state: &AppState,
    tenant: &Tenant,
    client: &Arc<Client>,
    params: &RawParams,
    proof: SenderProof<'_>,
) -> Result<TokenResponse, OAuthError> {
    let one = |n: &str| params.one(n).map_err(OAuthError::invalid_request);
    let code = one("code")?.ok_or_else(|| OAuthError::invalid_request("code is required"))?;
    let redirect_uri = one("redirect_uri")?;
    let verifier = one("code_verifier")?;

    let Some(record) = auth_codes::consume(state, tenant.id, code).await? else {
        // Unknown or already used. If it was used, revoke everything it
        // produced (RFC 6749 §4.1.2): the refresh family and the access token.
        let mut conn = state.redis.get().await?;
        let stored: Option<String> = redis::cmd("GETDEL")
            .arg(cache_keys::code_family(tenant.id, &code_hash(code)))
            .query_async(&mut conn)
            .await
            .map_err(AppError::from)?;
        if let Some(grant) = stored
            .as_deref()
            .and_then(|s| serde_json::from_str::<CodeGrant>(s).ok())
        {
            if let Some(f) = grant.family_id {
                let mut tx = crate::db::tenant_tx(&state.db, tenant.id).await?;
                crate::repos::refresh_tokens::revoke_family(&mut *tx, tenant.id, f).await?;
                tx.commit().await?;
            }
            if let Some(jti) = &grant.access_jti {
                denylist::deny(state, tenant.id, jti, grant.access_expires_at).await?;
            }
            tracing::warn!(tenant = %tenant.id, client = %client.client_id, "authorization code replayed; its tokens revoked");
        }
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "invalid authorization code",
        ));
    };
    if record.client_id != client.id {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "code was issued to another client",
        ));
    }
    if redirect_uri != Some(record.redirect_uri.as_str()) {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "redirect_uri does not match",
        ));
    }
    match (&record.code_challenge, verifier) {
        (Some(challenge), Some(v)) => {
            if !pkce::verify_s256(v, challenge) {
                return Err(OAuthError::new(
                    OAuthErrorCode::InvalidGrant,
                    "code_verifier does not match",
                ));
            }
        }
        (Some(_), None) => return Err(OAuthError::invalid_request("code_verifier is required")),
        (None, Some(_)) => {
            return Err(OAuthError::invalid_request(
                "code_verifier without a code_challenge",
            ));
        }
        (None, None) => {}
    }
    if (Utc::now() - record.issued_at).num_seconds() as u64 > auth_codes::CODE_TTL_SECS {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "authorization code expired",
        ));
    }
    // A code whose session was signed out before the exchange would mint
    // tokens for a session that no longer exists.
    let mut tx = crate::db::tenant_tx(&state.db, tenant.id).await?;
    let session_ended =
        crate::repos::sessions::is_revoked(&mut *tx, tenant.id, record.session_id).await?;
    tx.commit().await?;
    if session_ended {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "the session this code was issued in has ended",
        ));
    }

    if let Some(acting) = &record.acting {
        mark_acting(&acting.act);
    }
    let subject = load_subject(state, tenant.id, record.user_id, record.org_id).await?;
    let role_ids: Vec<Uuid> = subject.roles.iter().map(|r| r.id).collect();
    let extra = parse_resources(params)?;
    // RFC 8707 §2.2: resources named at /authorize bound the grant; the token
    // request may pick among them but not add others.
    if !record.audiences.is_empty()
        && let Some(r) = extra.iter().find(|r| !record.audiences.contains(r))
    {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidTarget,
            format!("resource `{r}` was not part of the authorization request"),
        ));
    }
    let requested_aud: Vec<String> = if extra.is_empty() {
        record.audiences.clone()
    } else {
        extra
    };
    let audience = resolve_audience(state, tenant.id, client, &requested_aud, &role_ids).await?;

    issue_tokens(
        state,
        Issue {
            tenant,
            client,
            subject: Some(&subject),
            scopes: &record.scopes,
            audience,
            session_id: Some(record.session_id),
            org_id: record.org_id,
            auth_time: Some(record.auth_time),
            amr: record.amr.clone(),
            acr: record.acr.clone(),
            nonce: record.nonce.clone(),
            issue_refresh: true,
            code_for_hash: Some(code_hash(code)),
            proof,
            act: record.acting.as_ref().map(|a| a.act.clone()),
            not_after: record.acting.as_ref().map(|a| a.until),
        },
    )
    .await
}

/// RFC 8628 §3.4: the device polls with its code until the user decides.
async fn device_code(
    state: &AppState,
    tenant: &Tenant,
    client: &Arc<Client>,
    params: &RawParams,
    proof: SenderProof<'_>,
) -> Result<TokenResponse, OAuthError> {
    let one = |n: &str| params.one(n).map_err(OAuthError::invalid_request);
    let code = one("device_code")?
        .ok_or_else(|| OAuthError::invalid_request("device_code is required"))?;
    let (record, approval) =
        match crate::services::device_codes::poll(state, tenant.id, client.id, code).await? {
            None => {
                return Err(OAuthError::new(
                    OAuthErrorCode::InvalidGrant,
                    "invalid device code",
                ));
            }
            Some(Poll::Pending) => {
                return Err(OAuthError::code(OAuthErrorCode::AuthorizationPending));
            }
            Some(Poll::SlowDown) => return Err(OAuthError::code(OAuthErrorCode::SlowDown)),
            Some(Poll::Denied) => return Err(OAuthError::code(OAuthErrorCode::AccessDenied)),
            Some(Poll::Expired) => return Err(OAuthError::code(OAuthErrorCode::ExpiredToken)),
            Some(Poll::Approved(record, approval)) => (record, approval),
        };
    if let Some(acting) = &approval.acting {
        mark_acting(&acting.act);
    }
    let subject = load_subject(state, tenant.id, approval.user_id, approval.org_id).await?;
    let role_ids: Vec<Uuid> = subject.roles.iter().map(|r| r.id).collect();
    let extra = parse_resources(params)?;
    let requested_aud: Vec<String> = if extra.is_empty() {
        record.audiences.clone()
    } else {
        extra
    };
    let audience = resolve_audience(state, tenant.id, client, &requested_aud, &role_ids).await?;
    issue_tokens(
        state,
        Issue {
            tenant,
            client,
            subject: Some(&subject),
            scopes: &approval.scopes,
            audience,
            session_id: Some(approval.session_id),
            org_id: approval.org_id,
            auth_time: Some(approval.auth_time),
            amr: approval.amr.clone(),
            acr: approval.acr.clone(),
            nonce: None,
            issue_refresh: true,
            code_for_hash: None,
            proof,
            act: approval.acting.as_ref().map(|a| a.act.clone()),
            not_after: approval.acting.as_ref().map(|a| a.until),
        },
    )
    .await
}

/// CIBA Core §10.1: the client collects what the user approved on their
/// own device. The answers while it waits are the device grant's.
async fn backchannel(
    state: &AppState,
    tenant: &Tenant,
    client: &Arc<Client>,
    params: &RawParams,
    proof: SenderProof<'_>,
) -> Result<TokenResponse, OAuthError> {
    use crate::services::ciba::{self, Poll as CibaPoll};
    let one = |n: &str| params.one(n).map_err(OAuthError::invalid_request);
    let auth_req_id = one("auth_req_id")?
        .ok_or_else(|| OAuthError::invalid_request("auth_req_id is required"))?;
    let (record, approval) = match ciba::poll(state, tenant.id, client.id, auth_req_id).await? {
        None => {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidGrant,
                "invalid auth_req_id",
            ));
        }
        Some(CibaPoll::Pending) => {
            return Err(OAuthError::code(OAuthErrorCode::AuthorizationPending));
        }
        Some(CibaPoll::SlowDown) => return Err(OAuthError::code(OAuthErrorCode::SlowDown)),
        Some(CibaPoll::Denied) => return Err(OAuthError::code(OAuthErrorCode::AccessDenied)),
        Some(CibaPoll::Expired) => return Err(OAuthError::code(OAuthErrorCode::ExpiredToken)),
        Some(CibaPoll::Approved(record, approval)) => (record, approval),
    };
    let subject = load_subject(state, tenant.id, approval.user_id, approval.org_id).await?;
    let role_ids: Vec<Uuid> = subject.roles.iter().map(|r| r.id).collect();
    let audience = resolve_audience(state, tenant.id, client, &record.audiences, &role_ids).await?;
    issue_tokens(
        state,
        Issue {
            tenant,
            client,
            subject: Some(&subject),
            scopes: &record.scopes,
            audience,
            session_id: Some(approval.session_id),
            org_id: approval.org_id,
            auth_time: Some(approval.auth_time),
            amr: approval.amr.clone(),
            acr: approval.acr.clone(),
            nonce: None,
            issue_refresh: true,
            code_for_hash: None,
            proof,
            act: None,
            not_after: None,
        },
    )
    .await
}

async fn refresh_token(
    state: &AppState,
    tenant: &Tenant,
    client: &Arc<Client>,
    params: &RawParams,
    proof: SenderProof<'_>,
) -> Result<TokenResponse, OAuthError> {
    let one = |n: &str| params.one(n).map_err(OAuthError::invalid_request);
    let presented = one("refresh_token")?
        .ok_or_else(|| OAuthError::invalid_request("refresh_token is required"))?;
    // A bound refresh token is only good with a proof from the same key.
    // RFC 8707 §2.2: `resource` may only narrow the original grant's audiences,
    // and RFC 6749 §6: `scope` may only narrow its scopes. Both are checked
    // before the token is spent, so a refused request leaves it usable.
    let extra = parse_resources(params)?;
    let requested_scopes = one("scope")?.map(scopes::parse_scope_param);
    // The FAPI 2.0 profile keeps the refresh token (§5.3.2.1): a client
    // that loses a rotated token's response loses its grant.
    let rotated = refresh_tokens::redeem(
        state,
        tenant.id,
        &client.client_id,
        presented,
        proof,
        &extra,
        requested_scopes.as_deref(),
        !client.is_fapi2(),
    )
    .await?;
    if let Some(act) = &rotated.record.act {
        mark_acting(act);
    }
    let scopes: Vec<String> = requested_scopes.unwrap_or_else(|| rotated.record.scopes.clone());
    let subject = match rotated.record.user_id {
        Some(uid) => Some(load_subject(state, tenant.id, uid, rotated.record.org_id).await?),
        None => None,
    };
    let role_ids: Vec<Uuid> = subject
        .as_ref()
        .map(|s| s.roles.iter().map(|r| r.id).collect())
        .unwrap_or_default();
    let requested_aud: Vec<String> = if extra.is_empty() {
        rotated.record.audiences.clone()
    } else {
        extra
    };
    let audience = resolve_audience(state, tenant.id, client, &requested_aud, &role_ids).await?;

    // The rotated refresh token is already minted; return it instead of a new family.
    let mut response = issue_tokens(
        state,
        Issue {
            tenant,
            client,
            subject: subject.as_ref(),
            scopes: &scopes,
            audience,
            session_id: rotated.record.session_id,
            org_id: rotated.record.org_id,
            // OIDC Core §12.2: the refreshed ID token repeats the original
            // authentication context.
            auth_time: rotated.record.auth_time,
            amr: rotated.record.amr.clone(),
            acr: rotated.record.acr.clone(),
            nonce: None,
            issue_refresh: false,
            code_for_hash: None,
            proof,
            // An impersonated family stops when its session would have.
            not_after: rotated
                .record
                .act
                .as_ref()
                .map(|_| rotated.record.expires_at),
            act: rotated.record.act.clone(),
        },
    )
    .await?;
    response.refresh_token = Some(rotated.token.to_string());
    Ok(response)
}

async fn client_credentials(
    state: &AppState,
    tenant: &Tenant,
    client: &Arc<Client>,
    params: &RawParams,
    proof: SenderProof<'_>,
) -> Result<TokenResponse, OAuthError> {
    if client.is_public() {
        return Err(OAuthError::new(
            OAuthErrorCode::UnauthorizedClient,
            "public clients cannot use client_credentials",
        ));
    }
    let one = |n: &str| params.one(n).map_err(OAuthError::invalid_request);
    let requested = scopes::parse_scope_param(one("scope")?.unwrap_or_default());
    if requested
        .iter()
        .any(|s| s == "openid" || s == "offline_access")
    {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidScope,
            "openid/offline_access are not valid for client_credentials",
        ));
    }
    // No scope named: the client's default scopes, less the user-only ones.
    let checked = scopes::validate_request(
        state,
        tenant.id,
        client,
        requested,
        &["openid", "offline_access"],
        false,
    )
    .await?;
    let requested = checked.scopes;
    let subject = match client.service_account_user_id {
        Some(uid) => Some(load_subject(state, tenant.id, uid, None).await?),
        None => None,
    };
    let role_ids: Vec<Uuid> = subject
        .as_ref()
        .map(|s| s.roles.iter().map(|r| r.id).collect())
        .unwrap_or_default();
    // A scope bound to a resource server targets it too.
    let wanted = scopes::with_bound_audiences(
        parse_resources(params)?,
        &client.allowed_audiences,
        checked.bound_audiences,
    );
    let audience = resolve_audience(state, tenant.id, client, &wanted, &role_ids).await?;
    issue_tokens(
        state,
        Issue {
            tenant,
            client,
            subject: subject.as_ref(),
            scopes: &requested,
            audience,
            session_id: None,
            // No user, so no organization.
            org_id: None,
            auth_time: None,
            amr: vec![],
            acr: None,
            nonce: None,
            issue_refresh: false,
            code_for_hash: None,
            proof,
            act: None,
            not_after: None,
        },
    )
    .await
}

/// RFC 8693 token exchange: trade an access token of this tenant for one
/// aimed at other audiences, optionally narrowed in scope, on behalf of
/// its subject (with `act` naming the acting party when an actor token is
/// given). The new token never outlives the subject token and inherits its
/// session, so signing out still ends it.
async fn token_exchange(
    state: &AppState,
    tenant: &Tenant,
    client: &Arc<Client>,
    params: &RawParams,
    proof: SenderProof<'_>,
) -> Result<TokenResponse, OAuthError> {
    let one = |n: &str| params.one(n).map_err(OAuthError::invalid_request);
    let is_access = |t: &str| t == token_types::ACCESS_TOKEN || t == token_types::JWT;
    let subject_token = one("subject_token")?
        .ok_or_else(|| OAuthError::invalid_request("subject_token is required"))?;
    let subject_type = one("subject_token_type")?
        .ok_or_else(|| OAuthError::invalid_request("subject_token_type is required"))?;
    if !is_access(subject_type) {
        return Err(OAuthError::invalid_request(
            "subject_token_type must be an access token or jwt type",
        ));
    }
    if let Some(requested) = one("requested_token_type")? {
        if !is_access(requested) {
            return Err(OAuthError::invalid_request(
                "requested_token_type must be an access token or jwt type",
            ));
        }
        // The issued token takes this client's format; a JWT cannot be
        // promised to a client registered for opaque tokens.
        if requested == token_types::JWT
            && client.access_token_format == crate::models::AccessTokenFormat::Opaque
        {
            return Err(OAuthError::invalid_request(
                "this client receives opaque access tokens; request urn:ietf:params:oauth:token-type:access_token",
            ));
        }
    }
    // An opaque access token is an access token, not a JWT (RFC 8693 §3).
    let typed_right = |token: &str, kind: &str| {
        kind == token_types::ACCESS_TOKEN || !crate::services::opaque_tokens::looks_like(token)
    };
    if !typed_right(subject_token, subject_type) {
        return Err(OAuthError::invalid_request(
            "subject_token is not a JWT; use urn:ietf:params:oauth:token-type:access_token",
        ));
    }
    let verify = VerifyOptions {
        check_denylist: true,
        ..Default::default()
    };
    let subject_map = tokens::verify_access(state, tenant, subject_token, &verify)
        .await
        .map_err(|_| {
            OAuthError::new(
                OAuthErrorCode::InvalidGrant,
                "subject_token is invalid, expired or revoked",
            )
        })?;
    // Optional claims are read through `Value` (a missing key is `Null`, not a panic).
    let subject_claims = serde_json::Value::Object(subject_map.clone());
    // A sender-constrained subject token may not be traded for a looser one:
    // without this, anyone holding a stolen DPoP-bound token could exchange it
    // for an unbound one and undo the binding (RFC 9449 §5).
    if let Some(bound) = subject_claims["cnf"]["jkt"].as_str()
        && proof.jkt != Some(bound)
    {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "subject_token is bound to a key this request did not prove",
        ));
    }
    // The same for a certificate-bound one (RFC 8705 §3): the request must
    // come with that certificate, and what it gets is bound to it again.
    if let Some(bound) = subject_claims["cnf"][mtls::CNF_X5T].as_str()
        && (proof.x5t != Some(bound) || !client.tls_client_certificate_bound_access_tokens)
    {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "subject_token is bound to a client certificate: exchange it over a connection \
             with that certificate, as a client registered for certificate-bound tokens",
        ));
    }
    let actor_claims = match (one("actor_token")?, one("actor_token_type")?) {
        (None, None) => None,
        (Some(token), Some(kind)) => {
            if !is_access(kind) {
                return Err(OAuthError::invalid_request(
                    "actor_token_type must be an access token or jwt type",
                ));
            }
            if !typed_right(token, kind) {
                return Err(OAuthError::invalid_request(
                    "actor_token is not a JWT; use urn:ietf:params:oauth:token-type:access_token",
                ));
            }
            let claims = tokens::verify_access(state, tenant, token, &verify)
                .await
                .map_err(|_| {
                    OAuthError::new(
                        OAuthErrorCode::InvalidGrant,
                        "actor_token is invalid, expired or revoked",
                    )
                })?;
            Some(serde_json::Value::Object(claims))
        }
        _ => {
            return Err(OAuthError::invalid_request(
                "actor_token and actor_token_type go together",
            ));
        }
    };

    // Scope may only be narrowed, and never beyond what this client may hold.
    let granted: Vec<String> =
        scopes::parse_scope_param(subject_claims["scope"].as_str().unwrap_or_default());
    let scopes: Vec<String> = match one("scope")? {
        Some(raw) => {
            let requested = scopes::parse_scope_param(raw);
            if let Some(extra) = requested.iter().find(|s| !granted.contains(s)) {
                return Err(OAuthError::new(
                    OAuthErrorCode::InvalidScope,
                    format!("scope `{extra}` is not held by the subject token"),
                ));
            }
            if let Some(bad) = requested
                .iter()
                .find(|s| !client.allowed_scopes.contains(s))
            {
                return Err(OAuthError::new(
                    OAuthErrorCode::InvalidScope,
                    format!("scope `{bad}` is not allowed for this client"),
                ));
            }
            requested
        }
        None => granted
            .into_iter()
            .filter(|s| client.allowed_scopes.contains(s))
            .collect(),
    };

    let subject = match tokens::subject_user_id(state, tenant, &subject_map).await? {
        Some(uid) => Some(
            load_subject(
                state,
                tenant.id,
                uid,
                subject_map
                    .get("org_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| Uuid::parse_str(s).ok()),
            )
            .await?,
        ),
        None => None,
    };
    let role_ids: Vec<Uuid> = subject
        .as_ref()
        .map(|s| s.roles.iter().map(|r| r.id).collect())
        .unwrap_or_default();
    let mut wanted = parse_resources(params)?;
    for a in params.many("audience") {
        let a = a.trim();
        if a.is_empty() {
            return Err(OAuthError::invalid_request("audience must not be empty"));
        }
        if !wanted.iter().any(|w| w == a) {
            wanted.push(a.to_string());
        }
    }
    // On every other grant the client acts for a user who authorized it, and an
    // empty `allowed_audiences` means "no restriction". Exchange is different:
    // the subject token may have been minted for someone else entirely, so an
    // unrestricted client would be able to mint a token for any audience
    // carrying any user's identity and permissions. Here the entitlement has to
    // be explicit.
    if client.allowed_audiences.is_empty() {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidTarget,
            "this client has no audiences it may exchange for",
        ));
    }
    for a in &wanted {
        if !client.allowed_audiences.contains(a) {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidTarget,
                format!("resource `{a}` is not allowed for this client"),
            ));
        }
    }
    let audience = resolve_audience(state, tenant.id, client, &wanted, &role_ids).await?;

    let act = actor_claims.map(|a| {
        let mut act = serde_json::json!({ "sub": a["sub"], "client_id": a["client_id"] });
        if let Some(previous) = subject_claims.get("act") {
            act["act"] = previous.clone();
        }
        act
    });
    let subject_exp = subject_claims["exp"]
        .as_i64()
        .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
        .unwrap_or_else(Utc::now);
    let session_id = subject_claims["sid"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok());
    let amr: Vec<String> = subject_claims["amr"]
        .as_array()
        .map(|v| {
            v.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let mut response = issue_tokens(
        state,
        Issue {
            tenant,
            client,
            subject: subject.as_ref(),
            scopes: &scopes,
            audience,
            session_id,
            auth_time: None,
            amr,
            acr: subject_claims["acr"].as_str().map(str::to_string),
            // The delegated token acts where the subject token acted.
            org_id: subject_claims
                .get("org_id")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok()),
            nonce: None,
            issue_refresh: false,
            code_for_hash: None,
            proof,
            act,
            not_after: Some(subject_exp),
        },
    )
    .await?;
    response.issued_token_type = Some(token_types::ACCESS_TOKEN);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audiences_must_agree_on_one_signing_algorithm() {
        // Nobody asks: the tenant default.
        assert_eq!(
            agreed_signing_alg([("a", None), ("b", None)]).unwrap(),
            None
        );
        // One asks, the others take whatever is chosen.
        assert_eq!(
            agreed_signing_alg([("a", None), ("b", Some("ES256")), ("c", Some("ES256"))]).unwrap(),
            Some(SigningAlg::ES256)
        );
        // Two ask for different ones: one token cannot satisfy both.
        let err = agreed_signing_alg([("a", Some("ES256")), ("b", Some("EdDSA"))]).unwrap_err();
        assert_eq!(err.error, OAuthErrorCode::InvalidTarget);
    }
}
