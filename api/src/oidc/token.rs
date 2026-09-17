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
use axum::http::{HeaderMap, HeaderValue, Method, header};
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
use crate::middleware::{TenantCtx, client_ip_addr};
use crate::models::{ClaimMapper, Client, Group, Role, Tenant, User, grants};
use crate::oidc::authorize::RawParams;
use crate::oidc::dpop;
use crate::oidc::{client_auth, pkce};
use crate::services::device_codes::Poll;
use crate::services::refresh_tokens::{self, IssueRequest};
use crate::services::tokens::{
    self, AccessTokenRequest, IdTokenRequest, TokenClient, VerifyOptions,
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

fn no_store(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    res
}

async fn token(
    State(state): State<AppState>,
    tenant: TenantCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let ip = client_ip_addr(&state, &headers, Some(peer));
    let is_form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"));
    if !is_form {
        return no_store(
            OAuthError::invalid_request("content type must be application/x-www-form-urlencoded")
                .into_response(),
        );
    }
    let params = RawParams::parse(&body);
    let outcome = handle(&state, &tenant, &headers, &params, ip).await;
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
) -> Result<TokenResponse, OAuthError> {
    let one = |n: &str| params.one(n).map_err(OAuthError::invalid_request);
    let token_endpoint = format!("{}/token", tenant.issuer(state));
    let (client, _method) =
        client_auth::authenticate(state, tenant, headers, params, &token_endpoint, ip).await?;
    // A DPoP proof binds every token of this response to the proof key; a
    // client registered for bound tokens must present one.
    let dpop_jkt = match dpop::header(headers)
        .map_err(|d| OAuthError::new(OAuthErrorCode::InvalidDpopProof, d))?
    {
        Some(proof) => {
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
        None if client.dpop_bound_access_tokens => {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidDpopProof,
                "this client must present a DPoP proof",
            ));
        }
        None => None,
    };
    let dpop_jkt = dpop_jkt.as_deref();
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
            authorization_code(state, tenant_row, &client, params, dpop_jkt).await
        }
        grants::REFRESH_TOKEN => refresh_token(state, tenant_row, &client, params, dpop_jkt).await,
        grants::CLIENT_CREDENTIALS => {
            client_credentials(state, tenant_row, &client, params, dpop_jkt).await
        }
        grants::DEVICE_CODE => device_code(state, tenant_row, &client, params, dpop_jkt).await,
        grants::TOKEN_EXCHANGE => {
            token_exchange(state, tenant_row, &client, params, dpop_jkt).await
        }
        _ => Err(OAuthError::code(OAuthErrorCode::UnsupportedGrantType)),
    }
}

/// Everything about the subject needed for claims.
struct Subject {
    user: User,
    roles: Vec<Role>,
    groups: Vec<Group>,
}

async fn load_subject(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
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
    let roles = roles::effective_roles(state, tenant_id, user_id)
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
) -> Result<Vec<ClaimMapper>, AppError> {
    effective_mappers(state, tenant_id, client)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))
}

async fn effective_mappers(
    state: &AppState,
    tenant_id: Uuid,
    client: &Client,
) -> Result<Vec<ClaimMapper>, OAuthError> {
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
                tx.commit().await?;
                let mappers: Vec<ClaimMapper> = rows
                    .into_iter()
                    .filter_map(|r| {
                        let mut cfg = r.config;
                        cfg["name"] = serde_json::Value::String(r.name);
                        serde_json::from_value::<ClaimMapper>(cfg).ok()
                    })
                    .collect();
                Ok(Some(mappers))
            },
        )
        .await?;
    Ok(rows.map(|m| m.as_ref().clone()).unwrap_or_default())
}

/// Access-token audience and permissions for the requested resource servers.
struct Audience {
    audiences: Vec<String>,
    ttl_override: Option<u64>,
    permissions: Vec<String>,
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
    if wanted.is_empty() {
        return Ok(Audience {
            audiences,
            ttl_override,
            permissions,
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
        let allowed = if rs.built_in {
            client.allowed_audiences.contains(identifier)
        } else {
            client.allowed_audiences.is_empty() || client.allowed_audiences.contains(identifier)
        };
        if !allowed {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidTarget,
                format!("resource `{identifier}` is not allowed for this client"),
            ));
        }
        audiences.push(rs.identifier.clone());
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
    Ok(Audience {
        audiences,
        ttl_override,
        permissions,
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
    nonce: Option<String>,
    with_refresh: Option<Uuid>, // family to continue, if rotating
    issue_refresh: bool,
    code_for_hash: Option<String>,
    /// Bind the tokens to a DPoP key.
    dpop_jkt: Option<&'a str>,
    /// `act` claim of a delegated token (token exchange).
    act: Option<serde_json::Value>,
    /// Never outlive this (token exchange: the subject token's remaining life).
    max_ttl: Option<std::time::Duration>,
}

async fn issue_tokens(state: &AppState, i: Issue<'_>) -> Result<TokenResponse, OAuthError> {
    let mappers = effective_mappers(state, i.tenant.id, i.client).await?;
    let mut tc = TokenClient::from_client(i.client, i.tenant, mappers);
    if let Some(ttl) = i.audience.ttl_override {
        tc.access_token_ttl = std::time::Duration::from_secs(ttl);
    }
    if let Some(max) = i.max_ttl {
        tc.access_token_ttl = tc
            .access_token_ttl
            .min(max.max(std::time::Duration::from_secs(1)));
    }
    // Permissions ride along as a hardcoded mapper so the pipeline stays single.
    if !i.audience.permissions.is_empty() {
        tc.mappers.push(ClaimMapper {
            name: "permissions".into(),
            kind: crate::models::MapperKind::Hardcoded {
                claim: "permissions".into(),
                value: serde_json::json!(i.audience.permissions),
            },
            include_in: vec![crate::models::TokenKind::Access],
        });
    }
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
            auth_time: i.auth_time,
            amr: &i.amr,
            acr: i.acr.as_deref(),
            cnf_jkt: i.dpop_jkt,
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
                    auth_time: i.auth_time.unwrap_or_else(Utc::now),
                    nonce: i.nonce.as_deref(),
                    amr: &i.amr,
                    acr: i.acr.as_deref(),
                    access_token: Some(&at.token),
                    code: None,
                },
            )
            .await?
            .token,
        ),
        _ => None,
    };

    let refresh = if i.issue_refresh && i.client.allows_grant(grants::REFRESH_TOKEN) {
        let ttl = Duration::seconds(
            i.client
                .refresh_token_ttl_secs
                .map(|s| s.max(1) as i64)
                .unwrap_or(i.tenant.settings.session.refresh_token_ttl_secs as i64),
        );
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
                // Public clients' refresh tokens are bound to the proof key
                // (RFC 9449 §5); confidential clients are bound by their credentials.
                dpop_jkt: if i.client.is_public() {
                    i.dpop_jkt
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
    let _ = i.with_refresh;

    // Remember what this authorization code produced, so replaying it can undo
    // all of it (RFC 6749 §4.1.2): the refresh family and the access token,
    // which is a JWT and stops only through the `jti` denylist.
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
        token_type: if i.dpop_jkt.is_some() {
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
    dpop_jkt: Option<&str>,
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

    let subject = load_subject(state, tenant.id, record.user_id).await?;
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
            scopes: &record.scopes,
            audience,
            session_id: Some(record.session_id),
            auth_time: Some(record.auth_time),
            amr: record.amr.clone(),
            acr: record.acr.clone(),
            nonce: record.nonce.clone(),
            with_refresh: None,
            issue_refresh: true,
            code_for_hash: Some(code_hash(code)),
            dpop_jkt,
            act: None,
            max_ttl: None,
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
    dpop_jkt: Option<&str>,
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
    let subject = load_subject(state, tenant.id, approval.user_id).await?;
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
            auth_time: Some(approval.auth_time),
            amr: approval.amr.clone(),
            acr: approval.acr.clone(),
            nonce: None,
            with_refresh: None,
            issue_refresh: true,
            code_for_hash: None,
            dpop_jkt,
            act: None,
            max_ttl: None,
        },
    )
    .await
}

async fn refresh_token(
    state: &AppState,
    tenant: &Tenant,
    client: &Arc<Client>,
    params: &RawParams,
    dpop_jkt: Option<&str>,
) -> Result<TokenResponse, OAuthError> {
    let one = |n: &str| params.one(n).map_err(OAuthError::invalid_request);
    let presented = one("refresh_token")?
        .ok_or_else(|| OAuthError::invalid_request("refresh_token is required"))?;
    // A bound refresh token is only good with a proof from the same key.
    let rotated =
        refresh_tokens::rotate(state, tenant.id, &client.client_id, presented, dpop_jkt).await?;
    let granted = &rotated.record.scopes;
    // Scope may only be narrowed (RFC 6749 §6).
    let scopes: Vec<String> = match one("scope")? {
        Some(raw) => {
            let requested = scopes::parse_scope_param(raw);
            if let Some(extra) = requested.iter().find(|s| !granted.contains(s)) {
                return Err(OAuthError::new(
                    OAuthErrorCode::InvalidScope,
                    format!("scope `{extra}` was not granted"),
                ));
            }
            requested
        }
        None => granted.clone(),
    };
    let subject = match rotated.record.user_id {
        Some(uid) => Some(load_subject(state, tenant.id, uid).await?),
        None => None,
    };
    let role_ids: Vec<Uuid> = subject
        .as_ref()
        .map(|s| s.roles.iter().map(|r| r.id).collect())
        .unwrap_or_default();
    let extra = parse_resources(params)?;
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
            // OIDC Core §12.2: the refreshed ID token repeats the original
            // authentication context.
            auth_time: rotated.record.auth_time,
            amr: rotated.record.amr.clone(),
            acr: rotated.record.acr.clone(),
            nonce: None,
            with_refresh: Some(rotated.record.family_id),
            issue_refresh: false,
            code_for_hash: None,
            dpop_jkt,
            act: None,
            max_ttl: None,
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
    dpop_jkt: Option<&str>,
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
    let (known, unknown) = scopes::resolve(state, tenant.id, &requested).await?;
    if !unknown.is_empty() {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidScope,
            format!("unknown scope(s): {}", unknown.join(" ")),
        ));
    }
    if let Some(bad) = known
        .iter()
        .find(|s| !client.allowed_scopes.contains(&s.name))
    {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidScope,
            format!("scope `{}` is not allowed for this client", bad.name),
        ));
    }
    let subject = match client.service_account_user_id {
        Some(uid) => Some(load_subject(state, tenant.id, uid).await?),
        None => None,
    };
    let role_ids: Vec<Uuid> = subject
        .as_ref()
        .map(|s| s.roles.iter().map(|r| r.id).collect())
        .unwrap_or_default();
    let audience = resolve_audience(
        state,
        tenant.id,
        client,
        &parse_resources(params)?,
        &role_ids,
    )
    .await?;
    issue_tokens(
        state,
        Issue {
            tenant,
            client,
            subject: subject.as_ref(),
            scopes: &requested,
            audience,
            session_id: None,
            auth_time: None,
            amr: vec![],
            acr: None,
            nonce: None,
            with_refresh: None,
            issue_refresh: false,
            code_for_hash: None,
            dpop_jkt,
            act: None,
            max_ttl: None,
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
    dpop_jkt: Option<&str>,
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
    if let Some(requested) = one("requested_token_type")?
        && !is_access(requested)
    {
        return Err(OAuthError::invalid_request(
            "requested_token_type must be an access token or jwt type",
        ));
    }
    let verify = VerifyOptions {
        typ: Some("at+jwt".into()),
        check_denylist: true,
        ..Default::default()
    };
    let subject_map = tokens::verify(state, tenant, subject_token, &verify)
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
        && dpop_jkt != Some(bound)
    {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "subject_token is bound to a key this request did not prove",
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
            let claims = tokens::verify(state, tenant, token, &verify)
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
        Some(uid) => Some(load_subject(state, tenant.id, uid).await?),
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
    let remaining = subject_claims["exp"].as_i64().unwrap_or_default() - Utc::now().timestamp();
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
            nonce: None,
            with_refresh: None,
            issue_refresh: false,
            code_for_hash: None,
            dpop_jkt,
            act,
            max_ttl: Some(std::time::Duration::from_secs(remaining.max(1) as u64)),
        },
    )
    .await?;
    response.issued_token_type = Some(token_types::ACCESS_TOKEN);
    Ok(response)
}
