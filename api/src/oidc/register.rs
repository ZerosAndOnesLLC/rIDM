//! Dynamic client registration (RFC 7591) and management (RFC 7592):
//! `POST /t/{slug}/register`, `GET|PUT|DELETE /t/{slug}/register/{client_id}`.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::AppError;
use crate::middleware::TenantCtx;
use crate::models::{
    Client, ClientSubjectType, ClientType, DcrMode, IdTokenEncryptionConfig, NewClient,
    TokenEndpointAuthMethod, grants,
};
use crate::oidc::bearer;
use crate::services::{clients, dcr};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/t/{slug}/register", post(register))
        .route(
            "/t/{slug}/register/{client_id}",
            get(read).put(update).delete(delete),
        )
}

/// Client metadata as defined by RFC 7591 §2 and OIDC Registration §2.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Metadata {
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub contacts: Vec<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub scope: Option<String>,
    pub jwks: Option<Value>,
    pub jwks_uri: Option<String>,
    pub application_type: Option<String>,
    pub subject_type: Option<String>,
    pub sector_identifier_uri: Option<String>,
    pub id_token_encrypted_response_alg: Option<String>,
    pub id_token_encrypted_response_enc: Option<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub backchannel_logout_uri: Option<String>,
    pub frontchannel_logout_uri: Option<String>,
    pub initiate_login_uri: Option<String>,
    pub require_pushed_authorization_requests: Option<bool>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegistrationError {
    error: &'static str,
    error_description: String,
}

fn error(status: StatusCode, error: &'static str, description: impl Into<String>) -> Response {
    let mut res = (
        status,
        axum::Json(RegistrationError {
            error,
            error_description: description.into(),
        }),
    )
        .into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn metadata_error(e: AppError) -> Response {
    match e {
        AppError::BadRequest(d) if d.contains("redirect_uri") => {
            error(StatusCode::BAD_REQUEST, "invalid_redirect_uri", d)
        }
        AppError::BadRequest(d) | AppError::Conflict(d) => {
            error(StatusCode::BAD_REQUEST, "invalid_client_metadata", d)
        }
        AppError::Validation(fields) => error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            fields
                .iter()
                .map(|f| format!("{}: {}", f.field, f.message))
                .collect::<Vec<_>>()
                .join("; "),
        ),
        other => other.into_response(),
    }
}

/// Map RFC 7591 metadata onto rIDM's client model.
pub fn to_new_client(m: &Metadata, policy_grants: &[String]) -> Result<NewClient, AppError> {
    let bad = |d: &str| AppError::BadRequest(d.to_string());
    let auth_method = match m.token_endpoint_auth_method.as_deref() {
        None | Some("client_secret_basic") => TokenEndpointAuthMethod::ClientSecretBasic,
        Some("client_secret_post") => TokenEndpointAuthMethod::ClientSecretPost,
        Some("private_key_jwt") => TokenEndpointAuthMethod::PrivateKeyJwt,
        Some("none") => TokenEndpointAuthMethod::None,
        Some(other) => {
            return Err(bad(&format!(
                "unsupported token_endpoint_auth_method `{other}`"
            )));
        }
    };
    let grant_types = m
        .grant_types
        .clone()
        .unwrap_or_else(|| vec![grants::AUTHORIZATION_CODE.to_string()]);
    for g in &grant_types {
        if !grants::ALL.contains(&g.as_str()) {
            return Err(bad(&format!("unsupported grant type `{g}`")));
        }
        if !policy_grants.is_empty() && !policy_grants.contains(g) {
            return Err(bad(&format!(
                "grant type `{g}` is not permitted for dynamic registration"
            )));
        }
    }
    if let Some(rt) = &m.response_types
        && rt.iter().any(|r| r != "code")
    {
        return Err(bad("only response_type `code` is supported"));
    }
    let has_code = grant_types.iter().any(|g| g == grants::AUTHORIZATION_CODE);
    let has_device = grant_types.iter().any(|g| g == grants::DEVICE_CODE);
    let client_type = match (
        m.application_type.as_deref(),
        auth_method,
        has_code,
        has_device,
    ) {
        (Some("native"), _, _, _) => ClientType::Native,
        (Some(other), _, _, _) if other != "web" => {
            return Err(bad(&format!("unsupported application_type `{other}`")));
        }
        (_, _, false, true) => ClientType::Device,
        (_, _, false, false) => ClientType::Machine,
        (_, TokenEndpointAuthMethod::None, true, _) => ClientType::Spa,
        _ => ClientType::Web,
    };
    let subject_type = match m.subject_type.as_deref() {
        None | Some("public") => ClientSubjectType::Public,
        Some("pairwise") => ClientSubjectType::Pairwise,
        Some(other) => return Err(bad(&format!("unsupported subject_type `{other}`"))),
    };
    let id_token_encryption = match (
        &m.id_token_encrypted_response_alg,
        &m.id_token_encrypted_response_enc,
    ) {
        (None, None) => None,
        (Some(alg), enc) => Some(IdTokenEncryptionConfig {
            alg: alg.clone(),
            enc: enc.clone().unwrap_or_else(|| "A128GCM".into()),
        }),
        (None, Some(_)) => return Err(bad("id_token_encrypted_response_enc requires ..._alg")),
    };
    let name = m
        .client_name
        .clone()
        .or_else(|| m.software_id.clone())
        .unwrap_or_else(|| "Dynamically registered client".into());
    Ok(NewClient {
        client_id: None,
        name,
        client_type: Some(client_type),
        description: None,
        logo_uri: m.logo_uri.clone(),
        client_uri: m.client_uri.clone(),
        tos_uri: m.tos_uri.clone(),
        policy_uri: m.policy_uri.clone(),
        token_endpoint_auth_method: Some(auth_method),
        jwks: m.jwks.clone(),
        jwks_uri: m.jwks_uri.clone(),
        redirect_uris: m.redirect_uris.clone(),
        post_logout_redirect_uris: m.post_logout_redirect_uris.clone(),
        allowed_grants: Some(grant_types),
        allowed_scopes: m
            .scope
            .as_deref()
            .map(crate::services::scopes::parse_scope_param),
        allowed_audiences: vec![],
        access_token_ttl_secs: None,
        refresh_token_ttl_secs: None,
        id_token_ttl_secs: None,
        access_token_format: None,
        id_token_encryption,
        subject_type: Some(subject_type),
        sector_identifier_uri: m.sector_identifier_uri.clone(),
        require_pkce: None,
        require_consent: Some(true),
        cors_origins: vec![],
        initiate_login_uri: m.initiate_login_uri.clone(),
        backchannel_logout_uri: m.backchannel_logout_uri.clone(),
        frontchannel_logout_uri: m.frontchannel_logout_uri.clone(),
    })
}

/// RFC 7591 §3.2.1 response document.
pub fn to_metadata(state: &AppState, tenant: &TenantCtx, client: &Client) -> Value {
    let mut v = json!({
        "client_id": client.client_id,
        "client_name": client.name,
        "redirect_uris": client.redirect_uris,
        "post_logout_redirect_uris": client.post_logout_redirect_uris,
        "grant_types": client.allowed_grants,
        "response_types": if client.allows_grant(grants::AUTHORIZATION_CODE) { vec!["code"] } else { vec![] },
        "token_endpoint_auth_method": client.token_endpoint_auth_method.as_str(),
        "application_type": match client.client_type { ClientType::Native => "native", _ => "web" },
        "subject_type": match client.subject_type { ClientSubjectType::Public => "public", ClientSubjectType::Pairwise => "pairwise" },
        "scope": client.allowed_scopes.join(" "),
        "registration_client_uri": format!("{}/register/{}", tenant.issuer(state), client.client_id),
        "client_id_issued_at": client.created_at.timestamp(),
    });
    for (k, val) in [
        ("client_uri", &client.client_uri),
        ("logo_uri", &client.logo_uri),
        ("tos_uri", &client.tos_uri),
        ("policy_uri", &client.policy_uri),
        ("jwks_uri", &client.jwks_uri),
        ("sector_identifier_uri", &client.sector_identifier_uri),
        ("backchannel_logout_uri", &client.backchannel_logout_uri),
        ("frontchannel_logout_uri", &client.frontchannel_logout_uri),
        ("initiate_login_uri", &client.initiate_login_uri),
    ] {
        if let Some(x) = val {
            v[k] = json!(x);
        }
    }
    if let Some(j) = &client.jwks {
        v["jwks"] = j.clone();
    }
    if let Some(e) = &client.id_token_encryption {
        v["id_token_encrypted_response_alg"] = json!(e.alg);
        v["id_token_encrypted_response_enc"] = json!(e.enc);
    }
    v
}

async fn register(
    State(state): State<AppState>,
    tenant: TenantCtx,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let policy = &tenant.tenant.settings.dcr;
    match policy.mode {
        DcrMode::Disabled => {
            return error(
                StatusCode::FORBIDDEN,
                "access_denied",
                "dynamic registration is disabled for this tenant",
            );
        }
        DcrMode::InitialAccessToken => {
            let Some(token) = bearer::extract(&headers, None) else {
                return bearer::error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "initial access token required",
                );
            };
            match dcr::consume_initial_access_token(&state, tenant.id(), &token).await {
                Ok(true) => {}
                Ok(false) => {
                    return bearer::invalid_token(
                        "initial access token is invalid, expired or exhausted",
                    );
                }
                Err(e) => return e.into_response(),
            }
        }
        DcrMode::Open => {}
    }
    let metadata: Metadata = match serde_json::from_slice(&body) {
        Ok(m) => m,
        Err(e) => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                format!("invalid JSON: {e}"),
            );
        }
    };
    let input = match to_new_client(&metadata, &policy.allowed_grants) {
        Ok(i) => i,
        Err(e) => return metadata_error(e),
    };
    let created =
        match clients::create(&state, tenant.id(), ridm_core::events::Actor::System, input).await {
            Ok(c) => c,
            Err(e) => return metadata_error(e),
        };
    let rat = match clients::issue_registration_token(&state, tenant.id(), created.client.id).await
    {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let mut doc = to_metadata(&state, &tenant, &created.client);
    doc["registration_access_token"] = json!(rat.as_str());
    if let Some(secret) = &created.client_secret {
        doc["client_secret"] = json!(secret.as_str());
        doc["client_secret_expires_at"] = json!(0);
    }
    let mut res = (StatusCode::CREATED, axum::Json(doc)).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// Resolve the client from the path and the bearer registration token.
async fn authorize_management(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    client_id: &str,
) -> Result<std::sync::Arc<Client>, Box<Response>> {
    let token = bearer::extract(headers, None).ok_or_else(|| {
        Box::new(bearer::error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "registration access token required",
        ))
    })?;
    let client = clients::find_by_client_id(state, tenant.id(), client_id)
        .await
        .map_err(|e| Box::new(e.into_response()))?
        .filter(|c| clients::verify_registration_token(c, &token))
        // Same answer for unknown clients and wrong tokens (RFC 7592 §2.1).
        .ok_or_else(|| {
            Box::new(bearer::invalid_token(
                "registration access token is invalid",
            ))
        })?;
    Ok(client)
}

async fn read(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_slug, client_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let client = match authorize_management(&state, &tenant, &headers, &client_id).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    let mut res = axum::Json(to_metadata(&state, &tenant, &client)).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

async fn update(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_slug, client_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let client = match authorize_management(&state, &tenant, &headers, &client_id).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    let metadata: Metadata = match serde_json::from_slice(&body) {
        Ok(m) => m,
        Err(e) => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                format!("invalid JSON: {e}"),
            );
        }
    };
    // RFC 7592 §2.2: client_id in the body, if present, must match.
    if let Ok(v) = serde_json::from_slice::<Value>(&body)
        && let Some(id) = v.get("client_id").and_then(Value::as_str)
        && id != client.client_id
    {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "client_id cannot be changed",
        );
    }
    let input = match to_new_client(&metadata, &tenant.tenant.settings.dcr.allowed_grants) {
        Ok(i) => i,
        Err(e) => return metadata_error(e),
    };
    match clients::update_metadata(
        &state,
        tenant.id(),
        ridm_core::events::Actor::System,
        client.id,
        input,
    )
    .await
    {
        Ok(c) => {
            let mut res = axum::Json(to_metadata(&state, &tenant, &c)).into_response();
            res.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            res
        }
        Err(e) => metadata_error(e),
    }
}

async fn delete(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_slug, client_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let client = match authorize_management(&state, &tenant, &headers, &client_id).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    match clients::delete(
        &state,
        tenant.id(),
        ridm_core::events::Actor::System,
        client.id,
    )
    .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}
