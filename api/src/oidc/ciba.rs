//! Backchannel authentication endpoint (OpenID CIBA Core 1.0 §7):
//! `POST /t/{slug}/bc-authorize`. An authenticated client names the user
//! (`login_hint` or `id_token_hint`), rIDM asks them on their own device,
//! and the client collects the tokens from `/token` with
//! `grant_type=urn:openid:params:grant-type:ciba` (see `token.rs`), polling
//! or after a ping.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::error::{OAuthError, OAuthErrorCode};
use crate::middleware::{TenantCtx, client_ip_addr};
use crate::models::{BackchannelDeliveryMode, Client, User, UserStatus, grants};
use crate::oidc::authorize::RawParams;
use crate::oidc::client_auth;
use crate::oidc::device::requested_resources;
use crate::services::ciba::{self, Acknowledgement, Start};
use crate::services::tokens::{self, VerifyOptions};
use crate::services::{scopes, users};
use crate::state::AppState;

pub fn router() -> axum::Router<AppState> {
    axum::Router::new().route(
        "/t/{slug}/bc-authorize",
        axum::routing::post(backchannel_authentication),
    )
}

pub async fn backchannel_authentication(
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
    let outcome = if is_form {
        handle(&state, &tenant, &headers, &body, ip).await
    } else {
        Err(OAuthError::invalid_request(
            "content type must be application/x-www-form-urlencoded",
        ))
    };
    let mut res = match outcome {
        Ok(v) => axum::Json(v).into_response(),
        Err(e) => e.into_response(),
    };
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn unknown_user() -> OAuthError {
    OAuthError::new(
        OAuthErrorCode::UnknownUserId,
        "the hint does not name a user who can be asked",
    )
}

async fn handle(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    body: &str,
    ip: Option<IpAddr>,
) -> Result<Acknowledgement, OAuthError> {
    let params = RawParams::parse(body);
    let one = |n: &str| params.one(n).map_err(OAuthError::invalid_request);
    let token_endpoint = format!("{}/token", tenant.issuer(state));
    let (client, _) =
        client_auth::authenticate(state, tenant, headers, &params, &token_endpoint, ip).await?;
    if !client.allows_grant(grants::CIBA) {
        return Err(OAuthError::new(
            OAuthErrorCode::UnauthorizedClient,
            "client may not use the CIBA grant",
        ));
    }
    let mode = client
        .backchannel_token_delivery_mode
        .unwrap_or(BackchannelDeliveryMode::Poll);
    if one("request")?.is_some() {
        return Err(OAuthError::invalid_request(
            "signed authentication requests are not supported",
        ));
    }

    // CIBA Core §7.1: `scope` is required (no client defaults) and is an
    // OpenID request, so it includes `openid`.
    let requested = scopes::parse_scope_param(one("scope")?.unwrap_or_default());
    if requested.is_empty() {
        return Err(OAuthError::invalid_request("scope is required"));
    }
    let checked =
        scopes::validate_request(state, tenant.id(), &client, requested, &[], true).await?;
    if !checked.scopes.iter().any(|s| s == "openid") {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidScope,
            "scope must include openid",
        ));
    }

    let notification_token = one("client_notification_token")?.map(str::to_string);
    if mode == BackchannelDeliveryMode::Ping {
        match &notification_token {
            None => {
                return Err(OAuthError::invalid_request(
                    "client_notification_token is required in ping mode",
                ));
            }
            Some(t) if t.is_empty() || t.len() > ciba::NOTIFICATION_TOKEN_MAX_LEN => {
                return Err(OAuthError::invalid_request(
                    "client_notification_token is empty or too long",
                ));
            }
            Some(_) => {}
        }
    }
    let binding_message = one("binding_message")?.map(str::to_string);
    if let Some(m) = &binding_message
        && !ciba::valid_binding_message(m)
    {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidBindingMessage,
            format!(
                "binding_message must be 1-{} letters, digits, spaces or -_.:#",
                ciba::BINDING_MESSAGE_MAX_CHARS
            ),
        ));
    }
    let expiry_secs = match one("requested_expiry")? {
        None => ciba::DEFAULT_EXPIRY_SECS,
        Some(v) => v
            .parse::<u64>()
            .ok()
            .filter(|s| (ciba::MIN_EXPIRY_SECS..=ciba::MAX_EXPIRY_SECS).contains(s))
            .ok_or_else(|| {
                OAuthError::invalid_request(format!(
                    "requested_expiry must be {}-{} seconds",
                    ciba::MIN_EXPIRY_SECS,
                    ciba::MAX_EXPIRY_SECS
                ))
            })?,
    };
    let acr_values: Vec<String> = one("acr_values")?
        .map(|v| {
            v.split(' ')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let audiences = requested_resources(state, tenant.id(), &client, &params).await?;
    let audiences = scopes::with_bound_audiences(
        audiences,
        &client.allowed_audiences,
        checked.bound_audiences,
    );

    let user = resolve_user(state, tenant, &client, &params).await?;
    if ciba::pending_count(state, tenant.id(), user.id).await? >= ciba::MAX_PENDING_PER_USER {
        return Err(OAuthError::new(
            OAuthErrorCode::AccessDenied,
            "too many requests are already waiting on this user",
        ));
    }
    let ip = ip.map(|a| a.to_string());
    Ok(ciba::start(
        state,
        tenant.tenant.as_ref(),
        &client,
        &user,
        Start {
            scopes: checked.scopes,
            audiences,
            binding_message,
            acr_values,
            notification_token,
            expiry_secs,
            ip: ip.as_deref(),
        },
    )
    .await?)
}

/// The user the request names: exactly one hint (CIBA Core §7.1). A
/// `login_hint` is a username or email address, as at sign-in; an
/// `id_token_hint` is an ID token this tenant issued to this client
/// (expired or not). `login_hint_token` has no standard format and is
/// refused. Only an active, unlocked user can be asked.
async fn resolve_user(
    state: &AppState,
    tenant: &TenantCtx,
    client: &Client,
    params: &RawParams,
) -> Result<User, OAuthError> {
    let one = |n: &str| params.one(n).map_err(OAuthError::invalid_request);
    let login_hint = one("login_hint")?;
    let id_token_hint = one("id_token_hint")?;
    let login_hint_token = one("login_hint_token")?;
    let hints = [login_hint, id_token_hint, login_hint_token]
        .iter()
        .filter(|h| h.is_some())
        .count();
    if hints != 1 {
        return Err(OAuthError::invalid_request(
            "exactly one of login_hint, id_token_hint or login_hint_token is required",
        ));
    }
    if login_hint_token.is_some() {
        return Err(OAuthError::invalid_request(
            "login_hint_token is not supported; use login_hint or id_token_hint",
        ));
    }
    let user = if let Some(hint) = login_hint {
        if hint.trim().is_empty() || hint.len() > 320 {
            return Err(unknown_user());
        }
        users::find_by_identifier(state, tenant.id(), hint).await?
    } else {
        let hint = id_token_hint.unwrap_or_default();
        let claims = tokens::verify(
            state,
            &tenant.tenant,
            hint,
            &VerifyOptions {
                allow_expired: true,
                typ: Some("JWT".into()),
                check_denylist: false,
                ..Default::default()
            },
        )
        .await
        .map_err(|_| {
            OAuthError::invalid_request("id_token_hint is not an ID token of this issuer")
        })?;
        let issued_to_client = match &claims.get("aud") {
            Some(serde_json::Value::String(a)) => a == &client.client_id,
            Some(serde_json::Value::Array(a)) => a.iter().any(|v| v == client.client_id.as_str()),
            _ => false,
        };
        if !issued_to_client {
            return Err(OAuthError::invalid_request(
                "id_token_hint was not issued to this client",
            ));
        }
        match tokens::subject_user_id(state, &tenant.tenant, &claims).await? {
            Some(id) => find_user(state, tenant.id(), id).await?,
            None => None,
        }
    };
    user.filter(|u| u.status == UserStatus::Active && u.deleted_at.is_none() && !u.is_locked_now())
        .ok_or_else(unknown_user)
}

async fn find_user(
    state: &AppState,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<User>, OAuthError> {
    match users::get(state, tenant_id, id).await {
        Ok(u) => Ok(Some(u)),
        Err(crate::error::AppError::NotFound(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}
