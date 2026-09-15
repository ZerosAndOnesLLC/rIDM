//! UserInfo endpoint (OIDC Core §5.3): `GET|POST /t/{slug}/userinfo`.

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Map, Value, json};

use crate::middleware::TenantCtx;
use crate::models::TokenKind;
use crate::oidc::authorize::RawParams;
use crate::oidc::bearer;
use crate::services::claims::{ClaimContext, apply_mappers, standard_claims};
use crate::services::tokens::{self, TokenClient, VerifyOptions};
use crate::services::{clients, groups, roles, users};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/t/{slug}/userinfo", get(userinfo_get).post(userinfo_post))
}

async fn userinfo_get(
    State(state): State<AppState>,
    tenant: TenantCtx,
    headers: HeaderMap,
) -> Response {
    handle(&state, &tenant, &headers, None).await
}

async fn userinfo_post(
    State(state): State<AppState>,
    tenant: TenantCtx,
    headers: HeaderMap,
    body: String,
) -> Response {
    let params = RawParams::parse(&body);
    let body_token = params
        .one("access_token")
        .ok()
        .flatten()
        .map(str::to_string);
    handle(&state, &tenant, &headers, body_token.as_deref()).await
}

async fn handle(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    body_token: Option<&str>,
) -> Response {
    let Some(token) = bearer::extract(headers, body_token) else {
        return bearer::error(
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid_request",
            "bearer token required",
        );
    };
    match build(state, tenant, &token).await {
        Ok(claims) => {
            let mut res = axum::Json(Value::Object(claims)).into_response();
            res.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            res
        }
        Err(Reject::Token(d)) => bearer::invalid_token(d),
        Err(Reject::Scope(d)) => bearer::insufficient_scope(d),
        Err(Reject::Internal(e)) => e.into_response(),
    }
}

enum Reject {
    Token(&'static str),
    Scope(&'static str),
    Internal(crate::error::AppError),
}

impl From<crate::error::AppError> for Reject {
    fn from(e: crate::error::AppError) -> Self {
        Reject::Internal(e)
    }
}

async fn build(
    state: &AppState,
    tenant: &TenantCtx,
    token: &str,
) -> Result<Map<String, Value>, Reject> {
    let claims = tokens::verify(
        state,
        &tenant.tenant,
        token,
        &VerifyOptions {
            typ: Some("at+jwt".into()),
            ..Default::default()
        },
    )
    .await
    .map_err(|_| Reject::Token("access token is invalid or expired"))?;
    let scopes: Vec<String> = claims["scope"]
        .as_str()
        .unwrap_or_default()
        .split(' ')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if !scopes.iter().any(|s| s == "openid") {
        return Err(Reject::Scope("the openid scope is required"));
    }
    let client_public = claims["client_id"].as_str().unwrap_or_default();
    let client = clients::find_by_client_id(state, tenant.id(), client_public)
        .await?
        .ok_or(Reject::Token("client no longer exists"))?;
    // The subject is the user id for public subjects; pairwise subjects cannot
    // be reversed, so the user is looked up from the session-bound `sid` / `sub`.
    let user_id = match uuid::Uuid::parse_str(claims["sub"].as_str().unwrap_or_default()) {
        Ok(id) => id,
        Err(_) => {
            // Pairwise: resolve through the session.
            let sid = claims["sid"]
                .as_str()
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                .ok_or(Reject::Token("token has no resolvable subject"))?;
            let session = crate::services::sessions::get(
                state,
                tenant.id(),
                sid,
                &tenant.tenant.settings.session,
            )
            .await?
            .ok_or(Reject::Token("session has ended"))?;
            session.user_id
        }
    };
    let user = users::get(state, tenant.id(), user_id)
        .await
        .map_err(|_| Reject::Token("user no longer exists"))?;
    let role_list = roles::effective_roles(state, tenant.id(), user.id).await?;
    let group_list = groups::groups_of_user(state, tenant.id(), user.id, true).await?;

    let mappers = crate::oidc::token::effective_mappers_for(state, tenant.id(), &client).await?;
    let tc = TokenClient::from_client(&client, &tenant.tenant, mappers);
    let mut out = standard_claims(&user, &scopes);
    let ctx = ClaimContext {
        tenant: &tenant.tenant,
        user: Some(&user),
        client_id: &client.client_id,
        scopes: &scopes,
        roles: &role_list,
        groups: &group_list,
    };
    apply_mappers(&tc.mappers, &ctx, TokenKind::Userinfo, &mut out)?;
    out.insert(
        "sub".into(),
        json!(tokens::subject_for(&tenant.tenant, &tc, &user)),
    );
    Ok(out)
}
