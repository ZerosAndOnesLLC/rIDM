//! `GET /t/{slug}/features`: the feature flags that are on for the bearer of
//! an access token of the tenant — for the user's organization when the
//! token names one (`org_id`), tenant-wide otherwise. The same list the
//! `features` scope puts in tokens, read live instead of at sign-in.

use axum::Router;
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;
use uuid::Uuid;

use crate::error::AppError;
use crate::middleware::{AdminRejection, TenantCtx, bearer_with_scheme, require_binding};
use crate::services::features;
use crate::services::tokens::{self, VerifyOptions};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/t/{slug}/features", get(list))
}

#[derive(Serialize)]
struct Features {
    /// The flags that are on, sorted.
    features: Vec<String>,
    /// The organization they were worked out for.
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<Uuid>,
}

async fn list(State(state): State<AppState>, tenant: TenantCtx, req: Request) -> Response {
    // The whole request, not just its headers: a DPoP proof binds the
    // method and URI too.
    let (mut parts, _) = req.into_parts();
    match features_of(&state, &tenant, &mut parts).await {
        Ok(f) => {
            let mut res = axum::Json(f).into_response();
            crate::middleware::security_headers::set_no_store(res.headers_mut());
            res
        }
        Err(e) => e.into_response(),
    }
}

async fn features_of(
    state: &AppState,
    path_tenant: &TenantCtx,
    parts: &mut Parts,
) -> Result<Features, AdminRejection> {
    let (scheme, token) = bearer_with_scheme(&parts.headers).ok_or_else(AdminRejection::missing)?;
    let (tenant, claims) = tokens::access_token_with_tenant(
        state,
        &token,
        Some(path_tenant.id()),
        &VerifyOptions::default(),
    )
    .await
    .map_err(|e| match e {
        AppError::Unauthorized => AdminRejection::invalid(),
        other => other.into(),
    })?
    .ok_or_else(AdminRejection::invalid)?;
    require_binding(state, &tenant, scheme, &token, &claims, parts).await?;
    let org_id = claims
        .get("org_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok());
    Ok(Features {
        features: features::enabled_for(state, &tenant, org_id).await?,
        org_id,
    })
}
