//! Public recovery endpoints used by the `/recover/` page.

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::middleware::TenantCtx;
use crate::middleware::security_headers::no_store;
use crate::services::recovery;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/t/{slug}/recovery/password", post(request_reset))
        .route("/t/{slug}/recovery/password/confirm", post(confirm_reset))
        .route(
            "/t/{slug}/verification/email/resend",
            post(resend_verification),
        )
}

#[derive(Deserialize)]
struct IdentifierBody {
    identifier: String,
    /// Locale the page is showing, so the email matches it.
    #[serde(default)]
    locale: Option<String>,
}

async fn request_reset(
    State(state): State<AppState>,
    tenant: TenantCtx,
    axum::Json(body): axum::Json<IdentifierBody>,
) -> Response {
    let requested: Vec<String> = body.locale.into_iter().collect();
    match recovery::request_password_reset(&state, &tenant.tenant, &body.identifier, &requested)
        .await
    {
        Ok(()) => {
            no_store((StatusCode::ACCEPTED, axum::Json(json!({"sent": true}))).into_response())
        }
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
struct ConfirmBody {
    token: String,
    new_password: String,
}

async fn confirm_reset(
    State(state): State<AppState>,
    tenant: TenantCtx,
    axum::Json(body): axum::Json<ConfirmBody>,
) -> Response {
    match recovery::complete_password_reset(
        &state,
        &tenant.tenant,
        &body.token,
        Zeroizing::new(body.new_password),
    )
    .await
    {
        Ok(user) => {
            no_store(axum::Json(json!({"reset": true, "username": user.username})).into_response())
        }
        Err(e) => e.into_response(),
    }
}

async fn resend_verification(
    State(state): State<AppState>,
    tenant: TenantCtx,
    axum::Json(body): axum::Json<IdentifierBody>,
) -> Response {
    match recovery::resend_verification(&state, &tenant.tenant, &body.identifier).await {
        Ok(()) => {
            no_store((StatusCode::ACCEPTED, axum::Json(json!({"sent": true}))).into_response())
        }
        Err(e) => e.into_response(),
    }
}
