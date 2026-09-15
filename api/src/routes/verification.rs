//! Email verification: `POST /t/{slug}/verification/email/confirm {token}`.
//! When the link belongs to a login flow waiting for verification, the user
//! is signed in and the flow state (with `finish_url`) is returned.

use axum::Router;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::Deserialize;
use serde_json::json;

use crate::middleware::TenantCtx;
use crate::routes::flows::client_ip;
use crate::services::flows::{self, AuthStep};
use crate::services::{registration, sessions};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/t/{slug}/verification/email/confirm", post(confirm))
}

#[derive(Deserialize)]
struct ConfirmBody {
    token: String,
}

async fn confirm(
    State(state): State<AppState>,
    tenant: TenantCtx,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<ConfirmBody>,
) -> Response {
    let confirmed = match registration::confirm(&state, &tenant.tenant, &body.token).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let mut res =
        axum::Json(json!({"verified": true, "username": confirmed.user.username})).into_response();
    if let Some(flow_id) = confirmed.flow_id {
        let ctx = flows::RequestContext {
            ip: client_ip(&state, &headers, Some(peer)),
            user_agent: headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.chars().take(512).collect()),
            existing_session: None,
        };
        match flows::resume_after_verification(&state, &tenant, flow_id, &confirmed.user, ctx).await
        {
            Ok(Some(AuthStep::Authenticated { session, flow })) => {
                let public = match flows::public_state(&state, &tenant.tenant, &flow).await {
                    Ok(p) => p,
                    Err(e) => return e.into_response(),
                };
                let mut body = serde_json::to_value(&public).unwrap_or_default();
                body["verified"] = json!(true);
                if public.stage == crate::services::login_flows::FlowStage::Done {
                    body["finish_url"] = json!(format!(
                        "{}/flows/{}/finish",
                        tenant.issuer(&state),
                        flow.id
                    ));
                }
                res = axum::Json(body).into_response();
                if let Ok(v) = HeaderValue::from_str(&sessions::set_cookie_header(
                    &state,
                    &tenant.tenant,
                    &session,
                )) {
                    res.headers_mut().append(header::SET_COOKIE, v);
                }
            }
            Ok(_) => {}
            Err(e) => return e.into_response(),
        }
    }
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}
