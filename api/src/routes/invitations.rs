//! Public invitation endpoints: look up and accept by token.

use axum::Router;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::middleware::TenantCtx;
use crate::middleware::client_ip;
use crate::services::flows::{self, AuthStep};
use crate::services::registration::RegistrationInput;
use crate::services::{invitations, sessions};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/t/{slug}/invitations/{token}", get(lookup).post(accept))
}

async fn lookup(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, token)): Path<(String, String)>,
) -> Response {
    match invitations::lookup(&state, &tenant.tenant, &token).await {
        Ok((_, public)) => {
            let mut res = axum::Json(public).into_response();
            res.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            res
        }
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
struct AcceptBody {
    #[serde(flatten)]
    input: RegistrationInput,
    /// Login flow to continue after accepting (from `/login/?flow=`).
    #[serde(default)]
    flow: Option<Uuid>,
}

async fn accept(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, token)): Path<(String, String)>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<AcceptBody>,
) -> Response {
    let user = match invitations::accept(&state, &tenant.tenant, &token, body.input).await {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let ctx = flows::RequestContext {
        ip: client_ip(&state, &headers, Some(peer)),
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(512).collect()),
        ..Default::default()
    };
    // Accepting proves control of the email: sign the user in.
    let policy = &tenant.tenant.settings.session;
    let session = match sessions::create(
        &state,
        tenant.id(),
        sessions::NewSession {
            user_id: user.id,
            amr: vec!["otp".into()],
            acr: Some(flows::ACR_SINGLE.to_string()),
            ip: ctx.ip.clone(),
            user_agent: ctx.user_agent.clone(),
            policy,
        },
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let mut body_json = json!({"accepted": true, "user_id": user.id, "username": user.username});
    if let Some(flow_id) = body.flow
        && let Ok(Some(flow)) =
            crate::services::login_flows::get(&state, tenant.id(), flow_id).await
        && matches!(
            flow.stage,
            crate::services::login_flows::FlowStage::Authenticate
                | crate::services::login_flows::FlowStage::Register
        )
    {
        let ctx2 = flows::RequestContext {
            ip: ctx.ip.clone(),
            user_agent: ctx.user_agent.clone(),
            existing_session: Some(session.clone()),
            ..Default::default()
        };
        if let Ok(AuthStep::Authenticated { flow, .. }) = flows::complete_authentication(
            &state,
            &tenant,
            flow,
            &user,
            vec!["otp".into()],
            ctx2,
            false,
        )
        .await
            && let Ok(public) = flows::public_state(&state, &tenant.tenant, &flow).await
        {
            let mut v = serde_json::to_value(&public).unwrap_or_default();
            if public.stage == crate::services::login_flows::FlowStage::Done {
                v["finish_url"] = json!(format!(
                    "{}/flows/{}/finish",
                    tenant.issuer(&state),
                    flow.id
                ));
            }
            body_json["flow"] = v;
        }
    }
    let mut res = (StatusCode::CREATED, axum::Json(body_json)).into_response();
    if let Ok(v) = HeaderValue::from_str(&sessions::set_cookie_header(
        &state,
        &tenant.tenant,
        &session,
    )) {
        res.headers_mut().append(header::SET_COOKIE, v);
    }
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}
