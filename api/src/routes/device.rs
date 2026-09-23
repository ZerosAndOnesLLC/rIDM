//! The user's side of the device authorization grant:
//! `POST /t/{slug}/device/verify {user_code}` turns the code shown on the
//! device into a login flow for the device's client. The flow runs like any
//! other (sign-in, second step, consent) and its finish approves the device
//! code instead of issuing an authorization code.

use axum::Router;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::{Json, TenantCtx};
use crate::services::login_flows::{self, AuthRequest, FlowStage, LoginFlow, ResponseMode};
use crate::services::{broker, clients, device_codes, flows, geoip, sessions};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/t/{slug}/device/verify", post(verify))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyBody {
    pub user_code: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct VerifyResponse {
    /// The page that continues the approval (sign-in, or consent when already signed in).
    pub redirect_to: String,
}

async fn verify(
    State(state): State<AppState>,
    tenant: TenantCtx,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<VerifyBody>,
) -> Response {
    let mut res = match handle(&state, &tenant, &headers, peer, &body.user_code).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(e) => e.into_response(),
    };
    crate::middleware::security_headers::set_no_store(res.headers_mut());
    res
}

async fn handle(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    peer: std::net::SocketAddr,
    user_code: &str,
) -> AppResult<VerifyResponse> {
    let origin = geoip::Origin::of_request(state, headers, Some(peer));
    let ip = origin.ip_string();
    let (device_hash, rec) =
        device_codes::find_by_user_code(state, tenant.id(), user_code, ip.as_deref())
            .await?
            .ok_or(AppError::NotFound("device code"))?;
    let client = clients::get(state, tenant.id(), rec.client_id).await?;
    if !client.is_active() {
        return Err(AppError::NotFound("device code"));
    }
    // The device page stands in for the client's redirect URI: denial and
    // approval both land there.
    let device_page = state.ui_page(&tenant.tenant, "device", &[("tenant", tenant.slug())]);
    let now = Utc::now();
    let mut flow = LoginFlow {
        id: Uuid::now_v7(),
        tenant_id: tenant.id(),
        request: AuthRequest {
            client_id: client.id,
            client_public_id: client.client_id.clone(),
            redirect_uri: device_page,
            response_mode: ResponseMode::Query,
            scopes: rec.scopes.clone(),
            audiences: rec.audiences.clone(),
            state: None,
            nonce: None,
            code_challenge: None,
            prompt: vec![],
            max_age: None,
            acr_values: vec![],
            login_hint: None,
            ui_locales: vec![],
            claims: None,
            skip_consent: !client.require_consent,
            organization: None,
            device_code: Some(device_hash.clone()),
            saml: None,
        },
        stage: FlowStage::Authenticate,
        session_id: None,
        user_id: None,
        pending_scopes: vec![],
        require_auth_after: None,
        csrf: String::new(),
        attempts: 0,
        amr: vec![],
        org_id: None,
        trusted_device: false,
        risk_step_up: false,
        remember_device: false,
        created_at: now,
        expires_at: now,
    };
    // A browser already signed in skips straight to what is left (a forced
    // password change, a second step, the profile, consent, or nothing),
    // judged the way `/authorize` judges a session: a user who is gone or no
    // longer active signs in again, and a password change the session still
    // owes comes first.
    if let Some(session) = sessions::from_request(state, &tenant.tenant, headers).await? {
        let owed = flows::unfinished_stage(
            state,
            &tenant.tenant,
            &session,
            headers,
            (ip.as_deref(), origin.location.as_ref()),
        )
        .await?;
        // The risk policy refused this session from here: the device is told
        // no rather than left polling for an approval that cannot come.
        if owed == flows::Owed::Blocked {
            device_codes::deny(state, tenant.id(), &device_hash).await?;
            return Err(AppError::Forbidden("the sign-in was refused".into()));
        }
        if owed.step() != Some(FlowStage::Authenticate) {
            flow.session_id = Some(session.id);
            flow.user_id = Some(session.user_id);
            flow.amr = session.amr.clone();
            // Whatever asked for a second step, the flow owes it.
            flow.risk_step_up = owed.step() == Some(FlowStage::Mfa);
            let must_change_password = owed.step() == Some(FlowStage::PasswordChange);
            flows::advance(state, &tenant.tenant, &mut flow, must_change_password).await?;
        }
    }
    let flow = login_flows::create(state, flow).await?;
    let page = broker::page_for(flow.stage);
    Ok(VerifyResponse {
        redirect_to: state.ui_page(
            &tenant.tenant,
            page,
            &[("tenant", tenant.slug()), ("flow", &flow.id.to_string())],
        ),
    })
}
