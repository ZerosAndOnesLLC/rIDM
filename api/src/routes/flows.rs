//! Login flow API used by the static UI: `/t/{slug}/flows/{id}[/{step}]`.
//!
//! Every mutating step carries the flow's CSRF token. Responses return the
//! public flow state; when the stage is `done`, the UI navigates the browser
//! to `finish_url`, which issues the code and returns to the client.

use axum::Router;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::AppError;
use crate::middleware::TenantCtx;
use crate::services::flows::{self, AuthStep, ConsentOutcome};
use crate::services::login_flows::FlowStage;
use crate::services::{sessions, trusted_devices};
use crate::state::AppState;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/t/{slug}/flows/{id}", get(get_flow))
        .route("/t/{slug}/flows/{id}/password", post(password))
        .route(
            "/t/{slug}/flows/{id}/password-change",
            post(password_change),
        )
        .route("/t/{slug}/flows/{id}/register", post(register))
        .route("/t/{slug}/flows/{id}/magic-link", post(send_magic_link))
        .route(
            "/t/{slug}/flows/{id}/magic-link/verify",
            post(verify_magic_link),
        )
        .route("/t/{slug}/flows/{id}/email-otp", post(send_email_otp))
        .route(
            "/t/{slug}/flows/{id}/email-otp/verify",
            post(verify_email_otp),
        )
        .route("/t/{slug}/flows/{id}/sms-otp", post(send_sms_otp))
        .route("/t/{slug}/flows/{id}/sms-otp/verify", post(verify_sms_otp))
        .route(
            "/t/{slug}/flows/{id}/mfa/totp/enroll",
            post(mfa_totp_enroll),
        )
        .route(
            "/t/{slug}/flows/{id}/mfa/totp/confirm",
            post(mfa_totp_confirm),
        )
        .route("/t/{slug}/flows/{id}/mfa/verify", post(mfa_verify))
        .route(
            "/t/{slug}/flows/{id}/mfa/passkey/register",
            post(mfa_passkey_register),
        )
        .route(
            "/t/{slug}/flows/{id}/mfa/passkey/register/finish",
            post(mfa_passkey_register_finish),
        )
        .route(
            "/t/{slug}/flows/{id}/mfa/passkey/start",
            post(mfa_passkey_start),
        )
        .route(
            "/t/{slug}/flows/{id}/mfa/passkey/finish",
            post(mfa_passkey_finish),
        )
        .route("/t/{slug}/flows/{id}/passkey/start", post(passkey_start))
        .route("/t/{slug}/flows/{id}/passkey/finish", post(passkey_finish))
        .route("/t/{slug}/flows/{id}/profile", post(profile))
        .route("/t/{slug}/flows/{id}/terms", post(terms))
        .route("/t/{slug}/flows/{id}/consent", post(consent))
        .route("/t/{slug}/flows/{id}/cancel", post(cancel))
        .route("/t/{slug}/flows/{id}/finish", get(finish))
}

fn no_store(mut res: Response) -> Response {
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// Client IP honouring `X-Forwarded-For` only from trusted proxies.
pub fn client_ip(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
) -> Option<String> {
    let peer_ip = peer.map(|p| p.ip());
    let trusted = peer_ip.is_some_and(|ip| {
        state
            .config
            .trusted_proxies
            .iter()
            .any(|net| net.contains(&ip))
    });
    if trusted
        && let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(first) = xff.split(',').next().map(str::trim)
        && let Ok(ip) = first.parse::<std::net::IpAddr>()
    {
        return Some(ip.to_string());
    }
    peer_ip.map(|ip| ip.to_string())
}

/// The public state as JSON, with `finish_url` once the flow is done.
async fn public_body(
    state: &AppState,
    tenant: &TenantCtx,
    flow: &crate::services::login_flows::LoginFlow,
) -> Result<serde_json::Value, AppError> {
    let mut public = flows::public_state(state, &tenant.tenant, flow).await?;
    let mut body = serde_json::to_value(&public).unwrap_or_default();
    if public.stage == FlowStage::Done {
        body["finish_url"] = json!(format!("{}/flows/{}/finish", tenant.issuer(state), flow.id));
    }
    // The csrf token is only needed by the UI; keep it in the body.
    public.csrf.clear();
    Ok(body)
}

async fn respond_state(
    state: &AppState,
    tenant: &TenantCtx,
    flow: &crate::services::login_flows::LoginFlow,
) -> Response {
    match public_body(state, tenant, flow).await {
        Ok(body) => no_store(axum::Json(body).into_response()),
        Err(e) => e.into_response(),
    }
}

async fn get_flow(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
) -> Response {
    match flows::load(&state, tenant.id(), id).await {
        Ok(flow) => respond_state(&state, &tenant, &flow).await,
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
struct PasswordBody {
    csrf: String,
    identifier: String,
    password: String,
    #[serde(default)]
    captcha_token: Option<String>,
    #[serde(default)]
    remember_device: bool,
}

async fn password(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<PasswordBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    let ip = client_ip(&state, &headers, Some(peer));
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(512).collect());
    let existing = sessions::from_request(&state, &tenant.tenant, &headers)
        .await
        .ok()
        .flatten();
    let attempt = flows::PasswordAttempt {
        identifier: body.identifier,
        password: Zeroizing::new(body.password),
        ip,
        user_agent: ua,
        existing_session: existing,
        captcha_token: body.captcha_token,
        device_secret: trusted_devices::secret_from_headers(&state, &headers),
        remember_device: body.remember_device,
    };
    match flows::password_step(&state, &tenant, flow, attempt).await {
        Ok(AuthStep::Authenticated { session, flow }) => {
            let mut res = respond_state(&state, &tenant, &flow).await;
            if let Ok(v) = HeaderValue::from_str(&sessions::set_cookie_header(
                &state,
                &tenant.tenant,
                &session,
            )) {
                res.headers_mut().append(header::SET_COOKIE, v);
            }
            res
        }
        Ok(AuthStep::Rejected { flow, locked }) => {
            let (code, message) = if locked {
                (
                    "account_locked",
                    "too many failed attempts; try again later",
                )
            } else {
                ("invalid_credentials", "incorrect identifier or password")
            };
            no_store(
                (
                    StatusCode::UNAUTHORIZED,
                    axum::Json(json!({"error": code, "error_description": message, "attempts": flow.attempts})),
                )
                    .into_response(),
            )
        }
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
struct PasswordChangeBody {
    csrf: String,
    new_password: String,
}

async fn password_change(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    axum::Json(body): axum::Json<PasswordChangeBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    match flows::password_change_step(
        &state,
        &tenant.tenant,
        flow,
        Zeroizing::new(body.new_password),
    )
    .await
    {
        Ok(flow) => respond_state(&state, &tenant, &flow).await,
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
struct ProfileBody {
    csrf: String,
    attributes: serde_json::Value,
}

async fn profile(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    axum::Json(body): axum::Json<ProfileBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    match flows::profile_step(&state, &tenant.tenant, flow, body.attributes).await {
        Ok(flow) => respond_state(&state, &tenant, &flow).await,
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
struct TermsBody {
    csrf: String,
    accepted: bool,
}

async fn terms(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    axum::Json(body): axum::Json<TermsBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    match flows::terms_step(&state, &tenant.tenant, flow, body.accepted).await {
        Ok(flow) => respond_state(&state, &tenant, &flow).await,
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
struct ConsentBody {
    csrf: String,
    approve: bool,
    #[serde(default)]
    scopes: Option<Vec<String>>,
}

async fn consent(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    axum::Json(body): axum::Json<ConsentBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    match flows::consent_step(&state, &tenant.tenant, flow, body.approve, body.scopes).await {
        Ok(ConsentOutcome::Granted { flow }) => respond_state(&state, &tenant, &flow).await,
        Ok(ConsentOutcome::Denied { redirect_to }) => {
            let _ = crate::services::login_flows::delete(&state, tenant.id(), id).await;
            no_store(
                axum::Json(json!({"stage": "denied", "redirect_to": redirect_to})).into_response(),
            )
        }
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
struct MfaBody {
    csrf: String,
    /// Authenticator code (six digits) or a recovery code.
    code: String,
    /// Enrolment only: a name for the authenticator.
    label: Option<String>,
    #[serde(default)]
    remember_device: bool,
}

async fn mfa_totp_enroll(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    axum::Json(body): axum::Json<CancelBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    match flows::mfa_enrol_begin(&state, &tenant, &flow).await {
        Ok(enrolment) => no_store(axum::Json(enrolment).into_response()),
        Err(e) => e.into_response(),
    }
}

async fn mfa_totp_confirm(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<MfaBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    let ip = client_ip(&state, &headers, Some(peer));
    let outcome = flows::mfa_enrol_confirm(
        &state,
        &tenant,
        flow,
        &body.code,
        body.label.as_deref(),
        body.remember_device,
        ip,
    )
    .await;
    respond_mfa(&state, &tenant, outcome, INVALID_CODE).await
}

/// The browser's answer to a passkey assertion challenge.
#[derive(Deserialize)]
struct PasskeyAssertionBody {
    csrf: String,
    credential: PublicKeyCredential,
    #[serde(default)]
    remember_device: bool,
}

/// The browser's answer to a passkey creation challenge.
#[derive(Deserialize)]
struct PasskeyRegistrationBody {
    csrf: String,
    credential: RegisterPublicKeyCredential,
    /// A name for the passkey.
    label: Option<String>,
    #[serde(default)]
    remember_device: bool,
}

async fn mfa_passkey_register(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    axum::Json(body): axum::Json<CancelBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    match flows::mfa_passkey_register_begin(&state, &tenant, &flow).await {
        Ok(options) => no_store(axum::Json(options).into_response()),
        Err(e) => e.into_response(),
    }
}

async fn mfa_passkey_register_finish(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<PasskeyRegistrationBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    let ip = client_ip(&state, &headers, Some(peer));
    let outcome = flows::mfa_passkey_register_finish(
        &state,
        &tenant,
        flow,
        &body.credential,
        body.label.as_deref(),
        body.remember_device,
        ip,
    )
    .await;
    respond_mfa(&state, &tenant, outcome, INVALID_PASSKEY).await
}

async fn mfa_passkey_start(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    axum::Json(body): axum::Json<CancelBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    match flows::mfa_passkey_begin(&state, &tenant, &flow).await {
        Ok(options) => no_store(axum::Json(options).into_response()),
        Err(e) => e.into_response(),
    }
}

async fn mfa_passkey_finish(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<PasskeyAssertionBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    let ip = client_ip(&state, &headers, Some(peer));
    let outcome = flows::mfa_passkey_finish(
        &state,
        &tenant,
        flow,
        &body.credential,
        body.remember_device,
        ip,
    )
    .await;
    respond_mfa(&state, &tenant, outcome, INVALID_PASSKEY).await
}

async fn passkey_start(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    axum::Json(body): axum::Json<CancelBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    match flows::passkey_begin(&state, &tenant, &flow).await {
        Ok(options) => no_store(axum::Json(options).into_response()),
        Err(e) => e.into_response(),
    }
}

/// Passwordless sign-in with a discoverable passkey.
async fn passkey_finish(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<PasskeyAssertionBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    let ctx = flows::RequestContext {
        ip: client_ip(&state, &headers, Some(peer)),
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(512).collect()),
        existing_session: sessions::from_request(&state, &tenant.tenant, &headers)
            .await
            .ok()
            .flatten(),
        device_secret: trusted_devices::secret_from_headers(&state, &headers),
        remember_device: body.remember_device,
    };
    match flows::passkey_finish(&state, &tenant, flow, &body.credential, ctx).await {
        Ok(AuthStep::Authenticated { session, flow }) => {
            let mut res = respond_state(&state, &tenant, &flow).await;
            if let Ok(v) = HeaderValue::from_str(&sessions::set_cookie_header(
                &state,
                &tenant.tenant,
                &session,
            )) {
                res.headers_mut().append(header::SET_COOKIE, v);
            }
            res
        }
        Ok(AuthStep::Rejected { flow, .. }) => no_store(
            (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"error": INVALID_PASSKEY.0, "error_description": INVALID_PASSKEY.1, "attempts": flow.attempts})),
            )
                .into_response(),
        ),
        Err(e) => e.into_response(),
    }
}

async fn mfa_verify(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<MfaBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    let ip = client_ip(&state, &headers, Some(peer));
    let outcome =
        flows::mfa_verify_step(&state, &tenant, flow, &body.code, body.remember_device, ip).await;
    respond_mfa(&state, &tenant, outcome, INVALID_CODE).await
}

/// Error code and description of a refused second factor.
const INVALID_CODE: (&str, &str) = ("invalid_code", "the code is invalid or was already used");
const INVALID_PASSKEY: (&str, &str) = ("invalid_passkey", "the passkey could not be verified");

/// A passed factor answers with the flow state; right after an enrolment the
/// state is wrapped as `{recovery_codes, flow}` so the UI shows the codes
/// before moving on. A refused factor is `401` with `rejected` as the error
/// and the attempt count.
async fn respond_mfa(
    state: &AppState,
    tenant: &TenantCtx,
    outcome: Result<flows::MfaStep, AppError>,
    rejected: (&str, &str),
) -> Response {
    match outcome {
        Ok(flows::MfaStep::Passed {
            flow,
            recovery_codes: None,
        }) => respond_state(state, tenant, &flow).await,
        Ok(flows::MfaStep::Passed {
            flow,
            recovery_codes: Some(codes),
        }) => match public_body(state, tenant, &flow).await {
            Ok(body) => no_store(
                axum::Json(json!({"recovery_codes": codes, "flow": body})).into_response(),
            ),
            Err(e) => e.into_response(),
        },
        Ok(flows::MfaStep::Rejected { flow }) => no_store(
            (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"error": rejected.0, "error_description": rejected.1, "attempts": flow.attempts})),
            )
                .into_response(),
        ),
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
struct CancelBody {
    csrf: String,
}

async fn cancel(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    axum::Json(body): axum::Json<CancelBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    match flows::cancel(&state, &flow).await {
        Ok(redirect_to) => no_store(
            axum::Json(json!({"stage": "cancelled", "redirect_to": redirect_to})).into_response(),
        ),
        Err(e) => e.into_response(),
    }
}

/// Browser navigation that completes the authorization: the session cookie
/// must belong to the user who completed the flow.
async fn finish(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if flow.stage != FlowStage::Done {
        return AppError::BadRequest("flow is not complete".into()).into_response();
    }
    let mut session = match sessions::from_request(&state, &tenant.tenant, &headers).await {
        Ok(Some(s)) if Some(s.id) == flow.session_id && Some(s.user_id) == flow.user_id => s,
        Ok(_) => return AppError::Unauthorized.into_response(),
        Err(e) => return e.into_response(),
    };
    // "Remember this device" takes effect only once every step (including a
    // second factor) is done, so a password alone never earns trust.
    let mut device_cookie = None;
    if flow.remember_device && !flow.trusted_device {
        let ip = client_ip(&state, &headers, Some(peer));
        let ua: Option<String> = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(512).collect());
        let (device, secret) = match trusted_devices::trust(
            &state,
            &tenant.tenant,
            session.user_id,
            None,
            ua.as_deref(),
            ip.as_deref(),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
        if let Err(e) = sessions::bind_device(&state, &mut session, device.id).await {
            return e.into_response();
        }
        device_cookie = Some(trusted_devices::set_cookie_header(
            &state,
            &tenant.tenant,
            &secret,
            tenant.tenant.settings.session.remember_device_days.max(1),
        ));
    }
    let client = match crate::services::clients::find_by_client_id(
        &state,
        tenant.id(),
        &flow.request.client_public_id,
    )
    .await
    {
        Ok(Some(c)) if c.is_active() => c,
        Ok(_) => return AppError::NotFound("client").into_response(),
        Err(e) => return e.into_response(),
    };
    let _ = crate::services::login_flows::delete(&state, tenant.id(), id).await;
    match crate::oidc::authorize::issue_code(&state, &tenant, &client, &flow.request, &session)
        .await
    {
        Ok(mut res) => {
            if let Some(v) = device_cookie
                .as_deref()
                .and_then(|c| HeaderValue::from_str(c).ok())
            {
                res.headers_mut().append(header::SET_COOKIE, v);
            }
            res
        }
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
struct SendBody {
    csrf: String,
    identifier: String,
    #[serde(default)]
    captcha_token: Option<String>,
}

async fn send_passwordless(
    state: AppState,
    tenant: TenantCtx,
    id: Uuid,
    peer: std::net::SocketAddr,
    headers: HeaderMap,
    body: SendBody,
    method: crate::services::passwordless::Method,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    let ip = client_ip(&state, &headers, Some(peer));
    match flows::passwordless_send_step(
        &state,
        &tenant,
        &flow,
        method,
        &body.identifier,
        body.captcha_token.as_deref(),
        ip.as_deref(),
    )
    .await
    {
        // Same answer whether or not the identifier exists.
        Ok(()) => no_store(
            (
                StatusCode::ACCEPTED,
                axum::Json(json!({"sent": true, "method": method.as_str()})),
            )
                .into_response(),
        ),
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
struct VerifyBody {
    csrf: String,
    /// The one-time code, or the magic-link token.
    #[serde(alias = "token")]
    code: String,
    #[serde(default)]
    remember_device: bool,
}

async fn verify_passwordless(
    state: AppState,
    tenant: TenantCtx,
    id: Uuid,
    peer: std::net::SocketAddr,
    headers: HeaderMap,
    body: VerifyBody,
    method: crate::services::passwordless::Method,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    let ctx = flows::RequestContext {
        ip: client_ip(&state, &headers, Some(peer)),
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(512).collect()),
        existing_session: sessions::from_request(&state, &tenant.tenant, &headers)
            .await
            .ok()
            .flatten(),
        device_secret: trusted_devices::secret_from_headers(&state, &headers),
        remember_device: body.remember_device,
    };
    match flows::passwordless_verify_step(&state, &tenant, flow, method, &body.code, ctx).await {
        Ok(AuthStep::Authenticated { session, flow }) => {
            let mut res = respond_state(&state, &tenant, &flow).await;
            if let Ok(v) = HeaderValue::from_str(&sessions::set_cookie_header(&state, &tenant.tenant, &session)) {
                res.headers_mut().append(header::SET_COOKIE, v);
            }
            res
        }
        Ok(AuthStep::Rejected { flow, .. }) => no_store(
            (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"error": "invalid_code", "error_description": "the code or link is invalid or expired", "attempts": flow.attempts})),
            )
                .into_response(),
        ),
        Err(e) => e.into_response(),
    }
}

macro_rules! passwordless_routes {
    ($send:ident, $verify:ident, $method:expr) => {
        async fn $send(
            State(state): State<AppState>,
            tenant: TenantCtx,
            Path((_, id)): Path<(String, Uuid)>,
            ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
            headers: HeaderMap,
            axum::Json(body): axum::Json<SendBody>,
        ) -> Response {
            send_passwordless(state, tenant, id, peer, headers, body, $method).await
        }

        async fn $verify(
            State(state): State<AppState>,
            tenant: TenantCtx,
            Path((_, id)): Path<(String, Uuid)>,
            ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
            headers: HeaderMap,
            axum::Json(body): axum::Json<VerifyBody>,
        ) -> Response {
            verify_passwordless(state, tenant, id, peer, headers, body, $method).await
        }
    };
}

passwordless_routes!(
    send_magic_link,
    verify_magic_link,
    crate::services::passwordless::Method::MagicLink
);
passwordless_routes!(
    send_email_otp,
    verify_email_otp,
    crate::services::passwordless::Method::EmailOtp
);
passwordless_routes!(
    send_sms_otp,
    verify_sms_otp,
    crate::services::passwordless::Method::SmsOtp
);

#[derive(Deserialize)]
struct RegisterBody {
    csrf: String,
    #[serde(flatten)]
    input: crate::services::registration::RegistrationInput,
    #[serde(default)]
    captcha_token: Option<String>,
}

async fn register(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<RegisterBody>,
) -> Response {
    let flow = match flows::load(&state, tenant.id(), id).await {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = flows::check_csrf(&flow, &body.csrf) {
        return e.into_response();
    }
    let ctx = flows::RequestContext {
        ip: client_ip(&state, &headers, Some(peer)),
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(512).collect()),
        ..Default::default()
    };
    match flows::register_step(
        &state,
        &tenant,
        flow,
        body.input,
        body.captcha_token.as_deref(),
        ctx,
    )
    .await
    {
        Ok(AuthStep::Authenticated { session, flow }) => {
            let mut res = respond_state(&state, &tenant, &flow).await;
            if let Ok(v) = HeaderValue::from_str(&sessions::set_cookie_header(
                &state,
                &tenant.tenant,
                &session,
            )) {
                res.headers_mut().append(header::SET_COOKIE, v);
            }
            res
        }
        // Waiting for the verification link.
        Ok(AuthStep::Rejected { flow, .. }) => respond_state(&state, &tenant, &flow).await,
        Err(e) => e.into_response(),
    }
}
