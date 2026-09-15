//! Authorization endpoint (RFC 6749 §4.1, OIDC Core §3.1.2):
//! `GET|POST /t/{slug}/authorize`.
//!
//! Validation order follows the spec: client and redirect_uri are checked
//! first and any problem there is shown to the user (never redirected);
//! everything else is reported to the client via the redirect URI with the
//! `state` echoed and `iss` added (RFC 9207).
//!
//! Outcomes: an authorization code (existing SSO session, consent satisfied),
//! a redirect into the UI with a login flow (authentication or consent
//! needed), or an error.

use axum::Router;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use chrono::Utc;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde_json::Value;
use uuid::Uuid;

use crate::error::{AppError, OAuthError, OAuthErrorCode};
use crate::middleware::TenantCtx;
use crate::models::{Client, ClientStatus, grants};
use crate::oidc::{pkce, redirect_uri};
use crate::services::auth_codes::{self, AuthCode};
use crate::services::login_flows::{self, AuthRequest, FlowStage, LoginFlow, ResponseMode};
use crate::services::sessions::{self, SsoSession};
use crate::services::{clients, consents, scopes};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/t/{slug}/authorize",
        get(authorize_get).post(authorize_post),
    )
}

/// Raw parameters as sent (query for GET, form body for POST). Repeated
/// parameters are an error (RFC 6749 §3.1).
#[derive(Debug, Default)]
pub struct RawParams(pub Vec<(String, String)>);

impl RawParams {
    pub fn parse(raw: &str) -> Self {
        Self(
            url::form_urlencoded::parse(raw.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect(),
        )
    }

    /// Single value; `Err` when the parameter is repeated.
    pub fn one(&self, name: &str) -> Result<Option<&str>, String> {
        let mut it = self.0.iter().filter(|(k, _)| k == name);
        let first = it.next().map(|(_, v)| v.as_str());
        if it.next().is_some() {
            return Err(format!("parameter `{name}` must not be repeated"));
        }
        Ok(first.map(str::trim).filter(|v| !v.is_empty()))
    }

    /// All values of a repeatable parameter (`resource`).
    pub fn many(&self, name: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

async fn authorize_get(
    State(state): State<AppState>,
    tenant: TenantCtx,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let params = RawParams::parse(raw.as_deref().unwrap_or_default());
    handle(&state, &tenant, &headers, params).await
}

async fn authorize_post(
    State(state): State<AppState>,
    tenant: TenantCtx,
    headers: HeaderMap,
    body: String,
) -> Response {
    let is_form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"));
    if !is_form {
        return error_page(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_request",
            "POST requires application/x-www-form-urlencoded",
        );
    }
    let params = RawParams::parse(&body);
    handle(&state, &tenant, &headers, params).await
}

/// How an error must be delivered.
pub enum Failure {
    /// Client / redirect_uri problem: render to the user.
    Page(&'static str, String),
    /// Everything else: redirect to the client.
    Redirect(OAuthError),
    /// Infrastructure failure.
    Internal(AppError),
}

impl From<AppError> for Failure {
    fn from(e: AppError) -> Self {
        Failure::Internal(e)
    }
}

impl From<sqlx::Error> for Failure {
    fn from(e: sqlx::Error) -> Self {
        Failure::Internal(AppError::from_db(e))
    }
}

/// Validated request plus the client it belongs to.
pub struct Validated {
    pub client: std::sync::Arc<Client>,
    pub request: AuthRequest,
}

async fn handle(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    params: RawParams,
) -> Response {
    // Pushed request: `client_id` + `request_uri` only (RFC 9126 §4).
    if let Ok(Some(uri)) = params.one("request_uri")
        && uri.starts_with(crate::oidc::par::URN_PREFIX)
    {
        return match crate::oidc::par::take(state, tenant, &params, uri).await {
            Ok((client, request)) => {
                finish_decision(state, tenant, headers, Validated { client, request }).await
            }
            Err(Failure::Page(code, desc)) => error_page(StatusCode::BAD_REQUEST, code, &desc),
            Err(Failure::Internal(e)) => e.into_response(),
            Err(Failure::Redirect(e)) => error_page(
                StatusCode::BAD_REQUEST,
                e.error.as_str(),
                e.error_description.as_deref().unwrap_or_default(),
            ),
        };
    }

    // Phase 1: client + redirect_uri (+ request object merge). Errors are shown to the user.
    let (client, params) = match resolve_client_and_merge(state, tenant, &params).await {
        Ok(v) => v,
        Err(Failure::Page(code, desc)) => return error_page(StatusCode::BAD_REQUEST, code, &desc),
        Err(Failure::Internal(e)) => return e.into_response(),
        Err(Failure::Redirect(e)) => {
            return error_page(
                StatusCode::BAD_REQUEST,
                e.error.as_str(),
                e.error_description.as_deref().unwrap_or_default(),
            );
        }
    };
    let (redirect, response_mode, state_param) = match resolve_redirect(&client, &params) {
        Ok(v) => v,
        Err(Failure::Page(code, desc)) => return error_page(StatusCode::BAD_REQUEST, code, &desc),
        Err(Failure::Internal(e)) => return e.into_response(),
        Err(Failure::Redirect(_)) => unreachable!("redirect resolution never redirects"),
    };

    // Phase 2: everything else. Errors go back to the client.
    match validate(
        state,
        tenant,
        &client,
        &params,
        &redirect,
        response_mode,
        state_param.clone(),
    )
    .await
    {
        Ok(v) => finish_decision(state, tenant, headers, v).await,
        Err(Failure::Redirect(e)) => {
            error_redirect(
                state,
                tenant,
                &client,
                &redirect,
                response_mode,
                e.with_state(state_param),
            )
            .await
        }
        Err(Failure::Page(code, desc)) => error_page(StatusCode::BAD_REQUEST, code, &desc),
        Err(Failure::Internal(e)) => {
            tracing::error!(error = ?e, "authorize failed");
            error_redirect(
                state,
                tenant,
                &client,
                &redirect,
                response_mode,
                OAuthError::server_error().with_state(state_param),
            )
            .await
        }
    }
}

async fn finish_decision(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    v: Validated,
) -> Response {
    let client = v.client.clone();
    let redirect = v.request.redirect_uri.clone();
    let mode = v.request.response_mode;
    let state_param = v.request.state.clone();
    match decide(state, tenant, headers, v).await {
        Ok(r) => r,
        Err(Failure::Redirect(e)) => {
            error_redirect(
                state,
                tenant,
                &client,
                &redirect,
                mode,
                e.with_state(state_param),
            )
            .await
        }
        Err(Failure::Page(code, desc)) => error_page(StatusCode::BAD_REQUEST, code, &desc),
        Err(Failure::Internal(e)) => {
            tracing::error!(error = ?e, "authorize failed");
            error_redirect(
                state,
                tenant,
                &client,
                &redirect,
                mode,
                OAuthError::server_error().with_state(state_param),
            )
            .await
        }
    }
}

/// Look up the client and, if a `request` object is present, verify it and
/// merge its claims over the plain parameters (RFC 9101 §6.3: the request
/// object wins; `client_id`/`response_type` outside must match inside).
pub async fn resolve_client_and_merge(
    state: &AppState,
    tenant: &TenantCtx,
    params: &RawParams,
) -> Result<(std::sync::Arc<Client>, RawParams), Failure> {
    let page = |d: String| Failure::Page("invalid_request", d);
    let client_id = params
        .one("client_id")
        .map_err(page)?
        .ok_or_else(|| page("client_id is required".into()))?;
    let client = clients::find_by_client_id(state, tenant.id(), client_id)
        .await?
        .ok_or_else(|| Failure::Page("unauthorized_client", "unknown client".into()))?;
    if client.status != ClientStatus::Active {
        return Err(Failure::Page(
            "unauthorized_client",
            "client is disabled".into(),
        ));
    }
    let merged = match params.one("request").map_err(page)? {
        Some(jwt) => crate::oidc::jar::merge(state, tenant, &client, params, jwt).await?,
        None => RawParams(params.0.clone()),
    };
    Ok((client, merged))
}

/// Validate `redirect_uri`, settle the response mode and `state`.
pub fn resolve_redirect(
    client: &Client,
    params: &RawParams,
) -> Result<(String, ResponseMode, Option<String>), Failure> {
    let page = |d: String| Failure::Page("invalid_request", d);
    let redirect = params
        .one("redirect_uri")
        .map_err(page)?
        .ok_or_else(|| page("redirect_uri is required".into()))?;
    if !redirect_uri::matches(&client.redirect_uris, redirect, client.client_type) {
        return Err(Failure::Page(
            "invalid_request",
            "redirect_uri is not registered for this client".into(),
        ));
    }
    // response_mode determines how even errors are delivered, so it is
    // settled here; an invalid value falls back to the default.
    let response_mode = params
        .one("response_mode")
        .map_err(page)?
        .and_then(ResponseMode::parse)
        .unwrap_or(ResponseMode::Query);
    let state_param = params.one("state").map_err(page)?.map(str::to_string);
    if let Some(s) = &state_param
        && s.len() > 1024
    {
        return Err(page("state is too long".into()));
    }
    Ok((redirect.to_string(), response_mode, state_param))
}

fn invalid(desc: impl Into<String>) -> Failure {
    Failure::Redirect(OAuthError::invalid_request(desc))
}

pub async fn validate(
    state: &AppState,
    tenant: &TenantCtx,
    client: &Client,
    params: &RawParams,
    redirect: &str,
    response_mode: ResponseMode,
    state_param: Option<String>,
) -> Result<Validated, Failure> {
    let one = |name: &str| params.one(name).map_err(invalid);

    // Request objects (JAR) and PAR arrive in Phase 3.6.
    if one("request")?.is_some() {
        return Err(Failure::Redirect(OAuthError::code(
            OAuthErrorCode::RequestNotSupported,
        )));
    }
    if one("request_uri")?.is_some() {
        return Err(Failure::Redirect(OAuthError::code(
            OAuthErrorCode::RequestUriNotSupported,
        )));
    }
    if let Some(mode) = one("response_mode")?
        && ResponseMode::parse(mode).is_none()
    {
        return Err(invalid(format!("unsupported response_mode `{mode}`")));
    }

    match one("response_type")? {
        Some("code") => {}
        Some(_) => {
            return Err(Failure::Redirect(OAuthError::code(
                OAuthErrorCode::UnsupportedResponseType,
            )));
        }
        None => return Err(invalid("response_type is required")),
    }
    if !client.allows_grant(grants::AUTHORIZATION_CODE) {
        return Err(Failure::Redirect(OAuthError::new(
            OAuthErrorCode::UnauthorizedClient,
            "client may not use the authorization code grant",
        )));
    }
    if response_mode == ResponseMode::Fragment
        && client.client_type == crate::models::ClientType::Web
    {
        // Allowed by spec; nothing to do. Kept explicit for future policy hooks.
    }

    // scope
    let requested = scopes::parse_scope_param(one("scope")?.unwrap_or_default());
    if requested.is_empty() {
        return Err(Failure::Redirect(OAuthError::new(
            OAuthErrorCode::InvalidScope,
            "scope is required",
        )));
    }
    let (known, unknown) = scopes::resolve(state, tenant.id(), &requested).await?;
    if !unknown.is_empty() {
        return Err(Failure::Redirect(OAuthError::new(
            OAuthErrorCode::InvalidScope,
            format!("unknown scope(s): {}", unknown.join(" ")),
        )));
    }
    let disallowed: Vec<&str> = known
        .iter()
        .map(|s| s.name.as_str())
        .filter(|n| !client.allowed_scopes.iter().any(|a| a == n))
        .collect();
    if !disallowed.is_empty() {
        return Err(Failure::Redirect(OAuthError::new(
            OAuthErrorCode::InvalidScope,
            format!(
                "scope(s) not allowed for this client: {}",
                disallowed.join(" ")
            ),
        )));
    }
    let is_oidc = requested.iter().any(|s| s == "openid");

    // PKCE
    let code_challenge = one("code_challenge")?.map(str::to_string);
    let method = one("code_challenge_method")?;
    match (&code_challenge, method) {
        (Some(c), Some("S256")) => {
            if !pkce::is_valid_challenge(c) {
                return Err(invalid("code_challenge is malformed"));
            }
        }
        (Some(_), Some("plain")) => {
            return Err(invalid(
                "code_challenge_method plain is not allowed; use S256",
            ));
        }
        (Some(_), Some(other)) => {
            return Err(invalid(format!(
                "unsupported code_challenge_method `{other}`"
            )));
        }
        (Some(_), None) => {
            // RFC 7636 defaults to plain when the method is absent; we do not accept plain.
            return Err(invalid("code_challenge_method S256 is required"));
        }
        (None, Some(_)) => {
            return Err(invalid(
                "code_challenge is required with code_challenge_method",
            ));
        }
        (None, None) => {
            if client.require_pkce || client.is_public() {
                return Err(invalid("code_challenge is required (PKCE)"));
            }
        }
    }

    // OIDC parameters
    let nonce = one("nonce")?.map(str::to_string);
    if let Some(n) = &nonce
        && n.len() > 512
    {
        return Err(invalid("nonce is too long"));
    }
    let prompt: Vec<String> = one("prompt")?
        .map(|p| {
            p.split(' ')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    for p in &prompt {
        if !matches!(
            p.as_str(),
            "none" | "login" | "consent" | "select_account" | "create"
        ) {
            return Err(invalid(format!("unsupported prompt value `{p}`")));
        }
    }
    if prompt.iter().any(|p| p == "none") && prompt.len() > 1 {
        return Err(invalid("prompt=none cannot be combined with other values"));
    }
    let max_age = match one("max_age")? {
        Some(v) => Some(
            v.parse::<u64>()
                .map_err(|_| invalid("max_age must be a non-negative integer"))?,
        ),
        None => None,
    };
    let acr_values: Vec<String> = one("acr_values")?
        .map(|v| {
            v.split(' ')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let ui_locales: Vec<String> = one("ui_locales")?
        .map(|v| {
            v.split(' ')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let login_hint = one("login_hint")?.map(str::to_string);
    let claims = match one("claims")? {
        Some(raw) => {
            if !is_oidc {
                return Err(invalid("claims requires the openid scope"));
            }
            let v: Value =
                serde_json::from_str(raw).map_err(|_| invalid("claims must be a JSON object"))?;
            if !v.is_object() {
                return Err(invalid("claims must be a JSON object"));
            }
            for key in v.as_object().map(|o| o.keys()).into_iter().flatten() {
                if !matches!(key.as_str(), "userinfo" | "id_token") {
                    return Err(invalid(format!("claims: unknown member `{key}`")));
                }
            }
            Some(v)
        }
        None => None,
    };
    if !is_oidc && (nonce.is_some() || max_age.is_some() || !acr_values.is_empty()) {
        // Plain OAuth requests may carry these, but they only mean something with openid.
    }

    // Resource indicators (RFC 8707): must be registered resource servers.
    let mut audiences: Vec<String> = vec![];
    for r in params.many("resource") {
        let r = r.trim();
        if r.is_empty()
            || url::Url::parse(r)
                .map(|u| u.fragment().is_some())
                .unwrap_or(true)
        {
            return Err(Failure::Redirect(OAuthError::new(
                OAuthErrorCode::InvalidTarget,
                format!("invalid resource `{r}`"),
            )));
        }
        let mut tx = crate::db::tenant_tx(&state.db, tenant.id()).await?;
        let known =
            crate::repos::resource_servers::find_by_identifier(&mut *tx, tenant.id(), r).await?;
        tx.commit().await?;
        if known.is_none() {
            return Err(Failure::Redirect(OAuthError::new(
                OAuthErrorCode::InvalidTarget,
                format!("unknown resource `{r}`"),
            )));
        }
        if !client.allowed_audiences.is_empty() && !client.allowed_audiences.iter().any(|a| a == r)
        {
            return Err(Failure::Redirect(OAuthError::new(
                OAuthErrorCode::InvalidTarget,
                format!("resource `{r}` is not allowed for this client"),
            )));
        }
        if !audiences.iter().any(|a| a == r) {
            audiences.push(r.to_string());
        }
    }

    Ok(Validated {
        request: AuthRequest {
            client_id: client.id,
            client_public_id: client.client_id.clone(),
            redirect_uri: redirect.to_string(),
            response_mode,
            scopes: requested,
            audiences,
            state: state_param,
            nonce,
            code_challenge,
            prompt,
            max_age,
            acr_values,
            login_hint,
            ui_locales,
            claims,
            skip_consent: !client.require_consent,
        },
        client: std::sync::Arc::new(client.clone()),
    })
}

/// With a validated request, decide between issuing a code, starting a flow,
/// or reporting `login_required` / `consent_required` for `prompt=none`.
async fn decide(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    v: Validated,
) -> Result<Response, Failure> {
    let req = &v.request;
    let prompt_none = req.prompt.iter().any(|p| p == "none");
    let force_login = req
        .prompt
        .iter()
        .any(|p| p == "login" || p == "select_account");
    let force_consent = req.prompt.iter().any(|p| p == "consent");
    let create = req.prompt.iter().any(|p| p == "create");

    let session = sessions::from_request(state, &tenant.tenant, headers).await?;
    let now = Utc::now();
    // `max_age=0` means "re-authenticate now" (OIDC Core §3.1.2.1).
    let fresh_enough = |s: &SsoSession| match req.max_age {
        Some(0) => false,
        Some(max) => (now - s.auth_time).num_seconds().max(0) as u64 <= max,
        None => true,
    };
    let acr_ok = |s: &SsoSession| {
        req.acr_values.is_empty()
            || s.acr
                .as_deref()
                .is_some_and(|acr| req.acr_values.iter().any(|v| v == acr))
    };

    let needs_auth = create
        || force_login
        || session
            .as_ref()
            .is_none_or(|s| !fresh_enough(s) || !acr_ok(s));

    if needs_auth {
        if prompt_none {
            return Err(Failure::Redirect(OAuthError::code(
                OAuthErrorCode::LoginRequired,
            )));
        }
        let stage = if create {
            FlowStage::Register
        } else {
            FlowStage::Authenticate
        };
        let flow = login_flows::create(
            state,
            LoginFlow {
                id: Uuid::now_v7(),
                tenant_id: tenant.id(),
                request: req.clone(),
                stage,
                session_id: None,
                user_id: None,
                pending_scopes: vec![],
                require_auth_after: Some(now),
                csrf: String::new(),
                created_at: now,
                expires_at: now,
            },
        )
        .await?;
        let page = if create { "register" } else { "login" };
        return Ok(redirect_to_ui(state, tenant, page, flow.id));
    }
    let session = session.expect("session present when no auth needed");

    // Consent.
    let pending = if req.skip_consent && !force_consent {
        vec![]
    } else if force_consent {
        req.scopes.clone()
    } else {
        consents::missing_scopes(
            state,
            tenant.id(),
            session.user_id,
            v.client.id,
            &req.scopes,
        )
        .await?
    };
    if !pending.is_empty() {
        if prompt_none {
            return Err(Failure::Redirect(OAuthError::code(
                OAuthErrorCode::ConsentRequired,
            )));
        }
        let flow = login_flows::create(
            state,
            LoginFlow {
                id: Uuid::now_v7(),
                tenant_id: tenant.id(),
                request: req.clone(),
                stage: FlowStage::Consent,
                session_id: Some(session.id),
                user_id: Some(session.user_id),
                pending_scopes: pending,
                require_auth_after: None,
                csrf: String::new(),
                created_at: now,
                expires_at: now,
            },
        )
        .await?;
        return Ok(redirect_to_ui(state, tenant, "consent", flow.id));
    }

    Ok(issue_code(state, tenant, &v.client, req, &session).await?)
}

/// Mint the code and build the success response for the client.
pub async fn issue_code(
    state: &AppState,
    tenant: &TenantCtx,
    client: &Client,
    req: &AuthRequest,
    session: &SsoSession,
) -> Result<Response, AppError> {
    let code = auth_codes::issue(
        state,
        &AuthCode {
            tenant_id: tenant.id(),
            client_id: client.id,
            client_public_id: client.client_id.clone(),
            user_id: session.user_id,
            session_id: session.id,
            redirect_uri: req.redirect_uri.clone(),
            scopes: req.scopes.clone(),
            audiences: req.audiences.clone(),
            nonce: req.nonce.clone(),
            code_challenge: req.code_challenge.clone(),
            auth_time: session.auth_time,
            amr: session.amr.clone(),
            acr: session.acr.clone(),
            claims: req.claims.clone(),
            issued_at: Utc::now(),
        },
    )
    .await?;
    sessions::add_client(state, session, &client.client_id).await?;
    state.events.publish(Event::new(
        Some(tenant.id()),
        Actor::User {
            id: session.user_id,
        },
        EventKind::AuthorizationGranted {
            user_id: session.user_id,
            client_id: client.id,
            scopes: req.scopes.clone(),
        },
    ));
    let mut params: Vec<(&str, String)> =
        vec![("code", code.to_string()), ("iss", tenant.issuer(state))];
    if let Some(s) = &req.state {
        params.push(("state", s.clone()));
    }
    deliver_to_client(
        state,
        tenant,
        client,
        &req.redirect_uri,
        req.response_mode,
        params,
    )
    .await
}

/// Deliver success or error parameters, wrapping them in a JARM JWT when the
/// response mode asks for it (JARM §4.1).
pub async fn deliver_to_client(
    state: &AppState,
    tenant: &TenantCtx,
    client: &Client,
    redirect_uri: &str,
    mode: ResponseMode,
    params: Vec<(&str, String)>,
) -> Result<Response, AppError> {
    if !mode.is_jarm() {
        return Ok(deliver(redirect_uri, mode, &params));
    }
    let key =
        crate::services::keys::ensure_active(state, tenant.id(), &tenant.tenant.settings.keys)
            .await?;
    let mut claims = serde_json::Map::new();
    claims.insert("iss".into(), serde_json::json!(tenant.issuer(state)));
    claims.insert("aud".into(), serde_json::json!(client.client_id));
    claims.insert(
        "exp".into(),
        serde_json::json!(Utc::now().timestamp() + 600),
    );
    for (k, v) in &params {
        if *k != "iss" {
            claims.insert((*k).to_string(), serde_json::json!(v));
        }
    }
    let jwt = crate::services::tokens::sign(state, &key, "JWT", &claims).await?;
    Ok(deliver(redirect_uri, mode.base(), &[("response", jwt)]))
}

fn redirect_to_ui(state: &AppState, tenant: &TenantCtx, page: &str, flow_id: Uuid) -> Response {
    let url = state.config.ui_page(
        page,
        &[("tenant", tenant.slug()), ("flow", &flow_id.to_string())],
    );
    let mut res = Redirect::to(&url).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// Deliver parameters to the redirect URI in the requested response mode.
pub fn deliver(redirect_uri: &str, mode: ResponseMode, params: &[(&str, String)]) -> Response {
    let mut res = match mode.base() {
        ResponseMode::Query => {
            let mut u = url::Url::parse(redirect_uri).expect("validated redirect uri");
            {
                let mut q = u.query_pairs_mut();
                for (k, v) in params {
                    q.append_pair(k, v);
                }
            }
            Redirect::to(u.as_str()).into_response()
        }
        ResponseMode::Fragment => {
            let mut u = url::Url::parse(redirect_uri).expect("validated redirect uri");
            let frag: String = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(params.iter().map(|(k, v)| (*k, v.as_str())))
                .finish();
            u.set_fragment(Some(&frag));
            Redirect::to(u.as_str()).into_response()
        }
        ResponseMode::FormPost
        | ResponseMode::QueryJwt
        | ResponseMode::FragmentJwt
        | ResponseMode::FormPostJwt => {
            let inputs: String = params
                .iter()
                .map(|(k, v)| {
                    format!(
                        "<input type=\"hidden\" name=\"{}\" value=\"{}\"/>",
                        html_escape(k),
                        html_escape(v)
                    )
                })
                .collect();
            let html = format!(
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Continue</title></head>\
                 <body onload=\"document.forms[0].submit()\">\
                 <form method=\"post\" action=\"{}\">{inputs}<noscript><button type=\"submit\">Continue</button></noscript></form>\
                 </body></html>",
                html_escape(redirect_uri)
            );
            (
                StatusCode::OK,
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("text/html; charset=utf-8"),
                    ),
                    (
                        header::CONTENT_SECURITY_POLICY,
                        HeaderValue::from_static(
                            "default-src 'none'; script-src 'unsafe-inline'; form-action *",
                        ),
                    ),
                ],
                html,
            )
                .into_response()
        }
    };
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    res
}

async fn error_redirect(
    state: &AppState,
    tenant: &TenantCtx,
    client: &Client,
    redirect_uri: &str,
    mode: ResponseMode,
    err: OAuthError,
) -> Response {
    let mut params: Vec<(&str, String)> = vec![("error", err.error.as_str().to_string())];
    if let Some(d) = &err.error_description {
        params.push(("error_description", d.clone()));
    }
    if let Some(s) = &err.state {
        params.push(("state", s.clone()));
    }
    params.push(("iss", tenant.issuer(state)));
    match deliver_to_client(state, tenant, client, redirect_uri, mode, params).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

/// Error shown to the end user when the client or redirect URI is untrusted.
pub fn error_page(status: StatusCode, code: &str, description: &str) -> Response {
    let html = format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Authorization error</title>\
         <style>body{{font-family:system-ui,sans-serif;margin:4rem auto;max-width:36rem;padding:0 1rem}}code{{color:#b00}}</style>\
         </head><body><h1>Authorization request rejected</h1><p><code>{}</code></p><p>{}</p>\
         <p>Contact the application's administrator; this request cannot be completed.</p></body></html>",
        html_escape(code),
        html_escape(description)
    );
    (
        status,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        html,
    )
        .into_response()
}

pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_parameters_are_rejected() {
        let p = RawParams::parse("client_id=a&client_id=b&scope=openid");
        assert!(p.one("client_id").is_err());
        assert_eq!(p.one("scope").unwrap(), Some("openid"));
        assert_eq!(p.one("missing").unwrap(), None);
        assert_eq!(p.one("empty").unwrap(), None);
    }

    #[test]
    fn escaping() {
        assert_eq!(
            html_escape("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }
}
