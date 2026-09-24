//! RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0):
//! `GET|POST /t/{slug}/end_session`, plus the UI confirmation step
//! `POST /t/{slug}/end_session/confirm`.
//!
//! With a valid `id_token_hint` that matches the browser session, logout is
//! immediate and the browser is sent to the validated
//! `post_logout_redirect_uri` (or the UI's logout page). Without it, the UI
//! asks the user first (protects against forced logout).

use axum::Router;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::AppError;
use crate::middleware::TenantCtx;
use crate::models::Client;
use crate::oidc::authorize::{RawParams, error_page};
use crate::services::clients;
use crate::services::logout::{self, LogoutFlow};
use crate::services::sessions;
use crate::services::tokens::{self, VerifyOptions};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/t/{slug}/end_session",
            get(end_session_get).post(end_session_post),
        )
        .route("/t/{slug}/end_session/confirm", post(confirm))
        .route("/t/{slug}/end_session/{flow}", get(logout_flow))
}

/// What the UI's logout page needs: whom the user is signing out of, and the
/// CSRF token the confirmation must echo. The flow stays until confirmed.
async fn logout_flow(
    State(state): State<AppState>,
    tenant: TenantCtx,
    headers: HeaderMap,
    Path((_, id)): Path<(String, Uuid)>,
) -> Response {
    let flow = match logout::peek_flow(&state, tenant.id(), id).await {
        Ok(Some(f)) => f,
        Ok(None) => return AppError::NotFound("logout flow").into_response(),
        Err(e) => return e.into_response(),
    };
    let client = match &flow.client_id {
        Some(cid) => match clients::find_by_client_id(&state, tenant.id(), cid).await {
            Ok(c) => c.map(|c| {
                serde_json::json!({"client_id": c.client_id, "name": c.name, "logo_uri": c.logo_uri})
            }),
            Err(e) => return e.into_response(),
        },
        None => None,
    };
    let session = match sessions::from_request(&state, &tenant.tenant, &headers).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let locale =
        crate::services::locale::negotiate(&flow.ui_locales, None, &tenant.tenant.settings.locale);
    let mut res = axum::Json(serde_json::json!({
        "id": flow.id,
        "csrf": flow.csrf,
        "client": client,
        "signed_in": session.is_some(),
        "returns_to_client": flow.post_logout_redirect_uri.is_some(),
        "locale": locale,
        "dir": crate::services::locale::direction(&locale),
    }))
    .into_response();
    crate::middleware::security_headers::set_no_store(res.headers_mut());
    res
}

async fn end_session_get(
    State(state): State<AppState>,
    tenant: TenantCtx,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let mut params = RawParams::parse(raw.as_deref().unwrap_or_default());
    // The browser coming back for a form it posted cross-site (see `park`).
    if let Some(id) = crate::oidc::park::parked_id(&params.0) {
        let form = match id {
            Some(id) => crate::oidc::park::unpark(&state, tenant.id(), "end_session", id).await,
            None => Ok(None),
        };
        params = match form {
            Ok(Some(form)) => RawParams::parse(&form),
            Ok(None) => {
                return crate::oidc::authorize::error_page(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "This sign-out request has expired or was already used; sign out again from the application.",
                );
            }
            Err(e) => return e.into_response(),
        };
    }
    handle(&state, &tenant, &headers, params).await
}

/// A form another site posted arrives without the session cookie (it is
/// `SameSite=Lax`), so the logout could not tell whether this browser is
/// signed in: park it and come back as a GET, which carries it.
async fn end_session_post(
    State(state): State<AppState>,
    tenant: TenantCtx,
    body: String,
) -> Response {
    match crate::oidc::park::park(&state, tenant.id(), "end_session", &body).await {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

async fn handle(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    params: RawParams,
) -> Response {
    match decide(state, tenant, headers, &params).await {
        Ok(r) => r,
        Err(Bad::Page(d)) => error_page(StatusCode::BAD_REQUEST, "invalid_request", &d),
        Err(Bad::Internal(e)) => e.into_response(),
    }
}

enum Bad {
    Page(String),
    Internal(AppError),
}

impl From<AppError> for Bad {
    fn from(e: AppError) -> Self {
        Bad::Internal(e)
    }
}

async fn decide(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    params: &RawParams,
) -> Result<Response, Bad> {
    let one = |n: &str| params.one(n).map_err(Bad::Page);
    let id_token_hint = one("id_token_hint")?;
    let client_id_param = one("client_id")?;
    let post_logout = one("post_logout_redirect_uri")?.map(str::to_string);
    let state_param = one("state")?.map(str::to_string);
    let ui_locales: Vec<String> = one("ui_locales")?
        .map(|v| {
            v.split(' ')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    // Identify the client from the hint and/or client_id.
    let mut hint_sid: Option<Uuid> = None;
    let mut hint_sub: Option<String> = None;
    let mut client: Option<std::sync::Arc<Client>> = None;
    if let Some(hint) = id_token_hint {
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
        .map_err(|_| Bad::Page("id_token_hint is not a valid ID token for this issuer".into()))?;
        let aud = claims["aud"].as_str().unwrap_or_default().to_string();
        if let Some(c) = client_id_param
            && c != aud
        {
            return Err(Bad::Page("client_id does not match id_token_hint".into()));
        }
        client = clients::find_by_client_id(state, tenant.id(), &aud).await?;
        hint_sid = claims["sid"].as_str().and_then(|s| Uuid::parse_str(s).ok());
        hint_sub = claims["sub"].as_str().map(str::to_string);
    } else if let Some(c) = client_id_param {
        client = clients::find_by_client_id(state, tenant.id(), c).await?;
    }
    if (id_token_hint.is_some() || client_id_param.is_some()) && client.is_none() {
        return Err(Bad::Page("unknown client".into()));
    }

    // post_logout_redirect_uri must be registered for the identified client.
    if let Some(uri) = &post_logout {
        match &client {
            Some(c) if c.post_logout_redirect_uris.iter().any(|r| r == uri) => {}
            Some(_) => {
                return Err(Bad::Page(
                    "post_logout_redirect_uri is not registered for this client".into(),
                ));
            }
            None => {
                return Err(Bad::Page(
                    "post_logout_redirect_uri requires id_token_hint or client_id".into(),
                ));
            }
        }
    }

    let session = sessions::from_request(state, &tenant.tenant, headers).await?;
    // Immediate logout when the hint provably refers to this browser's session.
    let hint_matches = match (&session, hint_sid, &hint_sub) {
        (Some(s), Some(sid), _) => s.id == sid,
        (Some(s), None, Some(sub)) => {
            // An id_token_hint names its client, resolved above.
            let c = client
                .as_ref()
                .ok_or_else(|| AppError::Internal("id_token_hint without its client".into()))?;
            let tc = tokens::TokenClient::from_client(c, &tenant.tenant, vec![]);
            crate::services::users::get(state, tenant.id(), s.user_id)
                .await
                .map(|u| tokens::subject_for(&tenant.tenant, &tc, &u) == *sub)
                .unwrap_or(false)
        }
        _ => false,
    };
    let no_session = session.is_none();

    if hint_matches || no_session {
        let mut outcome = logout::LogoutOutcome::default();
        if let Some(s) = &session {
            outcome = logout::end_session(state, &tenant.tenant, s.id).await?;
        }
        let target = final_target(
            state,
            tenant,
            post_logout.as_deref(),
            state_param.as_deref(),
        );
        // Downstream SAML SPs first, then the upstream IdP, then on.
        let target = crate::services::saml_sp::logout_upstream(
            state,
            &tenant.tenant,
            outcome.saml_upstream.take(),
            target,
        )
        .await?;
        let target = crate::services::saml_idp::logout_through(
            state,
            &tenant.tenant,
            std::mem::take(&mut outcome.saml_participants),
            target,
        )
        .await?;
        return Ok(finish(state, tenant, &target, &outcome));
    }

    // Otherwise ask the user through the UI.
    let flow = logout::create_flow(
        state,
        LogoutFlow {
            id: Uuid::now_v7(),
            tenant_id: tenant.id(),
            session_id: session.as_ref().map(|s| s.id),
            client_id: client.as_ref().map(|c| c.client_id.clone()),
            post_logout_redirect_uri: post_logout,
            state: state_param,
            ui_locales,
            csrf: String::new(),
        },
    )
    .await?;
    let url = state.ui_page(
        &tenant.tenant,
        "logout",
        &[("tenant", tenant.slug()), ("flow", &flow.id.to_string())],
    );
    let mut res = Redirect::to(&url).into_response();
    crate::middleware::security_headers::set_no_store(res.headers_mut());
    Ok(res)
}

/// Where a finished logout goes: the RP's registered URI (with `state`),
/// or the UI's signed-out page.
fn final_target(
    state: &AppState,
    tenant: &TenantCtx,
    post_logout: Option<&str>,
    state_param: Option<&str>,
) -> String {
    match post_logout {
        Some(uri) => {
            let mut u = url::Url::parse(uri).expect("validated uri");
            if let Some(s) = state_param {
                u.query_pairs_mut().append_pair("state", s);
            }
            u.to_string()
        }
        None => state.ui_page(
            &tenant.tenant,
            "logout",
            &[("tenant", tenant.slug()), ("done", "1")],
        ),
    }
}

/// Final response: clear the cookie and go to `target` (through the
/// session's SAML SPs when it had any).
fn finish(
    state: &AppState,
    tenant: &TenantCtx,
    target: &str,
    outcome: &logout::LogoutOutcome,
) -> Response {
    let target = target.to_string();
    let mut res = if outcome.frontchannel_logout_uris.is_empty() {
        Redirect::to(&target).into_response()
    } else {
        // Front-channel logout: render the RP iframes, then continue.
        let frames: String = outcome
            .frontchannel_logout_uris
            .iter()
            .map(|u| {
                format!(
                    "<iframe src=\"{}\" style=\"display:none\"></iframe>",
                    crate::oidc::authorize::html_escape(u)
                )
            })
            .collect();
        let html = format!(
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Signing out</title>\
             <meta http-equiv=\"refresh\" content=\"2;url={target}\"></head><body>{frames}\
             <p>Signing you out…</p><a href=\"{target}\">Continue</a></body></html>",
            target = crate::oidc::authorize::html_escape(&target)
        );
        // The page's whole purpose is to frame the relying parties, so it
        // carries its own policy naming exactly their origins; the API's
        // `default-src 'none'` would block every one of them.
        let mut origins: Vec<String> = outcome
            .frontchannel_logout_uris
            .iter()
            .filter_map(|u| url::Url::parse(u).ok())
            .map(|u| u.origin().ascii_serialization())
            .collect();
        origins.sort();
        origins.dedup();
        let csp = format!(
            "default-src 'none'; frame-src {}; style-src 'unsafe-inline'; \
             frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            origins.join(" ")
        );
        let mut res = (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            )],
            html,
        )
            .into_response();
        if let Ok(v) = HeaderValue::from_str(&csp) {
            res.headers_mut().insert(header::CONTENT_SECURITY_POLICY, v);
        }
        res
    };
    let h = res.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&sessions::clear_cookie_header(state, &tenant.tenant)) {
        h.append(header::SET_COOKIE, v);
    }
    crate::middleware::security_headers::set_no_store(h);
    res
}

#[derive(Debug, Deserialize)]
pub struct ConfirmBody {
    pub flow: Uuid,
    pub csrf: String,
    /// `false` cancels: the session stays and the user returns to the RP.
    #[serde(default = "default_true")]
    pub confirm: bool,
}

fn default_true() -> bool {
    true
}

/// Called by the UI's logout page after the user confirmed (or declined).
async fn confirm(
    State(state): State<AppState>,
    tenant: TenantCtx,
    headers: HeaderMap,
    axum::Json(body): axum::Json<ConfirmBody>,
) -> Response {
    let flow = match logout::take_flow(&state, tenant.id(), body.flow).await {
        Ok(Some(f)) => f,
        Ok(None) => return AppError::NotFound("logout flow").into_response(),
        Err(e) => return e.into_response(),
    };
    if !bool::from(subtle::ConstantTimeEq::ct_eq(
        flow.csrf.as_bytes(),
        body.csrf.as_bytes(),
    )) {
        return AppError::Forbidden("invalid csrf token".into()).into_response();
    }
    let session = match sessions::from_request(&state, &tenant.tenant, &headers).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if !body.confirm {
        let target = flow.post_logout_redirect_uri.clone().unwrap_or_else(|| {
            state.ui_page(
                &tenant.tenant,
                "logout",
                &[("tenant", tenant.slug()), ("cancelled", "1")],
            )
        });
        return axum::Json(serde_json::json!({"redirect_to": target, "logged_out": false}))
            .into_response();
    }
    let mut outcome = logout::LogoutOutcome::default();
    if let Some(s) = session {
        match logout::end_session(&state, &tenant.tenant, s.id).await {
            Ok(o) => outcome = o,
            Err(e) => return e.into_response(),
        }
    }
    let target = final_target(
        &state,
        &tenant,
        flow.post_logout_redirect_uri.as_deref(),
        flow.state.as_deref(),
    );
    // Downstream SAML SPs first, then the upstream IdP, then on.
    let target = match crate::services::saml_sp::logout_upstream(
        &state,
        &tenant.tenant,
        outcome.saml_upstream.take(),
        target,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let target = match crate::services::saml_idp::logout_through(
        &state,
        &tenant.tenant,
        std::mem::take(&mut outcome.saml_participants),
        target,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let mut res = axum::Json(serde_json::json!({
        "redirect_to": target,
        "logged_out": true,
        "frontchannel_logout_uris": outcome.frontchannel_logout_uris,
    }))
    .into_response();
    if let Ok(v) = HeaderValue::from_str(&sessions::clear_cookie_header(&state, &tenant.tenant)) {
        res.headers_mut().append(header::SET_COOKIE, v);
    }
    crate::middleware::security_headers::set_no_store(res.headers_mut());
    res
}
