//! Brokered sign-in: `/t/{slug}/broker/{alias}/start` sends the browser to
//! the upstream provider; `/t/{slug}/broker/{alias}/callback` (GET, or POST
//! for providers that post the response) receives it back and continues the
//! login flow, or finishes linking an identity from the account console.

use axum::Router;
use axum::extract::{ConnectInfo, Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::TenantCtx;
use crate::middleware::client_ip;
use crate::models::Tenant;
use crate::services::broker::{self, BrokerError, CallbackParams, Mode, Outcome};
use crate::services::{flows, identity_providers, sessions, trusted_devices};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/t/{slug}/broker/{alias}/start", get(start))
        .route(
            "/t/{slug}/broker/{alias}/callback",
            get(callback_get).post(callback_post),
        )
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct StartQuery {
    /// The login flow to sign in to.
    flow: Option<Uuid>,
    /// A link ticket from the account API.
    ticket: Option<String>,
}

fn no_store(mut res: Response) -> Response {
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn redirect(url: &str) -> Response {
    no_store(Redirect::to(url).into_response())
}

async fn start(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, alias)): Path<(String, String)>,
    Query(q): Query<StartQuery>,
) -> Response {
    match start_inner(&state, &tenant, &alias, q).await {
        Ok(url) => redirect(&url),
        Err(e) => e.into_response(),
    }
}

async fn start_inner(
    state: &AppState,
    tenant: &TenantCtx,
    alias: &str,
    q: StartQuery,
) -> AppResult<String> {
    let idp = identity_providers::get(state, tenant.id(), alias).await?;
    if !idp.enabled {
        return Err(AppError::NotFound("identity provider"));
    }
    let mode = match (q.flow, q.ticket) {
        (Some(flow_id), _) => Mode::Flow { flow_id },
        (None, Some(ticket)) => {
            broker::redeem_link_ticket(state, tenant.id(), idp.id, &ticket).await?
        }
        (None, None) => {
            return Err(AppError::BadRequest(
                "a flow or a link ticket is required".into(),
            ));
        }
    };
    broker::start(state, tenant, &idp, mode).await
}

async fn callback_get(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, alias)): Path<(String, String)>,
    Query(params): Query<CallbackParams>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Response {
    finish(state, tenant, alias, params, peer, headers).await
}

async fn callback_post(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, alias)): Path<(String, String)>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Form(params): Form<CallbackParams>,
) -> Response {
    finish(state, tenant, alias, params, peer, headers).await
}

/// The account console page a link returns to: a path on the UI, never a
/// foreign origin.
fn return_page(
    state: &AppState,
    tenant: &Tenant,
    return_to: Option<&str>,
    error: Option<&str>,
) -> String {
    let path = return_to
        .filter(|p| p.starts_with('/') && !p.starts_with("//"))
        .unwrap_or("/account/security/");
    let (page, existing_query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };
    let mut params: Vec<(&str, &str)> = vec![];
    if let Some(q) = existing_query {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                params.push((k, v));
            }
        }
    }
    let code;
    if let Some(e) = error {
        code = e.to_string();
        params.push(("link_error", &code));
    } else {
        params.push(("linked", "1"));
    }
    state.ui_page(tenant, page, &params)
}

async fn finish(
    state: AppState,
    tenant: TenantCtx,
    alias: String,
    params: CallbackParams,
    peer: std::net::SocketAddr,
    headers: HeaderMap,
) -> Response {
    let idp = match identity_providers::get(&state, tenant.id(), &alias).await {
        Ok(i) => i,
        Err(e) => return e.into_response(),
    };
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
        device_secret: trusted_devices::secret_from_headers(&state, &tenant.tenant, &headers),
        remember_device: false,
    };
    match broker::callback(&state, &tenant, &idp, params, ctx).await {
        Ok(Outcome::Authenticated { session, flow }) => {
            let url = state.ui_page(
                &tenant.tenant,
                broker::page_for(flow.stage),
                &[("tenant", tenant.slug()), ("flow", &flow.id.to_string())],
            );
            let mut res = redirect(&url);
            if let Ok(v) = HeaderValue::from_str(&sessions::set_cookie_header(
                &state,
                &tenant.tenant,
                &session,
            )) {
                res.headers_mut().append(header::SET_COOKIE, v);
            }
            res
        }
        Ok(Outcome::Linked { return_to }) => redirect(&return_page(
            &state,
            &tenant.tenant,
            return_to.as_deref(),
            None,
        )),
        Ok(Outcome::Failed {
            flow_id: Some(flow_id),
            error,
            ..
        }) => {
            let url = state.ui_page(
                &tenant.tenant,
                "login",
                &[
                    ("tenant", tenant.slug()),
                    ("flow", &flow_id.to_string()),
                    ("broker_error", error.code()),
                    ("provider", &idp.alias),
                ],
            );
            redirect(&url)
        }
        Ok(Outcome::Failed {
            flow_id: None,
            return_to,
            error: BrokerError::InvalidState,
        }) if return_to.is_none() => {
            // Nothing to return to: an unknown or replayed state.
            no_store(
                (
                    StatusCode::BAD_REQUEST,
                    axum::Json(serde_json::json!({
                        "error": "invalid_state",
                        "error_description": "the sign-in was not started here, already finished or has expired; start again"
                    })),
                )
                    .into_response(),
            )
        }
        Ok(Outcome::Failed {
            flow_id: None,
            return_to,
            error,
        }) => redirect(&return_page(
            &state,
            &tenant.tenant,
            return_to.as_deref(),
            Some(error.code()),
        )),
        Err(e) => e.into_response(),
    }
}
