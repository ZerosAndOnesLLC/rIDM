//! The browser side of impersonation (`services::impersonation`).
//!
//! * `GET /t/{slug}/impersonate?ticket=` opens the session a ticket from the
//!   admin API stands for, sets the tenant's session cookie and sends the
//!   browser to the account console, which signs in through it.
//! * `POST /t/{slug}/impersonation/end` ends the impersonated session the
//!   browser holds, puts back the browser's own session when it had one, and
//!   returns to the admin console. The account console's banner posts here.

use std::net::SocketAddr;

use axum::Router;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use crate::error::AppError;
use crate::middleware::{TenantCtx, client_ip};
use crate::services::{impersonation, sessions, tenants};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/t/{slug}/impersonate", get(start))
        .route("/t/{slug}/impersonation/end", post(end))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct StartQuery {
    ticket: String,
}

fn redirect(url: &str, cookie: Option<String>) -> Response {
    let mut res = Redirect::to(url).into_response();
    let headers = res.headers_mut();
    crate::middleware::security_headers::set_no_store(headers);
    // The ticket is in this page's URL; the next page must not see it.
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if let Some(v) = cookie.and_then(|c| HeaderValue::from_str(&c).ok()) {
        headers.insert(header::SET_COOKIE, v);
    }
    res
}

fn error_page(state: &AppState, tenant: &TenantCtx, err: &AppError) -> Response {
    let description = err.to_string();
    let url = state.ui_page(
        &tenant.tenant,
        "error",
        &[
            ("tenant", tenant.slug()),
            ("error", "impersonation_failed"),
            ("error_description", &description),
        ],
    );
    redirect(&url, None)
}

async fn start(
    State(state): State<AppState>,
    tenant: TenantCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<StartQuery>,
) -> Response {
    let ip = client_ip(&state, &headers, Some(peer));
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let own = match sessions::from_request(&state, &tenant.tenant, &headers).await {
        Ok(s) => s,
        Err(e) => return error_page(&state, &tenant, &e),
    };
    match impersonation::redeem(
        &state,
        &tenant.tenant,
        &q.ticket,
        own.as_ref(),
        ip,
        user_agent,
    )
    .await
    {
        Ok(session) => {
            let console = state.ui_page(
                &tenant.tenant,
                "account",
                &[("tenant", tenant.slug()), ("impersonate", "1")],
            );
            let cookie = sessions::set_cookie_header(&state, &tenant.tenant, &session);
            redirect(&console, Some(cookie))
        }
        Err(e) => error_page(&state, &tenant, &e),
    }
}

async fn end(State(state): State<AppState>, tenant: TenantCtx, headers: HeaderMap) -> Response {
    let session = match sessions::from_request(&state, &tenant.tenant, &headers).await {
        Ok(s) => s,
        Err(e) => return error_page(&state, &tenant, &e),
    };
    let Some(session) = session.filter(|s| s.impersonator.is_some()) else {
        // Nothing to end (it expired, or was ended from another tab).
        let account = state.ui_page(&tenant.tenant, "account", &[("tenant", tenant.slug())]);
        return redirect(&account, None);
    };
    let admin_tenant = session.impersonator.as_ref().map(|i| i.tenant_id);
    let restored = match impersonation::end(&state, &tenant.tenant, &session).await {
        Ok(r) => r,
        Err(e) => return error_page(&state, &tenant, &e),
    };
    let cookie = match &restored {
        Some(own) => sessions::set_cookie_header(&state, &tenant.tenant, own),
        None => sessions::clear_cookie_header(&state, &tenant.tenant),
    };
    // Back to the console the administrator came from.
    let home = match admin_tenant {
        Some(id) => tenants::get_cached(&state, id).await.ok().flatten(),
        None => None,
    };
    let url = match home {
        Some(t) => state.ui_page(&t, "console", &[]),
        None => state.ui_page(&tenant.tenant, "console", &[]),
    };
    redirect(&url, Some(cookie))
}
