//! rIDM as the service provider of an upstream SAML identity provider
//! (`services::saml_sp`); the sign-in starts at `/broker/{alias}/start`
//! like any provider's.
//!
//! * `GET /t/{slug}/broker/{alias}/saml/metadata` — rIDM's SP metadata for
//!   that IdP (its URL is also the SP entity ID);
//! * `POST /t/{slug}/broker/{alias}/saml/acs` — the assertion consumer
//!   service; an accepted response continues at `GET …/acs?continue=`,
//!   same-site, so the session cookie is sent;
//! * `GET|POST /t/{slug}/broker/{alias}/saml/slo` — the IdP's
//!   `LogoutRequest`s and its answers to rIDM's;
//!   `GET …/slo/out/{id}` sends rIDM's `LogoutRequest` at the end of a
//!   sign-out that started here, `GET …/slo/done/{id}` answers the IdP's
//!   once the downstream SPs had their turn.

use std::net::SocketAddr;

use axum::Router;
use axum::extract::{ConnectInfo, Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use uuid::Uuid;

use crate::middleware::TenantCtx;
use crate::models::{IdentityProvider, IdpKind};
use crate::oidc::authorize::RawParams;
use crate::routes::broker::{redirect, render, request_context};
use crate::routes::saml::{bad, post_message};
use crate::saml::binding;
use crate::services::broker::Outcome;
use crate::services::saml_sp::{self, AcsStep, Resumed};
use crate::services::{identity_providers, sessions};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/t/{slug}/broker/{alias}/saml/metadata", get(metadata))
        .route(
            "/t/{slug}/broker/{alias}/saml/acs",
            get(acs_continue).post(acs),
        )
        .route(
            "/t/{slug}/broker/{alias}/saml/slo",
            get(slo_get).post(slo_post),
        )
        .route("/t/{slug}/broker/{alias}/saml/slo/out/{id}", get(slo_out))
        .route("/t/{slug}/broker/{alias}/saml/slo/done/{id}", get(slo_done))
}

/// The provider, if it is a SAML one.
async fn saml_idp(
    state: &AppState,
    tenant: &TenantCtx,
    alias: &str,
) -> Result<IdentityProvider, Box<Response>> {
    match identity_providers::get(state, tenant.id(), alias).await {
        Ok(i) if i.kind == IdpKind::Saml => Ok(i),
        Ok(_) => Err(Box::new(
            crate::error::AppError::NotFound("SAML identity provider").into_response(),
        )),
        Err(e) => Err(Box::new(e.into_response())),
    }
}

async fn metadata(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, alias)): Path<(String, String)>,
) -> Response {
    let idp = match saml_idp(&state, &tenant, &alias).await {
        Ok(i) => i,
        Err(res) => return *res,
    };
    match saml_sp::metadata(&state, &tenant.tenant, &idp).await {
        Ok(xml) => (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/samlmetadata+xml"),
                ),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=300"),
                ),
                (
                    header::CONTENT_DISPOSITION,
                    HeaderValue::from_static("inline; filename=\"sp-metadata.xml\""),
                ),
            ],
            xml,
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

async fn acs(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, alias)): Path<(String, String)>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let idp = match saml_idp(&state, &tenant, &alias).await {
        Ok(i) => i,
        Err(res) => return *res,
    };
    let received = match post_message(&headers, &body) {
        Ok(r) => r,
        Err(res) => return *res,
    };
    match saml_sp::acs(&state, &tenant, &idp, &received).await {
        // 303: the browser follows with a GET, which carries the cookies
        // the cross-site POST could not.
        Ok(AcsStep::Continue(url)) => redirect(&url),
        Ok(AcsStep::Failed {
            flow_id,
            return_to,
            error,
        }) => render(
            &state,
            &tenant,
            &idp.alias,
            Outcome::Failed {
                flow_id,
                return_to,
                error,
            },
        ),
        Err(e) => e.into_response(),
    }
}

async fn acs_continue(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, alias)): Path<(String, String)>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let idp = match saml_idp(&state, &tenant, &alias).await {
        Ok(i) => i,
        Err(res) => return *res,
    };
    let params = RawParams::parse(raw.as_deref().unwrap_or_default());
    let Some(id) = params
        .one("continue")
        .ok()
        .flatten()
        .and_then(|v| Uuid::parse_str(v).ok())
    else {
        return bad("the assertion consumer service takes an HTTP-POST SAMLResponse");
    };
    let ctx = request_context(&state, &tenant, &headers, peer).await;
    let browser = saml_sp::browser_binding(&state, &tenant.tenant, &headers);
    let mut res = match saml_sp::resume(&state, &tenant, &idp, id, browser.as_deref(), ctx).await {
        Ok(Resumed::Broker(outcome)) => render(&state, &tenant, &idp.alias, outcome),
        Ok(Resumed::Landed { session, to }) => {
            let mut res = redirect(&to);
            if let Ok(v) = HeaderValue::from_str(&sessions::set_cookie_header(
                &state,
                &tenant.tenant,
                &session,
            )) {
                res.headers_mut().append(header::SET_COOKIE, v);
            }
            res
        }
        Err(e) => return e.into_response(),
    };
    if browser.is_some()
        && let Ok(v) =
            HeaderValue::from_str(&saml_sp::clear_browser_binding(&state, &tenant.tenant))
    {
        res.headers_mut().append(header::SET_COOKIE, v);
    }
    res
}

async fn slo_get(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, alias)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
) -> Response {
    let idp = match saml_idp(&state, &tenant, &alias).await {
        Ok(i) => i,
        Err(res) => return *res,
    };
    match binding::from_redirect(raw.as_deref().unwrap_or_default()) {
        Ok(received) => saml_sp::slo(&state, &tenant, &idp, received).await,
        Err(e) => bad(&e.to_string()),
    }
}

async fn slo_post(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, alias)): Path<(String, String)>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let idp = match saml_idp(&state, &tenant, &alias).await {
        Ok(i) => i,
        Err(res) => return *res,
    };
    match post_message(&headers, &body) {
        Ok(received) => saml_sp::slo(&state, &tenant, &idp, received).await,
        Err(res) => *res,
    }
}

async fn slo_out(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, alias, id)): Path<(String, String, Uuid)>,
) -> Response {
    let idp = match saml_idp(&state, &tenant, &alias).await {
        Ok(i) => i,
        Err(res) => return *res,
    };
    saml_sp::send_logout(&state, &tenant, &idp, id).await
}

async fn slo_done(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, alias, id)): Path<(String, String, Uuid)>,
) -> Response {
    let idp = match saml_idp(&state, &tenant, &alias).await {
        Ok(i) => i,
        Err(res) => return *res,
    };
    saml_sp::answer_logout(&state, &tenant, &idp, id).await
}
