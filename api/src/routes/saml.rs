//! SAML 2.0 identity provider endpoints:
//!
//! * `GET /t/{slug}/saml/metadata` — the IdP's metadata;
//! * `GET|POST /t/{slug}/saml/sso` — `AuthnRequest`s by HTTP-Redirect or
//!   HTTP-POST (a POST is parked and resumed by a same-site GET with
//!   `?continue=`, since the session cookie is `SameSite=Lax`);
//! * `GET /t/{slug}/saml/init?sp=…` — IdP-initiated sign-in, for SPs that
//!   allow it;
//! * `GET|POST /t/{slug}/saml/slo` — `LogoutRequest`s from SPs and their
//!   `LogoutResponse`s; `GET /t/{slug}/saml/slo/chain/{id}` walks a logout
//!   that started at rIDM through the session's SPs;
//! * `GET /t/{slug}/saml/respond/{ticket}` — a one-time failure response
//!   (the user cancelled, refused consent, or was refused).

use std::net::SocketAddr;

use axum::Router;
use axum::extract::{ConnectInfo, Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use uuid::Uuid;

use crate::middleware::TenantCtx;
use crate::oidc::authorize::{RawParams, error_page};
use crate::saml::binding::{self, Kind};
use crate::services::{geoip, saml_idp};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/t/{slug}/saml/metadata", get(metadata))
        .route("/t/{slug}/saml/sso", get(sso_get).post(sso_post))
        .route("/t/{slug}/saml/init", get(init))
        .route("/t/{slug}/saml/slo", get(slo_get).post(slo_post))
        .route("/t/{slug}/saml/slo/chain/{id}", get(slo_chain))
        .route("/t/{slug}/saml/respond/{ticket}", get(respond))
}

fn bad(desc: &str) -> Response {
    error_page(StatusCode::BAD_REQUEST, "invalid_saml_request", desc)
}

async fn metadata(State(state): State<AppState>, tenant: TenantCtx) -> Response {
    match saml_idp::metadata(&state, &tenant.tenant).await {
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
                    HeaderValue::from_static("inline; filename=\"idp-metadata.xml\""),
                ),
            ],
            xml,
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

async fn sso_get(
    State(state): State<AppState>,
    tenant: TenantCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let raw = raw.unwrap_or_default();
    let origin = geoip::Origin::of_request(&state, &headers, Some(peer));
    let params = RawParams::parse(&raw);
    // Back from a parked POST.
    if let Ok(Some(id)) = params.one("continue") {
        let Ok(id) = Uuid::parse_str(id) else {
            return bad("unknown request");
        };
        return match saml_idp::unpark(&state, tenant.id(), id).await {
            Ok(Some(admitted)) => {
                saml_idp::start(&state, &tenant, &headers, origin, admitted).await
            }
            Ok(None) => bad("this sign-in request has expired; start again from the application"),
            Err(e) => e.into_response(),
        };
    }
    let received = match binding::from_redirect(&raw) {
        Ok(r) => r,
        Err(e) => return bad(&e.to_string()),
    };
    match saml_idp::admit(&state, &tenant, &received).await {
        Ok(admitted) => saml_idp::start(&state, &tenant, &headers, origin, admitted).await,
        Err(refusal) => saml_idp::refuse(&state, &tenant, refusal).await,
    }
}

/// The form fields of a POST-binding message.
fn post_message(headers: &HeaderMap, body: &str) -> Result<binding::Received, Box<Response>> {
    let is_form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"));
    if !is_form {
        return Err(Box::new(error_page(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_saml_request",
            "the HTTP-POST binding sends a form",
        )));
    }
    let params = RawParams::parse(body);
    let one = |name: &str| params.one(name).map_err(|e| Box::new(bad(&e)));
    let relay = one("RelayState")?.map(str::to_string);
    let (kind, value) = match (one("SAMLRequest")?, one("SAMLResponse")?) {
        (Some(v), None) => (Kind::Request, v),
        (None, Some(v)) => (Kind::Response, v),
        _ => {
            return Err(Box::new(bad(
                "send exactly one of SAMLRequest and SAMLResponse",
            )));
        }
    };
    binding::from_post(kind, value, relay).map_err(|e| Box::new(bad(&e.to_string())))
}

async fn sso_post(
    State(state): State<AppState>,
    tenant: TenantCtx,
    headers: HeaderMap,
    body: String,
) -> Response {
    let received = match post_message(&headers, &body) {
        Ok(r) => r,
        Err(res) => return *res,
    };
    match saml_idp::admit(&state, &tenant, &received).await {
        Ok(admitted) => match saml_idp::park(&state, &tenant, &admitted).await {
            // 303: the browser follows with a GET, which carries the
            // session cookie the cross-site POST could not.
            Ok(url) => {
                let mut res = Redirect::to(&url).into_response();
                res.headers_mut()
                    .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                res
            }
            Err(e) => e.into_response(),
        },
        Err(refusal) => saml_idp::refuse(&state, &tenant, refusal).await,
    }
}

async fn init(
    State(state): State<AppState>,
    tenant: TenantCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let params = RawParams::parse(raw.as_deref().unwrap_or_default());
    let (sp, relay) = match (params.one("sp"), params.one("RelayState")) {
        (Ok(Some(sp)), Ok(relay)) => (sp.to_string(), relay.map(str::to_string)),
        (Ok(None), _) => return bad("name the service provider with `sp`"),
        (Err(e), _) | (_, Err(e)) => return bad(&e),
    };
    let origin = geoip::Origin::of_request(&state, &headers, Some(peer));
    match saml_idp::admit_unsolicited(&state, &tenant, &sp, relay).await {
        Ok(admitted) => saml_idp::start(&state, &tenant, &headers, origin, admitted).await,
        Err(refusal) => saml_idp::refuse(&state, &tenant, refusal).await,
    }
}

async fn slo_get(
    State(state): State<AppState>,
    tenant: TenantCtx,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    match binding::from_redirect(raw.as_deref().unwrap_or_default()) {
        Ok(received) => saml_idp::slo(&state, &tenant, &headers, received).await,
        Err(e) => bad(&e.to_string()),
    }
}

async fn slo_post(
    State(state): State<AppState>,
    tenant: TenantCtx,
    headers: HeaderMap,
    body: String,
) -> Response {
    match post_message(&headers, &body) {
        Ok(received) => saml_idp::slo(&state, &tenant, &headers, received).await,
        Err(res) => *res,
    }
}

async fn slo_chain(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, id)): Path<(String, Uuid)>,
) -> Response {
    saml_idp::continue_chain(&state, &tenant, id).await
}

async fn respond(
    State(state): State<AppState>,
    tenant: TenantCtx,
    Path((_, ticket)): Path<(String, Uuid)>,
) -> Response {
    saml_idp::redeem_ticket(&state, &tenant, ticket).await
}
