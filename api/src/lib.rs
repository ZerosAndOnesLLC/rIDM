//! rIDM API library crate. The binary in `main.rs` is a thin wrapper so that
//! integration tests can build the same router in-process.

pub mod cache;
pub mod config;
pub mod db;
pub mod error;
pub mod healthcheck;
pub mod jobs;
pub mod messaging;
pub mod middleware;
pub mod models;
pub mod oidc;
pub mod openapi;
pub mod repos;
pub mod routes;
pub mod saml;
pub mod services;
pub mod state;
pub mod telemetry;
pub mod util;

use axum::Router;
use axum::middleware::from_fn_with_state;

use crate::middleware::guard::{Guard, Style, guard};
use crate::middleware::{cors, security_headers};
use crate::services::rate_limit::Category;
use crate::state::AppState;

/// Build the full application router.
pub fn build_router(state: AppState) -> Router {
    build_router_with(state, Router::new())
}

/// Build the application router plus `extra` routes (used by integration
/// tests to exercise extractors and middleware in isolation).
pub fn build_router_with(state: AppState, extra: Router<AppState>) -> Router {
    // The metrics recorder must exist before the first counter is touched.
    let _ = telemetry::prometheus();
    let routed = routed_router(state.clone(), extra);
    // Every request is looked at by host first: one on a tenant's custom
    // domain is mapped onto that tenant's routes and nothing else (see `host`).
    Router::new().fallback(move |req: axum::extract::Request| {
        let state = state.clone();
        let routed = routed.clone();
        async move { middleware::host::dispatch(state, routed, req).await }
    })
}

/// Every route with its layers, under the primary host's paths.
fn routed_router(state: AppState, extra: Router<AppState>) -> Router {
    let (admin, mut api) = openapi::admin_router().split_for_parts();
    openapi::finalize(&mut api);
    let docs = if state.config.docs_enabled {
        Router::new()
            .merge(utoipa_swagger_ui::SwaggerUi::new("/docs").url("/openapi.json", api.clone()))
    } else {
        let served = api.clone();
        Router::new().route(
            "/openapi.json",
            axum::routing::get(move || {
                let doc = served.clone();
                async move { axum::Json(doc) }
            }),
        )
    };
    // Each endpoint family gets its own guard (tenant IP rules, then its rate
    // ceiling) and refusal format; the layer sits on the family's router so
    // its path parameters are already known.
    let limited = |router: Router<AppState>, category: Category, style: Style| {
        router.layer(from_fn_with_state(
            Guard::new(state.clone(), category, style),
            guard,
        ))
    };
    let flows = Router::new()
        .merge(routes::flows::router())
        .merge(routes::device::router())
        .merge(routes::invitations::router())
        .merge(routes::verification::router())
        .merge(routes::recovery::router());
    let oauth_tokens = Router::new()
        .merge(routes::features::router())
        .merge(oidc::token::router())
        .merge(oidc::device::router())
        .merge(oidc::ciba::router())
        .merge(oidc::userinfo::router())
        .merge(oidc::introspect::router())
        .merge(oidc::revoke::router());
    let oauth_json = Router::new()
        .merge(oidc::par::router())
        .merge(oidc::register::router());
    Router::new()
        .merge(routes::health::router())
        .merge(admin)
        .merge(docs)
        .merge(routes::branding::router())
        .merge(routes::wellknown::router())
        .merge(routes::webfinger::router())
        .merge(routes::jwks::router())
        .merge(routes::scim::router())
        .merge(limited(flows, Category::Flows, Style::Problem))
        .merge(limited(
            routes::broker::router(),
            Category::Flows,
            Style::Html,
        ))
        .merge(limited(
            routes::saml_sp::router(),
            Category::Flows,
            Style::Html,
        ))
        .merge(limited(
            routes::impersonation::router(),
            Category::Flows,
            Style::Html,
        ))
        .merge(oidc::discovery::router())
        .merge(limited(
            oidc::authorize::router(),
            Category::Authorize,
            Style::Html,
        ))
        .merge(limited(
            routes::saml::router(),
            Category::Authorize,
            Style::Html,
        ))
        .merge(limited(oauth_json, Category::Authorize, Style::OAuth))
        .merge(limited(oauth_tokens, Category::Token, Style::OAuth))
        .merge(oidc::end_session::router())
        .merge(extra)
        // Unmatched paths: the embedded UI's pages, compressed (hashed
        // bundles are large and the pages are text), or the API's 404.
        .fallback_service(
            tower::ServiceBuilder::new()
                .layer(tower_http::compression::CompressionLayer::new())
                .service(axum::handler::Handler::with_state(
                    routes::ui::fallback,
                    state.clone(),
                )),
        )
        .layer(from_fn_with_state(
            state.clone(),
            security_headers::security_headers,
        ))
        .layer(cors::layer(state.clone()))
        .layer(axum::middleware::from_fn(
            middleware::http_metrics::http_metrics,
        ))
        .layer(axum::middleware::from_fn(middleware::acting::acting_scope))
        .layer(telemetry::http_trace_layer())
        .with_state(state)
}
