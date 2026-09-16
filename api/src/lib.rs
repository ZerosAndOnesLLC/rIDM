//! rIDM API library crate. The binary in `main.rs` is a thin wrapper so that
//! integration tests can build the same router in-process.

pub mod cache;
pub mod config;
pub mod db;
pub mod error;
pub mod jobs;
pub mod messaging;
pub mod middleware;
pub mod models;
pub mod oidc;
pub mod openapi;
pub mod repos;
pub mod routes;
pub mod services;
pub mod state;
pub mod telemetry;
pub mod util;

use axum::Router;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Build the full application router.
pub fn build_router(state: AppState) -> Router {
    build_router_with(state, Router::new())
}

/// Build the application router plus `extra` routes (used by integration
/// tests to exercise extractors and middleware in isolation).
pub fn build_router_with(state: AppState, extra: Router<AppState>) -> Router {
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
    Router::new()
        .merge(routes::health::router())
        .merge(admin)
        .merge(docs)
        .merge(routes::branding::router())
        .merge(routes::wellknown::router())
        .merge(routes::webfinger::router())
        .merge(routes::jwks::router())
        .merge(routes::flows::router())
        .merge(routes::broker::router())
        .merge(routes::device::router())
        .merge(routes::invitations::router())
        .merge(routes::verification::router())
        .merge(routes::recovery::router())
        .merge(oidc::discovery::router())
        .merge(oidc::authorize::router())
        .merge(oidc::par::router())
        .merge(oidc::register::router())
        .merge(oidc::token::router())
        .merge(oidc::device::router())
        .merge(oidc::userinfo::router())
        .merge(oidc::introspect::router())
        .merge(oidc::revoke::router())
        .merge(oidc::end_session::router())
        .merge(extra)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
