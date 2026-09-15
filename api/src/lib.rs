//! rIDM API library crate. The binary in `main.rs` is a thin wrapper so that
//! integration tests can build the same router in-process.

pub mod cache;
pub mod config;
pub mod db;
pub mod error;
pub mod jobs;
pub mod middleware;
pub mod models;
pub mod oidc;
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
    Router::new()
        .merge(routes::health::router())
        .merge(routes::wellknown::router())
        .merge(routes::webfinger::router())
        .merge(routes::jwks::router())
        .merge(oidc::discovery::router())
        .merge(oidc::authorize::router())
        .merge(extra)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
