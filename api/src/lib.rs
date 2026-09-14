//! rIDM API library crate. The binary in `main.rs` is a thin wrapper so that
//! integration tests can build the same router in-process.

pub mod cache;
pub mod config;
pub mod db;
pub mod error;
pub mod routes;
pub mod state;
pub mod telemetry;
pub mod util;

use axum::Router;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Build the full application router.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .merge(routes::health::router())
        .merge(routes::wellknown::router())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
