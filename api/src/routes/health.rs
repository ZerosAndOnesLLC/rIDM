//! Liveness and readiness probes.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::state::AppState;
use crate::{cache, db};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct Readiness {
    status: &'static str,
    checks: Checks,
}

#[derive(Serialize)]
struct Checks {
    database: &'static str,
    cache: &'static str,
}

/// Process is up. Never touches dependencies.
async fn healthz() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Process can serve traffic: database and cache both answer.
async fn readyz(State(state): State<AppState>) -> Response {
    let (db_res, cache_res) = tokio::join!(db::ping(&state.db), cache::ping(&state.redis));
    let database = match db_res {
        Ok(()) => "ok",
        Err(err) => {
            tracing::warn!(error = %err, "readiness: database check failed");
            "fail"
        }
    };
    let cache = match cache_res {
        Ok(()) => "ok",
        Err(err) => {
            tracing::warn!(error = %err, "readiness: cache check failed");
            "fail"
        }
    };
    let ready = database == "ok" && cache == "ok";
    let body = Readiness {
        status: if ready { "ok" } else { "degraded" },
        checks: Checks { database, cache },
    };
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}
