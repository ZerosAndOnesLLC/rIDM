//! Liveness and readiness probes.

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::state::AppState;
use crate::{cache, config, db, telemetry};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
}

/// Prometheus exposition of every counter, gauge and histogram; behind
/// `METRICS_TOKEN` (`Authorization: Bearer`) when the deployment sets one.
async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(expected) = &state.config.metrics_token {
        let presented = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim);
        let ok = presented.is_some_and(|p| {
            use subtle::ConstantTimeEq as _;
            p.as_bytes().ct_eq(expected.expose().as_bytes()).into()
        });
        if !ok {
            return (
                StatusCode::UNAUTHORIZED,
                [(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer realm=\"metrics\""),
                )],
                "metrics token required",
            )
                .into_response();
        }
    }
    // Read at scrape time, so a consumer that is stuck is still visible.
    for q in state.events.durable_stats() {
        metrics::gauge!("ridm_event_queue_depth", "subscriber" => q.name).set(q.depth as f64);
        metrics::gauge!("ridm_event_queue_capacity", "subscriber" => q.name).set(q.capacity as f64);
        metrics::counter!("ridm_event_queue_dropped_total", "subscriber" => q.name)
            .absolute(q.dropped);
    }
    let body = telemetry::prometheus().render();
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )],
        body,
    )
        .into_response()
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
    /// `saturated` when an event consumer (the audit writer, the webhook
    /// dispatcher) has fallen so far behind that its queue is past
    /// [`EVENT_QUEUE_HIGH_WATER`] percent: the node stops taking traffic
    /// while it catches up, instead of dropping events once the queue fills.
    events: &'static str,
    /// Each data region's database and Valkey. Reported, but not part of
    /// readiness: a region's outage is its tenants' outage, and taking every
    /// node out of the load balancer for it would take all tenants down.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    regions: std::collections::BTreeMap<String, RegionChecks>,
}

#[derive(Serialize)]
struct RegionChecks {
    database: &'static str,
    cache: &'static str,
}

fn outcome<E: std::fmt::Display>(res: Result<(), E>, what: &str, region: &str) -> &'static str {
    match res {
        Ok(()) => "ok",
        Err(err) => {
            tracing::warn!(error = %err, region, "readiness: {what} check failed");
            "fail"
        }
    }
}

/// Process is up. Never touches dependencies.
async fn healthz() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Percent of a durable event queue's capacity past which the node reports
/// itself not ready.
pub const EVENT_QUEUE_HIGH_WATER: usize = 80;

/// Process can serve traffic: the home database and cache both answer, and
/// no event consumer is about to overflow its queue.
async fn readyz(State(state): State<AppState>) -> Response {
    let caches = state.redis.all();
    let home_cache = &caches[0].1;
    let (db_res, cache_res) = tokio::join!(db::ping(state.db.home()), cache::ping(home_cache));
    let database = outcome(db_res, "database", config::HOME_REGION);
    let cache = outcome(cache_res, "cache", config::HOME_REGION);
    let mut regions = std::collections::BTreeMap::new();
    for database in state.db.all().iter().filter(|d| !d.is_home()) {
        let valkey = caches
            .iter()
            .find(|(name, _)| *name == database.name)
            .map_or(home_cache, |(_, c)| c);
        let (db_res, cache_res) = tokio::join!(db::ping(&database.primary), cache::ping(valkey));
        regions.insert(
            database.name.to_string(),
            RegionChecks {
                database: outcome(db_res, "database", &database.name),
                cache: outcome(cache_res, "cache", &database.name),
            },
        );
    }
    let saturated: Vec<_> = state
        .events
        .durable_stats()
        .into_iter()
        .filter(|q| q.above(EVENT_QUEUE_HIGH_WATER))
        .collect();
    for q in &saturated {
        tracing::warn!(
            subscriber = q.name,
            depth = q.depth,
            capacity = q.capacity,
            "readiness: event queue saturated"
        );
    }
    let events = if saturated.is_empty() {
        "ok"
    } else {
        "saturated"
    };
    let ready = database == "ok" && cache == "ok" && events == "ok";
    let body = Readiness {
        status: if ready { "ok" } else { "degraded" },
        checks: Checks {
            database,
            cache,
            events,
            regions,
        },
    };
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}
