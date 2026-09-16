//! Request counts and latencies per route (`ridm_http_requests_total`,
//! `ridm_http_request_duration_seconds`). The route label is the matched
//! pattern (`/t/{slug}/token`), never the raw path, so cardinality stays flat.

use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;

pub async fn http_metrics(req: Request, next: Next) -> Response {
    let method = req.method().as_str().to_string();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());
    let started = Instant::now();
    let res = next.run(req).await;
    let status = res.status().as_u16().to_string();
    metrics::counter!("ridm_http_requests_total", "method" => method.clone(), "route" => route.clone(), "status" => status)
        .increment(1);
    metrics::histogram!("ridm_http_request_duration_seconds", "method" => method, "route" => route)
        .record(started.elapsed().as_secs_f64());
    res
}
