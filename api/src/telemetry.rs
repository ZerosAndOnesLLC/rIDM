//! Tracing, logging, traces export and metrics.
//!
//! * `init` sets up the log subscriber (`LOG_FORMAT`, `RUST_LOG`).
//! * `init_server` does the same and, when `OTEL_EXPORTER_OTLP_ENDPOINT` is
//!   set, adds an OpenTelemetry layer exporting spans over OTLP/HTTP
//!   (protobuf) under `OTEL_SERVICE_NAME`; `shutdown` flushes it.
//! * `http_trace_layer` opens one INFO span per request ([`REQUEST_SPAN`]),
//!   named by its route template, so the default `RUST_LOG=info` exports it.
//!   The log output does not gain it: the log layer and the OTLP layer have
//!   separate filters, and the log layer shows the request span only when
//!   `RUST_LOG` enables DEBUG somewhere (where tower-http's own DEBUG span
//!   used to appear).
//! * `prometheus` installs the process-wide metrics recorder once and hands
//!   out the handle `/metrics` renders.

use std::sync::OnceLock;

use std::time::Duration;

use axum::extract::MatchedPath;
use http::{Request, Response};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
use tower_http::trace::{DefaultOnRequest, DefaultOnResponse, MakeSpan, OnResponse, TraceLayer};
use tracing::Span;
use tracing_subscriber::filter::{FilterExt as _, LevelFilter, filter_fn};
use tracing_subscriber::layer::{Filter, Layer as _};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::{Config, LogFormat};

static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();
static PROMETHEUS: OnceLock<PrometheusHandle> = OnceLock::new();

/// Initialise the global tracing subscriber. `RUST_LOG` controls the filter
/// (default `info`); `LOG_FORMAT` selects JSON (production) or pretty (dev).
pub fn init(format: LogFormat) {
    init_with(format, None);
}

/// The server's subscriber: logs plus, when configured, OTLP trace export.
pub fn init_server(config: &Config) {
    let otel = config.otlp_endpoint.as_ref().and_then(|endpoint| {
        match tracer_provider(endpoint.as_str(), &config.otel_service_name) {
            Ok(provider) => Some(provider),
            Err(err) => {
                eprintln!("otlp: exporter not started: {err}");
                None
            }
        }
    });
    init_with(config.log_format, otel);
}

fn init_with(format: LogFormat, otel: Option<SdkTracerProvider>) {
    // The tracer is a plain value; the layer around it is generic over the
    // subscriber it joins, so it is built where it is added (first, on the
    // registry itself).
    let otel_layer = otel.map(|provider| {
        let tracer = provider.tracer("ridm");
        opentelemetry::global::set_tracer_provider(provider.clone());
        let _ = TRACER_PROVIDER.set(provider);
        tracing_opentelemetry::layer()
            .with_tracer(tracer)
            .with_filter(env_filter())
    });
    let registry = tracing_subscriber::registry().with(otel_layer);
    match format {
        LogFormat::Json => registry
            .with(
                fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(true)
                    .with_span_list(false)
                    .with_target(true)
                    .with_filter(log_filter()),
            )
            .init(),
        LogFormat::Pretty => registry
            .with(fmt::layer().with_target(true).with_filter(log_filter()))
            .init(),
    }
}

/// `RUST_LOG`, default `info`.
fn env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

/// What the log layer prints: `RUST_LOG`, minus the INFO request span unless
/// DEBUG is enabled (the level tower-http's request span had before it was
/// raised for export). Without it, every JSON line logged inside a request
/// would gain a `span` object.
fn log_filter<S>() -> impl Filter<S> {
    log_filter_from(env_filter())
}

fn log_filter_from<S>(env: EnvFilter) -> impl Filter<S> {
    let show_request_span = env
        .max_level_hint()
        .is_none_or(|max| max >= LevelFilter::DEBUG);
    env.and(filter_fn(move |meta| {
        show_request_span || !(meta.is_span() && meta.target() == REQUEST_SPAN)
    }))
}

/// Target of the per-request span.
pub const REQUEST_SPAN: &str = "ridm_api::http";

/// Opens the per-request span: INFO, named `METHOD /route/{template}` (the
/// matched route, never the concrete path or query: those can carry
/// invitation tokens and authorization codes), with the HTTP method, route
/// and, once known, the response status.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestSpan;

impl<B> MakeSpan<B> for RequestSpan {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        let route = request
            .extensions()
            .get::<MatchedPath>()
            .map_or("unmatched", MatchedPath::as_str);
        tracing::info_span!(
            target: REQUEST_SPAN,
            "request",
            otel.name = format!("{} {route}", request.method()),
            otel.kind = "server",
            http.request.method = %request.method(),
            http.route = route,
            http.response.status_code = tracing::field::Empty,
        )
    }
}

/// Records the status on the request span; the DEBUG "finished processing
/// request" event is tower-http's default, unchanged.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestSpanResponse;

impl<B> OnResponse<B> for RequestSpanResponse {
    fn on_response(self, response: &Response<B>, latency: Duration, span: &Span) {
        span.record("http.response.status_code", response.status().as_u16());
        DefaultOnResponse::default().on_response(response, latency, span);
    }
}

/// The tracing middleware for the router (see [`RequestSpan`]).
pub fn http_trace_layer() -> TraceLayer<
    SharedClassifier<ServerErrorsAsFailures>,
    RequestSpan,
    DefaultOnRequest,
    RequestSpanResponse,
> {
    TraceLayer::new_for_http()
        .make_span_with(RequestSpan)
        .on_response(RequestSpanResponse)
}

/// An OTLP/HTTP span exporter behind a batch processor. `endpoint` is the
/// collector's base URL; the traces path is appended.
fn tracer_provider(endpoint: &str, service_name: &str) -> Result<SdkTracerProvider, String> {
    let url = format!("{}/v1/traces", endpoint.trim_end_matches('/'));
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(url)
        .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
        .build()
        .map_err(|e| e.to_string())?;
    let resource = Resource::builder()
        .with_service_name(service_name.to_string())
        .with_attribute(opentelemetry::KeyValue::new(
            "service.version",
            env!("CARGO_PKG_VERSION"),
        ))
        .build();
    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build())
}

/// Flush and stop the trace exporter (call on shutdown).
pub fn shutdown() {
    if let Some(provider) = TRACER_PROVIDER.get()
        && let Err(err) = provider.shutdown()
    {
        eprintln!("otlp: shutdown: {err}");
    }
}

/// The process-wide Prometheus recorder, installed on first use. Latency
/// histograms get buckets suited to an identity API.
pub fn prometheus() -> &'static PrometheusHandle {
    PROMETHEUS.get_or_init(|| {
        PrometheusBuilder::new()
            .set_buckets_for_metric(
                Matcher::Suffix("_seconds".into()),
                &[
                    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ],
            )
            .expect("buckets")
            .install_recorder()
            .expect("install the prometheus recorder")
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt as _;
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id};
    use tracing_subscriber::layer::Context;

    use super::*;

    /// Records `target route` for every span a layer is shown.
    #[derive(Clone, Default)]
    struct Seen(Arc<Mutex<Vec<String>>>);

    struct Route(String);

    impl Visit for Route {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "http.route" {
                self.0 = format!("{value:?}");
            }
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "http.route" {
                self.0 = value.to_string();
            }
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Seen {
        fn on_new_span(&self, attrs: &Attributes<'_>, _: &Id, _: Context<'_, S>) {
            let mut route = Route(String::new());
            attrs.record(&mut route);
            self.0
                .lock()
                .unwrap()
                .push(format!("{} {}", attrs.metadata().target(), route.0));
        }
    }

    async fn spans_seen(rust_log: &str) -> (Vec<String>, Vec<String>) {
        let (exported, logged) = (Seen::default(), Seen::default());
        let subscriber = tracing_subscriber::registry()
            .with(exported.clone().with_filter(EnvFilter::new(rust_log)))
            .with(
                logged
                    .clone()
                    .with_filter(log_filter_from(EnvFilter::new(rust_log))),
            );
        let _guard = tracing::subscriber::set_default(subscriber);
        let app = Router::new()
            .route("/t/{slug}/invitations/{token}", get(|| async { "ok" }))
            .layer(http_trace_layer());
        let res = app
            .oneshot(
                Request::get("/t/acme/invitations/secret-token?code=abc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let take = |s: &Seen| s.0.lock().unwrap().clone();
        (take(&exported), take(&logged))
    }

    #[tokio::test]
    async fn request_spans_are_exported_at_info_without_changing_the_logs() {
        let span = format!("{REQUEST_SPAN} /t/{{slug}}/invitations/{{token}}");
        let (exported, logged) = spans_seen("info").await;
        assert_eq!(
            exported,
            std::slice::from_ref(&span),
            "the route template, no token"
        );
        assert!(logged.is_empty(), "{logged:?}");
        // With DEBUG on, the logs show it too, as tower-http's span was.
        let (exported, logged) = spans_seen("debug").await;
        assert_eq!(exported, std::slice::from_ref(&span));
        assert_eq!(logged, [span]);
    }
}
