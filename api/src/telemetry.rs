//! Tracing, logging, traces export and metrics.
//!
//! * `init` sets up the log subscriber (`LOG_FORMAT`, `RUST_LOG`).
//! * `init_server` does the same and, when `OTEL_EXPORTER_OTLP_ENDPOINT` is
//!   set, adds an OpenTelemetry layer exporting spans over OTLP/HTTP
//!   (protobuf) under `OTEL_SERVICE_NAME`; `shutdown` flushes it.
//! * `prometheus` installs the process-wide metrics recorder once and hands
//!   out the handle `/metrics` renders.

use std::sync::OnceLock;

use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
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
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let registry = tracing_subscriber::registry().with(filter);
    // The tracer is a plain value; the layer around it is generic over the
    // subscriber it joins, so it is built where it is added.
    let tracer = otel.map(|provider| {
        let tracer = provider.tracer("ridm");
        opentelemetry::global::set_tracer_provider(provider.clone());
        let _ = TRACER_PROVIDER.set(provider);
        tracer
    });
    match format {
        LogFormat::Json => {
            let base = registry.with(
                fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(true)
                    .with_span_list(false)
                    .with_target(true),
            );
            match tracer {
                Some(t) => base
                    .with(tracing_opentelemetry::layer().with_tracer(t))
                    .init(),
                None => base.init(),
            }
        }
        LogFormat::Pretty => {
            let base = registry.with(fmt::layer().with_target(true));
            match tracer {
                Some(t) => base
                    .with(tracing_opentelemetry::layer().with_tracer(t))
                    .init(),
                None => base.init(),
            }
        }
    }
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
