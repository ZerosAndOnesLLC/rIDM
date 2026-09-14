//! Tracing / logging setup.

use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::LogFormat;

/// Initialise the global tracing subscriber. `RUST_LOG` controls the filter
/// (default `info`); `LOG_FORMAT` selects JSON (production) or pretty (dev).
pub fn init(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let registry = tracing_subscriber::registry().with(filter);
    match format {
        LogFormat::Json => registry
            .with(
                fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(true)
                    .with_span_list(false)
                    .with_target(true),
            )
            .init(),
        LogFormat::Pretty => registry.with(fmt::layer().with_target(true)).init(),
    }
}
