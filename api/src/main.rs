use std::sync::Arc;

use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use ridm_api::config::Config;
use ridm_api::state::AppState;
use ridm_api::{build_router, cache, db, telemetry};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // Ignore a missing .env file; production sets real environment variables.
    let _ = dotenvy::dotenv();

    // `ridm-api --healthcheck` is used as the container HEALTHCHECK: distroless
    // images have no curl, so the binary probes itself.
    if std::env::args().any(|a| a == "--healthcheck") {
        std::process::exit(healthcheck().await);
    }

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(2);
        }
    };
    telemetry::init(config.log_format);

    if let Err(err) = run(config).await {
        tracing::error!(error = %err, "fatal");
        std::process::exit(1);
    }
}

async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| "failed to install rustls crypto provider")?;

    let db = db::connect(&config).await?;
    let cache = cache::connect(&config)?;
    cache::ping(&cache).await?;

    let state = AppState {
        config: Arc::new(config),
        db,
        cache,
    };
    let bind_addr = state.config.bind_addr;
    let tls = state.config.tls.clone();
    let app = build_router(state);

    let handle: Handle<SocketAddr> = Handle::new();
    tokio::spawn(shutdown_signal(handle.clone()));

    match tls {
        Some(tls) => {
            let rustls = RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path).await?;
            tracing::info!(%bind_addr, "listening (https)");
            axum_server::bind_rustls(bind_addr, rustls)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        }
        None => {
            tracing::info!(%bind_addr, "listening (http)");
            axum_server::bind(bind_addr)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        }
    }
    tracing::info!("shutdown complete");
    Ok(())
}

async fn shutdown_signal(handle: Handle<SocketAddr>) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received, draining connections");
    handle.graceful_shutdown(Some(std::time::Duration::from_secs(20)));
}

async fn healthcheck() -> i32 {
    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let port = bind.rsplit(':').next().unwrap_or("8080");
    let url = format!("http://127.0.0.1:{port}/healthz");
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(_) => return 1,
    };
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => 0,
        _ => 1,
    }
}
