use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use ridm_api::config::Config;
use ridm_api::services::bootstrap;
use ridm_api::state::AppState;
use ridm_api::{build_router, cache, db, telemetry};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // Ignore a missing .env file; production sets real environment variables.
    let _ = dotenvy::dotenv();

    // `ridm-api --healthcheck` is used as the container HEALTHCHECK: distroless
    // images have no curl, so the binary probes itself.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--healthcheck") {
        std::process::exit(healthcheck().await);
    }
    if args.first().map(String::as_str) == Some("bootstrap") {
        std::process::exit(bootstrap_command(&args[1..]).await);
    }
    if args.first().map(String::as_str) == Some("openapi") {
        match ridm_api::openapi::openapi().to_pretty_json() {
            Ok(json) => {
                println!("{json}");
                std::process::exit(0);
            }
            Err(err) => {
                eprintln!("openapi: {err}");
                std::process::exit(1);
            }
        }
    }
    if args.first().map(String::as_str) == Some("migrate") {
        std::process::exit(migrate_command().await);
    }
    if args.first().map(String::as_str) == Some("rotate-master-key") {
        std::process::exit(rotate_master_key_command(&args[1..]).await);
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
    if config.migrate_on_start {
        tracing::info!("applying pending migrations");
        db::migrate(&db).await?;
    }
    let cache = cache::connect(&config)?;
    cache::ping(&cache).await?;

    let bootstrap = config.bootstrap.clone();
    let state = AppState::new(config, db, cache);
    if let Some(b) = bootstrap {
        let outcome = bootstrap::run(
            &state,
            bootstrap::BootstrapRequest {
                admin_email: b.admin_email,
                admin_username: b.admin_username,
                admin_password: zeroize::Zeroizing::new(b.admin_password.expose().to_string()),
                must_change_password: true,
            },
        )
        .await?;
        if outcome == bootstrap::BootstrapOutcome::AlreadyBootstrapped {
            tracing::debug!("bootstrap: already done, skipping");
        }
    }
    let _invalidation_listener = state.cache.spawn_invalidation_listener();
    let _audit_writer = ridm_api::services::audit::spawn_writer(state.clone());
    let _webhook_dispatcher = ridm_api::services::webhooks::spawn_dispatcher(state.clone());
    let _jobs = ridm_api::jobs::spawn_all(state.clone());
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

/// `ridm-api bootstrap [--email E] [--username U] [--password-stdin] [--no-must-change]`
///
/// Creates the global administrator. Values not given as flags fall back to the
/// `BOOTSTRAP_*` environment variables, then to interactive prompts.
async fn bootstrap_command(args: &[String]) -> i32 {
    let mut email: Option<String> = None;
    let mut username: Option<String> = None;
    let mut password_stdin = false;
    let mut must_change = true;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--email" => {
                email = args.get(i + 1).cloned();
                i += 1;
            }
            "--username" => {
                username = args.get(i + 1).cloned();
                i += 1;
            }
            "--password-stdin" => password_stdin = true,
            "--no-must-change" => must_change = false,
            "-h" | "--help" => {
                println!(
                    "usage: ridm-api bootstrap [--email EMAIL] [--username NAME] \
                     [--password-stdin] [--no-must-change]"
                );
                return 0;
            }
            other => {
                eprintln!("unknown argument: {other}");
                return 2;
            }
        }
        i += 1;
    }

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("configuration error: {err}");
            return 2;
        }
    };
    let env_bootstrap = config.bootstrap.clone();
    let email = email
        .or_else(|| env_bootstrap.as_ref().map(|b| b.admin_email.clone()))
        .or_else(|| prompt("Admin email: "));
    let username = username
        .or_else(|| env_bootstrap.as_ref().map(|b| b.admin_username.clone()))
        .unwrap_or_else(|| "admin".to_string());
    let password = if password_stdin {
        let mut s = String::new();
        if std::io::stdin().read_line(&mut s).is_err() {
            eprintln!("failed to read password from stdin");
            return 2;
        }
        Some(zeroize::Zeroizing::new(
            s.trim_end_matches(['\r', '\n']).to_string(),
        ))
    } else if let Some(b) = &env_bootstrap {
        Some(zeroize::Zeroizing::new(
            b.admin_password.expose().to_string(),
        ))
    } else {
        prompt_password()
    };
    let (Some(email), Some(password)) = (email, password) else {
        eprintln!("email and password are required");
        return 2;
    };

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let db = match db::connect(&config).await {
        Ok(d) => d,
        Err(err) => {
            eprintln!("database: {err}");
            return 1;
        }
    };
    if let Err(err) = db::migrate(&db).await {
        eprintln!("migrate: {err}");
        return 1;
    }
    let cache = match cache::connect(&config) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("redis: {err}");
            return 1;
        }
    };
    let state = AppState::new(config, db, cache);
    match bootstrap::run(
        &state,
        bootstrap::BootstrapRequest {
            admin_email: email,
            admin_username: username,
            admin_password: password,
            must_change_password: must_change,
        },
    )
    .await
    {
        Ok(bootstrap::BootstrapOutcome::Created { admin_user_id }) => {
            println!("global admin created (user id {admin_user_id})");
            0
        }
        Ok(bootstrap::BootstrapOutcome::AlreadyBootstrapped) => {
            println!("already bootstrapped: a global owner exists; nothing changed");
            0
        }
        Err(err) => {
            eprintln!("bootstrap failed: {err}");
            if let ridm_api::error::AppError::Validation(fields) = &err {
                for f in fields {
                    eprintln!("  {}: {}", f.field, f.message);
                }
            }
            1
        }
    }
}

fn prompt(label: &str) -> Option<String> {
    use std::io::Write as _;
    print!("{label}");
    std::io::stdout().flush().ok()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).ok()?;
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn prompt_password() -> Option<zeroize::Zeroizing<String>> {
    let first = rpassword::prompt_password("Admin password: ").ok()?;
    let second = rpassword::prompt_password("Repeat password: ").ok()?;
    if first != second {
        eprintln!("passwords do not match");
        return None;
    }
    Some(zeroize::Zeroizing::new(first))
}

/// `ridm-api migrate`: apply pending migrations and exit. Run it as the role
/// that owns the schema (the migrator), e.g. from a compose one-shot service or
/// a Kubernetes job, so the API itself can run as a DML-only role.
async fn migrate_command() -> i32 {
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("configuration error: {err}");
            return 2;
        }
    };
    telemetry::init(config.log_format);
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let db = match db::connect(&config).await {
        Ok(d) => d,
        Err(err) => {
            tracing::error!(error = %err, "database connection failed");
            return 1;
        }
    };
    match db::migrate(&db).await {
        Ok(()) => {
            tracing::info!("migrations applied");
            0
        }
        Err(err) => {
            tracing::error!(error = %err, "migration failed");
            1
        }
    }
}

/// `ridm-api rotate-master-key [--status]`: re-encrypt secrets at rest under the
/// current `MASTER_KEY_VERSION` (see README, "Master key rotation").
async fn rotate_master_key_command(args: &[String]) -> i32 {
    let status_only = args.iter().any(|a| a == "--status");
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("configuration error: {err}");
            return 2;
        }
    };
    telemetry::init(config.log_format);
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let db = match db::connect(&config).await {
        Ok(d) => d,
        Err(err) => {
            eprintln!("database: {err}");
            return 1;
        }
    };
    let cache = match cache::connect(&config) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("redis: {err}");
            return 1;
        }
    };
    let state = AppState::new(config, db, cache);
    use ridm_api::services::master_key;
    let status = match master_key::status(&state).await {
        Ok(s) => s,
        Err(err) => {
            eprintln!("status failed: {err}");
            return 1;
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&status).unwrap_or_default()
    );
    if status_only {
        return 0;
    }
    if status.pending() == 0 {
        println!(
            "nothing to rotate: every row is on generation {}",
            status.current_version
        );
        return 0;
    }
    match master_key::rotate_all(&state).await {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
            if report.failed.values().sum::<u64>() > 0 {
                eprintln!("some rows could not be re-encrypted; check MASTER_KEY_PREVIOUS");
                1
            } else {
                0
            }
        }
        Err(err) => {
            eprintln!("rotation failed: {err}");
            1
        }
    }
}
