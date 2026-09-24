use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use ridm_api::config::Config;
use ridm_api::services::bootstrap;
use ridm_api::state::AppState;
use ridm_api::{build_router, cache, db, telemetry};
use std::net::SocketAddr;

// The static release binaries (see the `mimalloc` feature in Cargo.toml).
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() {
    // Ignore a missing .env file; production sets real environment variables.
    let _ = dotenvy::dotenv();

    // `ridm-api --healthcheck` is used as the container HEALTHCHECK: distroless
    // images have no curl, so the binary probes itself.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--healthcheck") {
        std::process::exit(ridm_api::healthcheck::run().await);
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
    if args.first().map(String::as_str) == Some("move-tenant") {
        std::process::exit(move_tenant_command(&args[1..]).await);
    }

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(2);
        }
    };
    telemetry::init_server(&config);

    let outcome = run(config).await;
    telemetry::shutdown();
    if let Err(err) = outcome {
        tracing::error!(error = %err, "fatal");
        std::process::exit(1);
    }
}

async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| "failed to install rustls crypto provider")?;

    let db = db::connect(&config).await?;
    let schema_current = if config.migrate_on_start {
        let applied = db::migrate_pending_all(&db).await?;
        if applied > 0 {
            tracing::info!(applied, "pending migrations applied");
        }
        true
    } else {
        let pending = db::pending_migrations_all(&db).await?;
        if pending > 0 {
            tracing::warn!(
                pending,
                "database migrations are pending; run `ridm-api migrate` as the schema owner"
            );
        }
        pending == 0
    };
    let unknown = db::unknown_migrations_all(&db).await?;
    if let Some(newest) = unknown.last() {
        tracing::warn!(
            count = unknown.len(),
            newest,
            "the database has migrations this release does not know: a newer release migrated \
             it. Run that release, or restore the backup taken before the upgrade"
        );
    }
    if let Some(expires) = config
        .security_txt
        .as_ref()
        .and_then(|t| t.document_expires())
        .filter(|e| *e <= chrono::Utc::now())
    {
        tracing::warn!(%expires, "the configured security.txt has expired; renew SECURITY_TXT");
    }
    let cache = cache::connect(&config)?;
    for (region, valkey) in cache.all() {
        match cache::ping(&valkey).await {
            Ok(()) => {}
            Err(err) if &*region != ridm_api::config::HOME_REGION => {
                tracing::error!(%region, error = %err, "data region's Valkey unreachable at start-up");
            }
            Err(err) => return Err(err.into()),
        }
    }

    let bootstrap = config.bootstrap.clone();
    let state = AppState::new(config, db, cache);
    let custody = ridm_api::key_custody::attach(&state).await?;
    if schema_current {
        check_master_key(&state).await?;
    }
    // Bootstrap and the built-in clients, one node at a time.
    ridm_api::services::startup::prepare(&state, bootstrap).await?;
    let _invalidation_listener = state.cache.spawn_invalidation_listener();
    let _audit_writer = ridm_api::services::audit::spawn_writer(state.clone());
    ridm_api::key_custody::record_created(&state, &custody);
    let _webhook_dispatcher = ridm_api::services::webhooks::spawn_dispatcher(state.clone());
    let _jobs = ridm_api::jobs::spawn_all(state.clone());
    let _key_refresh = ridm_api::key_custody::spawn_refresh(state.clone());
    let bind_addr = state.config.bind_addr;
    let tls = state.config.tls.clone();
    let mtls = state.config.mtls.clone();
    let draining = state.clone();
    let app = build_router(state);

    let handle: Handle<SocketAddr> = Handle::new();
    tokio::spawn(shutdown_signal(handle.clone()));

    // The mutual-TLS listener (RFC 8705): the same routes, on a port that
    // asks for client certificates. It stops with the main one.
    if let (Some(addr), Some(tls)) = (mtls.bind_addr, mtls.tls.as_ref()) {
        let config = ridm_api::tls::load(tls)?;
        // Bound here so that a port in use stops start-up, like the main one.
        let listener = std::net::TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let server = axum_server::from_tcp(listener)?;
        let app = app.clone();
        let handle = handle.clone();
        tracing::info!(%addr, "listening (mtls)");
        tokio::spawn(async move {
            if let Err(error) = server
                .acceptor(ridm_api::tls::PeerCertAcceptor::new(config))
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
            {
                tracing::error!(%error, "the mtls listener stopped");
            }
        });
    }

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
    drain_background(&draining, std::time::Duration::from_secs(15)).await;
    tracing::info!("shutdown complete");
    Ok(())
}

/// After the last request: give the event consumers (audit writer, webhook
/// dispatcher) time to empty their queues and the deliveries requests
/// started (messages, webhooks) time to finish, so a restart does not cut
/// them off. Whatever is still queued in memory after `limit` is lost;
/// deliveries already written to the database are sent by the delivery
/// jobs of the nodes still running.
async fn drain_background(state: &AppState, limit: std::time::Duration) {
    let queued = || -> usize { state.events.durable_stats().iter().map(|q| q.depth).sum() };
    let drained = tokio::time::timeout(limit, async {
        // A consumer marks itself busy with a batch as it takes it, and a
        // batch may start deliveries: done when both are empty at once.
        loop {
            while queued() > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            state.background.idle().await;
            if queued() == 0 && state.background.in_flight() == 0 {
                break;
            }
        }
    })
    .await;
    if drained.is_err() {
        tracing::warn!(
            events_queued = queued(),
            deliveries_in_flight = state.background.in_flight(),
            "shutdown: background work did not finish in time"
        );
    }
}

/// Refuse to start when the master keys do not decrypt the tenants' signing
/// keys: the node would report ready and then fail every token request, and
/// generate further keys under the wrong master key. That is a signing key
/// under the current generation that fails (the wrong `MASTER_KEY`), or no
/// signing key decrypting at all (a backup from before a master-key rotation,
/// restored without its generation in `MASTER_KEY_PREVIOUS`). Anything else
/// that fails is warned about: one damaged row cannot keep the service down,
/// and a deployment recovering from a lost master key, having deleted its
/// signing keys, starts and re-enters the other secrets.
async fn check_master_key(state: &AppState) -> Result<(), Box<dyn std::error::Error>> {
    let current = state.key_encryptor.current_version() as i32;
    let report = ridm_api::services::master_key::check(state).await?;
    for f in &report.failures {
        tracing::error!(
            table = f.table,
            key_version = f.key_version,
            error = %f.error,
            "a stored secret does not decrypt with the configured master keys"
        );
    }
    let failed_keys: Vec<i32> = report
        .failures
        .iter()
        .filter(|f| f.table == "signing_keys")
        .map(|f| f.key_version)
        .collect();
    if failed_keys.contains(&current) || (!failed_keys.is_empty() && report.signing_keys_ok == 0) {
        return Err(format!(
            "the configured master keys do not decrypt this database's signing keys \
             (generation(s) {failed_keys:?}; MASTER_KEY_VERSION is {current}). After a restore, \
             configure the master key that was current when the backup was taken, and any \
             older generation still in use in MASTER_KEY_PREVIOUS"
        )
        .into());
    }
    if !report.failures.is_empty() {
        tracing::warn!(
            "some stored secrets do not decrypt: add their generation to MASTER_KEY_PREVIOUS \
             (`ridm-api rotate-master-key --status` lists what is stored), or re-enter them if \
             that key is lost"
        );
    }
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
    // Migrations follow `MIGRATE_ON_START`, as at startup: this command runs
    // as `DATABASE_URL`'s role, usually the DML-only application role, which
    // cannot apply them (`ridm-api migrate` runs as the schema owner).
    let pending = if config.migrate_on_start {
        db::migrate_pending_all(&db)
            .await
            .map(|_| 0)
            .map_err(|e| e.to_string())
    } else {
        db::pending_migrations_all(&db)
            .await
            .map_err(|e| e.to_string())
    };
    match pending {
        Ok(0) => {}
        Ok(n) => {
            eprintln!(
                "{n} database migration(s) pending: run `ridm-api migrate` as the schema \
                 owner first (or set MIGRATE_ON_START=true for a role that owns the schema)"
            );
            return 1;
        }
        Err(err) => {
            eprintln!("migrate: {err}");
            return 1;
        }
    }
    let cache = match cache::connect(&config) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("redis: {err}");
            return 1;
        }
    };
    let sample_client = env_bootstrap.as_ref().is_some_and(|b| b.sample_client);
    let state = AppState::new(config, db, cache);
    let audit = ridm_api::services::audit::CommandRecorder::start(&state);
    match ridm_api::key_custody::attach(&state).await {
        Ok(report) => ridm_api::key_custody::record_created(&state, &report),
        Err(err) => {
            eprintln!("key custody: {err}");
            audit.flush(&state).await;
            return 1;
        }
    }
    let code = run_bootstrap(
        &state,
        sample_client,
        email,
        username,
        password,
        must_change,
    )
    .await;
    audit.flush(&state).await;
    code
}

async fn run_bootstrap(
    state: &AppState,
    sample_client: bool,
    email: String,
    username: String,
    password: zeroize::Zeroizing<String>,
    must_change: bool,
) -> i32 {
    if sample_client {
        match bootstrap::ensure_sample_client(state).await {
            Ok(true) => println!(
                "sample client `{}` created in master",
                bootstrap::SAMPLE_CLIENT_ID
            ),
            Ok(false) => {}
            Err(err) => {
                eprintln!("sample client: {err}");
                return 1;
            }
        }
    }
    match bootstrap::run(
        state,
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
    let config = match Config::from_env_without_keys() {
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
    match db::migrate_all(&db).await {
        Ok(()) => {
            tracing::info!(databases = db.all().len(), "migrations applied");
            0
        }
        Err(err) => {
            tracing::error!(error = %err, "migration failed");
            1
        }
    }
}

/// `ridm-api move-tenant <slug> --region <name|home> [--drain-seconds N]`:
/// move a tenant's data to another database (see README, "Data residency").
/// The tenant is unavailable while it runs; running it again after a failure
/// finishes or undoes what was left.
async fn move_tenant_command(args: &[String]) -> i32 {
    use ridm_api::services::relocation;
    let usage = "usage: ridm-api move-tenant <slug> --region <name|home> [--drain-seconds N]";
    let mut slug = None;
    let mut region = None;
    let mut opts = relocation::MoveOptions::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--region" => region = it.next().cloned(),
            "--drain-seconds" => match it.next().and_then(|v| v.parse::<u64>().ok()) {
                Some(n) => opts.drain = std::time::Duration::from_secs(n),
                None => {
                    eprintln!("move-tenant: --drain-seconds takes a number\n{usage}");
                    return 2;
                }
            },
            other if other.starts_with("--") || slug.is_some() => {
                eprintln!("move-tenant: unexpected argument `{other}`\n{usage}");
                return 2;
            }
            other => slug = Some(other.to_string()),
        }
    }
    let (Some(slug), Some(region)) = (slug, region) else {
        eprintln!("{usage}");
        return 2;
    };
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
    let audit = ridm_api::services::audit::CommandRecorder::start(&state);
    let code = match relocation::move_tenant(&state, &slug, Some(&region), &opts).await {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
            0
        }
        Err(err) => {
            eprintln!("move-tenant: {err}");
            if let Some(cause) = std::error::Error::source(&err) {
                eprintln!("  caused by: {cause}");
            }
            1
        }
    };
    audit.flush(&state).await;
    code
}

/// `ridm-api rotate-master-key [--status | --new-generation]`: re-encrypt
/// secrets at rest under the current generation (see README, "Master key
/// rotation"). `--new-generation` first has the key custody backend wrap a
/// new data key and makes it current.
async fn rotate_master_key_command(args: &[String]) -> i32 {
    let status_only = args.iter().any(|a| a == "--status");
    let new_generation = args.iter().any(|a| a == "--new-generation");
    if let Some(unknown) = args
        .iter()
        .find(|a| !matches!(a.as_str(), "--status" | "--new-generation"))
    {
        eprintln!("rotate-master-key: unknown argument `{unknown}`");
        return 2;
    }
    if status_only && new_generation {
        eprintln!("rotate-master-key: --status and --new-generation exclude each other");
        return 2;
    }
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
    let audit = ridm_api::services::audit::CommandRecorder::start(&state);
    match ridm_api::key_custody::attach(&state).await {
        Ok(report) => ridm_api::key_custody::record_created(&state, &report),
        Err(err) => {
            eprintln!("key custody: {err}");
            audit.flush(&state).await;
            return 1;
        }
    }
    if new_generation {
        match ridm_api::services::master_key::new_generation(&state).await {
            Ok(v) => println!("created master-key generation {v}"),
            Err(err) => {
                eprintln!("new generation: {err}");
                audit.flush(&state).await;
                return 1;
            }
        }
    }
    let code = run_master_key_rotation(&state, status_only).await;
    audit.flush(&state).await;
    code
}

async fn run_master_key_rotation(state: &AppState, status_only: bool) -> i32 {
    use ridm_api::services::master_key;
    let status = match master_key::status(state).await {
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
    match master_key::rotate_all(state).await {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
            if report.failed.values().sum::<u64>() > 0 {
                eprintln!(
                    "some rows could not be re-encrypted; check MASTER_KEY_PREVIOUS and \
                     KEY_WRAPPER_PREVIOUS"
                );
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
