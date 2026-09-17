//! `ridm bootstrap`: the one command that cannot use the admin API, because
//! it creates the account the first admin token will belong to.
//!
//! It reads the server's own configuration from the environment
//! (`DATABASE_URL`, `REDIS_URL`, `MASTER_KEY`, the `BOOTSTRAP_*` fallbacks)
//! and calls the same `services::bootstrap::run` the server calls at startup,
//! so an administrator made here is identical to one made there. Build the
//! CLI with `--no-default-features` to leave the command out.

use ridm_api::config::Config;
use ridm_api::services::bootstrap as service;
use ridm_api::state::AppState;
use ridm_api::{cache, db};
use zeroize::Zeroizing;

use crate::cli::BootstrapArgs;
use crate::error::{CliError, Result};
use crate::input;

pub async fn run(args: &BootstrapArgs) -> Result<()> {
    let config =
        Config::from_env().map_err(|e| CliError::usage(format!("configuration error: {e}")))?;
    let env = config.bootstrap.clone();

    let email = args
        .email
        .clone()
        .or_else(|| env.as_ref().map(|b| b.admin_email.clone()))
        .or(input::ask("Admin email: ")?)
        .ok_or_else(|| {
            CliError::usage("no admin email: pass --email or set BOOTSTRAP_ADMIN_EMAIL")
        })?;
    let username = args
        .username
        .clone()
        .or_else(|| env.as_ref().map(|b| b.admin_username.clone()))
        .unwrap_or_else(|| "admin".to_string());
    let password = if args.password_stdin {
        input::line_from_stdin("the admin password")?
    } else if let Some(b) = &env {
        Zeroizing::new(b.admin_password.expose().to_string())
    } else {
        input::new_password("Admin password")?
    };

    // The server installs this before it touches TLS; the CLI reaches
    // Postgres and Valkey the same way.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let db = db::connect(&config)
        .await
        .map_err(|e| CliError::failed(format!("database: {e}")))?;
    if !args.no_migrate {
        db::migrate(&db)
            .await
            .map_err(|e| CliError::failed(format!("migrate: {e}")))?;
    }
    let cache = cache::connect(&config).map_err(|e| CliError::failed(format!("redis: {e}")))?;
    let state = AppState::new(config, db, cache);

    let outcome = service::run(
        &state,
        service::BootstrapRequest {
            admin_email: email,
            admin_username: username,
            admin_password: password,
            must_change_password: !args.no_must_change,
        },
    )
    .await
    .map_err(|err| {
        let mut message = format!("bootstrap failed: {err}");
        if let ridm_api::error::AppError::Validation(fields) = &err {
            for f in fields {
                message.push_str(&format!("\n  {}: {}", f.field, f.message));
            }
        }
        CliError::failed(message)
    })?;

    match outcome {
        service::BootstrapOutcome::Created { admin_user_id } => {
            println!("Global admin created (user id {admin_user_id}).");
            println!("Next: `ridm login --url <server URL>` with a personal access token.");
        }
        service::BootstrapOutcome::AlreadyBootstrapped => {
            println!("Already bootstrapped: a global owner exists; nothing changed.");
        }
    }
    Ok(())
}
