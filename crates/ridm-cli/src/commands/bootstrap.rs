//! `ridm bootstrap`: the one command that cannot use the admin API, because
//! it creates the account the first admin token will belong to.
//!
//! It reads the server's own configuration from the environment
//! (`DATABASE_URL`, `REDIS_URL`, `MASTER_KEY`, the `BOOTSTRAP_*` fallbacks)
//! and calls the same `services::bootstrap::run` the server calls at startup,
//! so an administrator made here is identical to one made there. Build the
//! CLI with `--no-default-features` to leave the command out.
//!
//! `--issue-token` also mints a personal access token for that administrator,
//! straight through the database, so a fresh development stack can be driven
//! by scripts without a browser. It asks nothing of the database that
//! `DATABASE_URL` and `MASTER_KEY` do not already grant.

use ridm_api::config::Config;
use ridm_api::models::{MASTER_TENANT_ID, NewPersonalAccessToken};
use ridm_api::services::bootstrap as service;
use ridm_api::services::{audit, personal_access_tokens, tenants, users};
use ridm_api::state::AppState;
use ridm_api::{cache, db};
use ridm_core::events::Actor;
use zeroize::Zeroizing;

use crate::cli::BootstrapArgs;
use crate::error::{CliError, Result};
use crate::input;

pub async fn run(args: &BootstrapArgs) -> Result<()> {
    let config =
        Config::from_env().map_err(|e| CliError::usage(format!("configuration error: {e}")))?;
    let env = config.bootstrap.clone();
    let username = args
        .username
        .clone()
        .or_else(|| env.as_ref().map(|b| b.admin_username.clone()))
        .unwrap_or_else(|| "admin".to_string());

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

    // The admin and the token are recorded in the audit log like any other.
    let audit = audit::CommandRecorder::start(&state);
    let result = act(args, &state, env, username).await;
    if audit.flush(&state).await > 0 {
        eprintln!("warning: not every event of this run could be written to the audit log");
    }
    result
}

async fn act(
    args: &BootstrapArgs,
    state: &AppState,
    env: Option<ridm_api::config::BootstrapConfig>,
    username: String,
) -> Result<()> {
    // With a token to print, stdout carries the token alone so a script can
    // capture it; everything said to a person goes to stderr.
    let say = |line: &str| {
        if args.issue_token.is_some() {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };

    // Ask for an email and a password only when there is an admin to create:
    // minting a token on a bootstrapped database needs neither.
    let already = service::is_bootstrapped(state).await.map_err(failed)?;
    if already {
        say("Already bootstrapped: a global owner exists; nothing changed.");
    } else {
        let email = args
            .email
            .clone()
            .or_else(|| env.as_ref().map(|b| b.admin_email.clone()))
            .or(input::ask("Admin email: ")?)
            .ok_or_else(|| {
                CliError::usage("no admin email: pass --email or set BOOTSTRAP_ADMIN_EMAIL")
            })?;
        let password = if args.password_stdin {
            input::line_from_stdin("the admin password")?
        } else if let Some(b) = &env {
            Zeroizing::new(b.admin_password.expose().to_string())
        } else {
            input::new_password("Admin password")?
        };
        let outcome = service::run(
            state,
            service::BootstrapRequest {
                admin_email: email,
                admin_username: username.clone(),
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
            service::BootstrapOutcome::Created { .. } => {
                say("Global admin created in the master tenant.");
                if args.issue_token.is_none() {
                    say("Next: `ridm login --url <server URL>` with a personal access token.");
                }
            }
            // Another process got there between the check and the run.
            service::BootstrapOutcome::AlreadyBootstrapped => {
                say("Already bootstrapped: a global owner exists; nothing changed.");
            }
        }
    }

    if let Some(name) = &args.issue_token {
        let token = issue_token(state, &username, name, args.token_days).await?;
        println!("{}", token.as_str());
        eprintln!("  (a personal access token for the administrator, in `master`; shown once)");
    }
    Ok(())
}

/// Mint a token for `username` in `master` carrying every admin permission
/// that user holds, through the same service the account console uses.
async fn issue_token(
    state: &AppState,
    username: &str,
    name: &str,
    days: u32,
) -> Result<Zeroizing<String>> {
    let user = users::find_by_identifier(state, MASTER_TENANT_ID, username)
        .await
        .map_err(failed)?
        .ok_or_else(|| {
            CliError::usage(format!(
                "no user `{username}` in the master tenant; pass --username with the \
                 administrator's username"
            ))
        })?;
    let scopes = personal_access_tokens::available_scopes(state, MASTER_TENANT_ID, user.id)
        .await
        .map_err(failed)?;
    if scopes.len() <= 1 {
        return Err(CliError::failed(format!(
            "`{username}` holds no admin permissions in master"
        )));
    }
    let master = tenants::get(state, MASTER_TENANT_ID)
        .await
        .map_err(failed)?;
    let (token, _) = personal_access_tokens::create(
        state,
        &master,
        Actor::System,
        user.id,
        NewPersonalAccessToken {
            name: name.to_string(),
            scopes,
            expires_in_days: Some(days),
        },
    )
    .await
    .map_err(|err| {
        let mut message = format!("could not mint a token: {err}");
        if let ridm_api::error::AppError::Validation(fields) = &err {
            for f in fields {
                message.push_str(&format!("\n  {}: {}", f.field, f.message));
            }
        }
        CliError::failed(message)
    })?;
    Ok(token)
}

fn failed(err: ridm_api::error::AppError) -> CliError {
    CliError::failed(err.to_string())
}
