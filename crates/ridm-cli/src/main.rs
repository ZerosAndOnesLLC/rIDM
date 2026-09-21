//! `ridm` — command-line administration for an rIDM identity server.
//!
//! Every command but `bootstrap` is an admin API client: it resolves a server
//! URL, a tenant and a bearer token (see [`context`]), sends one or two
//! requests, and prints either a readable summary or the server's JSON. The
//! exit code says what happened — see [`error`].

mod api;
mod auth;
mod cli;
mod commands;
mod config;
mod context;
mod error;
mod input;
mod output;

use clap::Parser as _;

use crate::cli::{Cli, Command};
use crate::context::Ctx;
use crate::error::{CliError, Result};

#[tokio::main]
async fn main() {
    // A .env beside the working directory is convenient for `bootstrap`, and
    // harmless for the rest: RIDM_URL and RIDM_TOKEN may live there too.
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => {}
        Err(CliError::Changes) => std::process::exit(error::EXIT_CHANGES),
        Err(err) => {
            eprintln!("ridm: {err}");
            std::process::exit(err.code());
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    // Bootstrap reads the server's environment, not a profile.
    #[cfg(feature = "bootstrap")]
    if let Command::Bootstrap(args) = &cli.command {
        return commands::bootstrap::run(args).await;
    }

    let mut ctx = Ctx::resolve(&cli.global)?;
    match &cli.command {
        #[cfg(feature = "bootstrap")]
        Command::Bootstrap(_) => unreachable!("handled above"),
        Command::Login(args) => {
            commands::login::login(&mut ctx, args, cli.global.token.as_deref()).await
        }
        Command::Logout(args) => commands::login::logout(&mut ctx, args),
        Command::Whoami => commands::login::whoami(&mut ctx).await,
        Command::Profile { command } => commands::profiles::run(&mut ctx, command),
        Command::Tenant { command } => commands::tenants::run(&mut ctx, command).await,
        Command::Key { command } => commands::keys::run(&mut ctx, command).await,
        Command::MasterKey { command } => commands::keys::master(&mut ctx, command).await,
        Command::User { command } => commands::users::run(&mut ctx, command).await,
        Command::Client { command } => commands::clients::run(&mut ctx, command).await,
        Command::Audit { command } => commands::audit::run(&mut ctx, command).await,
    }
}
