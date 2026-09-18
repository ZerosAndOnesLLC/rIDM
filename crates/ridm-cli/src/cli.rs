//! The command line itself: every flag the CLI accepts, in one place.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::output::Format;

const ABOUT: &str = "Administer an rIDM identity server";

const LONG_ABOUT: &str = "\
Administer an rIDM identity server from the command line.

Every command but `bootstrap` talks to the admin API over HTTP with a bearer
token, so the CLI needs nothing but network access to the server. `bootstrap`
creates the very first administrator, when no token can exist yet, and so
talks to the database with the server's own configuration (DATABASE_URL,
REDIS_URL, MASTER_KEY).

Run `ridm login` once to store a server URL and a credential in a profile
(~/.config/ridm/config.json, mode 0600), or pass --url and --token (or set
RIDM_URL and RIDM_TOKEN) for a one-off command or a CI job.";

#[derive(Debug, Parser)]
#[command(name = "ridm", version, about = ABOUT, long_about = LONG_ABOUT)]
pub struct Cli {
    #[command(flatten)]
    pub global: Global,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Args)]
pub struct Global {
    /// Stored profile to use (default: the selected one, else `default`).
    #[arg(long, global = true, env = "RIDM_PROFILE", value_name = "NAME")]
    pub profile: Option<String>,
    /// Server origin, overriding the profile (`https://idm.example.com`).
    #[arg(long, global = true, env = "RIDM_URL", value_name = "URL")]
    pub url: Option<String>,
    /// Tenant to act on, overriding the profile's (`master` by default).
    #[arg(long, global = true, env = "RIDM_TENANT", value_name = "SLUG")]
    pub tenant: Option<String>,
    /// Bearer token to present, overriding the profile's credential.
    #[arg(
        long,
        global = true,
        env = "RIDM_TOKEN",
        value_name = "TOKEN",
        hide_env_values = true
    )]
    pub token: Option<String>,
    /// How to print results.
    #[arg(long, global = true, value_enum, default_value = "text")]
    pub output: Format,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Store a server URL and a credential in a profile.
    Login(LoginArgs),
    /// Forget a profile's credential (`--all` removes the profile).
    Logout(LogoutArgs),
    /// Show who the stored credential is, and what it may do.
    Whoami,
    /// Inspect and switch between stored profiles.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Create the first global administrator (talks to the database).
    #[cfg(feature = "bootstrap")]
    Bootstrap(BootstrapArgs),
    /// Tenants, and their configuration as code.
    Tenant {
        #[command(subcommand)]
        command: TenantCommand,
    },
    /// Token signing keys of a tenant.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// The master key that encrypts secrets at rest.
    #[command(name = "master-key")]
    MasterKey {
        #[command(subcommand)]
        command: MasterKeyCommand,
    },
    /// Users of a tenant.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// OAuth clients of a tenant.
    Client {
        #[command(subcommand)]
        command: ClientCommand,
    },
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Profile to write (default: the selected one, else `default`).
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// Read a personal access token from stdin instead of prompting.
    #[arg(long, conflicts_with = "client_id")]
    pub token_stdin: bool,
    /// Authenticate as this OAuth client instead of with a token.
    #[arg(long, value_name = "ID")]
    pub client_id: Option<String>,
    /// Read the client secret from stdin (prompted when absent).
    #[arg(long, requires = "client_id")]
    pub client_secret_stdin: bool,
    /// Approve in a browser (device grant) even for a confidential client.
    #[arg(long, requires = "client_id")]
    pub device: bool,
    /// Scope to ask for in a user-facing grant.
    #[arg(long, default_value = crate::auth::DEFAULT_SCOPE, value_name = "SCOPE")]
    pub scope: String,
}

#[derive(Debug, Args)]
pub struct LogoutArgs {
    /// Remove the profile entirely, not just its credential.
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// List stored profiles; the selected one is marked.
    List,
    /// Select the profile commands use by default.
    Use {
        /// Profile name.
        name: String,
    },
    /// Show one profile, with its credential redacted.
    Show {
        /// Profile name (default: the selected one).
        name: Option<String>,
    },
}

#[cfg(feature = "bootstrap")]
#[derive(Debug, Args)]
pub struct BootstrapArgs {
    /// Email of the administrator (else BOOTSTRAP_ADMIN_EMAIL, else asked).
    #[arg(long, value_name = "EMAIL")]
    pub email: Option<String>,
    /// Username of the administrator (default: `admin`).
    #[arg(long, value_name = "NAME")]
    pub username: Option<String>,
    /// Read the password from stdin instead of prompting.
    #[arg(long)]
    pub password_stdin: bool,
    /// Let the administrator keep this password past first login.
    #[arg(long)]
    pub no_must_change: bool,
    /// Assume the schema is current; do not apply migrations first.
    #[arg(long)]
    pub no_migrate: bool,
}

#[derive(Debug, Subcommand)]
pub enum TenantCommand {
    /// List the tenants the credential can see.
    List {
        /// Page size.
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Show one tenant as JSON.
    Show {
        /// Tenant slug (default: the profile's).
        slug: Option<String>,
    },
    /// Create a tenant (needs `ridm:tenants:create`, i.e. a `master` owner).
    Create {
        /// Slug the tenant is addressed by (`/t/{slug}/…`).
        slug: String,
        /// Display name (default: the slug).
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
    },
    /// Write a tenant's configuration document to a file or stdout.
    Export {
        /// Tenant slug (default: the profile's).
        slug: Option<String>,
        /// File to write (default: stdout).
        #[arg(short = 'o', long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// Apply a configuration document to a tenant.
    Import {
        /// Tenant slug (default: the profile's).
        slug: Option<String>,
        /// Document to apply (`-` for stdin).
        #[arg(short = 'f', long, default_value = "-", value_name = "FILE")]
        file: String,
        /// Also delete configuration the document does not mention.
        #[arg(long)]
        prune: bool,
        /// Apply without showing the plan and asking first.
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Show what an import would change, changing nothing.
    Diff {
        /// Tenant slug (default: the profile's).
        slug: Option<String>,
        /// Document to compare against (`-` for stdin).
        #[arg(short = 'f', long, default_value = "-", value_name = "FILE")]
        file: String,
        /// Count deletions too.
        #[arg(long)]
        prune: bool,
        /// Exit 3 when the plan is not empty (for pipelines).
        #[arg(long)]
        exit_code: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// List a tenant's signing keys.
    List {
        /// Only keys in this state (`pending`, `active`, `retiring`, `revoked`).
        #[arg(long, value_name = "STATUS")]
        status: Option<String>,
    },
    /// Mint a new signing key and start signing with it at once.
    Rotate,
}

#[derive(Debug, Subcommand)]
pub enum MasterKeyCommand {
    /// How many stored secrets are still on an older generation.
    Status,
    /// Re-encrypt every secret at rest under the current generation.
    Rotate {
        /// Rotate without asking first.
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum UserCommand {
    /// Create a user, optionally with a password.
    Create {
        /// Username, unique within the tenant.
        username: String,
        #[arg(long, value_name = "EMAIL")]
        email: Option<String>,
        /// Treat the email as already verified.
        #[arg(long)]
        email_verified: bool,
        #[arg(long, value_name = "PHONE")]
        phone: Option<String>,
        #[arg(long, value_name = "TAG")]
        locale: Option<String>,
        /// `active`, `disabled`, `locked` or `pending` (default: active).
        #[arg(long, value_name = "STATUS")]
        status: Option<String>,
        /// Identifier in the system this user came from.
        #[arg(long, value_name = "ID")]
        external_id: Option<String>,
        /// Profile attributes as a JSON object.
        #[arg(long, value_name = "JSON")]
        attributes: Option<String>,
        /// Read the password from stdin.
        #[arg(long, conflicts_with = "temporary_password")]
        password_stdin: bool,
        /// Generate a temporary password and print it once.
        #[arg(long)]
        temporary_password: bool,
    },
    /// Set or reset a user's password.
    Reset {
        /// User id, username or email address.
        user: String,
        /// Read the new password from stdin (else one is generated).
        #[arg(long)]
        password_stdin: bool,
        /// Keep the password past the next login.
        #[arg(long)]
        no_must_change: bool,
        /// Accept a password the tenant policy would refuse.
        #[arg(long)]
        skip_policy: bool,
        /// Email the user that their password changed.
        #[arg(long)]
        notify: bool,
        /// End the user's sessions so the new password is needed everywhere.
        #[arg(long)]
        revoke_sessions: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ClientCommand {
    /// Register an OAuth client; a confidential one prints its secret once.
    Create(Box<ClientCreate>),
    /// Initial access tokens for dynamic client registration, which
    /// `/register` demands when the tenant's `dcr.mode` is
    /// `initial_access_token`.
    Iat {
        #[command(subcommand)]
        command: IatCommand,
    },
}

#[derive(Debug, Args)]
pub struct ClientCreate {
    /// Display name, shown on the consent screen.
    #[arg(long, value_name = "NAME")]
    pub name: String,
    /// Public identifier (generated when absent).
    #[arg(long, value_name = "ID")]
    pub client_id: Option<String>,
    /// `spa`, `web`, `native`, `machine` or `device`.
    #[arg(long = "type", value_name = "TYPE")]
    pub client_type: Option<String>,
    #[arg(long = "redirect-uri", value_name = "URI")]
    pub redirect_uris: Vec<String>,
    #[arg(long = "post-logout-redirect-uri", value_name = "URI")]
    pub post_logout_redirect_uris: Vec<String>,
    /// Grant type the client may use; repeat for several.
    #[arg(long = "grant", value_name = "GRANT")]
    pub grants: Vec<String>,
    /// Scope the client may ask for; repeat for several.
    #[arg(long = "scope", value_name = "SCOPE")]
    pub scopes: Vec<String>,
    /// Resource server the client may get tokens for; repeat for several.
    #[arg(long = "audience", value_name = "AUDIENCE")]
    pub audiences: Vec<String>,
    /// Browser origin allowed to call the API; repeat for several.
    #[arg(long = "cors-origin", value_name = "ORIGIN")]
    pub cors_origins: Vec<String>,
    /// `none`, `client_secret_basic`, `client_secret_post`, `private_key_jwt`.
    #[arg(long, value_name = "METHOD")]
    pub auth_method: Option<String>,
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
    /// Do not require PKCE (confidential clients only).
    #[arg(long)]
    pub no_pkce: bool,
    /// Skip the consent screen (first-party applications).
    #[arg(long)]
    pub no_consent: bool,
}

#[derive(Debug, Subcommand)]
pub enum IatCommand {
    /// Issue a token; it is printed once.
    Create {
        /// What the token is for.
        #[arg(long, value_name = "TEXT")]
        description: Option<String>,
        /// Seconds until it expires (default: never).
        #[arg(long, value_name = "SECS")]
        expires_in: Option<u64>,
        /// Registrations it allows (default: no limit).
        #[arg(long, value_name = "N")]
        max_uses: Option<u32>,
    },
    /// List the tenant's tokens (never their secrets).
    List,
    /// Revoke a token by its id.
    Revoke {
        #[arg(value_name = "ID")]
        id: String,
    },
}
