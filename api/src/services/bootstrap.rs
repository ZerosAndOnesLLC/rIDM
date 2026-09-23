//! First-run bootstrap: make sure the `master` tenant exists and has a global
//! administrator. Idempotent: once any user holds the global owner role in
//! `master`, nothing is changed.
//!
//! Triggered at startup from `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD`,
//! or interactively with `ridm-api bootstrap`. `BOOTSTRAP_SAMPLE_CLIENT=true`
//! also makes sure `master` has the sample public client
//! ([`ensure_sample_client`]).

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{
    ClientType, MASTER_TENANT_ID, MASTER_TENANT_SLUG, NewClient, NewUser, Principal, Role,
};
use crate::repos;
use crate::services::password::{self, SetPasswordOptions};
use crate::services::{admin_access, clients, roles, tenants, users};
use crate::state::AppState;

/// Built-in role in `master` granting every admin permission across all
/// tenants (see [`crate::services::admin_access`]).
pub const GLOBAL_OWNER_ROLE: &str = admin_access::OWNER_ROLE;

/// `client_id` of the development sample client.
pub const SAMPLE_CLIENT_ID: &str = "sample-spa";
/// Where the sample client's authorization responses go: a SPA on the usual
/// development port.
pub const SAMPLE_CLIENT_REDIRECT: &str = "http://localhost:3000/callback";

#[derive(Debug, Clone)]
pub struct BootstrapRequest {
    pub admin_email: String,
    pub admin_username: String,
    pub admin_password: Zeroizing<String>,
    /// Force a password change at first login (recommended when the password
    /// came from an environment variable or compose file).
    pub must_change_password: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapOutcome {
    /// Nothing to do: a global owner already exists.
    AlreadyBootstrapped,
    /// Created the admin user (and the owner role if missing).
    Created { admin_user_id: Uuid },
}

/// Does `master` already have a user holding the global owner role?
pub async fn is_bootstrapped(state: &AppState) -> AppResult<bool> {
    let mut tx = db::tenant_tx(&state.db, MASTER_TENANT_ID).await?;
    let Some(role) =
        repos::roles::find_by_name(&mut *tx, MASTER_TENANT_ID, None, GLOBAL_OWNER_ROLE).await?
    else {
        return Ok(false);
    };
    let holders: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM role_assignments ra \
         JOIN users u ON u.tenant_id = ra.tenant_id AND u.id = ra.user_id \
         WHERE ra.tenant_id = $1 AND ra.role_id = $2 AND u.deleted_at IS NULL",
    )
    .bind(MASTER_TENANT_ID)
    .bind(role.id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(holders > 0)
}

async fn ensure_master_tenant(state: &AppState) -> AppResult<()> {
    if repos::tenants::find_by_id(state.db.home(), MASTER_TENANT_ID)
        .await?
        .is_some()
    {
        return Ok(());
    }
    // Migration 0001 seeds it; recreate defensively if it was removed.
    repos::tenants::insert(
        state.db.home(),
        MASTER_TENANT_ID,
        MASTER_TENANT_SLUG,
        "Master",
        &Default::default(),
        None,
    )
    .await
    .map_err(AppError::from_db)?;
    Ok(())
}

/// The owner role is seeded by the admin-model migration for every tenant;
/// re-run the seed if `master` somehow lacks it (it is idempotent).
async fn ensure_owner_role(state: &AppState) -> AppResult<Role> {
    let mut tx = db::tenant_tx(&state.db, MASTER_TENANT_ID).await?;
    let existing =
        repos::roles::find_by_name(&mut *tx, MASTER_TENANT_ID, None, GLOBAL_OWNER_ROLE).await?;
    if let Some(r) = existing {
        tx.commit().await?;
        return Ok(r);
    }
    sqlx::query("SELECT seed_admin_model($1)")
        .bind(MASTER_TENANT_ID)
        .execute(&mut *tx)
        .await?;
    let role = repos::roles::find_by_name(&mut *tx, MASTER_TENANT_ID, None, GLOBAL_OWNER_ROLE)
        .await?
        .ok_or_else(|| {
            AppError::Internal("seed_admin_model did not create the owner role".into())
        })?;
    tx.commit().await?;
    roles::bump_roles_version(state, MASTER_TENANT_ID).await?;
    Ok(role)
}

pub async fn run(state: &AppState, req: BootstrapRequest) -> AppResult<BootstrapOutcome> {
    ensure_master_tenant(state).await?;
    if is_bootstrapped(state).await? {
        return Ok(BootstrapOutcome::AlreadyBootstrapped);
    }
    let master = tenants::get(state, MASTER_TENANT_ID).await?;

    // Check the password policy before touching anything so that a rejected
    // password leaves no half-created admin behind.
    let problems = password::check_policy(&master.settings.password, &req.admin_password, None);
    if !problems.is_empty() {
        return Err(AppError::Validation(
            problems
                .into_iter()
                .map(|message| crate::error::FieldError {
                    field: "password".into(),
                    message,
                })
                .collect(),
        ));
    }

    let owner = ensure_owner_role(state).await?;

    // Reuse an existing user with that username/email (e.g. a partial earlier run).
    let existing = users::find_by_identifier(state, MASTER_TENANT_ID, &req.admin_username)
        .await?
        .or(users::find_by_identifier(state, MASTER_TENANT_ID, &req.admin_email).await?);
    let admin = match existing {
        Some(u) => u,
        None => {
            users::create(
                state,
                MASTER_TENANT_ID,
                Actor::System,
                NewUser {
                    username: req.admin_username.clone(),
                    email: Some(req.admin_email.clone()),
                    email_verified: true,
                    ..Default::default()
                },
            )
            .await?
        }
    };

    password::set_password(
        state,
        MASTER_TENANT_ID,
        &master.settings.password,
        Actor::System,
        admin.id,
        req.admin_password,
        SetPasswordOptions {
            must_change: req.must_change_password,
            skip_policy: false,
            by_user: false,
            notify: false,
        },
    )
    .await?;

    roles::assign(
        state,
        MASTER_TENANT_ID,
        Actor::System,
        owner.id,
        Principal::User { id: admin.id },
    )
    .await?;

    state.events.publish(Event::new(
        Some(MASTER_TENANT_ID),
        Actor::System,
        EventKind::Bootstrapped {
            admin_user_id: admin.id,
        },
    ));
    tracing::info!(user_id = %admin.id, username = %admin.username, "bootstrap: global admin created");
    Ok(BootstrapOutcome::Created {
        admin_user_id: admin.id,
    })
}

/// Make sure `master` has the development sample client: a public SPA client
/// ([`SAMPLE_CLIENT_ID`]) with PKCE, redirecting to [`SAMPLE_CLIENT_REDIRECT`].
/// Idempotent: an existing client with that id is left as it is. Returns
/// whether it was created now.
pub async fn ensure_sample_client(state: &AppState) -> AppResult<bool> {
    if clients::find_by_client_id(state, MASTER_TENANT_ID, SAMPLE_CLIENT_ID)
        .await?
        .is_some()
    {
        return Ok(false);
    }
    let created = clients::create(
        state,
        MASTER_TENANT_ID,
        Actor::System,
        NewClient {
            client_id: Some(SAMPLE_CLIENT_ID.into()),
            name: "Sample SPA".into(),
            client_type: Some(ClientType::Spa),
            description: Some("Development sample client (BOOTSTRAP_SAMPLE_CLIENT)".into()),
            redirect_uris: vec![SAMPLE_CLIENT_REDIRECT.into()],
            post_logout_redirect_uris: vec!["http://localhost:3000/".into()],
            cors_origins: vec!["http://localhost:3000".into()],
            ..Default::default()
        },
    )
    .await;
    match created {
        Ok(_) => {
            tracing::info!(
                tenant = MASTER_TENANT_SLUG,
                client_id = SAMPLE_CLIENT_ID,
                redirect_uri = SAMPLE_CLIENT_REDIRECT,
                "bootstrap: sample public client created"
            );
            Ok(true)
        }
        // Another node created it at the same moment.
        Err(AppError::Conflict(_)) => Ok(false),
        Err(e) => Err(e),
    }
}
