//! First-run bootstrap: make sure the `master` tenant exists and has a global
//! administrator. Idempotent: once any user holds the global owner role in
//! `master`, nothing is changed.
//!
//! Triggered at startup from `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD`,
//! or interactively with `ridm-api bootstrap`.

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{MASTER_TENANT_ID, MASTER_TENANT_SLUG, NewRole, NewUser, Principal, Role};
use crate::repos;
use crate::services::password::{self, SetPasswordOptions};
use crate::services::{roles, tenants, users};
use crate::state::AppState;

/// Built-in role in `master` granting every permission across all tenants.
/// Phase 5.1 attaches the `ridm:*` permission model to it.
pub const GLOBAL_OWNER_ROLE: &str = "ridm:owner";

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
    if repos::tenants::find_by_id(&state.db, MASTER_TENANT_ID)
        .await?
        .is_some()
    {
        return Ok(());
    }
    // Migration 0001 seeds it; recreate defensively if it was removed.
    repos::tenants::insert(
        &state.db,
        MASTER_TENANT_ID,
        MASTER_TENANT_SLUG,
        "Master",
        &Default::default(),
    )
    .await
    .map_err(AppError::from_db)?;
    Ok(())
}

async fn ensure_owner_role(state: &AppState) -> AppResult<Role> {
    let mut tx = db::tenant_tx(&state.db, MASTER_TENANT_ID).await?;
    let existing =
        repos::roles::find_by_name(&mut *tx, MASTER_TENANT_ID, None, GLOBAL_OWNER_ROLE).await?;
    tx.commit().await?;
    if let Some(r) = existing {
        return Ok(r);
    }
    roles::create(
        state,
        MASTER_TENANT_ID,
        Actor::System,
        NewRole {
            name: GLOBAL_OWNER_ROLE.into(),
            client_id: None,
            description: Some("Global owner: full access to every tenant".into()),
        },
    )
    .await
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
