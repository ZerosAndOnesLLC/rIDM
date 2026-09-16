//! Self-service account lifecycle: the applications a user granted access
//! to, the export of everything rIDM holds about them, and deleting the
//! account (soft delete now, purged after the tenant's retention period).

use chrono::{DateTime, Duration, Utc};
use ridm_core::events::Actor;
use serde::Serialize;
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{AuditEvent, AuditFilter, Credential, Group, Tenant, TrustedDevice, User};
use crate::repos;
use crate::services::sessions::SsoSession;
use crate::services::{
    admin_access, audit, clients, consents, groups, refresh_tokens, roles, sessions,
    trusted_devices,
};
use crate::state::AppState;

/// Audit rows an export carries at most (newest first).
const EXPORT_AUDIT_LIMIT: u32 = 1000;

/// An application the user granted scopes to.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ConsentedApp {
    /// The client's row id (the key for revocation).
    pub client_id: Uuid,
    /// The client's public `client_id`.
    pub client: String,
    pub name: String,
    pub logo_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
}

/// Live consents with the client behind each; a consent whose client is
/// gone is left out.
pub async fn consented_apps(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<ConsentedApp>> {
    let mut out = vec![];
    for c in consents::list_for_user(state, tenant_id, user_id).await? {
        if c.revoked_at.is_some() {
            continue;
        }
        let client = match clients::get(state, tenant_id, c.client_id).await {
            Ok(client) => client,
            Err(AppError::NotFound(_)) => continue,
            Err(e) => return Err(e),
        };
        out.push(ConsentedApp {
            client_id: client.id,
            client: client.client_id,
            name: client.name,
            logo_uri: client.logo_uri,
            tos_uri: client.tos_uri,
            policy_uri: client.policy_uri,
            scopes: c.scopes,
            granted_at: c.granted_at,
        });
    }
    out.sort_by_key(|a| std::cmp::Reverse(a.granted_at));
    Ok(out)
}

/// Withdraw a client's consent and the refresh tokens it holds for the user.
pub async fn revoke_app(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: Uuid,
) -> AppResult<bool> {
    let actor = Actor::User { id: user_id };
    if !consents::revoke(state, tenant_id, actor.clone(), user_id, client_id).await? {
        return Ok(false);
    }
    if let Ok(client) = clients::get(state, tenant_id, client_id).await {
        refresh_tokens::revoke_for_user(state, tenant_id, actor, user_id, Some(&client.client_id))
            .await?;
    }
    Ok(true)
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ExportedTenant {
    pub slug: String,
    pub display_name: String,
}

/// Everything rIDM holds about one user, for a data-portability request.
/// Secrets (password hashes, factor material, device keys) are never part
/// of it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AccountExport {
    pub exported_at: DateTime<Utc>,
    pub tenant: ExportedTenant,
    pub user: User,
    /// Second factors, passkeys and recovery-code sets (metadata only).
    pub credentials: Vec<Credential>,
    pub trusted_devices: Vec<TrustedDevice>,
    pub sessions: Vec<SsoSession>,
    pub consents: Vec<ConsentedApp>,
    /// Effective role names.
    pub roles: Vec<String>,
    /// Groups the user belongs to, ancestors included.
    pub groups: Vec<Group>,
    /// The user's audit trail (as actor or subject), newest first, capped.
    pub audit_events: Vec<AuditEvent>,
}

pub async fn export(state: &AppState, tenant: &Tenant, user: &User) -> AppResult<AccountExport> {
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let credentials = repos::credentials::list_for_user(&mut *tx, tenant.id, user.id).await?;
    tx.commit().await?;
    let audit_events = audit::list(
        state,
        Some(tenant.id),
        &AuditFilter {
            user_id: Some(user.id),
            ..Default::default()
        },
        None,
        Some(EXPORT_AUDIT_LIMIT),
    )
    .await?
    .items;
    Ok(AccountExport {
        exported_at: Utc::now(),
        tenant: ExportedTenant {
            slug: tenant.slug.clone(),
            display_name: tenant.display_name.clone(),
        },
        user: user.clone(),
        credentials,
        trusted_devices: trusted_devices::list(state, tenant.id, user.id).await?,
        sessions: sessions::list_live_for_user(state, tenant.id, user.id).await?,
        consents: consented_apps(state, tenant.id, user.id).await?,
        roles: roles::effective_role_names(state, tenant.id, user.id).await?,
        groups: groups::groups_of_user(state, tenant.id, user.id, true).await?,
        audit_events,
    })
}

/// Delete one's own account: every session, token and trusted device ends
/// now and the row is soft-deleted (the username and email free up at
/// once); the purge job removes it for good after the retention period.
/// Refused when the tenant does not allow it, and for administrators, who
/// must be removed by another administrator so a tenant is never left
/// without one by accident.
pub async fn delete_own(state: &AppState, tenant: &Tenant, user: &User) -> AppResult<()> {
    if !tenant.settings.account.self_deletion {
        return Err(AppError::Forbidden(
            "this organisation does not allow deleting your own account".into(),
        ));
    }
    if !admin_access::permissions_of_user(state, tenant.id, user.id)
        .await?
        .is_empty()
    {
        return Err(AppError::Forbidden(
            "administrators must be removed by another administrator".into(),
        ));
    }
    let actor = Actor::User { id: user.id };
    sessions::revoke_all_for_user(state, tenant.id, user.id).await?;
    refresh_tokens::revoke_for_user(state, tenant.id, actor.clone(), user.id, None).await?;
    trusted_devices::revoke_all(state, tenant.id, user.id).await?;
    crate::services::users::delete(state, tenant.id, actor, user.id).await
}

/// Remove soft-deleted users older than `retention_days` (everything
/// attached to them cascades). Returns the number of rows purged.
pub async fn purge_deleted(
    state: &AppState,
    tenant_id: Uuid,
    retention_days: u32,
) -> AppResult<u64> {
    let cutoff = Utc::now() - Duration::days(i64::from(retention_days));
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let n = repos::users::purge_deleted(&mut *tx, tenant_id, cutoff).await?;
    tx.commit().await?;
    Ok(n)
}
