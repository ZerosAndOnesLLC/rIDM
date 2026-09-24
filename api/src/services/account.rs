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

/// Live consents with the client behind each (read together), newest first.
pub async fn consented_apps(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<ConsentedApp>> {
    Ok(consents::list_for_user(state, tenant_id, user_id)
        .await?
        .into_iter()
        .map(|c| ConsentedApp {
            client_id: c.consent.client_id,
            client: c.client,
            name: c.client_name,
            logo_uri: c.logo_uri,
            tos_uri: c.tos_uri,
            policy_uri: c.policy_uri,
            scopes: c.consent.scopes,
            granted_at: c.consent.granted_at,
        })
        .collect())
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
    /// Personal access tokens (metadata only).
    pub personal_access_tokens: Vec<crate::models::PersonalAccessToken>,
    /// Upstream identities linked to the account.
    pub identities: Vec<crate::models::LinkedIdentity>,
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
        personal_access_tokens: crate::services::personal_access_tokens::list(
            state, tenant.id, user.id,
        )
        .await?,
        identities: crate::services::broker::identities_of(state, tenant.id, user.id).await?,
        roles: roles::effective_role_names(state, tenant.id, user.id, user.org_id).await?,
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
    if !admin_access::permissions_of_user(
        state,
        tenant.id,
        user.id,
        admin_access::OrgScope::Anywhere,
    )
    .await?
    .is_empty()
    {
        return Err(AppError::Forbidden(
            "administrators must be removed by another administrator".into(),
        ));
    }
    let actor = Actor::User { id: user.id };
    refresh_tokens::revoke_for_user(state, tenant.id, actor.clone(), user.id, None).await?;
    trusted_devices::revoke_all(state, tenant.id, user.id).await?;
    crate::services::personal_access_tokens::revoke_all_for_user(state, tenant.id, user.id).await?;
    // Ends every session too, telling the relying parties.
    crate::services::users::delete(state, tenant.id, actor, user.id).await
}

/// Remove soft-deleted users older than `retention_days` (everything
/// attached to them cascades). Returns the number of rows purged.
///
/// Users go in batches, each in its own transaction, so the cascade into
/// every attached table stays bounded. A batch that fails is retried one
/// user at a time: a row that cannot be removed is logged and left for the
/// next pass instead of holding back the rest of the tenant.
pub async fn purge_deleted(
    state: &AppState,
    tenant_id: Uuid,
    retention_days: u32,
) -> AppResult<u64> {
    const BATCH: i64 = 500;
    let cutoff = Utc::now() - Duration::days(i64::from(retention_days));
    let mut purged = 0;
    let mut after = None;
    loop {
        let mut tx = db::read_tx(&state.db, tenant_id).await?;
        let ids = repos::users::deleted_before(&mut *tx, tenant_id, cutoff, after, BATCH).await?;
        tx.commit().await?;
        let Some(last) = ids.last().copied() else {
            break;
        };
        after = Some(last);
        match purge_ids(state, tenant_id, &ids).await {
            Ok(n) => purged += n,
            Err(err) => {
                tracing::warn!(tenant = %tenant_id, error = %err, "user purge batch failed; retrying one by one");
                for id in &ids {
                    match purge_ids(state, tenant_id, std::slice::from_ref(id)).await {
                        Ok(n) => purged += n,
                        Err(err) => {
                            tracing::error!(tenant = %tenant_id, user = %id, error = %err, "deleted user could not be purged")
                        }
                    }
                }
            }
        }
        if (ids.len() as i64) < BATCH {
            break;
        }
    }
    Ok(purged)
}

async fn purge_ids(state: &AppState, tenant_id: Uuid, ids: &[Uuid]) -> AppResult<u64> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let n = repos::users::purge_ids(&mut *tx, tenant_id, ids).await?;
    tx.commit().await?;
    Ok(n)
}
