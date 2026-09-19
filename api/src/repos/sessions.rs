//! Session mirror rows (run inside a tenant transaction).

use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::SessionRow;
use crate::services::sessions::SsoSession;

const COLUMNS: &str = "id, tenant_id, user_id, auth_time, amr, acr, ip, user_agent, device_id, org_id, \
    created_at, last_seen_at, expires_at, idle_expires_at, revoked_at";

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    s: &SsoSession,
    device_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    let device_id = device_id.or(s.device_id);
    sqlx::query(
        "INSERT INTO sso_sessions (id, tenant_id, user_id, auth_time, amr, acr, ip, user_agent, device_id, \
         org_id, created_at, last_seen_at, expires_at, idle_expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(s.id)
    .bind(s.tenant_id)
    .bind(s.user_id)
    .bind(s.auth_time)
    .bind(&s.amr)
    .bind(&s.acr)
    .bind(&s.ip)
    .bind(&s.user_agent)
    .bind(device_id)
    .bind(s.org_id)
    .bind(s.created_at)
    .bind(s.last_seen_at)
    .bind(s.expires_at)
    .bind(s.idle_expires_at)
    .execute(exec)
    .await?;
    Ok(())
}

pub async fn touch<'e>(exec: impl PgExecutor<'e>, s: &SsoSession) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE sso_sessions SET last_seen_at = $3, idle_expires_at = $4, auth_time = $5, amr = $6, acr = $7 \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(s.tenant_id)
    .bind(s.id)
    .bind(s.last_seen_at)
    .bind(s.idle_expires_at)
    .bind(s.auth_time)
    .bind(&s.amr)
    .bind(&s.acr)
    .execute(exec)
    .await?;
    Ok(())
}

pub async fn set_device<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    device_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sso_sessions SET device_id = $3 WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .bind(device_id)
        .execute(exec)
        .await?;
    Ok(())
}

/// The organization a session acts in, chosen while signing in.
pub async fn set_organization<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    org_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sso_sessions SET org_id = $3 WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .bind(org_id)
        .execute(exec)
        .await?;
    Ok(())
}

pub async fn mark_revoked<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sso_sessions SET revoked_at = now() WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(())
}

/// Was this session revoked (signed out, as opposed to merely expired)? A
/// row already purged counts as not revoked.
pub async fn is_revoked<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let revoked: Option<bool> = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM sso_sessions WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(exec)
    .await?;
    Ok(revoked.unwrap_or(false))
}

/// Live sessions of a user, oldest first.
pub async fn list_live_for_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<SessionRow>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM sso_sessions WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND user_id = ")
        .push_bind(user_id)
        .push(" AND revoked_at IS NULL AND expires_at > now() AND idle_expires_at > now() ORDER BY created_at ASC");
    qb.build_query_as::<SessionRow>().fetch_all(exec).await
}

/// Earlier sessions of the user (excluding `exclude_session`): whether any
/// exist at all, and whether any came from the same browser (user agent).
pub async fn browser_history<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    user_agent: &str,
    exclude_session: Uuid,
) -> Result<(bool, bool), sqlx::Error> {
    sqlx::query_as(
        "SELECT count(*) > 0, COALESCE(bool_or(user_agent = $3), false) FROM sso_sessions \
         WHERE tenant_id = $1 AND user_id = $2 AND id <> $4",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(user_agent)
    .bind(exclude_session)
    .fetch_one(exec)
    .await
}

pub async fn purge<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    older_than: chrono::DateTime<chrono::Utc>,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM sso_sessions WHERE tenant_id = $1 AND (expires_at < $2 OR (revoked_at IS NOT NULL AND revoked_at < $2))")
        .bind(tenant_id)
        .bind(older_than)
        .execute(exec)
        .await?
        .rows_affected())
}
