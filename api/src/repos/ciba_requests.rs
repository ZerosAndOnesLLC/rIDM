//! Backchannel authentication requests (CIBA): the audit trail and the
//! account console's list (tenant-bound transactions). The live request is
//! in Valkey.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgExecutor;
use uuid::Uuid;

pub struct NewRequest<'a> {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub auth_req_hash: &'a str,
    pub scopes: &'a [String],
    pub binding_message: Option<&'a str>,
    pub acr_values: &'a [String],
    pub delivery_mode: &'a str,
    pub expires_at: DateTime<Utc>,
}

pub async fn insert<'e>(exec: impl PgExecutor<'e>, r: &NewRequest<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO ciba_requests (id, tenant_id, client_id, user_id, auth_req_hash, scopes, \
         binding_message, acr_values, delivery_mode, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(r.id)
    .bind(r.tenant_id)
    .bind(r.client_id)
    .bind(r.user_id)
    .bind(r.auth_req_hash)
    .bind(r.scopes)
    .bind(r.binding_message)
    .bind(r.acr_values)
    .bind(r.delivery_mode)
    .bind(r.expires_at)
    .execute(exec)
    .await?;
    Ok(())
}

/// Requests still waiting on `user_id`, for the per-user cap.
pub async fn count_pending<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM ciba_requests \
         WHERE tenant_id = $1 AND user_id = $2 AND status = 'pending' AND expires_at > now()",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(exec)
    .await
}

/// A request waiting on the user, as their account console shows it.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct PendingRequest {
    pub id: Uuid,
    /// The client's row id.
    pub client_id: Uuid,
    pub client_name: String,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub scopes: Vec<String>,
    /// The text the client shows on its own device, to compare.
    pub binding_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// What is waiting on `user_id`, newest first.
pub async fn list_pending<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<PendingRequest>, sqlx::Error> {
    sqlx::query_as(
        "SELECT r.id, r.client_id, c.name AS client_name, c.logo_uri, c.client_uri, r.scopes, \
         r.binding_message, r.created_at, r.expires_at \
         FROM ciba_requests r \
         JOIN clients c ON c.tenant_id = r.tenant_id AND c.id = r.client_id \
         WHERE r.tenant_id = $1 AND r.user_id = $2 AND r.status = 'pending' AND r.expires_at > now() \
         ORDER BY r.created_at DESC \
         LIMIT 50",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_all(exec)
    .await
}

/// The Valkey key of one of `user_id`'s pending requests, locked until the
/// transaction ends so two decisions cannot race.
pub async fn pending_hash_for_update<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT auth_req_hash FROM ciba_requests \
         WHERE tenant_id = $1 AND id = $2 AND user_id = $3 AND status = 'pending' \
         AND expires_at > now() FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(user_id)
    .fetch_optional(exec)
    .await
}

/// Record the user's decision (`approved` or `denied`).
pub async fn decide<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE ciba_requests SET status = $3, decided_at = now() \
         WHERE tenant_id = $1 AND id = $2 AND status = 'pending'",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(status)
    .execute(exec)
    .await?;
    Ok(())
}

/// The client collected its tokens.
pub async fn consume<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE ciba_requests SET status = 'consumed', consumed_at = now() \
         WHERE tenant_id = $1 AND id = $2 AND status = 'approved'",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(())
}
