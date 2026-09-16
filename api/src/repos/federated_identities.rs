//! Links between users and upstream identities (tenant-bound transactions).

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::models::{FederatedIdentity, LinkedIdentity};

pub async fn find<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
    external_subject: &str,
) -> Result<Option<FederatedIdentity>, sqlx::Error> {
    sqlx::query_as::<_, FederatedIdentity>(
        "SELECT tenant_id, user_id, idp_id, external_subject, external_email, external_username, linked_at, last_login_at FROM federated_identities WHERE tenant_id = $1 AND idp_id = $2 AND external_subject = $3",
    )
    .bind(tenant_id)
    .bind(idp_id)
    .bind(external_subject)
    .fetch_optional(exec)
    .await
}

pub async fn find_for_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    idp_id: Uuid,
) -> Result<Option<FederatedIdentity>, sqlx::Error> {
    sqlx::query_as::<_, FederatedIdentity>(
        "SELECT tenant_id, user_id, idp_id, external_subject, external_email, external_username, linked_at, last_login_at FROM federated_identities WHERE tenant_id = $1 AND user_id = $2 AND idp_id = $3",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(idp_id)
    .fetch_optional(exec)
    .await
}

/// A link to store.
pub struct NewLink<'a> {
    pub user_id: Uuid,
    pub idp_id: Uuid,
    pub external_subject: &'a str,
    pub external_email: Option<&'a str>,
    pub external_username: Option<&'a str>,
    pub last_login_at: Option<DateTime<Utc>>,
}

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    link: NewLink<'_>,
) -> Result<FederatedIdentity, sqlx::Error> {
    let NewLink {
        user_id,
        idp_id,
        external_subject,
        external_email,
        external_username,
        last_login_at,
    } = link;
    sqlx::query_as::<_, FederatedIdentity>(
        "INSERT INTO federated_identities (tenant_id, user_id, idp_id, external_subject, \
         external_email, external_username, last_login_at) VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING tenant_id, user_id, idp_id, external_subject, external_email, external_username, linked_at, last_login_at",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(idp_id)
    .bind(external_subject)
    .bind(external_email)
    .bind(external_username)
    .bind(last_login_at)
    .fetch_one(exec)
    .await
}

/// Record a sign-in through the identity and refresh what upstream said.
pub async fn touch<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
    external_subject: &str,
    external_email: Option<&str>,
    external_username: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE federated_identities SET last_login_at = now(), external_email = $4, \
         external_username = $5 WHERE tenant_id = $1 AND idp_id = $2 AND external_subject = $3",
    )
    .bind(tenant_id)
    .bind(idp_id)
    .bind(external_subject)
    .bind(external_email)
    .bind(external_username)
    .execute(exec)
    .await?;
    Ok(())
}

pub async fn delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    idp_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "DELETE FROM federated_identities WHERE tenant_id = $1 AND user_id = $2 AND idp_id = $3",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(idp_id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// A user's identities with their providers, in provider order.
pub async fn list_for_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<LinkedIdentity>, sqlx::Error> {
    sqlx::query_as::<_, LinkedIdentity>(
        "SELECT f.idp_id, p.alias, p.display_name, p.preset, f.external_subject, f.external_email, \
         f.external_username, f.linked_at, f.last_login_at \
         FROM federated_identities f JOIN identity_providers p ON p.tenant_id = f.tenant_id AND p.id = f.idp_id \
         WHERE f.tenant_id = $1 AND f.user_id = $2 ORDER BY p.sort_order, p.alias",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_all(exec)
    .await
}

/// How many users are linked to a provider.
pub async fn count_for_idp<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM federated_identities WHERE tenant_id = $1 AND idp_id = $2",
    )
    .bind(tenant_id)
    .bind(idp_id)
    .fetch_one(exec)
    .await
}
