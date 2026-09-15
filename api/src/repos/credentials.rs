//! Tenant-scoped credential rows (run inside a tenant-bound transaction).
//! Only the metadata columns are read here; the encrypted material is the
//! business of the factor that owns it.

use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::Credential;

const COLUMNS: &str = "id, tenant_id, user_id, type, label, created_at, last_used_at";

pub async fn list_for_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<Credential>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM credentials WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND user_id = ")
        .push_bind(user_id)
        .push(" ORDER BY created_at, id");
    qb.build_query_as::<Credential>().fetch_all(exec).await
}

pub async fn delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res =
        sqlx::query("DELETE FROM credentials WHERE tenant_id = $1 AND user_id = $2 AND id = $3")
            .bind(tenant_id)
            .bind(user_id)
            .bind(id)
            .execute(exec)
            .await?;
    Ok(res.rows_affected() > 0)
}

/// A credential together with its encrypted material, for the factor that owns it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CredentialSecret {
    pub id: Uuid,
    pub user_id: Uuid,
    #[sqlx(rename = "type")]
    pub kind: String,
    pub label: Option<String>,
    pub data_enc: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

const SECRET_COLUMNS: &str = "id, user_id, type, label, data_enc, created_at, last_used_at";

pub async fn list_secrets_of_type<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    kind: &str,
) -> Result<Vec<CredentialSecret>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(SECRET_COLUMNS)
        .push(" FROM credentials WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND user_id = ")
        .push_bind(user_id)
        .push(" AND type = ")
        .push_bind(kind)
        .push(" ORDER BY created_at, id");
    qb.build_query_as::<CredentialSecret>()
        .fetch_all(exec)
        .await
}

pub async fn count_of_types<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    kinds: &[&str],
) -> Result<i64, sqlx::Error> {
    let kinds: Vec<String> = kinds.iter().map(|k| k.to_string()).collect();
    sqlx::query_scalar(
        "SELECT count(*) FROM credentials WHERE tenant_id = $1 AND user_id = $2 AND type = ANY($3)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(&kinds)
    .fetch_one(exec)
    .await
}

/// A credential row to store, with its already-encrypted material.
pub struct NewCredential<'a> {
    pub id: Uuid,
    pub user_id: Uuid,
    pub kind: &'a str,
    pub label: Option<&'a str>,
    pub data_enc: &'a [u8],
    pub key_version: i32,
}

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    new: NewCredential<'_>,
) -> Result<Credential, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO credentials (id, tenant_id, user_id, type, label, data_enc, key_version) VALUES (",
    );
    qb.push_bind(new.id)
        .push(", ")
        .push_bind(tenant_id)
        .push(", ")
        .push_bind(new.user_id)
        .push(", ")
        .push_bind(new.kind)
        .push(", ")
        .push_bind(new.label)
        .push(", ")
        .push_bind(new.data_enc)
        .push(", ")
        .push_bind(new.key_version)
        .push(") RETURNING ")
        .push(COLUMNS);
    qb.build_query_as::<Credential>().fetch_one(exec).await
}

/// Replace the encrypted material (e.g. a recovery code marked used).
pub async fn update_data<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    data_enc: &[u8],
    key_version: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE credentials SET data_enc = $3, key_version = $4, last_used_at = now() \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(data_enc)
    .bind(key_version)
    .execute(exec)
    .await?;
    Ok(())
}

pub async fn touch_last_used<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE credentials SET last_used_at = now() WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(())
}

pub async fn delete_of_type<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    kind: &str,
) -> Result<u64, sqlx::Error> {
    let res =
        sqlx::query("DELETE FROM credentials WHERE tenant_id = $1 AND user_id = $2 AND type = $3")
            .bind(tenant_id)
            .bind(user_id)
            .bind(kind)
            .execute(exec)
            .await?;
    Ok(res.rows_affected())
}
