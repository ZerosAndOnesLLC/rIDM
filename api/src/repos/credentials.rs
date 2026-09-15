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
