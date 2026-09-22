//! Certificate authorities for `tls_client_auth` clients (tenant-bound
//! transactions).

use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::MtlsTrustAnchor;

const COLUMNS: &str =
    "id, tenant_id, name, certificate_pem, subject, fingerprint, not_before, not_after, created_at";

pub async fn list<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Vec<MtlsTrustAnchor>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM mtls_trust_anchors WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" ORDER BY created_at, id");
    qb.build_query_as::<MtlsTrustAnchor>().fetch_all(exec).await
}

pub async fn count<'e>(exec: impl PgExecutor<'e>, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM mtls_trust_anchors WHERE tenant_id = $1")
        .bind(tenant_id)
        .fetch_one(exec)
        .await
}

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    a: &MtlsTrustAnchor,
) -> Result<MtlsTrustAnchor, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO mtls_trust_anchors (id, tenant_id, name, certificate_pem, subject, \
         fingerprint, not_before, not_after) VALUES (",
    );
    let mut s = qb.separated(", ");
    s.push_bind(a.id)
        .push_bind(a.tenant_id)
        .push_bind(&a.name)
        .push_bind(&a.certificate_pem)
        .push_bind(&a.subject)
        .push_bind(&a.fingerprint)
        .push_bind(a.not_before)
        .push_bind(a.not_after);
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<MtlsTrustAnchor>().fetch_one(exec).await
}

pub async fn delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM mtls_trust_anchors WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}
