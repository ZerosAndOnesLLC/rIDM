//! Tenant-scoped client queries (run inside a tenant-bound transaction).

use sqlx::types::Json;
use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{Client, ClientSecretHash, ClientStatus};
use crate::util::cursor::Cursor;

const COLUMNS: &str = "id, tenant_id, client_id, name, client_type, description, logo_uri, client_uri, \
    tos_uri, policy_uri, secret_hashes, jwks, jwks_uri, token_endpoint_auth_method, redirect_uris, \
    post_logout_redirect_uris, allowed_grants, allowed_scopes, allowed_audiences, access_token_ttl_secs, \
    refresh_token_ttl_secs, id_token_ttl_secs, access_token_format, id_token_encryption, subject_type, \
    sector_identifier_uri, require_pkce, require_consent, cors_origins, initiate_login_uri, \
    backchannel_logout_uri, frontchannel_logout_uri, service_account_user_id, \
    registration_access_token_hash, status, created_at, updated_at";

pub async fn find_by_id<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<Client>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM clients WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<Client>().fetch_optional(exec).await
}

pub async fn find_by_client_id<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    client_id: &str,
) -> Result<Option<Client>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM clients WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND client_id = ")
        .push_bind(client_id);
    qb.build_query_as::<Client>().fetch_optional(exec).await
}

/// Insert a fully resolved client (defaults applied by the service).
pub async fn insert<'e>(exec: impl PgExecutor<'e>, c: &Client) -> Result<Client, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO clients (id, tenant_id, client_id, name, client_type, description, logo_uri, \
         client_uri, tos_uri, policy_uri, secret_hashes, jwks, jwks_uri, token_endpoint_auth_method, \
         redirect_uris, post_logout_redirect_uris, allowed_grants, allowed_scopes, allowed_audiences, \
         access_token_ttl_secs, refresh_token_ttl_secs, id_token_ttl_secs, access_token_format, \
         id_token_encryption, subject_type, sector_identifier_uri, require_pkce, require_consent, \
         cors_origins, initiate_login_uri, backchannel_logout_uri, frontchannel_logout_uri, \
         service_account_user_id, registration_access_token_hash, status) VALUES (",
    );
    let mut s = qb.separated(", ");
    s.push_bind(c.id)
        .push_bind(c.tenant_id)
        .push_bind(&c.client_id)
        .push_bind(&c.name)
        .push_bind(c.client_type)
        .push_bind(&c.description)
        .push_bind(&c.logo_uri)
        .push_bind(&c.client_uri)
        .push_bind(&c.tos_uri)
        .push_bind(&c.policy_uri)
        .push_bind(Json(&c.secret_hashes.0))
        .push_bind(&c.jwks)
        .push_bind(&c.jwks_uri)
        .push_bind(c.token_endpoint_auth_method)
        .push_bind(&c.redirect_uris)
        .push_bind(&c.post_logout_redirect_uris)
        .push_bind(&c.allowed_grants)
        .push_bind(&c.allowed_scopes)
        .push_bind(&c.allowed_audiences)
        .push_bind(c.access_token_ttl_secs)
        .push_bind(c.refresh_token_ttl_secs)
        .push_bind(c.id_token_ttl_secs)
        .push_bind(c.access_token_format)
        .push_bind(c.id_token_encryption.as_ref().map(|j| Json(&j.0)))
        .push_bind(c.subject_type)
        .push_bind(&c.sector_identifier_uri)
        .push_bind(c.require_pkce)
        .push_bind(c.require_consent)
        .push_bind(&c.cors_origins)
        .push_bind(&c.initiate_login_uri)
        .push_bind(&c.backchannel_logout_uri)
        .push_bind(&c.frontchannel_logout_uri)
        .push_bind(c.service_account_user_id)
        .push_bind(&c.registration_access_token_hash)
        .push_bind(c.status);
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<Client>().fetch_one(exec).await
}

pub async fn set_secret_hashes<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    hashes: &[ClientSecretHash],
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("UPDATE clients SET secret_hashes = $3 WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .bind(Json(hashes))
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn set_status<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    status: ClientStatus,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("UPDATE clients SET status = $3 WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .bind(status)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn set_service_account<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    user_id: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE clients SET service_account_user_id = $3 WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(user_id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM clients WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Keyset-paginated list with optional case-insensitive prefix search on client_id / name.
pub async fn list<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    search: Option<&str>,
    after: Option<Cursor>,
    limit: i64,
) -> Result<Vec<Client>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM clients WHERE tenant_id = ")
        .push_bind(tenant_id);
    if let Some(s) = search.map(str::trim).filter(|s| !s.is_empty()) {
        let pattern = format!(
            "{}%",
            s.replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        qb.push(" AND (client_id ILIKE ")
            .push_bind(pattern.clone())
            .push(" OR name ILIKE ")
            .push_bind(pattern)
            .push(")");
    }
    if let Some(c) = after {
        qb.push(" AND (created_at, id) > (")
            .push_bind(c.created_at)
            .push(", ")
            .push_bind(c.id)
            .push(")");
    }
    qb.push(" ORDER BY created_at, id LIMIT ")
        .push_bind(limit + 1);
    qb.build_query_as::<Client>().fetch_all(exec).await
}
