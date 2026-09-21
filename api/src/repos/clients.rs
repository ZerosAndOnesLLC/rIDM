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
    sector_identifier_uri, require_pkce, require_consent, id_token_scope_claims, cors_origins, initiate_login_uri, \
    backchannel_logout_uri, frontchannel_logout_uri, dpop_bound_access_tokens, \
    backchannel_token_delivery_mode, backchannel_client_notification_endpoint, security_profile, \
    require_pushed_authorization_requests, service_account_user_id, registration_access_token_hash, status, created_at, updated_at";

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
         id_token_scope_claims, \
         cors_origins, initiate_login_uri, backchannel_logout_uri, frontchannel_logout_uri, \
         dpop_bound_access_tokens, backchannel_token_delivery_mode, \
         backchannel_client_notification_endpoint, security_profile, \
         require_pushed_authorization_requests, service_account_user_id, \
         registration_access_token_hash, status) VALUES (",
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
        .push_bind(c.id_token_scope_claims)
        .push_bind(&c.cors_origins)
        .push_bind(&c.initiate_login_uri)
        .push_bind(&c.backchannel_logout_uri)
        .push_bind(&c.frontchannel_logout_uri)
        .push_bind(c.dpop_bound_access_tokens)
        .push_bind(c.backchannel_token_delivery_mode)
        .push_bind(&c.backchannel_client_notification_endpoint)
        .push_bind(c.security_profile)
        .push_bind(c.require_pushed_authorization_requests)
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

/// Every distinct CORS origin registered on an active client of the tenant.
pub async fn active_cors_origins<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT DISTINCT o FROM clients, unnest(cors_origins) AS o \
         WHERE tenant_id = $1 AND status = 'active'",
    )
    .bind(tenant_id)
    .fetch_all(exec)
    .await
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

/// Replace every metadata column from `c` (identity, secrets, status and
/// service account are left untouched).
pub async fn update_metadata<'e>(
    exec: impl PgExecutor<'e>,
    c: &Client,
) -> Result<Option<Client>, sqlx::Error> {
    let mut qb = QueryBuilder::new("UPDATE clients SET updated_at = now()");
    qb.push(", name = ").push_bind(&c.name);
    qb.push(", client_type = ").push_bind(c.client_type);
    qb.push(", description = ").push_bind(&c.description);
    qb.push(", logo_uri = ").push_bind(&c.logo_uri);
    qb.push(", client_uri = ").push_bind(&c.client_uri);
    qb.push(", tos_uri = ").push_bind(&c.tos_uri);
    qb.push(", policy_uri = ").push_bind(&c.policy_uri);
    qb.push(", jwks = ").push_bind(&c.jwks);
    qb.push(", jwks_uri = ").push_bind(&c.jwks_uri);
    qb.push(", token_endpoint_auth_method = ")
        .push_bind(c.token_endpoint_auth_method);
    qb.push(", redirect_uris = ").push_bind(&c.redirect_uris);
    qb.push(", post_logout_redirect_uris = ")
        .push_bind(&c.post_logout_redirect_uris);
    qb.push(", allowed_grants = ").push_bind(&c.allowed_grants);
    qb.push(", allowed_scopes = ").push_bind(&c.allowed_scopes);
    qb.push(", allowed_audiences = ")
        .push_bind(&c.allowed_audiences);
    qb.push(", access_token_ttl_secs = ")
        .push_bind(c.access_token_ttl_secs);
    qb.push(", refresh_token_ttl_secs = ")
        .push_bind(c.refresh_token_ttl_secs);
    qb.push(", id_token_ttl_secs = ")
        .push_bind(c.id_token_ttl_secs);
    qb.push(", access_token_format = ")
        .push_bind(c.access_token_format);
    qb.push(", id_token_encryption = ")
        .push_bind(c.id_token_encryption.as_ref().map(|j| Json(&j.0)));
    qb.push(", subject_type = ").push_bind(c.subject_type);
    qb.push(", sector_identifier_uri = ")
        .push_bind(&c.sector_identifier_uri);
    qb.push(", require_pkce = ").push_bind(c.require_pkce);
    qb.push(", id_token_scope_claims = ")
        .push_bind(c.id_token_scope_claims);
    qb.push(", require_consent = ").push_bind(c.require_consent);
    qb.push(", cors_origins = ").push_bind(&c.cors_origins);
    qb.push(", initiate_login_uri = ")
        .push_bind(&c.initiate_login_uri);
    qb.push(", backchannel_logout_uri = ")
        .push_bind(&c.backchannel_logout_uri);
    qb.push(", frontchannel_logout_uri = ")
        .push_bind(&c.frontchannel_logout_uri);
    qb.push(", dpop_bound_access_tokens = ")
        .push_bind(c.dpop_bound_access_tokens);
    qb.push(", backchannel_token_delivery_mode = ")
        .push_bind(c.backchannel_token_delivery_mode);
    qb.push(", backchannel_client_notification_endpoint = ")
        .push_bind(&c.backchannel_client_notification_endpoint);
    qb.push(", security_profile = ")
        .push_bind(c.security_profile);
    qb.push(", require_pushed_authorization_requests = ")
        .push_bind(c.require_pushed_authorization_requests);
    qb.push(" WHERE tenant_id = ")
        .push_bind(c.tenant_id)
        .push(" AND id = ")
        .push_bind(c.id)
        .push(" RETURNING ")
        .push(COLUMNS);
    qb.build_query_as::<Client>().fetch_optional(exec).await
}

pub async fn set_registration_token_hash<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    hash: Option<&[u8]>,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE clients SET registration_access_token_hash = $3 WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(hash)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}
