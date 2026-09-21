//! SAML service providers and the IdP's SAML signing keys (tenant-bound
//! transactions).

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use sqlx::types::Json;
use uuid::Uuid;

use crate::models::{SamlKeyStatus, SamlServiceProvider, SamlSigningKey};

const SP_COLUMNS: &str = "client_id, tenant_id, entity_id, acs_urls, slo_url, slo_binding, \
    name_id_format, signing_certificates, encryption_certificate, require_signed_requests, \
    sign_response, sign_assertion, encrypt_assertion, data_encryption, key_transport, \
    allow_idp_initiated, default_relay_state, attributes, assertion_ttl_secs, created_at, \
    updated_at";

/// Insert or replace the SAML settings of a client.
pub async fn upsert_sp<'e>(
    exec: impl PgExecutor<'e>,
    sp: &SamlServiceProvider,
) -> Result<SamlServiceProvider, sqlx::Error> {
    let sql = format!(
        "INSERT INTO saml_service_providers (client_id, tenant_id, entity_id, acs_urls, slo_url, \
         slo_binding, name_id_format, signing_certificates, encryption_certificate, \
         require_signed_requests, sign_response, sign_assertion, encrypt_assertion, \
         data_encryption, key_transport, allow_idp_initiated, default_relay_state, attributes, \
         assertion_ttl_secs) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) \
         ON CONFLICT (client_id) DO UPDATE SET entity_id = EXCLUDED.entity_id, \
         acs_urls = EXCLUDED.acs_urls, slo_url = EXCLUDED.slo_url, \
         slo_binding = EXCLUDED.slo_binding, name_id_format = EXCLUDED.name_id_format, \
         signing_certificates = EXCLUDED.signing_certificates, \
         encryption_certificate = EXCLUDED.encryption_certificate, \
         require_signed_requests = EXCLUDED.require_signed_requests, \
         sign_response = EXCLUDED.sign_response, sign_assertion = EXCLUDED.sign_assertion, \
         encrypt_assertion = EXCLUDED.encrypt_assertion, \
         data_encryption = EXCLUDED.data_encryption, key_transport = EXCLUDED.key_transport, \
         allow_idp_initiated = EXCLUDED.allow_idp_initiated, \
         default_relay_state = EXCLUDED.default_relay_state, attributes = EXCLUDED.attributes, \
         assertion_ttl_secs = EXCLUDED.assertion_ttl_secs \
         RETURNING {SP_COLUMNS}"
    );
    sqlx::query_as::<_, SamlServiceProvider>(sqlx::AssertSqlSafe(sql))
        .bind(sp.client_id)
        .bind(sp.tenant_id)
        .bind(&sp.entity_id)
        .bind(&sp.acs_urls)
        .bind(&sp.slo_url)
        .bind(sp.slo_binding)
        .bind(sp.name_id_format)
        .bind(&sp.signing_certificates)
        .bind(&sp.encryption_certificate)
        .bind(sp.require_signed_requests)
        .bind(sp.sign_response)
        .bind(sp.sign_assertion)
        .bind(sp.encrypt_assertion)
        .bind(sp.data_encryption)
        .bind(sp.key_transport)
        .bind(sp.allow_idp_initiated)
        .bind(&sp.default_relay_state)
        .bind(Json(&sp.attributes.0))
        .bind(sp.assertion_ttl_secs)
        .fetch_one(exec)
        .await
}

pub async fn find_sp<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    client_id: Uuid,
) -> Result<Option<SamlServiceProvider>, sqlx::Error> {
    let sql = format!(
        "SELECT {SP_COLUMNS} FROM saml_service_providers WHERE tenant_id = $1 AND client_id = $2"
    );
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(tenant_id)
        .bind(client_id)
        .fetch_optional(exec)
        .await
}

pub async fn find_sp_by_entity_id<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    entity_id: &str,
) -> Result<Option<SamlServiceProvider>, sqlx::Error> {
    let sql = format!(
        "SELECT {SP_COLUMNS} FROM saml_service_providers WHERE tenant_id = $1 AND entity_id = $2"
    );
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(tenant_id)
        .bind(entity_id)
        .fetch_optional(exec)
        .await
}

/// Every SP of the tenant, by entity id (the admin list; a tenant has tens).
pub async fn list_sps<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Vec<SamlServiceProvider>, sqlx::Error> {
    let sql = format!(
        "SELECT {SP_COLUMNS} FROM saml_service_providers WHERE tenant_id = $1 \
         ORDER BY entity_id LIMIT 1000"
    );
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(tenant_id)
        .fetch_all(exec)
        .await
}

const KEY_COLUMNS: &str = "id, tenant_id, private_key_enc, key_version, certificate, status, \
    not_after, activated_at, created_at, updated_at";

pub struct NewKey<'a> {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub private_key_enc: &'a [u8],
    pub key_version: i32,
    pub certificate: &'a [u8],
    pub status: SamlKeyStatus,
    pub not_after: DateTime<Utc>,
}

pub async fn insert_key<'e>(
    exec: impl PgExecutor<'e>,
    k: &NewKey<'_>,
) -> Result<SamlSigningKey, sqlx::Error> {
    let sql = format!(
        "INSERT INTO saml_signing_keys (id, tenant_id, private_key_enc, key_version, \
         certificate, status, not_after, activated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $6 = 'active' THEN now() END) \
         RETURNING {KEY_COLUMNS}"
    );
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(k.id)
        .bind(k.tenant_id)
        .bind(k.private_key_enc)
        .bind(k.key_version)
        .bind(k.certificate)
        .bind(k.status)
        .bind(k.not_after)
        .fetch_one(exec)
        .await
}

/// Every key of the tenant, oldest first (a handful at most).
pub async fn list_keys<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Vec<SamlSigningKey>, sqlx::Error> {
    let sql = format!(
        "SELECT {KEY_COLUMNS} FROM saml_signing_keys WHERE tenant_id = $1 ORDER BY created_at, id"
    );
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(tenant_id)
        .fetch_all(exec)
        .await
}

/// Make `id` the active key; the active one before it becomes `retiring`.
/// Returns false when `id` is not a pending or retiring key of the tenant.
pub async fn activate_key(
    conn: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query(
        "UPDATE saml_signing_keys SET status = 'retiring' \
         WHERE tenant_id = $1 AND status = 'active' AND id <> $2 \
           AND EXISTS (SELECT 1 FROM saml_signing_keys k WHERE k.tenant_id = $1 AND k.id = $2 \
                       AND k.status IN ('pending', 'retiring'))",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(&mut *conn)
    .await?;
    let done = sqlx::query(
        "UPDATE saml_signing_keys SET status = 'active', activated_at = now() \
         WHERE tenant_id = $1 AND id = $2 AND status IN ('pending', 'retiring')",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Delete a key that is not the active one.
pub async fn delete_inactive_key<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "DELETE FROM saml_signing_keys WHERE tenant_id = $1 AND id = $2 AND status <> 'active'",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(done.rows_affected() == 1)
}
