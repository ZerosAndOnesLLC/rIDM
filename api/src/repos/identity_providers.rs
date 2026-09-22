//! Per-tenant upstream identity providers (tenant-bound transactions).

use sqlx::types::Json;
use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{
    IdentityProvider, IdpAuthMethod, IdpKind, IdpMappers, LinkPolicy, SamlUpstream,
    SamlUpstreamSettings, SloBinding,
};

const COLUMNS: &str = "id, tenant_id, alias, kind, display_name, preset, enabled, hidden, issuer, \
     authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, client_id, \
     client_secret_enc, key_version, client_secret_set, token_endpoint_auth_method, scopes, pkce, \
     link_policy, trust_email, mappers, sort_order, created_at, updated_at";

pub async fn list<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Vec<IdentityProvider>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM identity_providers WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" ORDER BY sort_order, alias");
    qb.build_query_as::<IdentityProvider>()
        .fetch_all(exec)
        .await
}

pub async fn find_by_id<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<IdentityProvider>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM identity_providers WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<IdentityProvider>()
        .fetch_optional(exec)
        .await
}

pub async fn find_by_alias<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    alias: &str,
) -> Result<Option<IdentityProvider>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM identity_providers WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND alias = ")
        .push_bind(alias);
    qb.build_query_as::<IdentityProvider>()
        .fetch_optional(exec)
        .await
}

/// Every column of a new row; the service resolves presets and defaults.
pub struct NewRow<'a> {
    pub id: Uuid,
    pub alias: &'a str,
    pub kind: IdpKind,
    pub display_name: &'a str,
    pub preset: Option<&'a str>,
    pub enabled: bool,
    pub hidden: bool,
    pub issuer: Option<&'a str>,
    pub authorization_endpoint: Option<&'a str>,
    pub token_endpoint: Option<&'a str>,
    pub userinfo_endpoint: Option<&'a str>,
    pub jwks_uri: Option<&'a str>,
    pub client_id: &'a str,
    pub client_secret_enc: &'a [u8],
    pub key_version: i32,
    pub client_secret_set: bool,
    pub token_endpoint_auth_method: IdpAuthMethod,
    pub scopes: &'a [String],
    pub pkce: bool,
    pub link_policy: LinkPolicy,
    pub trust_email: bool,
    pub mappers: &'a IdpMappers,
    pub sort_order: i32,
}

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    row: NewRow<'_>,
) -> Result<IdentityProvider, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO identity_providers (id, tenant_id, alias, kind, display_name, preset, enabled, \
         hidden, issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, \
         client_id, client_secret_enc, key_version, client_secret_set, token_endpoint_auth_method, \
         scopes, pkce, link_policy, trust_email, mappers, sort_order) VALUES (",
    );
    let mut s = qb.separated(", ");
    s.push_bind(row.id)
        .push_bind(tenant_id)
        .push_bind(row.alias)
        .push_bind(row.kind)
        .push_bind(row.display_name)
        .push_bind(row.preset)
        .push_bind(row.enabled)
        .push_bind(row.hidden)
        .push_bind(row.issuer)
        .push_bind(row.authorization_endpoint)
        .push_bind(row.token_endpoint)
        .push_bind(row.userinfo_endpoint)
        .push_bind(row.jwks_uri)
        .push_bind(row.client_id)
        .push_bind(row.client_secret_enc)
        .push_bind(row.key_version)
        .push_bind(row.client_secret_set)
        .push_bind(row.token_endpoint_auth_method)
        .push_bind(row.scopes)
        .push_bind(row.pkce)
        .push_bind(row.link_policy)
        .push_bind(row.trust_email)
        .push_bind(Json(row.mappers.clone()))
        .push_bind(row.sort_order);
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<IdentityProvider>()
        .fetch_one(exec)
        .await
}

/// The resolved state of every column after a patch; the service merges
/// the patch over the stored row so the update is one statement.
pub struct UpdateRow<'a> {
    pub alias: &'a str,
    pub kind: IdpKind,
    pub display_name: &'a str,
    pub enabled: bool,
    pub hidden: bool,
    pub issuer: Option<&'a str>,
    pub authorization_endpoint: Option<&'a str>,
    pub token_endpoint: Option<&'a str>,
    pub userinfo_endpoint: Option<&'a str>,
    pub jwks_uri: Option<&'a str>,
    pub client_id: &'a str,
    /// `None` keeps the stored secret.
    pub client_secret: Option<(&'a [u8], i32, bool)>,
    pub token_endpoint_auth_method: IdpAuthMethod,
    pub scopes: &'a [String],
    pub pkce: bool,
    pub link_policy: LinkPolicy,
    pub trust_email: bool,
    pub mappers: &'a IdpMappers,
    pub sort_order: i32,
}

pub async fn update<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    row: UpdateRow<'_>,
) -> Result<Option<IdentityProvider>, sqlx::Error> {
    let mut qb = QueryBuilder::new("UPDATE identity_providers SET updated_at = now(), alias = ");
    qb.push_bind(row.alias)
        .push(", kind = ")
        .push_bind(row.kind)
        .push(", display_name = ")
        .push_bind(row.display_name)
        .push(", enabled = ")
        .push_bind(row.enabled)
        .push(", hidden = ")
        .push_bind(row.hidden)
        .push(", issuer = ")
        .push_bind(row.issuer)
        .push(", authorization_endpoint = ")
        .push_bind(row.authorization_endpoint)
        .push(", token_endpoint = ")
        .push_bind(row.token_endpoint)
        .push(", userinfo_endpoint = ")
        .push_bind(row.userinfo_endpoint)
        .push(", jwks_uri = ")
        .push_bind(row.jwks_uri)
        .push(", client_id = ")
        .push_bind(row.client_id)
        .push(", token_endpoint_auth_method = ")
        .push_bind(row.token_endpoint_auth_method)
        .push(", scopes = ")
        .push_bind(row.scopes)
        .push(", pkce = ")
        .push_bind(row.pkce)
        .push(", link_policy = ")
        .push_bind(row.link_policy)
        .push(", trust_email = ")
        .push_bind(row.trust_email)
        .push(", mappers = ")
        .push_bind(Json(row.mappers.clone()))
        .push(", sort_order = ")
        .push_bind(row.sort_order);
    if let Some((enc, version, set)) = row.client_secret {
        qb.push(", client_secret_enc = ")
            .push_bind(enc)
            .push(", key_version = ")
            .push_bind(version)
            .push(", client_secret_set = ")
            .push_bind(set);
    }
    qb.push(" WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(COLUMNS);
    qb.build_query_as::<IdentityProvider>()
        .fetch_optional(exec)
        .await
}

pub async fn delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM identity_providers WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}

const SAML_COLUMNS: &str = "idp_id, tenant_id, entity_id, sso_url, sso_binding, slo_url, \
    slo_binding, signing_certificates, name_id_format, sign_requests, want_assertions_signed, \
    require_encrypted_assertions, force_authn, authn_context_class_refs, allow_unsolicited, \
    unsolicited_client_id, metadata_url, metadata_refreshed_at, metadata_error, created_at, \
    updated_at";

/// The SAML settings of a provider.
pub async fn find_saml<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
) -> Result<Option<SamlUpstream>, sqlx::Error> {
    let sql = format!(
        "SELECT {SAML_COLUMNS} FROM saml_identity_providers WHERE tenant_id = $1 AND idp_id = $2"
    );
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(tenant_id)
        .bind(idp_id)
        .fetch_optional(exec)
        .await
}

/// Every SAML provider's settings in the tenant (a tenant has a handful).
pub async fn list_saml<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Vec<SamlUpstream>, sqlx::Error> {
    let sql = format!(
        "SELECT {SAML_COLUMNS} FROM saml_identity_providers WHERE tenant_id = $1 LIMIT 1000"
    );
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(tenant_id)
        .fetch_all(exec)
        .await
}

/// Insert or replace a provider's SAML settings. The metadata refresh
/// status is kept unless the metadata URL changed.
pub async fn upsert_saml<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
    s: &SamlUpstreamSettings,
) -> Result<SamlUpstream, sqlx::Error> {
    let sql = format!(
        "INSERT INTO saml_identity_providers (idp_id, tenant_id, entity_id, sso_url, sso_binding, \
         slo_url, slo_binding, signing_certificates, name_id_format, sign_requests, \
         want_assertions_signed, require_encrypted_assertions, force_authn, \
         authn_context_class_refs, allow_unsolicited, unsolicited_client_id, metadata_url) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) \
         ON CONFLICT (idp_id) DO UPDATE SET entity_id = EXCLUDED.entity_id, \
         sso_url = EXCLUDED.sso_url, sso_binding = EXCLUDED.sso_binding, \
         slo_url = EXCLUDED.slo_url, slo_binding = EXCLUDED.slo_binding, \
         signing_certificates = EXCLUDED.signing_certificates, \
         name_id_format = EXCLUDED.name_id_format, sign_requests = EXCLUDED.sign_requests, \
         want_assertions_signed = EXCLUDED.want_assertions_signed, \
         require_encrypted_assertions = EXCLUDED.require_encrypted_assertions, \
         force_authn = EXCLUDED.force_authn, \
         authn_context_class_refs = EXCLUDED.authn_context_class_refs, \
         allow_unsolicited = EXCLUDED.allow_unsolicited, \
         unsolicited_client_id = EXCLUDED.unsolicited_client_id, \
         metadata_refreshed_at = CASE WHEN saml_identity_providers.metadata_url \
             IS NOT DISTINCT FROM EXCLUDED.metadata_url \
             THEN saml_identity_providers.metadata_refreshed_at END, \
         metadata_error = CASE WHEN saml_identity_providers.metadata_url \
             IS NOT DISTINCT FROM EXCLUDED.metadata_url \
             THEN saml_identity_providers.metadata_error END, \
         metadata_url = EXCLUDED.metadata_url \
         RETURNING {SAML_COLUMNS}"
    );
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(idp_id)
        .bind(tenant_id)
        .bind(&s.entity_id)
        .bind(&s.sso_url)
        .bind(s.sso_binding)
        .bind(&s.slo_url)
        .bind(s.slo_binding)
        .bind(&s.signing_certificates)
        .bind(s.name_id_format)
        .bind(s.sign_requests)
        .bind(s.want_assertions_signed)
        .bind(s.require_encrypted_assertions)
        .bind(s.force_authn)
        .bind(&s.authn_context_class_refs)
        .bind(s.allow_unsolicited)
        .bind(&s.unsolicited_client_id)
        .bind(&s.metadata_url)
        .fetch_one(exec)
        .await
}

/// What a metadata refresh read: the endpoints and certificates, which
/// replace the stored ones.
pub struct RefreshedMetadata<'a> {
    pub sso_url: &'a str,
    pub sso_binding: SloBinding,
    pub slo_url: Option<&'a str>,
    pub slo_binding: SloBinding,
    pub signing_certificates: &'a [String],
}

/// Record a refresh: its result on success, its error otherwise. Returns
/// whether the row still exists with that metadata URL (an administrator
/// may have changed it meanwhile, and then nothing is written).
pub async fn record_refresh<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
    metadata_url: &str,
    outcome: Result<RefreshedMetadata<'_>, &str>,
) -> Result<bool, sqlx::Error> {
    let res =
        match outcome {
            Ok(m) => sqlx::query(
                "UPDATE saml_identity_providers SET sso_url = $4, sso_binding = $5, slo_url = $6, \
                 slo_binding = $7, signing_certificates = $8, metadata_refreshed_at = now(), \
                 metadata_error = NULL \
                 WHERE tenant_id = $1 AND idp_id = $2 AND metadata_url = $3",
            )
            .bind(tenant_id)
            .bind(idp_id)
            .bind(metadata_url)
            .bind(m.sso_url)
            .bind(m.sso_binding)
            .bind(m.slo_url)
            .bind(m.slo_binding)
            .bind(m.signing_certificates)
            .execute(exec)
            .await?,
            Err(error) => {
                sqlx::query(
                    "UPDATE saml_identity_providers SET metadata_error = left($4, 1000) \
                 WHERE tenant_id = $1 AND idp_id = $2 AND metadata_url = $3",
                )
                .bind(tenant_id)
                .bind(idp_id)
                .bind(metadata_url)
                .bind(error)
                .execute(exec)
                .await?
            }
        };
    Ok(res.rows_affected() > 0)
}

/// Providers whose metadata is due for a refresh (never read, or last read
/// successfully before `before`), across tenants, after the keyset cursor.
/// Needs a transaction that bypasses row level security.
pub async fn due_metadata_refresh<'e>(
    exec: impl PgExecutor<'e>,
    before: chrono::DateTime<chrono::Utc>,
    after: (Uuid, Uuid),
    limit: i64,
) -> Result<Vec<(Uuid, Uuid)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT tenant_id, idp_id FROM saml_identity_providers \
         WHERE metadata_url IS NOT NULL \
           AND (metadata_refreshed_at IS NULL OR metadata_refreshed_at < $1) \
           AND (tenant_id, idp_id) > ($2, $3) \
         ORDER BY tenant_id, idp_id LIMIT $4",
    )
    .bind(before)
    .bind(after.0)
    .bind(after.1)
    .bind(limit)
    .fetch_all(exec)
    .await
}
