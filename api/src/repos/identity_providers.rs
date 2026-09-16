//! Per-tenant upstream identity providers (tenant-bound transactions).

use sqlx::types::Json;
use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{IdentityProvider, IdpAuthMethod, IdpKind, IdpMappers, LinkPolicy};

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
