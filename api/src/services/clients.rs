//! OAuth/OIDC client lifecycle: creation with type-driven defaults, secrets
//! with rotation grace, lookup by public `client_id` (cached).

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use sha2::{Digest as _, Sha256};
use sqlx::types::Json;
use subtle::ConstantTimeEq as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cache::keys as cache_keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{
    AccessTokenFormat, Client, ClientSecretHash, ClientStatus, ClientSubjectType, ClientType,
    NewClient, NewUser, STANDARD_SCOPES, TokenEndpointAuthMethod, User, grants,
};
use crate::repos;
use crate::state::AppState;
use crate::util::cursor::{Cursor, Page, page_size};

const CLIENT_CACHE_TTL: Duration = Duration::from_secs(300);
/// How long a rotated-out secret keeps working.
pub const SECRET_ROTATION_GRACE: chrono::Duration = chrono::Duration::hours(24);
const SECRET_PREFIX: &str = "cs_";

/// Result of creating a client: the secret is shown exactly once.
#[derive(Debug)]
pub struct CreatedClient {
    pub client: Client,
    pub client_secret: Option<Zeroizing<String>>,
}

fn hash_secret(secret: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}

fn random_secret() -> Zeroizing<String> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    Zeroizing::new(format!("{SECRET_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

fn random_client_id() -> String {
    let mut bytes = [0u8; 12];
    rand::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes).replace(['-', '_'], "0")
}

pub fn is_valid_client_id(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'))
}

fn validate_uri(field: &str, uri: &str, client_type: ClientType) -> AppResult<()> {
    let parsed = url::Url::parse(uri)
        .map_err(|_| AppError::BadRequest(format!("{field}: `{uri}` is not a valid URL")))?;
    if parsed.fragment().is_some() {
        return Err(AppError::BadRequest(format!(
            "{field}: fragments are not allowed"
        )));
    }
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            let host = parsed.host_str().unwrap_or_default();
            let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
            if loopback {
                Ok(())
            } else {
                Err(AppError::BadRequest(format!(
                    "{field}: plain http is only allowed for loopback addresses"
                )))
            }
        }
        // Custom schemes for native apps (RFC 8252 §7.1).
        _ if client_type == ClientType::Native => Ok(()),
        other => Err(AppError::BadRequest(format!(
            "{field}: scheme `{other}` is not allowed for this client type"
        ))),
    }
}

/// Resolve `NewClient` into a full `Client` using type-driven defaults.
pub fn resolve(
    tenant_id: Uuid,
    input: NewClient,
) -> AppResult<(Client, Option<Zeroizing<String>>)> {
    let name = input.name.trim().to_string();
    if name.is_empty() || name.len() > 255 {
        return Err(AppError::BadRequest("name must be 1-255 characters".into()));
    }
    let client_type = input.client_type.unwrap_or(ClientType::Web);
    let client_id = match input.client_id.map(|s| s.trim().to_string()) {
        Some(id) if !id.is_empty() => {
            if !is_valid_client_id(&id) {
                return Err(AppError::BadRequest(
                    "client_id must be 1-128 characters of [A-Za-z0-9._:-] starting alphanumeric"
                        .into(),
                ));
            }
            id
        }
        _ => random_client_id(),
    };

    let (default_auth, default_grants, default_pkce): (TokenEndpointAuthMethod, Vec<&str>, bool) =
        match client_type {
            ClientType::Spa => (
                TokenEndpointAuthMethod::None,
                vec![grants::AUTHORIZATION_CODE, grants::REFRESH_TOKEN],
                true,
            ),
            ClientType::Web => (
                TokenEndpointAuthMethod::ClientSecretBasic,
                vec![grants::AUTHORIZATION_CODE, grants::REFRESH_TOKEN],
                true,
            ),
            ClientType::Native => (
                TokenEndpointAuthMethod::None,
                vec![grants::AUTHORIZATION_CODE, grants::REFRESH_TOKEN],
                true,
            ),
            ClientType::Machine => (
                TokenEndpointAuthMethod::ClientSecretBasic,
                vec![grants::CLIENT_CREDENTIALS],
                false,
            ),
            ClientType::Device => (
                TokenEndpointAuthMethod::None,
                vec![grants::DEVICE_CODE, grants::REFRESH_TOKEN],
                true,
            ),
        };
    let auth_method = input.token_endpoint_auth_method.unwrap_or(default_auth);
    let allowed_grants = input
        .allowed_grants
        .unwrap_or_else(|| default_grants.iter().map(|s| s.to_string()).collect());
    for g in &allowed_grants {
        if !grants::ALL.contains(&g.as_str()) {
            return Err(AppError::BadRequest(format!(
                "unsupported grant type `{g}`"
            )));
        }
    }
    if auth_method == TokenEndpointAuthMethod::None
        && allowed_grants
            .iter()
            .any(|g| g == grants::CLIENT_CREDENTIALS)
    {
        return Err(AppError::BadRequest(
            "client_credentials requires client authentication".into(),
        ));
    }
    if auth_method == TokenEndpointAuthMethod::PrivateKeyJwt
        && input.jwks.is_none()
        && input.jwks_uri.is_none()
    {
        return Err(AppError::BadRequest(
            "private_key_jwt requires jwks or jwks_uri".into(),
        ));
    }
    let needs_redirect = allowed_grants
        .iter()
        .any(|g| g == grants::AUTHORIZATION_CODE);
    if needs_redirect && input.redirect_uris.is_empty() {
        return Err(AppError::BadRequest(
            "authorization_code clients need at least one redirect_uri".into(),
        ));
    }
    for uri in &input.redirect_uris {
        validate_uri("redirect_uris", uri, client_type)?;
    }
    for uri in &input.post_logout_redirect_uris {
        validate_uri("post_logout_redirect_uris", uri, client_type)?;
    }
    for origin in &input.cors_origins {
        let u = url::Url::parse(origin)
            .map_err(|_| AppError::BadRequest(format!("cors_origins: `{origin}` is not a URL")))?;
        if u.path() != "/" || u.query().is_some() {
            return Err(AppError::BadRequest(format!(
                "cors_origins: `{origin}` must be an origin (scheme://host[:port])"
            )));
        }
    }
    let subject_type = input.subject_type.unwrap_or(ClientSubjectType::Public);
    if let Some(enc) = &input.id_token_encryption {
        if crate::services::jwe::KeyAlg::parse(&enc.alg).is_none() {
            return Err(AppError::BadRequest(format!(
                "unsupported id_token_encryption.alg `{}`",
                enc.alg
            )));
        }
        if crate::services::jwe::ContentEnc::parse(&enc.enc).is_none() {
            return Err(AppError::BadRequest(format!(
                "unsupported id_token_encryption.enc `{}`",
                enc.enc
            )));
        }
        if input.jwks.is_none() && input.jwks_uri.is_none() {
            return Err(AppError::BadRequest(
                "id_token_encryption requires the client's jwks or jwks_uri".into(),
            ));
        }
    }
    let allowed_scopes = input.allowed_scopes.unwrap_or_else(|| match client_type {
        ClientType::Machine => vec![],
        _ => STANDARD_SCOPES.iter().map(|s| s.to_string()).collect(),
    });

    let (secret_hashes, secret) = if auth_method.uses_secret() {
        let secret = random_secret();
        (
            vec![ClientSecretHash {
                id: Uuid::now_v7(),
                hash: hash_secret(&secret),
                created_at: Utc::now(),
                expires_at: None,
            }],
            Some(secret),
        )
    } else {
        (vec![], None)
    };

    let now = Utc::now();
    let client = Client {
        id: Uuid::now_v7(),
        tenant_id,
        client_id,
        name,
        client_type,
        description: input.description,
        logo_uri: input.logo_uri,
        client_uri: input.client_uri,
        tos_uri: input.tos_uri,
        policy_uri: input.policy_uri,
        secret_hashes: Json(secret_hashes),
        jwks: input.jwks,
        jwks_uri: input.jwks_uri,
        token_endpoint_auth_method: auth_method,
        redirect_uris: input.redirect_uris,
        post_logout_redirect_uris: input.post_logout_redirect_uris,
        allowed_grants,
        allowed_scopes,
        allowed_audiences: input.allowed_audiences,
        access_token_ttl_secs: input.access_token_ttl_secs,
        refresh_token_ttl_secs: input.refresh_token_ttl_secs,
        id_token_ttl_secs: input.id_token_ttl_secs,
        access_token_format: input.access_token_format.unwrap_or(AccessTokenFormat::Jwt),
        id_token_encryption: input.id_token_encryption.map(Json),
        subject_type,
        sector_identifier_uri: input.sector_identifier_uri,
        require_pkce: input.require_pkce.unwrap_or(default_pkce),
        require_consent: input.require_consent.unwrap_or(true),
        cors_origins: input.cors_origins,
        initiate_login_uri: input.initiate_login_uri,
        backchannel_logout_uri: input.backchannel_logout_uri,
        frontchannel_logout_uri: input.frontchannel_logout_uri,
        service_account_user_id: None,
        registration_access_token_hash: None,
        status: ClientStatus::Active,
        created_at: now,
        updated_at: now,
    };
    Ok((client, secret))
}

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    input: NewClient,
) -> AppResult<CreatedClient> {
    let (client, secret) = resolve(tenant_id, input)?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let client = repos::clients::insert(&mut *tx, &client)
        .await
        .map_err(|e| match AppError::from_db(e) {
            AppError::Conflict(_) => AppError::Conflict("client_id already exists".into()),
            other => other,
        })?;
    tx.commit().await?;
    state
        .cache
        .invalidate(&[cache_keys::client_by_client_id(
            tenant_id,
            &client.client_id,
        )])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ClientCreated {
            client_id: client.id,
            public_id: client.client_id.clone(),
        },
    ));
    Ok(CreatedClient {
        client,
        client_secret: secret,
    })
}

pub async fn get(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<Client> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let c = repos::clients::find_by_id(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    c.ok_or(AppError::NotFound("client"))
}

/// Lookup by public `client_id` through the cache (hot path for every OAuth request).
pub async fn find_by_client_id(
    state: &AppState,
    tenant_id: Uuid,
    client_id: &str,
) -> AppResult<Option<Arc<Client>>> {
    if !is_valid_client_id(client_id) {
        return Ok(None);
    }
    let db = state.db.clone();
    let cid = client_id.to_string();
    state
        .cache
        .get_or_load(
            &cache_keys::client_by_client_id(tenant_id, client_id),
            CLIENT_CACHE_TTL,
            || async move {
                let mut tx = db::tenant_tx(&db, tenant_id).await?;
                let c = repos::clients::find_by_client_id(&mut *tx, tenant_id, &cid).await?;
                tx.commit().await?;
                Ok(c)
            },
        )
        .await
}

pub async fn list(
    state: &AppState,
    tenant_id: Uuid,
    search: Option<&str>,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> AppResult<Page<Client>> {
    let after = cursor.map(Cursor::decode).transpose()?;
    let limit = page_size(limit);
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::clients::list(&mut *tx, tenant_id, search, after, limit).await?;
    tx.commit().await?;
    Ok(Page::from_rows(rows, limit, |c| Cursor {
        created_at: c.created_at,
        id: c.id,
    }))
}

/// Constant-time check of a presented secret against every active secret.
pub fn verify_secret(client: &Client, presented: &str) -> bool {
    let h = hash_secret(presented);
    let mut ok = false;
    for s in client.active_secrets() {
        ok |= bool::from(s.hash.as_bytes().ct_eq(h.as_bytes()));
    }
    ok
}

/// Add a new secret; the previous one keeps working for `grace` (default 24h,
/// `Some(0)` retires it immediately). At most two secrets exist at any time.
pub async fn rotate_secret(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
    grace: Option<chrono::Duration>,
) -> AppResult<(Client, Zeroizing<String>)> {
    let grace = grace.unwrap_or(SECRET_ROTATION_GRACE);
    if grace < chrono::Duration::zero() || grace > chrono::Duration::days(30) {
        return Err(AppError::BadRequest(
            "grace must be between 0 and 30 days".into(),
        ));
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let client = repos::clients::find_by_id(&mut *tx, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("client"))?;
    if !client.token_endpoint_auth_method.uses_secret() {
        return Err(AppError::BadRequest(
            "this client does not use a secret".into(),
        ));
    }
    let now = Utc::now();
    let secret = random_secret();
    let mut hashes: Vec<ClientSecretHash> = client
        .secret_hashes
        .iter()
        .filter(|s| s.is_active(now))
        .cloned()
        .collect();
    // Newest existing secret gets the grace window; anything older is dropped.
    hashes.sort_by_key(|s| std::cmp::Reverse(s.created_at));
    hashes.truncate(1);
    if grace.is_zero() {
        hashes.clear();
    }
    for h in &mut hashes {
        h.expires_at = Some(now + grace);
    }
    hashes.insert(
        0,
        ClientSecretHash {
            id: Uuid::now_v7(),
            hash: hash_secret(&secret),
            created_at: now,
            expires_at: None,
        },
    );
    repos::clients::set_secret_hashes(&mut *tx, tenant_id, id, &hashes).await?;
    let client = repos::clients::find_by_id(&mut *tx, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("client"))?;
    tx.commit().await?;
    state
        .cache
        .invalidate(&[cache_keys::client_by_client_id(
            tenant_id,
            &client.client_id,
        )])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ClientSecretRotated { client_id: id },
    ));
    Ok((client, secret))
}

/// Drop every secret except the newest (ends a rotation grace early).
pub async fn revoke_old_secrets(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> AppResult<Client> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let client = repos::clients::find_by_id(&mut *tx, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("client"))?;
    let mut hashes = client.secret_hashes.0.clone();
    hashes.sort_by_key(|s| std::cmp::Reverse(s.created_at));
    hashes.truncate(1);
    repos::clients::set_secret_hashes(&mut *tx, tenant_id, id, &hashes).await?;
    let client = repos::clients::find_by_id(&mut *tx, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("client"))?;
    tx.commit().await?;
    state
        .cache
        .invalidate(&[cache_keys::client_by_client_id(
            tenant_id,
            &client.client_id,
        )])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ClientSecretRotated { client_id: id },
    ));
    Ok(client)
}

pub async fn set_status(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
    status: ClientStatus,
) -> AppResult<Client> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    if !repos::clients::set_status(&mut *tx, tenant_id, id, status).await? {
        return Err(AppError::NotFound("client"));
    }
    let client = repos::clients::find_by_id(&mut *tx, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("client"))?;
    tx.commit().await?;
    state
        .cache
        .invalidate(&[cache_keys::client_by_client_id(
            tenant_id,
            &client.client_id,
        )])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ClientUpdated { client_id: id },
    ));
    Ok(client)
}

pub async fn delete(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let client = get(state, tenant_id, id).await?;
    if super::admin_console::is_builtin_client(&client.client_id) {
        return Err(AppError::Forbidden(
            "the admin console client is built in and cannot be deleted".into(),
        ));
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::clients::delete(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound("client"));
    }
    state
        .cache
        .invalidate(&[cache_keys::client_by_client_id(
            tenant_id,
            &client.client_id,
        )])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ClientDeleted { client_id: id },
    ));
    Ok(())
}

/// Replace a client's metadata (RFC 7592 PUT, admin "replace"). The public
/// `client_id`, status, service account and timestamps are kept. Secrets are
/// kept when the client goes on using them, dropped when it switches to
/// `none` or `private_key_jwt`, and a fresh one is generated (and returned,
/// shown exactly once) when it switches to a secret-based method.
pub async fn update_metadata(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
    mut input: NewClient,
) -> AppResult<(Client, Option<Zeroizing<String>>)> {
    let current = get(state, tenant_id, id).await?;
    input.client_id = Some(current.client_id.clone());
    let (mut resolved, fresh_secret) = resolve(tenant_id, input)?;
    resolved.id = current.id;
    let secret = if !resolved.token_endpoint_auth_method.uses_secret() {
        resolved.secret_hashes = Json(vec![]);
        None
    } else if current.active_secrets().is_empty() {
        // `resolve` already minted one for a secret-based method.
        fresh_secret
    } else {
        resolved.secret_hashes = current.secret_hashes.clone();
        None
    };
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let client = repos::clients::update_metadata(&mut *tx, &resolved)
        .await
        .map_err(AppError::from_db)?
        .ok_or(AppError::NotFound("client"))?;
    if resolved.secret_hashes.0 != current.secret_hashes.0 {
        repos::clients::set_secret_hashes(&mut *tx, tenant_id, id, &resolved.secret_hashes.0)
            .await?;
    }
    let client = Client {
        secret_hashes: resolved.secret_hashes,
        ..client
    };
    tx.commit().await?;
    state
        .cache
        .invalidate(&[
            cache_keys::client_by_client_id(tenant_id, &client.client_id),
            cache_keys::client_jwks(tenant_id, client.id),
        ])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ClientUpdated { client_id: id },
    ));
    Ok((client, secret))
}

/// Revoke one secret by id (ends a rotation grace early or drops a leaked
/// secret). The last secret of a secret-based client cannot be revoked:
/// rotate instead so the client never ends up unable to authenticate.
pub async fn revoke_secret(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
    secret_id: Uuid,
) -> AppResult<Client> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let client = repos::clients::find_by_id(&mut *tx, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("client"))?;
    if !client.secret_hashes.iter().any(|s| s.id == secret_id) {
        return Err(AppError::NotFound("client secret"));
    }
    let hashes: Vec<ClientSecretHash> = client
        .secret_hashes
        .iter()
        .filter(|s| s.id != secret_id)
        .cloned()
        .collect();
    if client.token_endpoint_auth_method.uses_secret() && hashes.is_empty() {
        return Err(AppError::BadRequest(
            "the last secret cannot be revoked; rotate it instead".into(),
        ));
    }
    repos::clients::set_secret_hashes(&mut *tx, tenant_id, id, &hashes).await?;
    let client = repos::clients::find_by_id(&mut *tx, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("client"))?;
    tx.commit().await?;
    state
        .cache
        .invalidate(&[cache_keys::client_by_client_id(
            tenant_id,
            &client.client_id,
        )])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ClientSecretRotated { client_id: id },
    ));
    Ok(client)
}

/// Username of the user a client acts as under `client_credentials`.
pub fn service_account_username(client_id: &str) -> String {
    format!("svc-{}", client_id.to_lowercase())
}

/// Give the client a service account: a user of its own that
/// `client_credentials` tokens are issued for, so roles, groups and
/// permissions can be assigned to the client like to any user. Idempotent.
pub async fn enable_service_account(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> AppResult<(Client, User)> {
    let client = get(state, tenant_id, id).await?;
    if !client.allows_grant(grants::CLIENT_CREDENTIALS) {
        return Err(AppError::BadRequest(
            "a service account needs the client_credentials grant".into(),
        ));
    }
    if let Some(uid) = client.service_account_user_id
        && let Ok(user) = crate::services::users::get(state, tenant_id, uid).await
        && user.deleted_at.is_none()
    {
        return Ok((client, user));
    }
    let user = crate::services::users::create(
        state,
        tenant_id,
        actor.clone(),
        NewUser {
            username: service_account_username(&client.client_id),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| match e {
        AppError::Conflict(_) => AppError::Conflict(format!(
            "user `{}` already exists",
            service_account_username(&client.client_id)
        )),
        other => other,
    })?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::clients::set_service_account(&mut *tx, tenant_id, id, Some(user.id)).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound("client"));
    }
    state
        .cache
        .invalidate(&[cache_keys::client_by_client_id(
            tenant_id,
            &client.client_id,
        )])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ClientUpdated { client_id: id },
    ));
    let client = get(state, tenant_id, id).await?;
    Ok((client, user))
}

/// Remove the client's service account (the user is deleted). Idempotent.
pub async fn disable_service_account(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> AppResult<Client> {
    let client = get(state, tenant_id, id).await?;
    let Some(uid) = client.service_account_user_id else {
        return Ok(client);
    };
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    repos::clients::set_service_account(&mut *tx, tenant_id, id, None).await?;
    tx.commit().await?;
    match crate::services::users::delete(state, tenant_id, actor.clone(), uid).await {
        Ok(()) | Err(AppError::NotFound(_)) => {}
        Err(e) => return Err(e),
    }
    state
        .cache
        .invalidate(&[cache_keys::client_by_client_id(
            tenant_id,
            &client.client_id,
        )])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ClientUpdated { client_id: id },
    ));
    get(state, tenant_id, id).await
}

const REGISTRATION_TOKEN_PREFIX: &str = "rat_";

/// Issue (or replace) the RFC 7592 registration access token for a client.
pub async fn issue_registration_token(
    state: &AppState,
    tenant_id: Uuid,
    id: Uuid,
) -> AppResult<Zeroizing<String>> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let token = Zeroizing::new(format!(
        "{REGISTRATION_TOKEN_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(bytes)
    ));
    let hash = Sha256::digest(token.as_bytes()).to_vec();
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let client = repos::clients::find_by_id(&mut *tx, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("client"))?;
    repos::clients::set_registration_token_hash(&mut *tx, tenant_id, id, Some(&hash)).await?;
    tx.commit().await?;
    // RFC 7592 management authenticates against the cached client; a replaced
    // token must stop working at once.
    state
        .cache
        .invalidate(&[cache_keys::client_by_client_id(
            tenant_id,
            &client.client_id,
        )])
        .await?;
    Ok(token)
}

pub fn verify_registration_token(client: &Client, presented: &str) -> bool {
    let Some(stored) = &client.registration_access_token_hash else {
        return false;
    };
    let hash = Sha256::digest(presented.as_bytes());
    stored.len() == hash.len() && bool::from(stored.as_slice().ct_eq(hash.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_id_and_secret_shapes() {
        assert!(is_valid_client_id("web-app"));
        assert!(is_valid_client_id("urn:my:app"));
        assert!(!is_valid_client_id(""));
        assert!(!is_valid_client_id("-x"));
        assert!(!is_valid_client_id("a b"));
        assert!(is_valid_client_id(&random_client_id()));
        let s = random_secret();
        assert!(s.starts_with("cs_") && s.len() > 40);
        assert_ne!(hash_secret(&s), hash_secret("other"));
    }

    #[test]
    fn redirect_uri_rules() {
        assert!(validate_uri("r", "https://app.example/cb", ClientType::Web).is_ok());
        assert!(validate_uri("r", "http://localhost:3000/cb", ClientType::Spa).is_ok());
        assert!(validate_uri("r", "http://127.0.0.1/cb", ClientType::Native).is_ok());
        assert!(validate_uri("r", "http://app.example/cb", ClientType::Web).is_err());
        assert!(validate_uri("r", "https://app.example/cb#frag", ClientType::Web).is_err());
        assert!(validate_uri("r", "com.example.app:/oauth", ClientType::Native).is_ok());
        assert!(validate_uri("r", "com.example.app:/oauth", ClientType::Web).is_err());
        assert!(validate_uri("r", "not a url", ClientType::Web).is_err());
    }
}
