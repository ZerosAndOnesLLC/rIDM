//! SAML service providers: a `saml` client row and its SAML settings,
//! written together in one transaction and cached by entity ID for the SSO
//! endpoints.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use uuid::Uuid;

use crate::cache::keys as cache_keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{
    AccessTokenFormat, Client, ClientStatus, ClientSubjectType, ClientType, NameIdFormat,
    SamlAttribute, SamlServiceProvider, SecurityProfile, SloBinding, TokenEndpointAuthMethod,
};
use crate::repos;
use crate::saml::binding::MAX_RELAY_STATE;
use crate::saml::cert::Certificate;
use crate::saml::metadata::parse_sp_metadata;
use crate::saml::xmlenc::{DataEncryption, KeyTransport};
use crate::services::clients;
use crate::state::AppState;

const SP_CACHE_TTL: Duration = Duration::from_secs(300);
const MAX_SIGNING_CERTS: usize = 4;
const MAX_ATTRIBUTES: usize = 100;

/// Scopes a new SP releases attributes for, unless told otherwise.
const DEFAULT_SCOPES: [&str; 3] = ["openid", "profile", "email"];

/// A service provider as the admin API reads and writes it: the client's
/// own fields and the SAML settings side by side.
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SamlSpInput {
    pub name: String,
    pub description: Option<String>,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    /// The public client id; generated when absent.
    pub client_id: Option<String>,
    /// Scopes whose claims may be released as attributes.
    pub allowed_scopes: Option<Vec<String>>,
    /// Ask the user before releasing attributes. Off by default: SAML SPs
    /// are enterprise applications an administrator connected.
    pub require_consent: Option<bool>,
    pub entity_id: String,
    pub acs_urls: Vec<String>,
    pub slo_url: Option<String>,
    pub slo_binding: Option<SloBinding>,
    pub name_id_format: Option<NameIdFormat>,
    /// PEM or base64 DER.
    pub signing_certificates: Vec<String>,
    pub encryption_certificate: Option<String>,
    pub require_signed_requests: Option<bool>,
    pub sign_response: Option<bool>,
    pub sign_assertion: Option<bool>,
    pub encrypt_assertion: Option<bool>,
    pub data_encryption: Option<DataEncryption>,
    pub key_transport: Option<KeyTransport>,
    pub allow_idp_initiated: Option<bool>,
    pub default_relay_state: Option<String>,
    pub attributes: Option<Vec<SamlAttribute>>,
    pub assertion_ttl_secs: Option<i32>,
}

/// A registered SP.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SamlSpView {
    pub client: Client,
    pub saml: SamlServiceProvider,
}

/// What the SSO endpoints look up by entity ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpEntry {
    pub sp: SamlServiceProvider,
    pub client_public_id: String,
}

fn bad(msg: impl Into<String>) -> AppError {
    AppError::BadRequest(msg.into())
}

fn trimmed(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn certificate(field: &str, pem: &str) -> AppResult<Certificate> {
    Certificate::parse(pem).map_err(|e| bad(format!("{field}: {e}")))
}

/// Check the input and turn it into the two rows.
pub(crate) fn resolve(
    tenant_id: Uuid,
    client_row_id: Uuid,
    public_id: Option<String>,
    input: SamlSpInput,
) -> AppResult<(Client, SamlServiceProvider)> {
    let name = input.name.trim().to_string();
    if name.is_empty() || name.len() > 255 {
        return Err(bad("name must be 1-255 characters"));
    }
    let client_id = match public_id.or(trimmed(input.client_id)) {
        Some(id) => {
            if !clients::is_valid_client_id(&id) {
                return Err(bad(
                    "client_id must be 1-128 characters of [A-Za-z0-9._:-] starting alphanumeric",
                ));
            }
            id
        }
        None => clients::random_client_id(),
    };
    let entity_id = input.entity_id.trim().to_string();
    if entity_id.is_empty()
        || entity_id.len() > 1024
        || entity_id
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(bad("entity_id must be 1-1024 characters without spaces"));
    }
    if input.acs_urls.is_empty() || input.acs_urls.len() > 32 {
        return Err(bad("acs_urls must list 1-32 URLs"));
    }
    let acs_urls: Vec<String> = input
        .acs_urls
        .iter()
        .map(|u| u.trim().to_string())
        .collect();
    for u in &acs_urls {
        clients::validate_uri("acs_urls", u, ClientType::Web)?;
    }
    let slo_url = trimmed(input.slo_url);
    if let Some(u) = &slo_url {
        clients::validate_uri("slo_url", u, ClientType::Web)?;
    }

    if input.signing_certificates.len() > MAX_SIGNING_CERTS {
        return Err(bad(format!(
            "at most {MAX_SIGNING_CERTS} signing certificates"
        )));
    }
    let mut signing_certificates = vec![];
    for pem in &input.signing_certificates {
        let b64 = certificate("signing_certificates", pem)?.to_base64();
        if !signing_certificates.contains(&b64) {
            signing_certificates.push(b64);
        }
    }
    let encryption_certificate = match trimmed(input.encryption_certificate) {
        Some(pem) => {
            let cert = certificate("encryption_certificate", &pem)?;
            if cert.rsa_spki().is_none() {
                return Err(bad("encryption_certificate must hold an RSA key"));
            }
            Some(cert.to_base64())
        }
        None => None,
    };
    let require_signed_requests = input.require_signed_requests.unwrap_or(false);
    if require_signed_requests && signing_certificates.is_empty() {
        return Err(bad(
            "require_signed_requests needs at least one signing certificate",
        ));
    }
    let encrypt_assertion = input.encrypt_assertion.unwrap_or(false);
    if encrypt_assertion && encryption_certificate.is_none() {
        return Err(bad("encrypt_assertion needs an encryption_certificate"));
    }
    let sign_response = input.sign_response.unwrap_or(true);
    let sign_assertion = input.sign_assertion.unwrap_or(true);
    if !sign_response && !sign_assertion {
        return Err(bad(
            "sign the response, the assertion or both: an unsigned assertion proves nothing",
        ));
    }
    let default_relay_state = trimmed(input.default_relay_state);
    if default_relay_state
        .as_ref()
        .is_some_and(|r| r.len() > MAX_RELAY_STATE)
    {
        return Err(bad(format!(
            "default_relay_state is longer than {MAX_RELAY_STATE} bytes"
        )));
    }
    let attributes = input.attributes.unwrap_or_default();
    if attributes.len() > MAX_ATTRIBUTES {
        return Err(bad(format!("at most {MAX_ATTRIBUTES} attributes")));
    }
    let mut names = std::collections::BTreeSet::new();
    for a in &attributes {
        if a.claim.trim().is_empty() || a.claim.len() > 128 {
            return Err(bad("attributes: claim must be 1-128 characters"));
        }
        if a.name.trim().is_empty() || a.name.len() > 1024 {
            return Err(bad("attributes: name must be 1-1024 characters"));
        }
        if !names.insert(a.name.as_str()) {
            return Err(bad(format!("attributes: `{}` is listed twice", a.name)));
        }
    }
    let assertion_ttl_secs = input.assertion_ttl_secs.unwrap_or(300);
    if !(30..=3600).contains(&assertion_ttl_secs) {
        return Err(bad("assertion_ttl_secs must be 30-3600"));
    }

    let now = Utc::now();
    let client = Client {
        id: client_row_id,
        tenant_id,
        client_id,
        name,
        client_type: ClientType::Saml,
        description: trimmed(input.description),
        logo_uri: trimmed(input.logo_uri),
        client_uri: trimmed(input.client_uri),
        tos_uri: None,
        policy_uri: None,
        secret_hashes: Json(vec![]),
        jwks: None,
        jwks_uri: None,
        token_endpoint_auth_method: TokenEndpointAuthMethod::None,
        redirect_uris: vec![],
        post_logout_redirect_uris: vec![],
        allowed_grants: vec![],
        allowed_scopes: input
            .allowed_scopes
            .unwrap_or_else(|| DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect()),
        allowed_audiences: vec![],
        access_token_ttl_secs: None,
        refresh_token_ttl_secs: None,
        id_token_ttl_secs: None,
        access_token_format: AccessTokenFormat::Jwt,
        id_token_encryption: None,
        subject_type: ClientSubjectType::Pairwise,
        sector_identifier_uri: None,
        require_pkce: false,
        require_consent: input.require_consent.unwrap_or(false),
        id_token_scope_claims: false,
        cors_origins: vec![],
        initiate_login_uri: None,
        backchannel_logout_uri: None,
        frontchannel_logout_uri: None,
        dpop_bound_access_tokens: false,
        backchannel_token_delivery_mode: None,
        backchannel_client_notification_endpoint: None,
        security_profile: SecurityProfile::None,
        require_pushed_authorization_requests: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_san_dns: None,
        tls_client_auth_san_uri: None,
        tls_client_auth_san_ip: None,
        tls_client_auth_san_email: None,
        tls_client_certificate_bound_access_tokens: false,
        service_account_user_id: None,
        registration_access_token_hash: None,
        status: ClientStatus::Active,
        created_at: now,
        updated_at: now,
    };
    let sp = SamlServiceProvider {
        client_id: client_row_id,
        tenant_id,
        entity_id,
        acs_urls,
        slo_url,
        slo_binding: input.slo_binding.unwrap_or_default(),
        name_id_format: input.name_id_format.unwrap_or_default(),
        signing_certificates,
        encryption_certificate,
        require_signed_requests,
        sign_response,
        sign_assertion,
        encrypt_assertion,
        data_encryption: input.data_encryption.unwrap_or_default(),
        key_transport: input.key_transport.unwrap_or_default(),
        allow_idp_initiated: input.allow_idp_initiated.unwrap_or(false),
        default_relay_state,
        attributes: Json(attributes),
        assertion_ttl_secs,
        created_at: now,
        updated_at: now,
    };
    Ok((client, sp))
}

/// The input that reproduces a registered SP, every field spelled out
/// (the tenant document's form).
pub fn to_input(client: &Client, sp: &SamlServiceProvider) -> SamlSpInput {
    SamlSpInput {
        name: client.name.clone(),
        description: client.description.clone(),
        logo_uri: client.logo_uri.clone(),
        client_uri: client.client_uri.clone(),
        client_id: Some(client.client_id.clone()),
        allowed_scopes: Some(client.allowed_scopes.clone()),
        require_consent: Some(client.require_consent),
        entity_id: sp.entity_id.clone(),
        acs_urls: sp.acs_urls.clone(),
        slo_url: sp.slo_url.clone(),
        slo_binding: Some(sp.slo_binding),
        name_id_format: Some(sp.name_id_format),
        signing_certificates: sp.signing_certificates.clone(),
        encryption_certificate: sp.encryption_certificate.clone(),
        require_signed_requests: Some(sp.require_signed_requests),
        sign_response: Some(sp.sign_response),
        sign_assertion: Some(sp.sign_assertion),
        encrypt_assertion: Some(sp.encrypt_assertion),
        data_encryption: Some(sp.data_encryption),
        key_transport: Some(sp.key_transport),
        allow_idp_initiated: Some(sp.allow_idp_initiated),
        default_relay_state: sp.default_relay_state.clone(),
        attributes: Some(sp.attributes.0.clone()),
        assertion_ttl_secs: Some(sp.assertion_ttl_secs),
    }
}

/// Cache entries an SP write must evict.
pub fn sp_cache_keys(sp: &SamlServiceProvider) -> Vec<String> {
    vec![
        cache_keys::saml_sp(sp.tenant_id, sp.client_id),
        cache_keys::saml_sp_by_entity(sp.tenant_id, &sp.entity_id),
    ]
}

fn entity_conflict(e: AppError) -> AppError {
    match e {
        AppError::Conflict(_) => {
            AppError::Conflict("a client or service provider with that id already exists".into())
        }
        other => other,
    }
}

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    input: SamlSpInput,
) -> AppResult<SamlSpView> {
    let (client, sp) = resolve(tenant_id, Uuid::now_v7(), None, input)?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let client = repos::clients::insert(&mut *tx, &client)
        .await
        .map_err(|e| entity_conflict(AppError::from_db(e)))?;
    let saml = repos::saml::upsert_sp(&mut *tx, &sp)
        .await
        .map_err(|e| entity_conflict(AppError::from_db(e)))?;
    tx.commit().await?;
    state
        .cache
        .invalidate(
            &[
                clients::client_cache_keys(tenant_id, &client.client_id),
                sp_cache_keys(&saml),
            ]
            .concat(),
        )
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ClientCreated {
            client_id: client.id,
            public_id: client.client_id.clone(),
        },
    ));
    Ok(SamlSpView { client, saml })
}

/// The SP whose client row is `id`.
pub async fn get(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<SamlSpView> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let client = repos::clients::find_by_id(&mut *tx, tenant_id, id).await?;
    let saml = repos::saml::find_sp(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    match (client, saml) {
        (Some(client), Some(saml)) => Ok(SamlSpView { client, saml }),
        _ => Err(AppError::NotFound("SAML service provider")),
    }
}

pub async fn list(state: &AppState, tenant_id: Uuid) -> AppResult<Vec<SamlSpView>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let sps = repos::saml::list_sps(&mut *tx, tenant_id).await?;
    let mut out = Vec::with_capacity(sps.len());
    for saml in sps {
        if let Some(client) =
            repos::clients::find_by_id(&mut *tx, tenant_id, saml.client_id).await?
        {
            out.push(SamlSpView { client, saml });
        }
    }
    tx.commit().await?;
    Ok(out)
}

/// Replace an SP's settings. The public client id, status and creation
/// time are kept.
pub async fn replace(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
    input: SamlSpInput,
) -> AppResult<SamlSpView> {
    let current = get(state, tenant_id, id).await?;
    let (mut client, sp) = resolve(tenant_id, id, Some(current.client.client_id.clone()), input)?;
    client.status = current.client.status;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let client = repos::clients::update_metadata(&mut *tx, &client)
        .await
        .map_err(AppError::from_db)?
        .ok_or(AppError::NotFound("SAML service provider"))?;
    let saml = repos::saml::upsert_sp(&mut *tx, &sp)
        .await
        .map_err(|e| entity_conflict(AppError::from_db(e)))?;
    tx.commit().await?;
    state
        .cache
        .invalidate(
            &[
                clients::client_cache_keys(tenant_id, &client.client_id),
                sp_cache_keys(&current.saml),
                sp_cache_keys(&saml),
            ]
            .concat(),
        )
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ClientUpdated {
            client_id: client.id,
        },
    ));
    Ok(SamlSpView { client, saml })
}

/// Evict an SP about to disappear with its client (the client routes'
/// delete goes through here for `saml` clients too).
pub async fn forget(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let saml = repos::saml::find_sp(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if let Some(saml) = saml {
        state.cache.invalidate(&sp_cache_keys(&saml)).await?;
    }
    Ok(())
}

/// The SP registered under `entity_id`, if any (cached).
pub async fn find_by_entity_id(
    state: &AppState,
    tenant_id: Uuid,
    entity_id: &str,
) -> AppResult<Option<Arc<SpEntry>>> {
    if entity_id.is_empty() || entity_id.len() > 1024 {
        return Ok(None);
    }
    let db = state.db.clone();
    let entity = entity_id.to_string();
    state
        .cache
        .get_or_load(
            &cache_keys::saml_sp_by_entity(tenant_id, entity_id),
            SP_CACHE_TTL,
            || async move {
                let mut tx = db::tenant_tx(&db, tenant_id).await?;
                let sp = repos::saml::find_sp_by_entity_id(&mut *tx, tenant_id, &entity).await?;
                let entry = match sp {
                    Some(sp) => repos::clients::find_by_id(&mut *tx, tenant_id, sp.client_id)
                        .await?
                        .map(|c| SpEntry {
                            sp,
                            client_public_id: c.client_id,
                        }),
                    None => None,
                };
                tx.commit().await?;
                Ok(entry)
            },
        )
        .await
}

/// The SP of the client row `client_id`, if it is one (cached).
pub async fn find_by_client(
    state: &AppState,
    tenant_id: Uuid,
    client_id: Uuid,
) -> AppResult<Option<Arc<SamlServiceProvider>>> {
    let db = state.db.clone();
    state
        .cache
        .get_or_load(
            &cache_keys::saml_sp(tenant_id, client_id),
            SP_CACHE_TTL,
            || async move {
                let mut tx = db::tenant_tx(&db, tenant_id).await?;
                let sp = repos::saml::find_sp(&mut *tx, tenant_id, client_id).await?;
                tx.commit().await?;
                Ok(sp)
            },
        )
        .await
}

/// Prefill a registration from an SP's metadata document (nothing is
/// saved; the caller reviews and creates).
pub fn from_metadata(xml: &str) -> AppResult<SamlSpInput> {
    let m = parse_sp_metadata(xml).map_err(|e| bad(e.to_string()))?;
    let name_id_format = m
        .name_id_formats
        .iter()
        .find_map(|f| NameIdFormat::from_urn(f));
    let host = url::Url::parse(&m.entity_id)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string));
    Ok(SamlSpInput {
        name: host.unwrap_or_else(|| m.entity_id.chars().take(255).collect()),
        entity_id: m.entity_id,
        acs_urls: m.acs_urls,
        slo_binding: m.slo.as_ref().map(|(_, redirect)| {
            if *redirect {
                SloBinding::Redirect
            } else {
                SloBinding::Post
            }
        }),
        slo_url: m.slo.map(|(u, _)| u),
        name_id_format,
        require_signed_requests: Some(
            m.authn_requests_signed && !m.signing_certificates.is_empty(),
        ),
        signing_certificates: m.signing_certificates,
        encryption_certificate: m.encryption_certificate,
        ..SamlSpInput::default()
    })
}
