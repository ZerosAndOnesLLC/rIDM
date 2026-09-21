//! The IdP's SAML signing keys. Unlike the JWT keys they never rotate on a
//! timer: SPs pin the certificate from metadata, often by hand. A rollover
//! is an operator's three steps — add a pending key (metadata lists it at
//! once), activate it once the SPs have the new metadata, delete the old
//! one — and the first key is made on first use.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use ridm_core::providers::Encrypted;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cache::keys as cache_keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::jobs::leader;
use crate::models::{RsaBits, SamlKeyStatus, SamlSigningKey, SigningAlg, Tenant};
use crate::repos;
use crate::saml::cert::{self, Certificate};
use crate::saml::dsig::Signer;
use crate::state::AppState;

/// Certificates are containers for the key, not trust anchors; SPs that
/// check validity still get a decade.
const CERT_YEARS: i32 = 10;
const LIST_TTL: Duration = Duration::from_secs(300);
const SIGNER_L1_TTL: Duration = Duration::from_secs(300);
const CREATE_LOCK_TTL: Duration = Duration::from_secs(120);
const CREATE_WAIT: Duration = Duration::from_secs(90);

/// A key as metadata and the console show it.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SamlKeyView {
    pub id: Uuid,
    pub status: SamlKeyStatus,
    /// base64 DER.
    pub certificate: String,
    /// SHA-256 of the certificate, hex with colons, as SP consoles show it.
    pub sha256_fingerprint: String,
    pub not_after: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<&SamlSigningKey> for SamlKeyView {
    fn from(k: &SamlSigningKey) -> Self {
        use base64::Engine as _;
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &k.certificate);
        Self {
            id: k.id,
            status: k.status,
            certificate: base64::engine::general_purpose::STANDARD.encode(&k.certificate),
            sha256_fingerprint: digest
                .as_ref()
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":"),
            not_after: k.not_after,
            activated_at: k.activated_at,
            created_at: k.created_at,
        }
    }
}

fn aad_for(tenant_id: Uuid, key_id: Uuid) -> Vec<u8> {
    format!("saml_signing_keys:{tenant_id}:{key_id}").into_bytes()
}

async fn invalidate(state: &AppState, tenant_id: Uuid) -> AppResult<()> {
    state
        .cache
        .invalidate(&[cache_keys::saml_keys(tenant_id)])
        .await
}

/// Every key of the tenant (cached; metadata is fetched by every SP).
pub async fn list(state: &AppState, tenant_id: Uuid) -> AppResult<Vec<SamlKeyView>> {
    let db = state.db.clone();
    let loaded = state
        .cache
        .get_or_load(&cache_keys::saml_keys(tenant_id), LIST_TTL, || async move {
            let mut tx = db::tenant_tx(&db, tenant_id).await?;
            let rows = repos::saml::list_keys(&mut *tx, tenant_id).await?;
            tx.commit().await?;
            Ok(Some(rows.iter().map(SamlKeyView::from).collect::<Vec<_>>()))
        })
        .await?;
    Ok(loaded.map(|v| (*v).clone()).unwrap_or_default())
}

/// The published certificates: every key there is, active first.
pub async fn certificates(state: &AppState, tenant: &Tenant) -> AppResult<Vec<Certificate>> {
    ensure_active(state, tenant).await?;
    let mut keys = list(state, tenant.id).await?;
    keys.sort_by_key(|k| k.status != SamlKeyStatus::Active);
    keys.iter()
        .map(|k| {
            Certificate::parse(&k.certificate)
                .map_err(|e| AppError::Internal(format!("stored SAML certificate: {e}")))
        })
        .collect()
}

async fn generate(
    state: &AppState,
    tenant: &Tenant,
    actor: Actor,
    status: SamlKeyStatus,
) -> AppResult<SamlSigningKey> {
    let bits: RsaBits = tenant.settings.keys.rsa_bits;
    let common_name = format!("rIDM SAML {}", tenant.slug);
    let (pkcs8, certificate) = tokio::task::spawn_blocking(move || {
        let generated = crate::services::keys::generate(SigningAlg::RS256, bits)?;
        let certificate = cert::self_signed(&generated.private_der, &common_name, CERT_YEARS)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok::<_, AppError>((generated.private_der, certificate))
    })
    .await
    .map_err(|e| AppError::Internal(format!("keygen task: {e}")))??;
    let not_after = Certificate::from_der(certificate.clone())
        .map_err(|e| AppError::Internal(e.to_string()))?
        .not_after;
    let id = Uuid::now_v7();
    let encrypted = state
        .key_encryptor
        .encrypt(&pkcs8, &aad_for(tenant.id, id))
        .await
        .map_err(|e| AppError::Internal(format!("key encryption: {e}")))?;
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let key = repos::saml::insert_key(
        &mut *tx,
        &repos::saml::NewKey {
            id,
            tenant_id: tenant.id,
            private_key_enc: &encrypted.to_bytes(),
            key_version: encrypted.key_version as i32,
            certificate: &certificate,
            status,
            not_after,
        },
    )
    .await
    .map_err(AppError::from_db)?;
    tx.commit().await?;
    invalidate(state, tenant.id).await?;
    state.events.publish(Event::new(
        Some(tenant.id),
        actor,
        EventKind::SamlKeyCreated { key_id: key.id },
    ));
    Ok(key)
}

async fn active_row(state: &AppState, tenant_id: Uuid) -> AppResult<Option<SamlSigningKey>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::saml::list_keys(&mut *tx, tenant_id).await?;
    tx.commit().await?;
    Ok(rows.into_iter().find(|k| k.status == SamlKeyStatus::Active))
}

/// The active key's id, creating the tenant's first key if it has none.
/// Nodes racing to make the first key wait on one lock; the unique index
/// keeps a second active key out even if the lock holder dies.
pub async fn ensure_active(state: &AppState, tenant: &Tenant) -> AppResult<Uuid> {
    if let Some(k) = list(state, tenant.id)
        .await?
        .iter()
        .find(|k| k.status == SamlKeyStatus::Active)
    {
        return Ok(k.id);
    }
    let lock_name = format!("saml-keys:{}", tenant.id);
    let deadline = std::time::Instant::now() + CREATE_WAIT;
    loop {
        if let Some(lock) = leader::try_acquire(&state.redis, &lock_name, CREATE_LOCK_TTL).await? {
            let made = match active_row(state, tenant.id).await? {
                Some(k) => Ok(k.id),
                None => first_key(state, tenant).await,
            };
            lock.release().await?;
            return made;
        }
        if let Some(k) = active_row(state, tenant.id).await? {
            invalidate(state, tenant.id).await?;
            return Ok(k.id);
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    first_key(state, tenant).await
}

async fn first_key(state: &AppState, tenant: &Tenant) -> AppResult<Uuid> {
    match generate(state, tenant, Actor::System, SamlKeyStatus::Active).await {
        Ok(k) => Ok(k.id),
        Err(AppError::Conflict(_)) => {
            active_row(state, tenant.id)
                .await?
                .map(|k| k.id)
                .ok_or(AppError::Internal(
                    "no active SAML key after creation".into(),
                ))
        }
        Err(e) => Err(e),
    }
}

/// The signer for the active key (the key decrypted once per node).
pub async fn signer(state: &AppState, tenant: &Tenant) -> AppResult<Arc<Signer>> {
    let id = ensure_active(state, tenant).await?;
    let cache_key = cache_keys::saml_key_material(id);
    if let Some(s) = state.cache.l1().get::<Signer>(&cache_key) {
        return Ok(s);
    }
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let rows = repos::saml::list_keys(&mut *tx, tenant.id).await?;
    tx.commit().await?;
    let key = rows
        .into_iter()
        .find(|k| k.id == id)
        .ok_or(AppError::NotFound("SAML signing key"))?;
    let encrypted = Encrypted::from_bytes(&key.private_key_enc)
        .map_err(|e| AppError::Internal(format!("stored key blob: {e}")))?;
    let pkcs8 = state
        .key_encryptor
        .decrypt(&encrypted, &aad_for(tenant.id, key.id))
        .await
        .map_err(|e| AppError::Internal(format!("key decryption: {e}")))?;
    let signer = Arc::new(
        Signer::new(&pkcs8, &key.certificate).map_err(|e| AppError::Internal(e.to_string()))?,
    );
    state
        .cache
        .l1()
        .insert(cache_key, signer.clone(), SIGNER_L1_TTL);
    Ok(signer)
}

/// Start a rollover: a new key, published at once, signing nothing yet.
pub async fn add_pending(
    state: &AppState,
    tenant: &Tenant,
    actor: Actor,
) -> AppResult<SamlKeyView> {
    ensure_active(state, tenant).await?;
    if list(state, tenant.id)
        .await?
        .iter()
        .any(|k| k.status == SamlKeyStatus::Pending)
    {
        return Err(AppError::Conflict(
            "a pending SAML key already exists; activate or delete it first".into(),
        ));
    }
    let key = generate(state, tenant, actor, SamlKeyStatus::Pending).await?;
    Ok(SamlKeyView::from(&key))
}

/// Make `id` the signing key; the previous one stays published as
/// `retiring` until deleted.
pub async fn activate(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let done = repos::saml::activate_key(&mut tx, tenant_id, id).await?;
    tx.commit().await?;
    if !done {
        return Err(AppError::NotFound("pending or retiring SAML key"));
    }
    invalidate(state, tenant_id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::SamlKeyStatusChanged {
            key_id: id,
            status: "active".into(),
        },
    ));
    Ok(())
}

/// Delete a key that is not signing (a retired one, or a pending one
/// abandoned); it leaves metadata at once.
pub async fn delete(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let done = repos::saml::delete_inactive_key(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !done {
        return Err(AppError::Conflict(
            "no such inactive SAML key (the active key cannot be deleted)".into(),
        ));
    }
    invalidate(state, tenant_id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::SamlKeyStatusChanged {
            key_id: id,
            status: "deleted".into(),
        },
    ));
    Ok(())
}
