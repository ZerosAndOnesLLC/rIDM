//! The certificate authorities a tenant trusts for `tls_client_auth`
//! clients (RFC 8705 §2.1). A client certificate must chain to one of them;
//! which client it authenticates is then decided by the subject registered
//! on the client.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{MtlsTrustAnchor, NewMtlsTrustAnchor};
use crate::oidc::mtls;
use crate::repos;
use crate::state::AppState;

/// Anchors are evicted on every change; the TTL only bounds staleness after
/// a missed invalidation.
const ANCHORS_TTL: Duration = Duration::from_secs(300);
/// A tenant trusts a handful of CAs, not a public root store.
pub const MAX_ANCHORS: i64 = 50;

/// A trust anchor ready to verify with.
#[derive(Debug, Clone)]
pub struct Anchor {
    pub der: Vec<u8>,
}

/// Every anchor of the tenant, through the cache.
pub async fn cached(state: &AppState, tenant_id: Uuid) -> AppResult<Arc<Vec<Anchor>>> {
    let db = state.db.clone();
    let rows = state
        .cache
        .get_or_load(
            &keys::mtls_trust_anchors(tenant_id),
            ANCHORS_TTL,
            || async move {
                let mut tx = db::tenant_tx(&db, tenant_id).await?;
                let rows = repos::mtls_trust_anchors::list(&mut *tx, tenant_id).await?;
                tx.commit().await?;
                Ok(Some(rows))
            },
        )
        .await?
        .unwrap_or_default();
    Ok(Arc::new(
        rows.iter()
            .filter_map(|a| mtls::parse_header(&a.certificate_pem)?.into_iter().next())
            .map(|der| Anchor { der })
            .collect(),
    ))
}

pub async fn list(state: &AppState, tenant_id: Uuid) -> AppResult<Vec<MtlsTrustAnchor>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::mtls_trust_anchors::list(&mut *tx, tenant_id).await?;
    tx.commit().await?;
    Ok(rows)
}

/// Check an uploaded CA certificate and describe it. One certificate, a CA
/// (basic constraints `cA`), not yet expired.
pub fn inspect(tenant_id: Uuid, input: NewMtlsTrustAnchor) -> AppResult<MtlsTrustAnchor> {
    let bad = |m: &str| AppError::BadRequest(m.into());
    let name = input.name.trim().to_string();
    if name.is_empty() || name.len() > 255 {
        return Err(bad("name must be 1-255 characters"));
    }
    let pem = input.certificate_pem.trim();
    if !pem.starts_with("-----BEGIN CERTIFICATE-----") || pem.len() > 16 * 1024 {
        return Err(bad("certificate_pem must be one PEM certificate"));
    }
    let ders =
        mtls::parse_header(pem).ok_or_else(|| bad("certificate_pem is not a PEM certificate"))?;
    let [der] = ders.as_slice() else {
        return Err(bad("certificate_pem must hold exactly one certificate"));
    };
    let info = mtls::describe_ca(der)
        .map_err(|e| AppError::BadRequest(format!("certificate_pem: {e}")))?;
    if info.not_after <= Utc::now() {
        return Err(bad("the certificate has expired"));
    }
    Ok(MtlsTrustAnchor {
        id: Uuid::now_v7(),
        tenant_id,
        name,
        certificate_pem: format!("{pem}\n"),
        subject: info.subject,
        fingerprint: mtls::thumbprint(der),
        not_before: info.not_before,
        not_after: info.not_after,
        created_at: Utc::now(),
    })
}

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    input: NewMtlsTrustAnchor,
) -> AppResult<MtlsTrustAnchor> {
    let anchor = inspect(tenant_id, input)?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    if repos::mtls_trust_anchors::count(&mut *tx, tenant_id).await? >= MAX_ANCHORS {
        return Err(AppError::BadRequest(format!(
            "a tenant trusts at most {MAX_ANCHORS} certificate authorities"
        )));
    }
    let anchor = repos::mtls_trust_anchors::insert(&mut *tx, &anchor)
        .await
        .map_err(|e| match AppError::from_db(e) {
            AppError::Conflict(_) => {
                AppError::Conflict("this certificate is already trusted".into())
            }
            other => other,
        })?;
    tx.commit().await?;
    state
        .cache
        .invalidate(&[keys::mtls_trust_anchors(tenant_id)])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::MtlsTrustAnchorCreated {
            anchor_id: anchor.id,
            fingerprint: anchor.fingerprint.clone(),
        },
    ));
    Ok(anchor)
}

pub async fn delete(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::mtls_trust_anchors::delete(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound("trust anchor"));
    }
    state
        .cache
        .invalidate(&[keys::mtls_trust_anchors(tenant_id)])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::MtlsTrustAnchorDeleted { anchor_id: id },
    ));
    Ok(())
}
