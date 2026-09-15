//! Per-tenant JWK Set: `GET /t/{slug}/.well-known/jwks.json`.
//!
//! Cached (L1 + Redis) and invalidated on every key change; served with a
//! strong ETag so relying parties revalidate cheaply.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::cache::keys as cache_keys;
use crate::error::{AppError, OAuthError};
use crate::middleware::TenantCtx;
use crate::services::keys;
use crate::state::AppState;

const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);
/// What clients may cache the document for. Shorter than key overlap.
const MAX_AGE_SECS: u64 = 300;

pub fn router() -> Router<AppState> {
    Router::new().route("/t/{slug}/.well-known/jwks.json", get(jwks))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<serde_json::Value>,
}

/// Cached JWKS document plus its ETag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedJwks {
    pub body: String,
    pub etag: String,
}

pub async fn load_jwks(state: &AppState, tenant: &TenantCtx) -> Result<Arc<CachedJwks>, AppError> {
    let tenant_id = tenant.id();
    let policy = tenant.tenant.settings.keys.clone();
    let st = state.clone();
    let cached = state
        .cache
        .get_or_load(
            &cache_keys::jwks(tenant_id),
            JWKS_CACHE_TTL,
            || async move {
                let mut keys = keys::published_jwks(&st, tenant_id).await?;
                if keys.is_empty() {
                    // First contact: create the tenant's initial key so RPs can
                    // pre-fetch before the first token is issued.
                    keys::ensure_active(&st, tenant_id, &policy).await?;
                    keys = keys::published_jwks(&st, tenant_id).await?;
                }
                let body = serde_json::to_string(&JwkSet { keys })?;
                let etag = format!(
                    "\"{}\"",
                    hex::encode(&Sha256::digest(body.as_bytes())[..16])
                );
                Ok(Some(CachedJwks { body, etag }))
            },
        )
        .await?;
    cached.ok_or_else(|| AppError::Internal("jwks loader returned nothing".into()))
}

async fn jwks(
    State(state): State<AppState>,
    tenant: TenantCtx,
    headers: HeaderMap,
) -> Result<Response, OAuthError> {
    let doc = load_jwks(&state, &tenant).await?;
    let mut response = if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|inm| {
            inm.split(',')
                .any(|t| t.trim() == doc.etag || t.trim() == "*")
        }) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/jwk-set+json"),
            )],
            doc.body.clone(),
        )
            .into_response()
    };
    let h = response.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&doc.etag) {
        h.insert(header::ETAG, v);
    }
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&format!("public, max-age={MAX_AGE_SECS}, must-revalidate"))
            .expect("static header"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    Ok(response)
}
