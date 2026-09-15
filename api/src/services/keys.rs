//! Signing key generation, storage and retrieval.
//!
//! Private keys never leave this module unencrypted except as a
//! `Zeroizing<Vec<u8>>` PKCS#8 DER handed to the token service.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use ridm_core::providers::Encrypted;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cache::keys as cache_keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{KeyStatus, RsaBits, SigningAlg, SigningKey};
use crate::repos;
use crate::state::AppState;

/// A freshly generated key pair.
pub struct GeneratedKey {
    pub alg: SigningAlg,
    /// RFC 7638 thumbprint, base64url(SHA-256) of the canonical public JWK.
    pub kid: String,
    /// Public JWK including `kid`, `alg`, `use`.
    pub public_jwk: Value,
    /// PKCS#8 DER private key.
    pub private_der: Zeroizing<Vec<u8>>,
}

/// Generate a key pair. CPU-bound (RSA especially); call through
/// `spawn_blocking` on request paths.
pub fn generate(alg: SigningAlg, rsa_bits: RsaBits) -> AppResult<GeneratedKey> {
    let (params, private_der): (Value, Zeroizing<Vec<u8>>) = match alg {
        SigningAlg::RS256 | SigningAlg::RS384 | SigningAlg::RS512 => {
            use rsa::pkcs8::EncodePrivateKey as _;
            use rsa::traits::PublicKeyParts as _;
            let key = rsa::RsaPrivateKey::new(&mut rand_core_06::OsRng, rsa_bits.bits())
                .map_err(|e| AppError::Internal(format!("rsa keygen: {e}")))?;
            let der = key
                .to_pkcs8_der()
                .map_err(|e| AppError::Internal(format!("rsa pkcs8: {e}")))?;
            let n = URL_SAFE_NO_PAD.encode(key.n().to_bytes_be());
            let e = URL_SAFE_NO_PAD.encode(key.e().to_bytes_be());
            (
                json!({"kty": "RSA", "n": n, "e": e}),
                Zeroizing::new(der.as_bytes().to_vec()),
            )
        }
        SigningAlg::ES256 => {
            use p256::elliptic_curve::Generate as _;
            use p256::elliptic_curve::sec1::ToSec1Point as _;
            use p256::pkcs8::EncodePrivateKey as _;
            let secret = p256::SecretKey::generate_from_rng(&mut rand::rng());
            let der = secret
                .to_pkcs8_der()
                .map_err(|e| AppError::Internal(format!("p256 pkcs8: {e}")))?;
            let point = secret.public_key().to_sec1_point(false);
            let x = point
                .x()
                .ok_or_else(|| AppError::Internal("p256 x".into()))?;
            let y = point
                .y()
                .ok_or_else(|| AppError::Internal("p256 y".into()))?;
            (
                json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "x": URL_SAFE_NO_PAD.encode(x),
                    "y": URL_SAFE_NO_PAD.encode(y),
                }),
                Zeroizing::new(der.as_bytes().to_vec()),
            )
        }
        SigningAlg::EdDSA => {
            use ed25519_dalek::pkcs8::EncodePrivateKey as _;
            let signing = ed25519_dalek::SigningKey::generate(&mut rand::rng());
            let der = signing
                .to_pkcs8_der()
                .map_err(|e| AppError::Internal(format!("ed25519 pkcs8: {e}")))?;
            (
                json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
                }),
                Zeroizing::new(der.as_bytes().to_vec()),
            )
        }
    };
    let kid = thumbprint(&params)?;
    let mut public_jwk = params;
    public_jwk["kid"] = Value::String(kid.clone());
    public_jwk["alg"] = Value::String(alg.as_str().into());
    public_jwk["use"] = Value::String("sig".into());
    Ok(GeneratedKey {
        alg,
        kid,
        public_jwk,
        private_der,
    })
}

/// RFC 7638 JWK thumbprint: SHA-256 over the required members in
/// lexicographic order with no whitespace, base64url-encoded.
pub fn thumbprint(jwk: &Value) -> AppResult<String> {
    let kty = jwk["kty"].as_str().unwrap_or_default();
    let members: &[&str] = match kty {
        "RSA" => &["e", "kty", "n"],
        "EC" => &["crv", "kty", "x", "y"],
        "OKP" => &["crv", "kty", "x"],
        other => return Err(AppError::BadRequest(format!("unsupported kty `{other}`"))),
    };
    let mut canonical = String::from("{");
    for (i, m) in members.iter().enumerate() {
        let v = jwk[m]
            .as_str()
            .ok_or_else(|| AppError::BadRequest(format!("jwk missing `{m}`")))?;
        if i > 0 {
            canonical.push(',');
        }
        canonical.push_str(&format!("\"{m}\":\"{v}\""));
    }
    canonical.push('}');
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

fn aad_for(tenant_id: Uuid, key_id: Uuid) -> Vec<u8> {
    format!("signing_keys:{tenant_id}:{key_id}").into_bytes()
}

/// Generate and store a new key for a tenant.
pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    alg: SigningAlg,
    rsa_bits: RsaBits,
    status: KeyStatus,
    not_before: Option<DateTime<Utc>>,
) -> AppResult<SigningKey> {
    let generated = tokio::task::spawn_blocking(move || generate(alg, rsa_bits))
        .await
        .map_err(|e| AppError::Internal(format!("keygen task: {e}")))??;
    let id = Uuid::now_v7();
    let encrypted = state
        .key_encryptor
        .encrypt(&generated.private_der, &aad_for(tenant_id, id))
        .await
        .map_err(|e| AppError::Internal(format!("key encryption: {e}")))?;

    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let key = repos::signing_keys::insert(
        &mut *tx,
        tenant_id,
        id,
        &generated.kid,
        alg,
        &generated.public_jwk,
        &encrypted.to_bytes(),
        encrypted.key_version as i32,
        status,
        not_before.unwrap_or_else(Utc::now),
        None,
    )
    .await
    .map_err(AppError::from_db)?;
    tx.commit().await?;

    state
        .cache
        .invalidate(&[cache_keys::jwks(tenant_id)])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::SigningKeyCreated {
            key_id: key.id,
            kid: key.kid.clone(),
            alg: alg.as_str().into(),
        },
    ));
    Ok(key)
}

/// Decrypt a key's private half (PKCS#8 DER).
pub async fn private_der(state: &AppState, key: &SigningKey) -> AppResult<Zeroizing<Vec<u8>>> {
    let encrypted = Encrypted::from_bytes(&key.private_key_enc)
        .map_err(|e| AppError::Internal(format!("stored key blob: {e}")))?;
    state
        .key_encryptor
        .decrypt(&encrypted, &aad_for(key.tenant_id, key.id))
        .await
        .map_err(|e| AppError::Internal(format!("key decryption: {e}")))
}

pub async fn get(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<SigningKey> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let k = repos::signing_keys::find_by_id(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    k.ok_or(AppError::NotFound("signing key"))
}

pub async fn list(
    state: &AppState,
    tenant_id: Uuid,
    status: Option<KeyStatus>,
) -> AppResult<Vec<SigningKey>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::signing_keys::list(&mut *tx, tenant_id, status).await?;
    tx.commit().await?;
    Ok(rows)
}

/// The key currently used to sign for `alg`, if any.
pub async fn active(
    state: &AppState,
    tenant_id: Uuid,
    alg: SigningAlg,
) -> AppResult<Option<SigningKey>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let k = repos::signing_keys::find_active(&mut *tx, tenant_id, alg).await?;
    tx.commit().await?;
    Ok(k)
}

/// Public JWK set (pending + active + retiring) for a tenant.
pub async fn published_jwks(state: &AppState, tenant_id: Uuid) -> AppResult<Vec<Value>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::signing_keys::list_published(&mut *tx, tenant_id).await?;
    tx.commit().await?;
    Ok(rows.into_iter().map(|k| k.public_jwk).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_every_algorithm_with_thumbprint_kid() {
        for alg in SigningAlg::ALL {
            let k = generate(alg, RsaBits::B2048).unwrap();
            assert_eq!(k.public_jwk["kty"], alg.kty(), "{alg}");
            assert_eq!(k.public_jwk["alg"], alg.as_str());
            assert_eq!(k.public_jwk["use"], "sig");
            assert_eq!(k.public_jwk["kid"], k.kid);
            assert_eq!(
                thumbprint(&k.public_jwk).unwrap(),
                k.kid,
                "kid is the RFC 7638 thumbprint"
            );
            assert!(!k.private_der.is_empty());
            // Private material must not appear in the public JWK.
            let s = k.public_jwk.to_string();
            assert!(!s.contains("\"d\""));
            assert!(!s.contains("\"p\""));
        }
    }

    #[test]
    fn rfc7638_example_thumbprint() {
        // RFC 7638 §3.1 example key and its published thumbprint.
        let jwk = json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        });
        assert_eq!(
            thumbprint(&jwk).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }
}
