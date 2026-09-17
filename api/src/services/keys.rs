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

use redis::AsyncCommands as _;

use crate::cache::keys as cache_keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::jobs::leader;
use crate::models::{KeyPolicy, KeyStatus, RsaBits, SigningAlg, SigningKey};
use crate::repos;
use crate::state::AppState;

/// How long the keys version token lives; any key change writes a new one.
const KEYS_VERSION_TTL: u64 = 24 * 60 * 60;
/// One node at a time generates a tenant's first key. Long enough for an RSA
/// key on a slow (debug) build, short enough that a dead node is not waited on.
const CREATE_LOCK_TTL: std::time::Duration = std::time::Duration::from_secs(120);
/// How long the others wait for the key that node is generating.
const CREATE_WAIT: std::time::Duration = std::time::Duration::from_secs(90);

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

    bump_keys_version(state, tenant_id).await?;
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

/// Make `id` the signing key for its algorithm. Any other active key of the
/// same algorithm moves to `retiring` and stays published for
/// `retire_overlap_hours` so tokens it signed keep verifying.
pub async fn activate(
    state: &AppState,
    tenant_id: Uuid,
    policy: &KeyPolicy,
    actor: Actor,
    id: Uuid,
) -> AppResult<SigningKey> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let key = repos::signing_keys::find_by_id(&mut *tx, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("signing key"))?;
    if key.status == KeyStatus::Revoked {
        return Err(AppError::BadRequest(
            "a revoked key cannot be activated".into(),
        ));
    }
    let overlap = Utc::now() + chrono::Duration::hours(i64::from(policy.retire_overlap_hours));
    let mut retired = vec![];
    for other in repos::signing_keys::list(&mut *tx, tenant_id, Some(KeyStatus::Active)).await? {
        if other.id != id && other.alg == key.alg {
            repos::signing_keys::set_status(
                &mut *tx,
                tenant_id,
                other.id,
                KeyStatus::Retiring,
                Some(overlap),
            )
            .await?;
            retired.push(other);
        }
    }
    let key = repos::signing_keys::set_status(&mut *tx, tenant_id, id, KeyStatus::Active, None)
        .await?
        .ok_or(AppError::NotFound("signing key"))?;
    tx.commit().await?;
    bump_keys_version(state, tenant_id).await?;
    for r in retired {
        publish_status(state, tenant_id, actor.clone(), &r, KeyStatus::Retiring);
    }
    publish_status(state, tenant_id, actor, &key, KeyStatus::Active);
    Ok(key)
}

/// Stop signing with a key but keep it published until `expires_at`.
pub async fn retire(
    state: &AppState,
    tenant_id: Uuid,
    policy: &KeyPolicy,
    actor: Actor,
    id: Uuid,
) -> AppResult<SigningKey> {
    let overlap = Utc::now() + chrono::Duration::hours(i64::from(policy.retire_overlap_hours));
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let key = repos::signing_keys::find_by_id(&mut *tx, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("signing key"))?;
    if key.status == KeyStatus::Revoked {
        return Err(AppError::BadRequest("key is already revoked".into()));
    }
    let key = repos::signing_keys::set_status(
        &mut *tx,
        tenant_id,
        id,
        KeyStatus::Retiring,
        Some(overlap),
    )
    .await?
    .ok_or(AppError::NotFound("signing key"))?;
    tx.commit().await?;
    bump_keys_version(state, tenant_id).await?;
    publish_status(state, tenant_id, actor, &key, KeyStatus::Retiring);
    Ok(key)
}

/// Unpublish a key immediately. Tokens signed with it stop verifying.
pub async fn revoke(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> AppResult<SigningKey> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let key = repos::signing_keys::set_status(
        &mut *tx,
        tenant_id,
        id,
        KeyStatus::Revoked,
        Some(Utc::now()),
    )
    .await?
    .ok_or(AppError::NotFound("signing key"))?;
    tx.commit().await?;
    bump_keys_version(state, tenant_id).await?;
    publish_status(state, tenant_id, actor, &key, KeyStatus::Revoked);
    Ok(key)
}

/// Generate a new key with the tenant's default algorithm, activate it, and
/// retire the previous active key with overlap.
pub async fn rotate(
    state: &AppState,
    tenant_id: Uuid,
    policy: &KeyPolicy,
    actor: Actor,
) -> AppResult<SigningKey> {
    let fresh = create(
        state,
        tenant_id,
        actor.clone(),
        policy.default_alg,
        policy.rsa_bits,
        KeyStatus::Pending,
        None,
    )
    .await?;
    activate(state, tenant_id, policy, actor, fresh.id).await
}

/// Current keys version for a tenant, creating one if absent. Every cached
/// JWKS document hangs off it.
pub async fn keys_version(state: &AppState, tenant_id: Uuid) -> AppResult<String> {
    let key = cache_keys::keys_version(tenant_id);
    let mut conn = state.redis.get().await?;
    if let Some(v) = conn.get::<_, Option<String>>(&key).await? {
        return Ok(v);
    }
    let fresh = Uuid::now_v7().simple().to_string();
    // SET NX so concurrent initialisers agree on one token.
    let set: bool = redis::cmd("SET")
        .arg(&key)
        .arg(&fresh)
        .arg("NX")
        .arg("EX")
        .arg(KEYS_VERSION_TTL)
        .query_async(&mut conn)
        .await?;
    if set {
        return Ok(fresh);
    }
    Ok(conn.get::<_, Option<String>>(&key).await?.unwrap_or(fresh))
}

/// Replace the keys version, orphaning every cached JWKS document of the
/// tenant. Used instead of deleting the entry: a document read before a key
/// change can still be written after it, and would then outlive the delete.
pub async fn bump_keys_version(state: &AppState, tenant_id: Uuid) -> AppResult<()> {
    let key = cache_keys::keys_version(tenant_id);
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(&key, Uuid::now_v7().simple().to_string(), KEYS_VERSION_TTL)
        .await?;
    Ok(())
}

/// The active key for the tenant's default algorithm, created on first use.
///
/// One node generates it: a key costs real CPU (RSA especially) and every
/// request that finds none would otherwise generate one of its own, leaving
/// several active keys behind — of which tokens would use the newest while a
/// JWKS document fetched moments earlier named another. The others wait here
/// for the key rather than making their own.
pub async fn ensure_active(
    state: &AppState,
    tenant_id: Uuid,
    policy: &KeyPolicy,
) -> AppResult<SigningKey> {
    if let Some(k) = active(state, tenant_id, policy.default_alg).await? {
        return Ok(k);
    }
    let lock_name = format!("keys:{tenant_id}:{}", policy.default_alg.as_str());
    let deadline = std::time::Instant::now() + CREATE_WAIT;
    loop {
        if let Some(lock) = leader::try_acquire(&state.redis, &lock_name, CREATE_LOCK_TTL).await? {
            // Ours to make, unless another holder finished between the two checks.
            let made = match active(state, tenant_id, policy.default_alg).await? {
                Some(k) => Ok(k),
                None => first_key(state, tenant_id, policy).await,
            };
            lock.release().await?;
            return made;
        }
        // Someone else is generating it. Wait for the key, not for the lock.
        if let Some(k) = active(state, tenant_id, policy.default_alg).await? {
            return Ok(k);
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    // The holder died or is slower than the wait. Make one; the unique index
    // over (tenant, alg) for active keys keeps whichever lands first.
    tracing::warn!(%tenant_id, "waited out another node's first signing key; making one");
    first_key(state, tenant_id, policy).await
}

/// Create the tenant's first active key, adopting another node's if it landed
/// first (the partial unique index turns that into a conflict).
async fn first_key(state: &AppState, tenant_id: Uuid, policy: &KeyPolicy) -> AppResult<SigningKey> {
    match create(
        state,
        tenant_id,
        Actor::System,
        policy.default_alg,
        policy.rsa_bits,
        KeyStatus::Active,
        None,
    )
    .await
    {
        Ok(k) => Ok(k),
        // Lost a race with another node: use what it created.
        Err(AppError::Conflict(_)) => active(state, tenant_id, policy.default_alg)
            .await?
            .ok_or(AppError::Internal("no active key after creation".into())),
        Err(e) => Err(e),
    }
}

/// Housekeeping for one tenant: revoke retiring keys past their overlap and
/// rotate the active key when it is older than the rotation interval.
/// Returns `(revoked, rotated)`.
pub async fn maintain(
    state: &AppState,
    tenant_id: Uuid,
    policy: &KeyPolicy,
) -> AppResult<(usize, bool)> {
    let now = Utc::now();
    let mut revoked = 0;
    for key in list(state, tenant_id, Some(KeyStatus::Retiring)).await? {
        if key.expires_at.is_some_and(|t| t <= now) {
            revoke(state, tenant_id, Actor::System, key.id).await?;
            revoked += 1;
        }
    }
    let mut rotated = false;
    if policy.rotation_interval_days > 0
        && let Some(current) = active(state, tenant_id, policy.default_alg).await?
        && current.not_before + chrono::Duration::days(i64::from(policy.rotation_interval_days))
            <= now
    {
        rotate(state, tenant_id, policy, Actor::System).await?;
        rotated = true;
    }
    Ok((revoked, rotated))
}

fn publish_status(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    key: &SigningKey,
    status: KeyStatus,
) {
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::SigningKeyStatusChanged {
            key_id: key.id,
            kid: key.kid.clone(),
            status: status.as_str().into(),
        },
    ));
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
