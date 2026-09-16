//! DPoP: sender-constrained tokens (RFC 9449).
//!
//! A client presents a `DPoP` header — a JWT signed with a key it embeds in
//! the header — on the token endpoint and on every resource request. The
//! proof is checked here ([`verify_proof`]): type, algorithm, signature,
//! method, URL, freshness, one-time `jti`, and at resources the hash of the
//! access token (`ath`). The key's thumbprint is what the token is bound to
//! (`cnf.jkt`); [`enforce_binding`] refuses a bound token presented as a
//! plain bearer token or with a proof from another key. Server-provided
//! nonces are not used.

use axum::http::{HeaderMap, Method};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::error::AppError;
use crate::models::Tenant;
use crate::oidc::bearer::Scheme;
use crate::services::keys;
use crate::state::AppState;

/// Proof algorithms accepted (asymmetric only, RFC 9449 §4.2).
pub const ALGS: [&str; 9] = [
    "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA",
];
/// A proof's `iat` may lie this far in the past ...
const MAX_AGE_SECS: i64 = 300;
/// ... or this far in the future (clock skew).
const MAX_SKEW_SECS: i64 = 30;

/// A verified proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// RFC 7638 thumbprint of the proof key.
    pub jkt: String,
}

fn algorithm(name: &str) -> Option<Algorithm> {
    ALGS.contains(&name)
        .then(|| name.parse::<Algorithm>().ok())
        .flatten()
}

/// Normalize an `htu` for comparison: scheme and host lower-cased, no query
/// or fragment (RFC 9449 §4.3).
fn normalize_htu(raw: &str) -> Option<String> {
    let mut u = Url::parse(raw).ok()?;
    u.set_query(None);
    u.set_fragment(None);
    Some(u.to_string())
}

/// The URLs a client may legitimately name for a tenant endpoint: the
/// issuer's form (custom domain when set) and the primary `/t/{slug}` form.
/// `rest` is the path below the tenant prefix, e.g. `/token`.
pub fn htu_candidates(state: &AppState, tenant: &Tenant, rest: &str) -> Vec<String> {
    let primary = format!(
        "{}/t/{}{rest}",
        state.config.public_url.as_str().trim_end_matches('/'),
        tenant.slug
    );
    let mut v = vec![primary];
    if let Some(host) = &tenant.settings.custom_domain {
        v.push(format!("https://{host}{rest}"));
    }
    v
}

/// `htu` candidates for a request path as routed (`/t/{slug}/...` or a global path).
pub fn htu_for_path(state: &AppState, tenant: &Tenant, path: &str) -> Vec<String> {
    let prefix = format!("/t/{}", tenant.slug);
    match path.strip_prefix(&prefix) {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => {
            htu_candidates(state, tenant, rest)
        }
        _ => vec![format!(
            "{}{path}",
            state.config.public_url.as_str().trim_end_matches('/')
        )],
    }
}

/// Base64url SHA-256 of an access token (the `ath` claim).
pub fn access_token_hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

/// Exactly one `DPoP` header, or none.
pub fn header(headers: &HeaderMap) -> Result<Option<&str>, &'static str> {
    let mut all = headers.get_all("dpop").iter();
    let first = all.next();
    if all.next().is_some() {
        return Err("more than one DPoP header");
    }
    match first {
        None => Ok(None),
        Some(v) => v
            .to_str()
            .map(|s| Some(s.trim()))
            .map_err(|_| "DPoP header is not valid text"),
    }
}

/// Verify a proof for `method` on one of `htu` (RFC 9449 §4.3). With
/// `access_token`, the proof must also carry its hash (`ath`).
pub async fn verify_proof(
    state: &AppState,
    tenant: &Tenant,
    proof: &str,
    method: &Method,
    htu: &[String],
    access_token: Option<&str>,
) -> Result<Proof, String> {
    if proof.is_empty() || proof.len() > 4096 {
        return Err("DPoP proof is empty or too long".into());
    }
    let header = jsonwebtoken::decode_header(proof).map_err(|_| "DPoP proof is not a JWT")?;
    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err("DPoP proof typ must be dpop+jwt".into());
    }
    let alg_name = format!("{:?}", header.alg);
    let alg = algorithm(&alg_name).ok_or("DPoP proof algorithm is not allowed")?;
    let jwk = header.jwk.ok_or("DPoP proof carries no jwk")?;
    let jwk_value = serde_json::to_value(&jwk).map_err(|_| "DPoP jwk is malformed")?;
    if jwk_value.get("d").is_some() {
        return Err("DPoP jwk must be a public key".into());
    }
    let decoding = DecodingKey::from_jwk(&jwk).map_err(|_| "DPoP jwk is not usable")?;
    let mut validation = Validation::new(alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let data = jsonwebtoken::decode::<Map<String, Value>>(proof, &decoding, &validation)
        .map_err(|_| "DPoP proof signature is invalid")?;
    let claims = data.claims;

    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|j| !j.is_empty() && j.len() <= 256)
        .ok_or("DPoP proof needs a jti")?;
    let htm = claims
        .get("htm")
        .and_then(Value::as_str)
        .ok_or("DPoP proof needs htm")?;
    if htm != method.as_str() {
        return Err("DPoP htm does not match the request method".into());
    }
    let claimed = claims
        .get("htu")
        .and_then(Value::as_str)
        .and_then(normalize_htu)
        .ok_or("DPoP proof needs htu")?;
    if !htu
        .iter()
        .filter_map(|h| normalize_htu(h))
        .any(|h| h == claimed)
    {
        return Err("DPoP htu does not match the request URL".into());
    }
    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or("DPoP proof needs iat")?;
    let now = Utc::now().timestamp();
    if iat < now - MAX_AGE_SECS || iat > now + MAX_SKEW_SECS {
        return Err("DPoP proof iat is too old or in the future".into());
    }
    match (access_token, claims.get("ath").and_then(Value::as_str)) {
        (Some(token), Some(ath)) if ath == access_token_hash(token) => {}
        (Some(_), _) => return Err("DPoP ath does not match the access token".into()),
        (None, _) => {}
    }

    // One use per jti within the acceptance window.
    let key = format!(
        "{}:t:{}:dpop:jti:{}",
        crate::cache::keys::PREFIX,
        tenant.id,
        URL_SAFE_NO_PAD.encode(Sha256::digest(jti.as_bytes()))
    );
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::from(e).to_string())?;
    let fresh: bool = redis::cmd("SET")
        .arg(&key)
        .arg(1u8)
        .arg("NX")
        .arg("EX")
        .arg((MAX_AGE_SECS + MAX_SKEW_SECS) as u64)
        .query_async(&mut *conn)
        .await
        .map_err(|e| AppError::from(e).to_string())?;
    if !fresh {
        return Err("DPoP proof replayed".into());
    }
    let jkt = keys::thumbprint(&jwk_value).map_err(|e| e.to_string())?;
    Ok(Proof { jkt })
}

/// The key thumbprint a token is bound to, if any.
pub fn bound_jkt(claims: &Map<String, Value>) -> Option<&str> {
    claims.get("cnf")?.get("jkt")?.as_str()
}

/// An access token as it arrived at a resource.
#[derive(Debug, Clone, Copy)]
pub struct Presented<'a> {
    pub scheme: Scheme,
    pub token: &'a str,
    pub claims: &'a Map<String, Value>,
}

/// At a resource: a bound token must come as `Authorization: DPoP` with a
/// proof from the same key that also names the token (`ath`). Unbound
/// tokens pass under either scheme.
pub async fn enforce_binding(
    state: &AppState,
    tenant: &Tenant,
    presented: Presented<'_>,
    headers: &HeaderMap,
    method: &Method,
    htu: &[String],
) -> Result<(), String> {
    let Some(expected) = bound_jkt(presented.claims) else {
        return Ok(());
    };
    if presented.scheme != Scheme::Dpop {
        return Err("this token is DPoP-bound and must be sent with the DPoP scheme".into());
    }
    let proof = header(headers)?.ok_or("DPoP proof required")?;
    let proof = verify_proof(state, tenant, proof, method, htu, Some(presented.token)).await?;
    if proof.jkt != expected {
        return Err("DPoP proof key does not match the token's binding".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn htu_normalization_ignores_query_and_case() {
        assert_eq!(
            normalize_htu("HTTPS://ID.Example.com/t/acme/token?x=1#f"),
            Some("https://id.example.com/t/acme/token".into())
        );
        assert_eq!(normalize_htu("nonsense"), None);
    }

    #[test]
    fn algorithms() {
        assert!(algorithm("ES256").is_some());
        assert!(algorithm("HS256").is_none());
        assert!(algorithm("none").is_none());
    }
}
