//! Client authentication at the token endpoint (RFC 6749 §2.3, OIDC Core §9).
//!
//! The method used must be the one registered for the client; anything else
//! is `invalid_client`.

use std::net::IpAddr;
use std::sync::Arc;

use axum::http::{HeaderMap, header};
use base64::Engine as _;
use chrono::Utc;
use jsonwebtoken::{DecodingKey, Validation};
use serde_json::Value;
use uuid::Uuid;

use crate::error::{OAuthError, OAuthErrorCode};
use crate::middleware::{TenantCtx, cors};
use crate::models::{Client, ClientStatus, TokenEndpointAuthMethod};
use crate::oidc::authorize::RawParams;
use crate::services::{client_keys, clients, ip_rules, rate_limit};
use crate::state::AppState;

pub const JWT_BEARER_ASSERTION: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const MAX_ASSERTION_LIFETIME_SECS: i64 = 600;

fn invalid_client(desc: &str) -> OAuthError {
    OAuthError::new(OAuthErrorCode::InvalidClient, desc)
}

/// Credentials as presented, before knowing the client.
enum Presented {
    Basic { client_id: String, secret: String },
    Post { client_id: String, secret: String },
    Assertion { assertion: String },
    None { client_id: String },
}

fn parse_basic(headers: &HeaderMap) -> Result<Option<(String, String)>, OAuthError> {
    let Some(v) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Ok(None);
    };
    let v = v
        .to_str()
        .map_err(|_| invalid_client("malformed Authorization header"))?;
    let Some(b64) = v.strip_prefix("Basic ") else {
        return Ok(None);
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| invalid_client("malformed Basic credentials"))?;
    let decoded =
        String::from_utf8(decoded).map_err(|_| invalid_client("malformed Basic credentials"))?;
    let (id, secret) = decoded
        .split_once(':')
        .ok_or_else(|| invalid_client("malformed Basic credentials"))?;
    // RFC 6749 §2.3.1: both parts are form-urlencoded.
    let dec = |s: &str| {
        url::form_urlencoded::parse(format!("v={s}").as_bytes())
            .next()
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    };
    Ok(Some((dec(id), dec(secret))))
}

/// Authenticate the client for this request. Returns the client and the
/// method that was used. `ip` is the client address (`client_ip_addr`) for
/// the client-scoped IP rules and the per-client ceiling.
pub async fn authenticate(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    params: &RawParams,
    token_endpoint: &str,
    ip: Option<IpAddr>,
) -> Result<(Arc<Client>, TokenEndpointAuthMethod), OAuthError> {
    let one = |n: &str| params.one(n).map_err(OAuthError::invalid_request);
    let basic = parse_basic(headers)?;
    let body_id = one("client_id")?.map(str::to_string);
    let body_secret = one("client_secret")?.map(str::to_string);
    let assertion = one("client_assertion")?.map(str::to_string);
    let assertion_type = one("client_assertion_type")?;

    // Exactly one mechanism (RFC 6749 §2.3: MUST NOT use more than one).
    let mut count = 0;
    if basic.is_some() {
        count += 1;
    }
    if body_secret.is_some() {
        count += 1;
    }
    if assertion.is_some() {
        count += 1;
    }
    if count > 1 {
        return Err(OAuthError::invalid_request(
            "multiple client authentication methods used",
        ));
    }

    let presented = if let Some((client_id, secret)) = basic {
        if let Some(b) = &body_id
            && b != &client_id
        {
            return Err(invalid_client(
                "client_id in body does not match Authorization header",
            ));
        }
        Presented::Basic { client_id, secret }
    } else if let Some(secret) = body_secret {
        Presented::Post {
            client_id: body_id
                .clone()
                .ok_or_else(|| invalid_client("client_id is required"))?,
            secret,
        }
    } else if let Some(assertion) = assertion {
        if assertion_type != Some(JWT_BEARER_ASSERTION) {
            return Err(OAuthError::invalid_request(
                "unsupported client_assertion_type",
            ));
        }
        Presented::Assertion { assertion }
    } else {
        Presented::None {
            client_id: body_id
                .clone()
                .ok_or_else(|| invalid_client("client_id is required"))?,
        }
    };

    // Resolve the client id (for assertions it is the JWT's `iss`/`sub`).
    let client_id = match &presented {
        Presented::Basic { client_id, .. }
        | Presented::Post { client_id, .. }
        | Presented::None { client_id } => client_id.clone(),
        Presented::Assertion { assertion } => {
            let claims = peek_claims(assertion)?;
            let iss = claims["iss"].as_str().unwrap_or_default();
            let sub = claims["sub"].as_str().unwrap_or_default();
            if iss.is_empty() || iss != sub {
                return Err(invalid_client(
                    "client_assertion iss and sub must equal the client_id",
                ));
            }
            if let Some(b) = &body_id
                && b != iss
            {
                return Err(invalid_client("client_id does not match client_assertion"));
            }
            iss.to_string()
        }
    };
    let client = clients::find_by_client_id(state, tenant.id(), &client_id)
        .await
        .map_err(OAuthError::from)?
        .ok_or_else(|| invalid_client("unknown client"))?;
    if client.status != ClientStatus::Active {
        return Err(invalid_client("client is disabled"));
    }
    ip_rules::require_client(state, tenant.id(), client.id, ip)
        .await
        .map_err(OAuthError::from)?;
    // Per-client ceiling, counted before the credentials are checked so that
    // guessing a secret is bounded as well.
    let decision = rate_limit::hit_client(state, tenant.tenant.as_ref(), client.id).await;
    if let Some(secs) = decision.retry_after_secs {
        return Err(OAuthError::rate_limited(secs));
    }

    let method = match (&presented, client.token_endpoint_auth_method) {
        (Presented::Basic { secret, .. }, TokenEndpointAuthMethod::ClientSecretBasic)
        | (Presented::Post { secret, .. }, TokenEndpointAuthMethod::ClientSecretPost) => {
            if !clients::verify_secret(&client, secret) {
                return Err(invalid_client("invalid client credentials"));
            }
            client.token_endpoint_auth_method
        }
        (Presented::Assertion { assertion }, TokenEndpointAuthMethod::PrivateKeyJwt) => {
            verify_assertion(state, tenant, &client, assertion, token_endpoint).await?;
            TokenEndpointAuthMethod::PrivateKeyJwt
        }
        (Presented::None { .. }, TokenEndpointAuthMethod::None) => TokenEndpointAuthMethod::None,
        (Presented::None { .. }, _) => {
            return Err(invalid_client("client authentication required"));
        }
        _ => {
            return Err(invalid_client(
                "client authentication method does not match the registered method",
            ));
        }
    };
    // A browser call (it carries `Origin`) must come from an origin registered
    // on this client; the tenant-wide CORS layer only knew the union.
    if let Some(origin) = headers.get(header::ORIGIN)
        && !cors::origin_allowed_for_client(state, tenant.tenant.as_ref(), &client, origin)
    {
        return Err(OAuthError::invalid_request(
            "origin is not registered for this client",
        ));
    }
    Ok((client, method))
}

fn peek_claims(jwt: &str) -> Result<Value, OAuthError> {
    let payload = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| invalid_client("malformed client_assertion"))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| invalid_client("malformed client_assertion"))?;
    serde_json::from_slice(&bytes).map_err(|_| invalid_client("malformed client_assertion"))
}

/// Validate a `private_key_jwt` assertion (RFC 7523 §3) against the client's keys.
async fn verify_assertion(
    state: &AppState,
    tenant: &TenantCtx,
    client: &Client,
    assertion: &str,
    token_endpoint: &str,
) -> Result<(), OAuthError> {
    let header = jsonwebtoken::decode_header(assertion)
        .map_err(|_| invalid_client("malformed client_assertion"))?;
    if matches!(
        header.alg,
        jsonwebtoken::Algorithm::HS256
            | jsonwebtoken::Algorithm::HS384
            | jsonwebtoken::Algorithm::HS512
    ) {
        return Err(invalid_client(
            "client_assertion must use an asymmetric algorithm",
        ));
    }
    if client.is_fapi2() && !crate::oidc::fapi::allows_jws(header.alg) {
        return Err(invalid_client(
            "the FAPI 2.0 profile allows PS256, ES256 or EdDSA assertions only",
        ));
    }
    let mut keys = client_keys::jwks(state, client, false)
        .await
        .map_err(OAuthError::from)?;
    let pick = |keys: &[Value]| -> Option<Value> {
        match &header.kid {
            Some(kid) => keys.iter().find(|k| k["kid"] == kid.as_str()).cloned(),
            None if keys.len() == 1 => keys.first().cloned(),
            None => None,
        }
    };
    let mut jwk = pick(&keys);
    if jwk.is_none() && client.jwks_uri.is_some() {
        keys = client_keys::jwks(state, client, true)
            .await
            .map_err(OAuthError::from)?;
        jwk = pick(&keys);
    }
    let jwk = jwk.ok_or_else(|| invalid_client("no matching client key"))?;
    let parsed: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(jwk).map_err(|_| invalid_client("invalid client key"))?;
    let decoding =
        DecodingKey::from_jwk(&parsed).map_err(|_| invalid_client("invalid client key"))?;

    let mut validation = Validation::new(header.alg);
    validation.leeway = 30;
    validation.validate_nbf = true;
    validation.set_issuer(&[client.client_id.as_str()]);
    // Accept the token endpoint URL or the issuer as audience (RFC 7523 §3, OIDC Core §9).
    validation.set_audience(&[token_endpoint, &tenant.issuer(state)]);
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud", "jti"]);
    let data = jsonwebtoken::decode::<Value>(assertion, &decoding, &validation)
        .map_err(|e| invalid_client(&format!("client_assertion rejected: {e}")))?;
    let claims = data.claims;
    // FAPI 2.0 §5.3.2.1: the issuer identifier, as a string, is the only
    // audience the profile accepts.
    if client.is_fapi2() && claims["aud"] != tenant.issuer(state).as_str() {
        return Err(invalid_client(
            "client_assertion aud must be the issuer identifier (FAPI 2.0)",
        ));
    }
    if claims["sub"] != client.client_id.as_str() {
        return Err(invalid_client("client_assertion sub must be the client_id"));
    }
    let exp = claims["exp"].as_i64().unwrap_or_default();
    let iat = claims["iat"]
        .as_i64()
        .unwrap_or(exp - MAX_ASSERTION_LIFETIME_SECS);
    if exp - iat > MAX_ASSERTION_LIFETIME_SECS {
        return Err(invalid_client("client_assertion lifetime too long"));
    }
    // jti replay protection for the assertion's lifetime.
    let jti = claims["jti"].as_str().unwrap_or_default();
    if jti.is_empty() || jti.len() > 256 {
        return Err(invalid_client("client_assertion jti is required"));
    }
    let ttl = (exp - Utc::now().timestamp()).clamp(1, MAX_ASSERTION_LIFETIME_SECS) as u64;
    let mut conn = state.redis.get().await.map_err(OAuthError::from)?;
    let fresh: bool = redis::cmd("SET")
        .arg(crate::cache::keys::client_assertion_jti(
            tenant.id(),
            client.id,
            jti,
        ))
        .arg(1u8)
        .arg("NX")
        .arg("EX")
        .arg(ttl)
        .query_async(&mut conn)
        .await
        .map_err(|e| OAuthError::from(crate::error::AppError::from(e)))?;
    if !fresh {
        return Err(invalid_client("client_assertion replayed"));
    }
    Ok(())
}

/// Helper for tests and tools: build a `private_key_jwt` assertion.
pub fn build_assertion(
    client_id: &str,
    audience: &str,
    alg: crate::models::SigningAlg,
    kid: &str,
    private_pkcs8_der: &[u8],
    lifetime_secs: i64,
) -> Result<String, crate::error::AppError> {
    let now = Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + lifetime_secs,
        "jti": Uuid::now_v7().to_string(),
    });
    let mut header = jsonwebtoken::Header::new(crate::services::tokens::jwt_alg(alg));
    header.kid = Some(kid.to_string());
    let key = crate::services::tokens::encoding_key_from_der(alg, private_pkcs8_der)?;
    jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|e| crate::error::AppError::Internal(format!("assertion sign: {e}")))
}
