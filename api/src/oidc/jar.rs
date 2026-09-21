//! JWT-secured authorization requests (RFC 9101): the `request` parameter is
//! a JWT signed with one of the client's registered keys.

use jsonwebtoken::{DecodingKey, Validation};
use serde_json::Value;

use crate::error::{OAuthError, OAuthErrorCode};
use crate::middleware::TenantCtx;
use crate::models::Client;
use crate::oidc::authorize::{Failure, RawParams};
use crate::services::client_keys;
use crate::state::AppState;

fn bad(desc: &str) -> Failure {
    Failure::Page("invalid_request_object", desc.to_string())
}

/// Verify `jwt` and return the plain parameters merged with the object's
/// claims (object wins). `client_id` and `response_type`, when present
/// outside, must equal the values inside.
pub async fn merge(
    state: &AppState,
    tenant: &TenantCtx,
    client: &Client,
    params: &RawParams,
    jwt: &str,
) -> Result<RawParams, Failure> {
    if jwt.len() > 16 * 1024 {
        return Err(bad("request object too large"));
    }
    let header = jsonwebtoken::decode_header(jwt).map_err(|_| bad("malformed request object"))?;
    if matches!(
        header.alg,
        jsonwebtoken::Algorithm::HS256
            | jsonwebtoken::Algorithm::HS384
            | jsonwebtoken::Algorithm::HS512
    ) {
        return Err(bad("request objects must be signed with an asymmetric key"));
    }
    if client.is_fapi2() && !crate::oidc::fapi::allows_jws(header.alg) {
        return Err(bad(
            "the FAPI 2.0 profile allows PS256, ES256 or EdDSA request objects only",
        ));
    }
    let keys = client_keys::jwks(state, client, false)
        .await
        .map_err(Failure::Internal)?;
    let pick = |keys: &[Value]| -> Option<Value> {
        match &header.kid {
            Some(kid) => keys.iter().find(|k| k["kid"] == kid.as_str()).cloned(),
            None if keys.len() == 1 => keys.first().cloned(),
            None => None,
        }
    };
    let mut jwk = pick(&keys);
    if jwk.is_none() && client.jwks_uri.is_some() {
        let refreshed = client_keys::jwks(state, client, true)
            .await
            .map_err(Failure::Internal)?;
        jwk = pick(&refreshed);
    }
    let jwk = jwk.ok_or_else(|| bad("no matching client key for the request object"))?;
    let parsed: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(jwk).map_err(|_| bad("invalid client key"))?;
    let decoding = DecodingKey::from_jwk(&parsed).map_err(|_| bad("invalid client key"))?;

    let mut validation = Validation::new(header.alg);
    validation.leeway = 30;
    validation.validate_nbf = true;
    validation.set_issuer(&[client.client_id.as_str()]);
    validation.set_audience(&[tenant.issuer(state)]);
    validation.set_required_spec_claims(&["iss", "aud", "exp"]);
    let data = jsonwebtoken::decode::<Value>(jwt, &decoding, &validation)
        .map_err(|e| bad(&format!("request object rejected: {e}")))?;
    let obj = data
        .claims
        .as_object()
        .ok_or_else(|| bad("request object payload must be an object"))?;

    // Consistency with the plain parameters.
    for key in ["client_id", "response_type"] {
        if let (Ok(Some(outside)), Some(inside)) =
            (params.one(key), obj.get(key).and_then(Value::as_str))
            && outside != inside
        {
            return Err(bad(&format!(
                "{key} differs between the request and the request object"
            )));
        }
    }
    if obj.get("client_id").and_then(Value::as_str) != Some(client.client_id.as_str()) {
        return Err(bad("request object client_id must equal the client_id"));
    }
    if obj.contains_key("request") || obj.contains_key("request_uri") {
        return Err(bad("request objects cannot nest"));
    }

    // Object claims override plain params.
    let mut merged: Vec<(String, String)> = params
        .0
        .iter()
        .filter(|(k, _)| k != "request" && !obj.contains_key(k.as_str()))
        .cloned()
        .collect();
    for (k, v) in obj {
        if matches!(k.as_str(), "iss" | "aud" | "exp" | "iat" | "nbf" | "jti") {
            continue;
        }
        match v {
            Value::String(s) => merged.push((k.clone(), s.clone())),
            Value::Number(n) => merged.push((k.clone(), n.to_string())),
            Value::Bool(b) => merged.push((k.clone(), b.to_string())),
            Value::Array(items) => {
                for item in items {
                    if let Some(s) = item.as_str() {
                        merged.push((k.clone(), s.to_string()));
                    }
                }
            }
            Value::Object(_) => merged.push((k.clone(), v.to_string())),
            Value::Null => {}
        }
    }
    Ok(RawParams(merged))
}

/// Error type the authorization endpoint reports for JAR failures.
pub fn as_oauth(f: &Failure) -> OAuthError {
    match f {
        Failure::Page(_, d) => OAuthError::new(OAuthErrorCode::InvalidRequestObject, d.clone()),
        Failure::Redirect(e) => e.clone(),
        Failure::Internal(_) => OAuthError::server_error(),
    }
}
