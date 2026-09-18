//! OpenID Provider metadata: `GET /t/{slug}/.well-known/openid-configuration`
//! (OpenID Connect Discovery 1.0 §3, RFC 8414).
//!
//! The document advertises exactly what this build implements. Features that
//! arrive in later phases are switched on in [`CAPABILITIES`] when their
//! endpoints exist, and the contract test (Phase 3.10) checks that every
//! advertised endpoint answers.

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
use crate::error::AppError;
use crate::middleware::TenantCtx;
use crate::models::{SigningAlg, Tenant};
use crate::services::scopes;
use crate::state::AppState;

const DISCOVERY_CACHE_TTL: Duration = Duration::from_secs(300);
const MAX_AGE_SECS: u64 = 300;

/// Feature switches; each is flipped when the corresponding phase lands.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    pub authorization_code: bool,
    pub userinfo: bool,
    pub introspection: bool,
    pub revocation: bool,
    pub end_session: bool,
    pub backchannel_logout: bool,
    pub frontchannel_logout: bool,
    pub form_post: bool,
    pub claims_parameter: bool,
    pub par: bool,
    pub jar: bool,
    pub jarm: bool,
    pub dcr: bool,
    pub device: bool,
    pub token_exchange: bool,
    pub dpop: bool,
}

pub const CAPABILITIES: Capabilities = Capabilities {
    authorization_code: true,
    userinfo: true,
    introspection: true,
    revocation: true,
    end_session: true,
    backchannel_logout: true,
    frontchannel_logout: true,
    form_post: false,
    claims_parameter: false,
    par: true,
    jar: true,
    jarm: true,
    dcr: true,
    device: true,
    token_exchange: true,
    dpop: true,
};

pub const STANDARD_CLAIMS: [&str; 30] = [
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "azp",
    "sid",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "updated_at",
    "email",
    "email_verified",
    "phone_number",
    "phone_number_verified",
    "address",
    "locale",
];

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/t/{slug}/.well-known/openid-configuration",
        get(configuration),
    )
}

/// Provider metadata. Optional members are omitted when unsupported.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<&'static str>,
    pub response_modes_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub id_token_encryption_alg_values_supported: Vec<&'static str>,
    pub id_token_encryption_enc_values_supported: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signing_alg_values_supported: Option<Vec<&'static str>>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub token_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_methods_supported: Option<Vec<&'static str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_methods_supported: Option<Vec<&'static str>>,
    pub claims_supported: Vec<&'static str>,
    pub acr_values_supported: Vec<&'static str>,
    pub claim_types_supported: Vec<&'static str>,
    pub claims_parameter_supported: bool,
    pub request_parameter_supported: bool,
    pub request_uri_parameter_supported: bool,
    pub require_request_uri_registration: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pushed_authorization_requests: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg_values_supported: Option<Vec<&'static str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_signing_alg_values_supported: Option<Vec<&'static str>>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub ui_locales_supported: Vec<String>,
    pub prompt_values_supported: Vec<&'static str>,
    pub authorization_response_iss_parameter_supported: bool,
    pub backchannel_logout_supported: bool,
    pub backchannel_logout_session_supported: bool,
    pub frontchannel_logout_supported: bool,
    pub frontchannel_logout_session_supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<&'static str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_policy_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_tos_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<String>,
}

fn signing_algs() -> Vec<&'static str> {
    SigningAlg::ALL.iter().map(|a| a.as_str()).collect()
}

/// Build the metadata for a tenant. `issuer` already reflects a custom domain.
pub fn build(
    tenant: &Tenant,
    issuer: &str,
    scope_names: Vec<String>,
    caps: &Capabilities,
) -> ProviderMetadata {
    let ep = |path: &str| format!("{issuer}{path}");
    let mut response_modes = vec!["query", "fragment"];
    if caps.form_post {
        response_modes.push("form_post");
    }
    if caps.jarm {
        response_modes.extend(["jwt", "query.jwt", "fragment.jwt", "form_post.jwt"]);
    }
    let mut grant_types = vec!["authorization_code", "refresh_token", "client_credentials"];
    if caps.device {
        grant_types.push("urn:ietf:params:oauth:grant-type:device_code");
    }
    if caps.token_exchange {
        grant_types.push("urn:ietf:params:oauth:grant-type:token-exchange");
    }
    let auth_methods = vec![
        "none",
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
    ];
    let mut prompts = vec!["none", "login", "consent", "select_account"];
    if caps.authorization_code {
        prompts.push("create");
    }
    let branding = &tenant.settings.branding;

    ProviderMetadata {
        issuer: issuer.to_string(),
        authorization_endpoint: ep("/authorize"),
        token_endpoint: ep("/token"),
        jwks_uri: ep("/.well-known/jwks.json"),
        userinfo_endpoint: caps.userinfo.then(|| ep("/userinfo")),
        registration_endpoint: (caps.dcr
            && tenant.settings.dcr.mode != crate::models::DcrMode::Disabled)
            .then(|| ep("/register")),
        introspection_endpoint: caps.introspection.then(|| ep("/introspect")),
        revocation_endpoint: caps.revocation.then(|| ep("/revoke")),
        end_session_endpoint: caps.end_session.then(|| ep("/end_session")),
        pushed_authorization_request_endpoint: caps.par.then(|| ep("/par")),
        device_authorization_endpoint: caps.device.then(|| ep("/device_authorization")),
        scopes_supported: scope_names,
        response_types_supported: vec!["code"],
        response_modes_supported: response_modes,
        grant_types_supported: grant_types,
        subject_types_supported: vec!["public", "pairwise"],
        id_token_signing_alg_values_supported: signing_algs(),
        id_token_encryption_alg_values_supported: vec!["RSA-OAEP-256", "RSA-OAEP"],
        id_token_encryption_enc_values_supported: vec!["A256GCM", "A128GCM"],
        // userinfo responses are plain JSON (no signed userinfo yet).
        userinfo_signing_alg_values_supported: None,
        token_endpoint_auth_methods_supported: auth_methods.clone(),
        token_endpoint_auth_signing_alg_values_supported: signing_algs(),
        introspection_endpoint_auth_methods_supported: caps
            .introspection
            .then(|| auth_methods.clone()),
        revocation_endpoint_auth_methods_supported: caps.revocation.then(|| auth_methods.clone()),
        claims_supported: STANDARD_CLAIMS.to_vec(),
        acr_values_supported: vec![
            crate::services::flows::ACR_SINGLE,
            crate::services::flows::ACR_MFA,
        ],
        claim_types_supported: vec!["normal"],
        claims_parameter_supported: caps.claims_parameter,
        request_parameter_supported: caps.jar,
        request_uri_parameter_supported: caps.par,
        require_request_uri_registration: false,
        require_pushed_authorization_requests: caps.par.then_some(false),
        request_object_signing_alg_values_supported: caps.jar.then(signing_algs),
        authorization_signing_alg_values_supported: caps.jarm.then(signing_algs),
        code_challenge_methods_supported: vec!["S256"],
        ui_locales_supported: tenant.settings.locale.supported.clone(),
        prompt_values_supported: prompts,
        authorization_response_iss_parameter_supported: true,
        backchannel_logout_supported: caps.backchannel_logout,
        backchannel_logout_session_supported: caps.backchannel_logout,
        frontchannel_logout_supported: caps.frontchannel_logout,
        frontchannel_logout_session_supported: caps.frontchannel_logout,
        // The proof verifier's own list, so discovery never promises less (or
        // more) than `/token` accepts.
        dpop_signing_alg_values_supported: caps.dpop.then(|| crate::oidc::dpop::ALGS.to_vec()),
        op_policy_uri: tenant.settings.registration.privacy_url.clone(),
        op_tos_uri: tenant.settings.registration.terms_url.clone(),
        service_documentation: branding.support_url.clone(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDocument {
    pub body: String,
    pub etag: String,
}

pub async fn load(state: &AppState, tenant: &TenantCtx) -> Result<Arc<CachedDocument>, AppError> {
    let tenant_id = tenant.id();
    let issuer = tenant.issuer(state);
    let t = tenant.tenant.clone();
    let st = state.clone();
    let doc = state
        .cache
        .get_or_load(
            &cache_keys::discovery(tenant_id),
            DISCOVERY_CACHE_TTL,
            || async move {
                let names: Vec<String> = scopes::list(&st, tenant_id)
                    .await?
                    .iter()
                    .map(|s| s.name.clone())
                    .collect();
                let body = serde_json::to_string(&build(&t, &issuer, names, &CAPABILITIES))?;
                let etag = format!(
                    "\"{}\"",
                    hex::encode(&Sha256::digest(body.as_bytes())[..16])
                );
                Ok(Some(CachedDocument { body, etag }))
            },
        )
        .await?;
    doc.ok_or_else(|| AppError::Internal("discovery loader returned nothing".into()))
}

async fn configuration(
    State(state): State<AppState>,
    tenant: TenantCtx,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let doc = load(&state, &tenant).await?;
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
                HeaderValue::from_static("application/json"),
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
