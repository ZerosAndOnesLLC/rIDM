//! Upstream identity providers: configuration (with presets for the common
//! ones), OpenID discovery, the encrypted client secret, and the cached JWK
//! set an OIDC provider signs ID tokens with. The sign-in itself is
//! [`crate::services::broker`].

use std::sync::Arc;
use std::time::Duration;

use redis::AsyncCommands as _;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use ridm_core::providers::Encrypted;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult, FieldError};
use crate::models::{
    IdentityProvider, IdentityProviderUpdate, IdpAuthMethod, IdpKind, IdpMappers, LinkPolicy,
    NewIdentityProvider, PublicIdentityProvider, SamlUpstreamSettings,
};
use crate::repos;
use crate::state::AppState;

const OFFERED_TTL: Duration = Duration::from_secs(60);
const JWKS_CACHE_SECS: u64 = 3600;
const JWKS_REFRESH_THROTTLE_SECS: u64 = 60;
const MAX_DOCUMENT_BYTES: usize = 256 * 1024;
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------

/// A well-known provider: everything but the client credentials.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct Preset {
    pub name: &'static str,
    pub display_name: &'static str,
    pub kind: IdpKind,
    pub issuer: Option<&'static str>,
    pub authorization_endpoint: Option<&'static str>,
    pub token_endpoint: Option<&'static str>,
    pub userinfo_endpoint: Option<&'static str>,
    pub jwks_uri: Option<&'static str>,
    pub scopes: &'static [&'static str],
    pub token_endpoint_auth_method: IdpAuthMethod,
    /// The provider vouches for the addresses it returns.
    pub trust_email: bool,
    /// Where the identity's fields come from when the provider is not
    /// plain OpenID Connect.
    pub subject_claim: Option<&'static str>,
    pub username_claim: Option<&'static str>,
    /// Notes shown to the administrator setting it up.
    pub hint: &'static str,
}

pub const PRESETS: &[Preset] = &[
    Preset {
        name: "google",
        display_name: "Google",
        kind: IdpKind::Oidc,
        issuer: Some("https://accounts.google.com"),
        authorization_endpoint: None,
        token_endpoint: None,
        userinfo_endpoint: None,
        jwks_uri: None,
        scopes: &["openid", "email", "profile"],
        token_endpoint_auth_method: IdpAuthMethod::ClientSecretPost,
        trust_email: true,
        subject_claim: None,
        username_claim: None,
        hint: "Create an OAuth client ID (web application) in Google Cloud Console and add the callback URL to its authorised redirect URIs.",
    },
    Preset {
        name: "microsoft",
        display_name: "Microsoft",
        kind: IdpKind::Oidc,
        issuer: Some("https://login.microsoftonline.com/common/v2.0"),
        authorization_endpoint: None,
        token_endpoint: None,
        userinfo_endpoint: None,
        jwks_uri: None,
        scopes: &["openid", "email", "profile"],
        token_endpoint_auth_method: IdpAuthMethod::ClientSecretPost,
        trust_email: false,
        subject_claim: None,
        username_claim: None,
        hint: "Register an application in Microsoft Entra ID with the callback URL as a web redirect URI. Replace `common` in the issuer with your directory (tenant) ID to accept only its accounts.",
    },
    Preset {
        name: "github",
        display_name: "GitHub",
        kind: IdpKind::Oauth2,
        issuer: None,
        authorization_endpoint: Some("https://github.com/login/oauth/authorize"),
        token_endpoint: Some("https://github.com/login/oauth/access_token"),
        userinfo_endpoint: Some("https://api.github.com/user"),
        jwks_uri: None,
        scopes: &["read:user", "user:email"],
        token_endpoint_auth_method: IdpAuthMethod::ClientSecretPost,
        trust_email: true,
        subject_claim: Some("id"),
        username_claim: Some("login"),
        hint: "Register an OAuth app in GitHub developer settings with the callback URL as its authorization callback URL. The primary verified email is used.",
    },
    Preset {
        name: "apple",
        display_name: "Apple",
        kind: IdpKind::Oidc,
        issuer: Some("https://appleid.apple.com"),
        authorization_endpoint: None,
        token_endpoint: None,
        userinfo_endpoint: None,
        jwks_uri: None,
        scopes: &["openid", "email", "name"],
        token_endpoint_auth_method: IdpAuthMethod::ClientSecretPost,
        trust_email: true,
        subject_claim: None,
        username_claim: None,
        hint: "Use the Services ID as the client ID and a client secret JWT signed with your Sign in with Apple key (valid for at most six months; rotate it before it expires).",
    },
    Preset {
        name: "gitlab",
        display_name: "GitLab",
        kind: IdpKind::Oidc,
        issuer: Some("https://gitlab.com"),
        authorization_endpoint: None,
        token_endpoint: None,
        userinfo_endpoint: None,
        jwks_uri: None,
        scopes: &["openid", "email", "profile"],
        token_endpoint_auth_method: IdpAuthMethod::ClientSecretPost,
        trust_email: true,
        subject_claim: None,
        username_claim: None,
        hint: "Create an application in GitLab (user or group settings) with the callback URL as its redirect URI and the openid, email and profile scopes. For self-managed GitLab change the issuer to your instance.",
    },
];

pub fn preset(name: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.name == name)
}

// ---------------------------------------------------------------------------
// Validation and HTTP
// ---------------------------------------------------------------------------

pub fn validate_alias(raw: &str) -> AppResult<String> {
    let a = raw.trim().to_lowercase();
    let ok = !a.is_empty()
        && a.len() <= 64
        && a.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && a != "presets"
        && a != "discover"
        && a != "saml-metadata";
    if ok {
        Ok(a)
    } else {
        Err(AppError::Validation(vec![FieldError {
            field: "alias".into(),
            message: "must be 1-64 lowercase letters, digits and hyphens, starting with a letter or digit".into(),
        }]))
    }
}

/// Upstream endpoints must be https; plain http is accepted for loopback
/// hosts only (development and tests).
pub fn validate_endpoint(field: &str, raw: &str) -> AppResult<String> {
    let s = raw.trim();
    let bad = |message: &str| {
        AppError::Validation(vec![FieldError {
            field: field.into(),
            message: message.into(),
        }])
    };
    let u = url::Url::parse(s).map_err(|_| bad("must be an absolute URL"))?;
    let loopback = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    match u.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err(bad("must use https")),
    }
    if u.fragment().is_some() {
        return Err(bad("must not carry a fragment"));
    }
    Ok(u.to_string().trim_end_matches('/').to_string())
}

/// A client for one upstream request. Upstream endpoints are a tenant
/// admin's (or a discovery document's) choice: an IP-literal `url` must be
/// public, and names resolve to public addresses only (SSRF).
fn client_for(what: &str, url: &str) -> AppResult<reqwest::Client> {
    crate::util::outbound::check_url(url)
        .map_err(|e| AppError::Unavailable(format!("{what}: {e}")))?;
    crate::util::outbound::client_builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|e| AppError::Internal(e.to_string()))
}

async fn read_json(what: &str, res: reqwest::Response) -> AppResult<Value> {
    let status = res.status();
    let bytes = res
        .bytes()
        .await
        .map_err(|e| AppError::Unavailable(format!("{what}: {e}")))?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(AppError::Unavailable(format!("{what}: answer too large")));
    }
    let body: Value = serde_json::from_slice(&bytes)
        .or_else(|_| {
            // Some token endpoints (GitHub without an Accept header) answer form-encoded.
            std::str::from_utf8(&bytes).map(|text| {
                Value::Object(
                    url::form_urlencoded::parse(text.as_bytes())
                        .map(|(k, v)| (k.into_owned(), Value::String(v.into_owned())))
                        .collect(),
                )
            })
        })
        .map_err(|_| AppError::Unavailable(format!("{what}: not JSON ({status})")))?;
    if !status.is_success() {
        let detail = body["error_description"]
            .as_str()
            .or_else(|| body["error"].as_str())
            .unwrap_or("");
        return Err(AppError::Unavailable(format!("{what}: {status} {detail}")));
    }
    Ok(body)
}

/// `GET` a JSON document (a discovery document, JWK set or userinfo).
pub async fn get_json(what: &str, url: &str, bearer: Option<&str>) -> AppResult<Value> {
    let mut req = client_for(what, url)?
        .get(url)
        .header("accept", "application/json")
        .header("user-agent", "rIDM");
    if let Some(t) = bearer {
        req = req.bearer_auth(t);
    }
    let res = req.send().await.map_err(|e| {
        AppError::Unavailable(format!("{what}: {}", crate::util::outbound::describe(&e)))
    })?;
    read_json(what, res).await
}

/// `GET` a text document (an IdP's SAML metadata), size-capped.
pub async fn get_text(what: &str, url: &str) -> AppResult<String> {
    let res = client_for(what, url)?
        .get(url)
        .header(
            "accept",
            "application/samlmetadata+xml, application/xml, text/xml",
        )
        .header("user-agent", "rIDM")
        .send()
        .await
        .map_err(|e| {
            AppError::Unavailable(format!("{what}: {}", crate::util::outbound::describe(&e)))
        })?;
    let status = res.status();
    if !status.is_success() {
        return Err(AppError::Unavailable(format!("{what}: {status}")));
    }
    if res
        .content_length()
        .is_some_and(|l| l > crate::saml::xml::MAX_DOCUMENT_BYTES as u64)
    {
        return Err(AppError::Unavailable(format!("{what}: document too large")));
    }
    let bytes = res
        .bytes()
        .await
        .map_err(|e| AppError::Unavailable(format!("{what}: {e}")))?;
    if bytes.len() > crate::saml::xml::MAX_DOCUMENT_BYTES {
        return Err(AppError::Unavailable(format!("{what}: document too large")));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| AppError::Unavailable(format!("{what}: not UTF-8")))
}

/// `POST` a form (the token request) and read the JSON answer.
pub async fn post_form(
    what: &str,
    url: &str,
    form: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> AppResult<Value> {
    let mut req = client_for(what, url)?
        .post(url)
        .header("accept", "application/json")
        .header("user-agent", "rIDM")
        .form(form);
    if let Some((user, pass)) = basic {
        req = req.basic_auth(user, Some(pass));
    }
    let res = req.send().await.map_err(|e| {
        AppError::Unavailable(format!("{what}: {}", crate::util::outbound::describe(&e)))
    })?;
    read_json(what, res).await
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// The parts of an OpenID discovery document rIDM uses.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

/// Fetch `{issuer}/.well-known/openid-configuration`. The document's
/// `issuer` must match, except for Microsoft's multi-tenant `common`
/// issuer, which the document reports with a placeholder.
pub async fn discover(issuer: &str) -> AppResult<Discovery> {
    let issuer = validate_endpoint("issuer", issuer)?;
    let url = format!("{issuer}/.well-known/openid-configuration");
    let doc = get_json("discovery", &url, None).await?;
    let found = doc["issuer"]
        .as_str()
        .unwrap_or_default()
        .trim_end_matches('/');
    if found != issuer && !issuer_matches(&issuer, found) {
        return Err(AppError::BadRequest(format!(
            "the discovery document names another issuer (`{found}`)"
        )));
    }
    let need = |k: &str| -> AppResult<String> {
        doc[k]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| AppError::BadRequest(format!("the discovery document has no `{k}`")))
    };
    Ok(Discovery {
        issuer,
        authorization_endpoint: need("authorization_endpoint")?,
        token_endpoint: need("token_endpoint")?,
        userinfo_endpoint: doc["userinfo_endpoint"].as_str().map(str::to_string),
        jwks_uri: need("jwks_uri")?,
        scopes_supported: doc["scopes_supported"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// Does `found` (an issuer a document or token names) satisfy the
/// configured issuer? Exact, or the Microsoft multi-tenant form where the
/// configured `common`/`organizations`/`consumers` segment stands for any
/// directory.
pub fn issuer_matches(configured: &str, found: &str) -> bool {
    let configured = configured.trim_end_matches('/');
    let found = found.trim_end_matches('/');
    if configured == found {
        return true;
    }
    const MS: &str = "https://login.microsoftonline.com/";
    if let Some(rest) = configured.strip_prefix(MS)
        && let Some((segment, tail)) = rest.split_once('/')
        && matches!(segment, "common" | "organizations" | "consumers")
        && let Some(found_rest) = found.strip_prefix(MS)
        && let Some((found_segment, found_tail)) = found_rest.split_once('/')
    {
        return tail == found_tail
            && (found_segment == "{tenantid}" || Uuid::parse_str(found_segment).is_ok());
    }
    false
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

fn aad(tenant_id: Uuid, id: Uuid) -> Vec<u8> {
    format!("identity_providers:{tenant_id}:{id}").into_bytes()
}

async fn encrypt_secret(
    state: &AppState,
    tenant_id: Uuid,
    id: Uuid,
    secret: &str,
) -> AppResult<Encrypted> {
    state
        .key_encryptor
        .encrypt(secret.as_bytes(), &aad(tenant_id, id))
        .await
        .map_err(|e| AppError::Internal(format!("identity provider secret encrypt: {e}")))
}

/// The stored client secret, when one is set.
pub async fn client_secret(
    state: &AppState,
    idp: &IdentityProvider,
) -> AppResult<Option<Zeroizing<String>>> {
    if !idp.client_secret_set {
        return Ok(None);
    }
    let enc = Encrypted::from_bytes(&idp.client_secret_enc)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let plain = state
        .key_encryptor
        .decrypt(&enc, &aad(idp.tenant_id, idp.id))
        .await
        .map_err(|e| AppError::Internal(format!("identity provider secret decrypt: {e}")))?;
    Ok(Some(Zeroizing::new(
        String::from_utf8(plain.to_vec()).map_err(|e| AppError::Internal(e.to_string()))?,
    )))
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

/// Every field of a provider, resolved from a preset, the input and
/// discovery, ready to be stored.
#[derive(Debug, Clone)]
struct Resolved {
    alias: String,
    kind: IdpKind,
    display_name: String,
    preset: Option<String>,
    enabled: bool,
    hidden: bool,
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    jwks_uri: Option<String>,
    client_id: String,
    token_endpoint_auth_method: IdpAuthMethod,
    scopes: Vec<String>,
    pkce: bool,
    link_policy: LinkPolicy,
    trust_email: bool,
    mappers: IdpMappers,
    sort_order: i32,
    saml: Option<SamlUpstreamSettings>,
}

fn opt(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn validate_scopes(scopes: Vec<String>) -> AppResult<Vec<String>> {
    let mut out = vec![];
    for s in scopes {
        let s = s.trim().to_string();
        if s.is_empty() || s.len() > 128 || s.chars().any(char::is_whitespace) {
            return Err(AppError::Validation(vec![FieldError {
                field: "scopes".into(),
                message: format!("`{s}` is not a scope"),
            }]));
        }
        if !out.contains(&s) {
            out.push(s);
        }
    }
    Ok(out)
}

fn validate_mappers(m: &IdpMappers) -> AppResult<()> {
    for (attr, claim) in &m.attributes {
        if !crate::services::profile_schema::is_valid_attribute_name(attr)
            || claim.trim().is_empty()
        {
            return Err(AppError::Validation(vec![FieldError {
                field: format!("mappers.attributes.{attr}"),
                message:
                    "attribute names match ^[a-zA-Z][a-zA-Z0-9_]{0,63}$ and claims are not empty"
                        .into(),
            }]));
        }
    }
    Ok(())
}

/// Complete and check a provider's fields, discovering the endpoints of an
/// OIDC provider from its issuer when they were not given.
async fn finish(mut r: Resolved, has_secret: bool) -> AppResult<Resolved> {
    r.alias = validate_alias(&r.alias)?;
    if r.display_name.trim().is_empty() || r.display_name.len() > 100 {
        return Err(AppError::Validation(vec![FieldError {
            field: "display_name".into(),
            message: "must be 1-100 characters".into(),
        }]));
    }
    if r.kind == IdpKind::Saml {
        return finish_saml(r);
    }
    if r.saml.is_some() {
        return Err(field_error("saml", "is only for a provider of kind `saml`"));
    }
    if r.client_id.trim().is_empty() {
        return Err(AppError::Validation(vec![FieldError {
            field: "client_id".into(),
            message: "is required".into(),
        }]));
    }
    r.client_id = r.client_id.trim().to_string();
    r.scopes = validate_scopes(r.scopes)?;
    validate_mappers(&r.mappers)?;
    if let Some(i) = &r.issuer {
        r.issuer = Some(validate_endpoint("issuer", i)?);
    }
    for (name, field) in [
        ("authorization_endpoint", &mut r.authorization_endpoint),
        ("token_endpoint", &mut r.token_endpoint),
        ("userinfo_endpoint", &mut r.userinfo_endpoint),
        ("jwks_uri", &mut r.jwks_uri),
    ] {
        if let Some(v) = field {
            *field = Some(validate_endpoint(name, v)?);
        }
    }
    match r.kind {
        IdpKind::Oidc => {
            let missing = r.authorization_endpoint.is_none()
                || r.token_endpoint.is_none()
                || r.jwks_uri.is_none();
            if missing {
                let Some(issuer) = &r.issuer else {
                    return Err(AppError::Validation(vec![FieldError {
                        field: "issuer".into(),
                        message: "is required unless every endpoint is given".into(),
                    }]));
                };
                let d = discover(issuer).await?;
                r.authorization_endpoint
                    .get_or_insert(d.authorization_endpoint);
                r.token_endpoint.get_or_insert(d.token_endpoint);
                r.jwks_uri.get_or_insert(d.jwks_uri);
                if r.userinfo_endpoint.is_none() {
                    r.userinfo_endpoint = d.userinfo_endpoint;
                }
            }
            if r.issuer.is_none() {
                return Err(AppError::Validation(vec![FieldError {
                    field: "issuer".into(),
                    message: "is required for an OpenID Connect provider".into(),
                }]));
            }
            if !r.scopes.iter().any(|s| s == "openid") {
                r.scopes.insert(0, "openid".into());
            }
        }
        IdpKind::Saml => unreachable!("finished by finish_saml"),
        IdpKind::Oauth2 => {
            for (name, present) in [
                ("authorization_endpoint", r.authorization_endpoint.is_some()),
                ("token_endpoint", r.token_endpoint.is_some()),
                ("userinfo_endpoint", r.userinfo_endpoint.is_some()),
            ] {
                if !present {
                    return Err(AppError::Validation(vec![FieldError {
                        field: name.into(),
                        message: "is required for an OAuth 2.0 provider".into(),
                    }]));
                }
            }
        }
    }
    // Without a secret the client authenticates with PKCE alone; the method
    // stays configured for the day a secret is set (imports carry none).
    if has_secret && r.token_endpoint_auth_method == IdpAuthMethod::None {
        r.token_endpoint_auth_method = IdpAuthMethod::ClientSecretBasic;
    }
    if !has_secret && !r.pkce {
        return Err(AppError::Validation(vec![FieldError {
            field: "pkce".into(),
            message: "a provider without a client secret needs PKCE".into(),
        }]));
    }
    Ok(r)
}

fn field_error(field: &str, message: &str) -> AppError {
    AppError::Validation(vec![FieldError {
        field: field.into(),
        message: message.into(),
    }])
}

/// A SAML provider has none of the OAuth fields: they are cleared, and its
/// SAML settings are checked instead.
fn finish_saml(mut r: Resolved) -> AppResult<Resolved> {
    let settings = r
        .saml
        .take()
        .ok_or_else(|| field_error("saml", "is required for a provider of kind `saml`"))?;
    r.saml = Some(validate_saml(settings)?);
    r.preset = None;
    r.issuer = None;
    r.authorization_endpoint = None;
    r.token_endpoint = None;
    r.userinfo_endpoint = None;
    r.jwks_uri = None;
    r.client_id = String::new();
    r.token_endpoint_auth_method = IdpAuthMethod::None;
    r.scopes = vec![];
    r.pkce = false;
    Ok(r)
}

/// Check and normalize a SAML provider's settings: https endpoints,
/// certificates parsed and stored as base64 DER, bounded lists.
pub fn validate_saml(mut s: SamlUpstreamSettings) -> AppResult<SamlUpstreamSettings> {
    s.entity_id = s.entity_id.trim().to_string();
    if s.entity_id.is_empty() || s.entity_id.len() > 1024 {
        return Err(field_error("saml.entity_id", "must be 1-1024 characters"));
    }
    s.sso_url = validate_endpoint("saml.sso_url", &s.sso_url)?;
    s.slo_url = match opt(s.slo_url) {
        Some(u) => Some(validate_endpoint("saml.slo_url", &u)?),
        None => None,
    };
    s.metadata_url = match opt(s.metadata_url) {
        Some(u) => Some(validate_endpoint("saml.metadata_url", &u)?),
        None => None,
    };
    let mut certs: Vec<String> = vec![];
    for (i, c) in s.signing_certificates.iter().enumerate() {
        let parsed = crate::saml::cert::Certificate::parse(c)
            .map_err(|e| field_error(&format!("saml.signing_certificates.{i}"), &e.to_string()))?;
        let b64 = parsed.to_base64();
        if !certs.contains(&b64) {
            certs.push(b64);
        }
    }
    if certs.is_empty() || certs.len() > 10 {
        return Err(field_error(
            "saml.signing_certificates",
            "one to ten certificates are required: nothing unsigned is accepted",
        ));
    }
    s.signing_certificates = certs;
    let mut classes: Vec<String> = vec![];
    for c in &s.authn_context_class_refs {
        let c = c.trim().to_string();
        if c.is_empty() || c.len() > 256 {
            return Err(field_error(
                "saml.authn_context_class_refs",
                "each class is 1-256 characters",
            ));
        }
        if !classes.contains(&c) {
            classes.push(c);
        }
    }
    if classes.len() > 10 {
        return Err(field_error(
            "saml.authn_context_class_refs",
            "at most ten classes",
        ));
    }
    s.authn_context_class_refs = classes;
    s.unsolicited_client_id = opt(s.unsolicited_client_id);
    Ok(s)
}

/// The settings of a new SAML provider as an IdP's metadata describes it
/// (`url`, when it was fetched, becomes the metadata URL). Checked like any
/// settings, so what the console shows for review would be accepted.
pub fn saml_settings_from_metadata(
    text: &str,
    url: Option<String>,
) -> AppResult<SamlUpstreamSettings> {
    use crate::models::{NameIdFormat, SloBinding};
    let m = crate::saml::metadata::parse_idp_metadata(text)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    let binding = |redirect: bool| {
        if redirect {
            SloBinding::Redirect
        } else {
            SloBinding::Post
        }
    };
    // Persistent first: it is the one made for account linking.
    let name_id_format = [NameIdFormat::Persistent, NameIdFormat::Email]
        .into_iter()
        .find(|f| m.name_id_formats.iter().any(|n| n == f.urn()));
    validate_saml(SamlUpstreamSettings {
        entity_id: m.entity_id,
        sso_url: m.sso.0,
        sso_binding: binding(m.sso.1),
        slo_url: m.slo.as_ref().map(|s| s.0.clone()),
        slo_binding: m.slo.as_ref().map(|s| binding(s.1)).unwrap_or_default(),
        signing_certificates: m.signing_certificates,
        name_id_format,
        metadata_url: url,
        ..SamlUpstreamSettings::default()
    })
}

/// The client an unsolicited SAML sign-in lands on must exist and say
/// where (`initiate_login_uri`).
async fn check_unsolicited_target(
    state: &AppState,
    tenant_id: Uuid,
    s: Option<&SamlUpstreamSettings>,
) -> AppResult<()> {
    let Some(client_id) = s.and_then(|s| s.unsolicited_client_id.as_deref()) else {
        return Ok(());
    };
    match crate::services::clients::find_by_client_id(state, tenant_id, client_id).await? {
        Some(c) if c.initiate_login_uri.is_some() => Ok(()),
        Some(_) => Err(field_error(
            "saml.unsolicited_client_id",
            "the client has no initiate_login_uri to send the browser to",
        )),
        None => Err(field_error("saml.unsolicited_client_id", "no such client")),
    }
}

fn from_new(input: NewIdentityProvider) -> AppResult<Resolved> {
    let preset_def = match input
        .preset
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        Some(name) => Some(preset(name).ok_or_else(|| {
            AppError::Validation(vec![FieldError {
                field: "preset".into(),
                message: format!(
                    "unknown; one of {}",
                    PRESETS
                        .iter()
                        .map(|p| p.name)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }])
        })?),
        None => None,
    };
    let p = preset_def;
    let mut mappers = input.mappers.unwrap_or_default();
    if let Some(p) = p {
        if mappers.subject.is_none() {
            mappers.subject = p.subject_claim.map(str::to_string);
        }
        if mappers.username.is_none() {
            mappers.username = p.username_claim.map(str::to_string);
        }
    }
    let alias = input.alias.trim().to_string();
    Ok(Resolved {
        alias: alias.clone(),
        kind: input.kind.or(p.map(|p| p.kind)).unwrap_or(IdpKind::Oidc),
        display_name: opt(input.display_name)
            .or(p.map(|p| p.display_name.to_string()))
            .unwrap_or_else(|| alias.clone()),
        preset: p.map(|p| p.name.to_string()),
        enabled: input.enabled.unwrap_or(true),
        hidden: input.hidden.unwrap_or(false),
        issuer: opt(input.issuer).or(p.and_then(|p| p.issuer.map(str::to_string))),
        authorization_endpoint: opt(input.authorization_endpoint)
            .or(p.and_then(|p| p.authorization_endpoint.map(str::to_string))),
        token_endpoint: opt(input.token_endpoint)
            .or(p.and_then(|p| p.token_endpoint.map(str::to_string))),
        userinfo_endpoint: opt(input.userinfo_endpoint)
            .or(p.and_then(|p| p.userinfo_endpoint.map(str::to_string))),
        jwks_uri: opt(input.jwks_uri).or(p.and_then(|p| p.jwks_uri.map(str::to_string))),
        client_id: input.client_id,
        token_endpoint_auth_method: input
            .token_endpoint_auth_method
            .or(p.map(|p| p.token_endpoint_auth_method))
            .unwrap_or(IdpAuthMethod::ClientSecretBasic),
        scopes: input.scopes.unwrap_or_else(|| {
            p.map(|p| p.scopes.iter().map(|s| s.to_string()).collect())
                .unwrap_or_else(|| vec!["openid".into(), "email".into(), "profile".into()])
        }),
        pkce: input.pkce.unwrap_or(true),
        link_policy: input.link_policy.unwrap_or(LinkPolicy::VerifiedEmail),
        trust_email: input
            .trust_email
            .or(p.map(|p| p.trust_email))
            .unwrap_or(false),
        mappers,
        sort_order: input.sort_order.unwrap_or(0),
        saml: input.saml,
    })
}

fn from_existing(idp: &IdentityProvider) -> Resolved {
    Resolved {
        alias: idp.alias.clone(),
        kind: idp.kind,
        display_name: idp.display_name.clone(),
        preset: idp.preset.clone(),
        enabled: idp.enabled,
        hidden: idp.hidden,
        issuer: idp.issuer.clone(),
        authorization_endpoint: idp.authorization_endpoint.clone(),
        token_endpoint: idp.token_endpoint.clone(),
        userinfo_endpoint: idp.userinfo_endpoint.clone(),
        jwks_uri: idp.jwks_uri.clone(),
        client_id: idp.client_id.clone(),
        token_endpoint_auth_method: idp.token_endpoint_auth_method,
        scopes: idp.scopes.clone(),
        pkce: idp.pkce,
        link_policy: idp.link_policy,
        trust_email: idp.trust_email,
        mappers: idp.mappers.0.clone(),
        sort_order: idp.sort_order,
        saml: idp.saml.as_ref().map(|s| s.settings()),
    }
}

async fn invalidate(state: &AppState, tenant_id: Uuid) -> AppResult<()> {
    state
        .cache
        .invalidate(&[keys::identity_providers(tenant_id)])
        .await
}

pub async fn list(state: &AppState, tenant_id: Uuid) -> AppResult<Vec<IdentityProvider>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let mut rows = repos::identity_providers::list(&mut *tx, tenant_id).await?;
    if rows.iter().any(|r| r.kind == IdpKind::Saml) {
        let mut saml = repos::identity_providers::list_saml(&mut *tx, tenant_id).await?;
        for r in &mut rows {
            if let Some(i) = saml.iter().position(|s| s.idp_id == r.id) {
                r.saml = Some(saml.swap_remove(i));
            }
        }
    }
    tx.commit().await?;
    Ok(rows)
}

/// By row id or alias.
pub async fn get(state: &AppState, tenant_id: Uuid, key: &str) -> AppResult<IdentityProvider> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let row = match Uuid::parse_str(key) {
        Ok(id) => repos::identity_providers::find_by_id(&mut *tx, tenant_id, id).await?,
        Err(_) => {
            repos::identity_providers::find_by_alias(&mut *tx, tenant_id, &key.to_lowercase())
                .await?
        }
    };
    let mut row = row.ok_or(AppError::NotFound("identity provider"))?;
    if row.kind == IdpKind::Saml {
        row.saml = repos::identity_providers::find_saml(&mut *tx, tenant_id, row.id).await?;
    }
    tx.commit().await?;
    Ok(row)
}

/// Providers offered on the login page (enabled, not hidden), cached.
pub async fn offered(state: &AppState, tenant_id: Uuid) -> AppResult<Vec<PublicIdentityProvider>> {
    let db = state.db.clone();
    let cached: Option<Arc<Vec<PublicIdentityProvider>>> = state
        .cache
        .get_or_load(
            &keys::identity_providers(tenant_id),
            OFFERED_TTL,
            || async move {
                let mut tx = db::tenant_tx(&db, tenant_id).await?;
                let rows = repos::identity_providers::list(&mut *tx, tenant_id).await?;
                tx.commit().await?;
                Ok(Some(
                    rows.iter()
                        .filter(|p| p.offered())
                        .map(PublicIdentityProvider::from)
                        .collect::<Vec<_>>(),
                ))
            },
        )
        .await?;
    Ok(cached.map(|v| v.as_ref().clone()).unwrap_or_default())
}

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    input: NewIdentityProvider,
) -> AppResult<IdentityProvider> {
    let secret = input
        .client_secret
        .clone()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let r = finish(from_new(input)?, secret.is_some()).await?;
    check_unsolicited_target(state, tenant_id, r.saml.as_ref()).await?;
    let id = Uuid::now_v7();
    let enc = encrypt_secret(state, tenant_id, id, secret.as_deref().unwrap_or("")).await?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let row = repos::identity_providers::insert(
        &mut *tx,
        tenant_id,
        repos::identity_providers::NewRow {
            id,
            alias: &r.alias,
            kind: r.kind,
            display_name: &r.display_name,
            preset: r.preset.as_deref(),
            enabled: r.enabled,
            hidden: r.hidden,
            issuer: r.issuer.as_deref(),
            authorization_endpoint: r.authorization_endpoint.as_deref(),
            token_endpoint: r.token_endpoint.as_deref(),
            userinfo_endpoint: r.userinfo_endpoint.as_deref(),
            jwks_uri: r.jwks_uri.as_deref(),
            client_id: &r.client_id,
            client_secret_enc: &enc.to_bytes(),
            key_version: enc.key_version as i32,
            client_secret_set: secret.is_some(),
            token_endpoint_auth_method: r.token_endpoint_auth_method,
            scopes: &r.scopes,
            pkce: r.pkce,
            link_policy: r.link_policy,
            trust_email: r.trust_email,
            mappers: &r.mappers,
            sort_order: r.sort_order,
        },
    )
    .await
    .map_err(|e| match AppError::from_db(e) {
        AppError::Conflict(_) => AppError::Conflict("alias already in use".into()),
        other => other,
    })?;
    let mut row = row;
    if let Some(saml) = &r.saml {
        row.saml = Some(store_saml(&mut tx, tenant_id, row.id, saml).await?);
    }
    tx.commit().await?;
    invalidate(state, tenant_id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::IdentityProviderCreated { idp_id: row.id },
    ));
    Ok(row)
}

pub async fn update(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    key: &str,
    patch: IdentityProviderUpdate,
) -> AppResult<IdentityProvider> {
    let existing = get(state, tenant_id, key).await?;
    if patch.is_empty() {
        return Ok(existing);
    }
    let mut r = from_existing(&existing);
    let issuer_changed =
        matches!(&patch.issuer, Some(Some(i)) if Some(i) != existing.issuer.as_ref());
    let endpoints_given = (
        patch.authorization_endpoint.is_some(),
        patch.token_endpoint.is_some(),
        patch.jwks_uri.is_some(),
        patch.userinfo_endpoint.is_some(),
    );
    if let Some(v) = patch.alias {
        r.alias = v;
    }
    if let Some(v) = patch.kind {
        r.kind = v;
    }
    if let Some(v) = patch.display_name {
        r.display_name = v;
    }
    if let Some(v) = patch.enabled {
        r.enabled = v;
    }
    if let Some(v) = patch.hidden {
        r.hidden = v;
    }
    if let Some(v) = patch.issuer {
        r.issuer = opt(v);
    }
    if let Some(v) = patch.authorization_endpoint {
        r.authorization_endpoint = opt(v);
    }
    if let Some(v) = patch.token_endpoint {
        r.token_endpoint = opt(v);
    }
    if let Some(v) = patch.userinfo_endpoint {
        r.userinfo_endpoint = opt(v);
    }
    if let Some(v) = patch.jwks_uri {
        r.jwks_uri = opt(v);
    }
    if let Some(v) = patch.client_id {
        r.client_id = v;
    }
    if let Some(v) = patch.token_endpoint_auth_method {
        r.token_endpoint_auth_method = v;
    }
    if let Some(v) = patch.scopes {
        r.scopes = v;
    }
    if let Some(v) = patch.pkce {
        r.pkce = v;
    }
    if let Some(v) = patch.link_policy {
        r.link_policy = v;
    }
    if let Some(v) = patch.trust_email {
        r.trust_email = v;
    }
    if let Some(v) = patch.mappers {
        r.mappers = v;
    }
    if let Some(v) = patch.sort_order {
        r.sort_order = v;
    }
    if let Some(v) = patch.saml {
        r.saml = Some(v);
    }
    if (r.kind == IdpKind::Saml) != (existing.kind == IdpKind::Saml) {
        return Err(field_error(
            "kind",
            "a provider cannot change to or from SAML; create another one",
        ));
    }
    // A new issuer means new endpoints unless the patch names them.
    if issuer_changed && r.kind == IdpKind::Oidc {
        if !endpoints_given.0 {
            r.authorization_endpoint = None;
        }
        if !endpoints_given.1 {
            r.token_endpoint = None;
        }
        if !endpoints_given.2 {
            r.jwks_uri = None;
        }
        if !endpoints_given.3 {
            r.userinfo_endpoint = None;
        }
    }
    let secret: Option<Option<String>> = patch
        .client_secret
        .map(|s| s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty()));
    let has_secret = match &secret {
        Some(s) => s.is_some(),
        None => existing.client_secret_set,
    };
    let r = finish(r, has_secret).await?;
    check_unsolicited_target(state, tenant_id, r.saml.as_ref()).await?;
    let enc = match &secret {
        Some(s) => {
            Some(encrypt_secret(state, tenant_id, existing.id, s.as_deref().unwrap_or("")).await?)
        }
        None => None,
    };
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let row = repos::identity_providers::update(
        &mut *tx,
        tenant_id,
        existing.id,
        repos::identity_providers::UpdateRow {
            alias: &r.alias,
            kind: r.kind,
            display_name: &r.display_name,
            enabled: r.enabled,
            hidden: r.hidden,
            issuer: r.issuer.as_deref(),
            authorization_endpoint: r.authorization_endpoint.as_deref(),
            token_endpoint: r.token_endpoint.as_deref(),
            userinfo_endpoint: r.userinfo_endpoint.as_deref(),
            jwks_uri: r.jwks_uri.as_deref(),
            client_id: &r.client_id,
            client_secret: enc
                .as_ref()
                .map(|e| (e.to_bytes(), e.key_version as i32, has_secret))
                .as_ref()
                .map(|(b, v, s)| (b.as_slice(), *v, *s)),
            token_endpoint_auth_method: r.token_endpoint_auth_method,
            scopes: &r.scopes,
            pkce: r.pkce,
            link_policy: r.link_policy,
            trust_email: r.trust_email,
            mappers: &r.mappers,
            sort_order: r.sort_order,
        },
    )
    .await
    .map_err(|e| match AppError::from_db(e) {
        AppError::Conflict(_) => AppError::Conflict("alias already in use".into()),
        other => other,
    })?
    .ok_or(AppError::NotFound("identity provider"))?;
    let mut row = row;
    if let Some(saml) = &r.saml {
        row.saml = Some(store_saml(&mut tx, tenant_id, row.id, saml).await?);
    }
    tx.commit().await?;
    invalidate(state, tenant_id).await?;
    if row.jwks_uri != existing.jwks_uri {
        forget_jwks(state, tenant_id, row.id).await?;
    }
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::IdentityProviderUpdated { idp_id: row.id },
    ));
    Ok(row)
}

/// Write a SAML provider's settings; another provider already using the
/// entity ID is a conflict.
async fn store_saml(
    tx: &mut crate::db::Tx,
    tenant_id: Uuid,
    idp_id: Uuid,
    saml: &SamlUpstreamSettings,
) -> AppResult<crate::models::SamlUpstream> {
    repos::identity_providers::upsert_saml(&mut **tx, tenant_id, idp_id, saml)
        .await
        .map_err(|e| match AppError::from_db(e) {
            AppError::Conflict(_) => AppError::Conflict(
                "another identity provider already has this SAML entity ID".into(),
            ),
            other => other,
        })
}

/// Delete a provider and, through the database, the identities linked to
/// it. Users who only ever signed in through it keep their accounts.
pub async fn delete(state: &AppState, tenant_id: Uuid, actor: Actor, key: &str) -> AppResult<()> {
    let existing = get(state, tenant_id, key).await?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::identity_providers::delete(&mut *tx, tenant_id, existing.id).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound("identity provider"));
    }
    invalidate(state, tenant_id).await?;
    forget_jwks(state, tenant_id, existing.id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::IdentityProviderDeleted {
            idp_id: existing.id,
        },
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// JWKS
// ---------------------------------------------------------------------------

/// The provider's JWK set, cached for an hour. `refresh` re-fetches (once
/// per throttle window) when a `kid` is unknown, so rotated keys are found.
pub async fn jwks(
    state: &AppState,
    idp: &IdentityProvider,
    refresh: bool,
) -> AppResult<Vec<Value>> {
    let Some(uri) = &idp.jwks_uri else {
        return Err(AppError::BadRequest("the provider has no jwks_uri".into()));
    };
    let key = keys::idp_jwks(idp.tenant_id, idp.id);
    let mut conn = state.redis.get().await?;
    let cached: Option<Value> = conn
        .get::<_, Option<String>>(&key)
        .await?
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok());
    if !refresh && let Some(v) = &cached {
        return Ok(v["keys"].as_array().cloned().unwrap_or_default());
    }
    if refresh && cached.is_some() {
        let throttle = format!("{key}:refreshed");
        let allowed: bool = redis::cmd("SET")
            .arg(&throttle)
            .arg(1u8)
            .arg("NX")
            .arg("EX")
            .arg(JWKS_REFRESH_THROTTLE_SECS)
            .query_async(&mut conn)
            .await?;
        if !allowed {
            return Ok(cached
                .map(|v| v["keys"].as_array().cloned().unwrap_or_default())
                .unwrap_or_default());
        }
    }
    let doc = get_json("jwks", uri, None).await?;
    let _: () = conn.set_ex(&key, doc.to_string(), JWKS_CACHE_SECS).await?;
    Ok(doc["keys"].as_array().cloned().unwrap_or_default())
}

async fn forget_jwks(state: &AppState, tenant_id: Uuid, idp_id: Uuid) -> AppResult<()> {
    let key = keys::idp_jwks(tenant_id, idp_id);
    let mut conn = state.redis.get().await?;
    let _: () = conn.del(&[key.clone(), format!("{key}:refreshed")]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_are_url_safe_and_never_a_route_word() {
        assert_eq!(validate_alias(" Google ").unwrap(), "google");
        assert!(validate_alias("my idp").is_err());
        assert!(validate_alias("-x").is_err());
        assert!(validate_alias("presets").is_err());
        assert!(validate_alias("").is_err());
    }

    #[test]
    fn endpoints_need_https_except_loopback() {
        assert_eq!(
            validate_endpoint("issuer", "https://accounts.google.com/").unwrap(),
            "https://accounts.google.com"
        );
        assert!(validate_endpoint("issuer", "http://idp.example.com").is_err());
        assert!(validate_endpoint("issuer", "http://127.0.0.1:9000/mock").is_ok());
        assert!(validate_endpoint("issuer", "not a url").is_err());
    }

    #[test]
    fn microsoft_common_accepts_any_directory() {
        assert!(issuer_matches(
            "https://login.microsoftonline.com/common/v2.0",
            "https://login.microsoftonline.com/{tenantid}/v2.0"
        ));
        assert!(issuer_matches(
            "https://login.microsoftonline.com/common/v2.0",
            "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
        ));
        assert!(!issuer_matches(
            "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
            "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
        ));
        assert!(!issuer_matches(
            "https://accounts.google.com",
            "https://accounts.google.com.evil"
        ));
    }

    #[test]
    fn presets_fill_in_what_they_know() {
        let r = from_new(NewIdentityProvider {
            alias: "gh".into(),
            preset: Some("github".into()),
            client_id: "abc".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(r.kind, IdpKind::Oauth2);
        assert_eq!(r.display_name, "GitHub");
        assert_eq!(r.mappers.subject.as_deref(), Some("id"));
        assert_eq!(r.mappers.username.as_deref(), Some("login"));
        assert_eq!(r.scopes, ["read:user", "user:email"]);
        assert!(
            from_new(NewIdentityProvider {
                alias: "x".into(),
                preset: Some("nope".into()),
                client_id: "abc".into(),
                ..Default::default()
            })
            .is_err()
        );
    }
}
