//! JWT issuance and verification.
//!
//! * Access tokens: RFC 9068 (`typ: at+jwt`), short-lived, audience-scoped.
//! * ID tokens: OIDC Core §2, with `at_hash`/`c_hash`, optional JWE per client.
//! * Verification: by `kid` against the tenant's published keys (revoked keys
//!   are not published, so their tokens fail immediately).
//! * Opaque access tokens: a client with `access_token_format: opaque` gets
//!   `at_<random>` standing for the same claims ([`super::opaque_tokens`]);
//!   [`verify_access`] accepts either form.
//!
//! Parsed private keys are cached in the in-process L1 only, never in Redis.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use uuid::Uuid;

use crate::cache::keys as cache_keys;
use crate::error::{AppError, AppResult};
use crate::models::{
    AccessTokenFormat, ClaimMapper, Exposure, Group, Role, SigningAlg, SigningKey, Tenant,
    TokenKind, User,
};
use crate::services::claims::{ClaimContext, apply_mappers, profile_claims, scope_claims};
use crate::services::{features, jwe, keys, opaque_tokens, profile_schema, scopes};
use crate::state::AppState;

const MATERIAL_L1_TTL: Duration = Duration::from_secs(300);

/// Minimal client view the token service needs (built from the DB client in Phase 3).
#[derive(Debug, Clone)]
pub struct TokenClient {
    pub client_id: String,
    pub subject_type: SubjectType,
    /// Host used for pairwise subjects (sector identifier or first redirect URI host).
    pub sector_identifier: Option<String>,
    /// Encrypt ID tokens for this client with its RSA public JWK.
    pub id_token_encryption: Option<IdTokenEncryption>,
    pub access_token_ttl: Duration,
    pub id_token_ttl: Duration,
    pub mappers: Vec<ClaimMapper>,
    /// Repeat the scope-derived standard claims in the ID token (opt-in;
    /// OIDC Core §5.4 puts them at the userinfo endpoint).
    pub id_token_scope_claims: bool,
    /// JWT, or an opaque reference only introspection resolves.
    pub access_token_format: AccessTokenFormat,
    /// Sign access tokens with this algorithm instead of the tenant's
    /// default (the audience's resource server asks for it).
    pub access_token_alg: Option<SigningAlg>,
    /// Sign ID tokens with this algorithm instead of the tenant's default
    /// (a FAPI 2.0 client, when the default is one the profile forbids).
    pub id_token_alg: Option<SigningAlg>,
    /// `permissions` claim of the access token: what the subject's roles
    /// hold on the requested resource servers (empty: no claim).
    pub permissions: Vec<String>,
    /// The access token expires no later than this, whatever the TTL says
    /// (token exchange: the subject token's own `exp`). An instant rather
    /// than a shorter TTL, so a clock second passing between the caller's
    /// arithmetic and signing cannot push `exp` past it.
    pub not_after: Option<DateTime<Utc>>,
}

impl TokenClient {
    /// Build from a stored client and the tenant's defaults.
    pub fn from_client(
        client: &crate::models::Client,
        tenant: &Tenant,
        mappers: Vec<ClaimMapper>,
    ) -> Self {
        let policy = &tenant.settings.session;
        let fapi_alg = client
            .is_fapi2()
            .then(|| crate::oidc::fapi::signing_alg(tenant));
        let sector_identifier = client
            .sector_identifier_uri
            .as_deref()
            .and_then(|u| url::Url::parse(u).ok())
            .and_then(|u| u.host_str().map(str::to_string))
            .or_else(|| {
                client
                    .redirect_uris
                    .first()
                    .and_then(|u| url::Url::parse(u).ok())
                    .and_then(|u| u.host_str().map(str::to_string))
            });
        let id_token_encryption = client.id_token_encryption.as_ref().and_then(|cfg| {
            let alg = jwe::KeyAlg::parse(&cfg.alg)?;
            let enc = jwe::ContentEnc::parse(&cfg.enc)?;
            let recipient_jwk = client
                .jwks
                .as_ref()
                .and_then(|j| j["keys"].as_array().cloned())
                .and_then(|keys| {
                    keys.iter()
                        .find(|k| k["kty"] == "RSA" && k["use"] == "enc")
                        .or_else(|| keys.iter().find(|k| k["kty"] == "RSA"))
                        .cloned()
                })?;
            Some(IdTokenEncryption {
                alg,
                enc,
                recipient_jwk,
            })
        });
        Self {
            client_id: client.client_id.clone(),
            subject_type: match client.subject_type {
                crate::models::ClientSubjectType::Public => SubjectType::Public,
                crate::models::ClientSubjectType::Pairwise => SubjectType::Pairwise,
            },
            sector_identifier,
            id_token_scope_claims: client.id_token_scope_claims,
            access_token_format: client.access_token_format,
            access_token_alg: fapi_alg,
            id_token_alg: fapi_alg,
            permissions: vec![],
            not_after: None,
            id_token_encryption,
            access_token_ttl: Duration::from_secs(
                client
                    .access_token_ttl_secs
                    .map(|s| s.max(1) as u64)
                    .unwrap_or(policy.access_token_ttl_secs),
            ),
            id_token_ttl: Duration::from_secs(
                client
                    .id_token_ttl_secs
                    .map(|s| s.max(1) as u64)
                    .unwrap_or(policy.id_token_ttl_secs),
            ),
            mappers,
        }
    }

    pub fn public(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            subject_type: SubjectType::Public,
            sector_identifier: None,
            id_token_encryption: None,
            access_token_ttl: Duration::from_secs(300),
            id_token_ttl: Duration::from_secs(300),
            mappers: vec![],
            id_token_scope_claims: false,
            access_token_format: AccessTokenFormat::Jwt,
            access_token_alg: None,
            id_token_alg: None,
            permissions: vec![],
            not_after: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectType {
    Public,
    Pairwise,
}

#[derive(Debug, Clone)]
pub struct IdTokenEncryption {
    pub alg: jwe::KeyAlg,
    pub enc: jwe::ContentEnc,
    pub recipient_jwk: Value,
}

/// Inputs for an access token.
pub struct AccessTokenRequest<'a> {
    pub tenant: &'a Tenant,
    pub client: &'a TokenClient,
    /// `None` for client_credentials without a service-account user.
    pub user: Option<&'a User>,
    pub scopes: &'a [String],
    /// Resource servers / audiences requested (validated by the caller).
    pub audiences: &'a [String],
    pub roles: &'a [Role],
    pub groups: &'a [Group],
    pub session_id: Option<Uuid>,
    pub auth_time: Option<DateTime<Utc>>,
    pub amr: &'a [String],
    pub acr: Option<&'a str>,
    /// Organization the sign-in acts in (`org_id`). The roles above were
    /// resolved in it.
    pub org_id: Option<Uuid>,
    /// DPoP key thumbprint the token is bound to (`cnf.jkt`, RFC 9449 §6.1).
    pub cnf_jkt: Option<&'a str>,
    /// Client certificate thumbprint the token is bound to (`cnf.x5t#S256`,
    /// RFC 8705 §3.1).
    pub cnf_x5t: Option<&'a str>,
    /// Acting party of a delegated token (`act`, RFC 8693 §4.1).
    pub act: Option<Value>,
}

/// What a token request proved possession of: the key of a DPoP proof
/// (its thumbprint) and the TLS client certificate (its `x5t#S256`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SenderProof<'a> {
    pub jkt: Option<&'a str>,
    pub x5t: Option<&'a str>,
}

pub struct IdTokenRequest<'a> {
    pub tenant: &'a Tenant,
    pub client: &'a TokenClient,
    pub user: &'a User,
    pub scopes: &'a [String],
    pub roles: &'a [Role],
    pub groups: &'a [Group],
    pub session_id: Option<Uuid>,
    pub auth_time: DateTime<Utc>,
    /// Organization the sign-in acts in (`org_id`).
    pub org_id: Option<Uuid>,
    pub nonce: Option<&'a str>,
    pub amr: &'a [String],
    pub acr: Option<&'a str>,
    /// Access token issued alongside (for `at_hash`).
    pub access_token: Option<&'a str>,
    /// Authorization code (for `c_hash`, hybrid-less: only when returned with a code).
    pub code: Option<&'a str>,
    /// The administrator behind an impersonated sign-in (`act`), so a
    /// relying party can tell from the ID token too.
    pub act: Option<Value>,
}

pub struct IssuedToken {
    pub token: String,
    pub claims: Map<String, Value>,
    pub kid: String,
    pub expires_at: DateTime<Utc>,
}

/// Subject identifier for a user as seen by a client (OIDC Core §8).
pub fn subject_for(tenant: &Tenant, client: &TokenClient, user: &User) -> String {
    match client.subject_type {
        SubjectType::Public => user.id.to_string(),
        SubjectType::Pairwise => {
            let sector = client
                .sector_identifier
                .as_deref()
                .unwrap_or(&client.client_id);
            let mut h = Sha256::new();
            h.update(sector.as_bytes());
            h.update(b"|");
            h.update(user.id.as_bytes());
            h.update(b"|");
            h.update(&tenant.pairwise_salt);
            URL_SAFE_NO_PAD.encode(h.finalize())
        }
    }
}

/// `at_hash` / `c_hash`: left half of the hash matching the signing alg.
pub fn half_hash(alg: SigningAlg, input: &str) -> String {
    let digest: Vec<u8> = match alg {
        SigningAlg::RS256 | SigningAlg::ES256 => Sha256::digest(input.as_bytes()).to_vec(),
        SigningAlg::RS384 => Sha384::digest(input.as_bytes()).to_vec(),
        // Ed25519 uses SHA-512 (OpenID Connect Core errata for EdDSA).
        SigningAlg::RS512 | SigningAlg::EdDSA => Sha512::digest(input.as_bytes()).to_vec(),
    };
    URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
}

pub fn jwt_alg(alg: SigningAlg) -> Algorithm {
    match alg {
        SigningAlg::RS256 => Algorithm::RS256,
        SigningAlg::RS384 => Algorithm::RS384,
        SigningAlg::RS512 => Algorithm::RS512,
        SigningAlg::ES256 => Algorithm::ES256,
        SigningAlg::EdDSA => Algorithm::EdDSA,
    }
}

/// jsonwebtoken encoding key from a PKCS#8 DER private key.
pub fn encoding_key_from_der(alg: SigningAlg, der: &[u8]) -> AppResult<EncodingKey> {
    Ok(match alg {
        SigningAlg::RS256 | SigningAlg::RS384 | SigningAlg::RS512 => {
            // jsonwebtoken (aws-lc-rs) wants PKCS#1 for RSA; we store PKCS#8.
            use rsa::pkcs1::EncodeRsaPrivateKey as _;
            use rsa::pkcs8::DecodePrivateKey as _;
            let private = rsa::RsaPrivateKey::from_pkcs8_der(der)
                .map_err(|e| AppError::Internal(format!("rsa key parse: {e}")))?;
            let pkcs1 = private
                .to_pkcs1_der()
                .map_err(|e| AppError::Internal(format!("rsa pkcs1: {e}")))?;
            EncodingKey::from_rsa_der(pkcs1.as_bytes())
        }
        SigningAlg::ES256 => EncodingKey::from_ec_der(der),
        SigningAlg::EdDSA => EncodingKey::from_ed_der(der),
    })
}

/// Parsed signing material, cached per node.
async fn encoding_key(state: &AppState, key: &SigningKey) -> AppResult<Arc<EncodingKey>> {
    let cache_key = cache_keys::signing_key_material(key.id);
    if let Some(k) = state.cache.material().get::<EncodingKey>(&cache_key) {
        return Ok(k);
    }
    let der = keys::private_der(state, key).await?;
    let encoding = Arc::new(encoding_key_from_der(key.alg, &der)?);
    state
        .cache
        .material()
        .insert(cache_key, encoding.clone(), MATERIAL_L1_TTL);
    Ok(encoding)
}

/// Sign arbitrary claims with `key`. `typ` is the JOSE header type.
pub async fn sign(
    state: &AppState,
    key: &SigningKey,
    typ: &str,
    claims: &Map<String, Value>,
) -> AppResult<String> {
    let mut header = Header::new(jwt_alg(key.alg));
    header.kid = Some(key.kid.clone());
    header.typ = Some(typ.to_string());
    let enc = encoding_key(state, key).await?;
    let encode = move |claims: &Map<String, Value>| {
        jsonwebtoken::encode(&header, claims, &enc)
            .map_err(|e| AppError::Internal(format!("jwt sign: {e}")))
    };
    match key.alg {
        // An RSA signature is about a millisecond of CPU: off the runtime.
        SigningAlg::RS256 | SigningAlg::RS384 | SigningAlg::RS512 => {
            let claims = claims.clone();
            tokio::task::spawn_blocking(move || encode(&claims))
                .await
                .map_err(|e| AppError::Internal(format!("jwt signing task: {e}")))?
        }
        SigningAlg::ES256 | SigningAlg::EdDSA => encode(claims),
    }
}

pub fn issuer(state: &AppState, tenant: &Tenant) -> String {
    match &tenant.settings.custom_domain {
        Some(host) => format!("https://{host}"),
        None => state.config.issuer_for(&tenant.slug),
    }
}

pub async fn issue_access_token(
    state: &AppState,
    req: AccessTokenRequest<'_>,
) -> AppResult<IssuedToken> {
    let now = Utc::now();
    let mut exp = now + chrono::Duration::from_std(req.client.access_token_ttl).unwrap_or_default();
    if let Some(limit) = req.client.not_after {
        exp = exp.min(limit);
    }

    // Profile attributes exposed to access tokens first, then the mappers,
    // which may override them.
    let mut claims = Map::new();
    if let Some(user) = req.user {
        let schema = profile_schema::get(state, req.tenant.id).await?;
        profile_claims(user, &schema, Exposure::AccessToken, &mut claims);
    }
    let ctx = ClaimContext {
        tenant: req.tenant,
        user: req.user,
        client_id: &req.client.client_id,
        scopes: req.scopes,
        roles: req.roles,
        groups: req.groups,
    };
    let extra_aud = apply_mappers(&req.client.mappers, &ctx, TokenKind::Access, &mut claims)?;

    let mut aud: Vec<String> = req.audiences.to_vec();
    aud.extend(extra_aud);
    if aud.is_empty() {
        aud.push(req.client.client_id.clone());
    }
    aud.dedup();

    claims.insert("iss".into(), json!(issuer(state, req.tenant)));
    let sub = match req.user {
        Some(u) => subject_for(req.tenant, req.client, u),
        None => req.client.client_id.clone(),
    };
    claims.insert("sub".into(), json!(sub));
    claims.insert(
        "aud".into(),
        if aud.len() == 1 {
            json!(aud[0])
        } else {
            json!(aud)
        },
    );
    claims.insert("client_id".into(), json!(req.client.client_id));
    claims.insert("azp".into(), json!(req.client.client_id));
    claims.insert("iat".into(), json!(now.timestamp()));
    claims.insert("nbf".into(), json!(now.timestamp()));
    claims.insert("exp".into(), json!(exp.timestamp()));
    claims.insert("jti".into(), json!(Uuid::now_v7()));
    claims.insert("tid".into(), json!(req.tenant.id));
    claims.insert("scope".into(), json!(req.scopes.join(" ")));
    // The organization this sign-in acts in, not the user's primary one: the
    // same user in another organization gets another token.
    if let Some(org) = req.org_id {
        claims.insert("org_id".into(), json!(org));
    }
    if req.scopes.iter().any(|s| s == features::SCOPE) {
        let on = features::enabled_for(state, req.tenant, req.org_id).await?;
        claims.insert("features".into(), json!(on));
    }
    if req.user.is_some() {
        // A `roles` or `groups` mapper reshapes these (a client's roles only,
        // group paths); its output stands. Mappers of any other kind cannot
        // write them (`claims::mapper_claim_refusal`).
        if !claims.contains_key("roles") {
            let roles: Vec<&str> = req.roles.iter().map(|r| r.name.as_str()).collect();
            claims.insert("roles".into(), json!(roles));
        }
        if !claims.contains_key("groups") {
            let groups: Vec<&str> = req.groups.iter().map(|g| g.name.as_str()).collect();
            claims.insert("groups".into(), json!(groups));
        }
    }
    if !req.client.permissions.is_empty() {
        claims.insert("permissions".into(), json!(req.client.permissions));
    }
    if let Some(sid) = req.session_id {
        claims.insert("sid".into(), json!(sid));
    }
    if let Some(t) = req.auth_time {
        claims.insert("auth_time".into(), json!(t.timestamp()));
    }
    if !req.amr.is_empty() {
        claims.insert("amr".into(), json!(req.amr));
    }
    if let Some(acr) = req.acr {
        claims.insert("acr".into(), json!(acr));
    }
    let mut cnf = serde_json::Map::new();
    if let Some(jkt) = req.cnf_jkt {
        cnf.insert("jkt".into(), json!(jkt));
    }
    if let Some(x5t) = req.cnf_x5t {
        cnf.insert(crate::oidc::mtls::CNF_X5T.into(), json!(x5t));
    }
    if !cnf.is_empty() {
        claims.insert("cnf".into(), Value::Object(cnf));
    }
    if let Some(act) = req.act {
        claims.insert("act".into(), act);
    }

    if req.client.access_token_format == AccessTokenFormat::Opaque {
        let token = opaque_tokens::issue(state, &claims, exp).await?;
        return Ok(IssuedToken {
            token,
            claims,
            kid: String::new(),
            expires_at: exp,
        });
    }
    let key = match req.client.access_token_alg {
        Some(alg) => {
            keys::ensure_active_alg(state, req.tenant.id, &req.tenant.settings.keys, alg).await?
        }
        None => keys::ensure_active(state, req.tenant.id, &req.tenant.settings.keys).await?,
    };
    let token = sign(state, &key, "at+jwt", &claims).await?;
    Ok(IssuedToken {
        token,
        claims,
        kid: key.kid,
        expires_at: exp,
    })
}

pub async fn issue_id_token(state: &AppState, req: IdTokenRequest<'_>) -> AppResult<IssuedToken> {
    let key = match req.client.id_token_alg {
        Some(alg) => {
            keys::ensure_active_alg(state, req.tenant.id, &req.tenant.settings.keys, alg).await?
        }
        None => keys::ensure_active(state, req.tenant.id, &req.tenant.settings.keys).await?,
    };
    let now = Utc::now();
    let exp = now + chrono::Duration::from_std(req.client.id_token_ttl).unwrap_or_default();

    // With an access token issued, the scope-derived claims are read from the
    // userinfo endpoint (OIDC Core §5.4); a client may ask for them here too.
    let mut claims = if req.client.id_token_scope_claims {
        let defs = scopes::list(state, req.tenant.id).await?;
        scope_claims(req.user, req.scopes, &defs)
    } else {
        Map::new()
    };
    let schema = profile_schema::get(state, req.tenant.id).await?;
    profile_claims(req.user, &schema, Exposure::IdToken, &mut claims);
    let ctx = ClaimContext {
        tenant: req.tenant,
        user: Some(req.user),
        client_id: &req.client.client_id,
        scopes: req.scopes,
        roles: req.roles,
        groups: req.groups,
    };
    apply_mappers(&req.client.mappers, &ctx, TokenKind::Id, &mut claims)?;

    claims.insert("iss".into(), json!(issuer(state, req.tenant)));
    claims.insert(
        "sub".into(),
        json!(subject_for(req.tenant, req.client, req.user)),
    );
    claims.insert("aud".into(), json!(req.client.client_id));
    claims.insert("azp".into(), json!(req.client.client_id));
    claims.insert("iat".into(), json!(now.timestamp()));
    claims.insert("exp".into(), json!(exp.timestamp()));
    claims.insert("auth_time".into(), json!(req.auth_time.timestamp()));
    claims.insert("tid".into(), json!(req.tenant.id));
    if let Some(org) = req.org_id {
        claims.insert("org_id".into(), json!(org));
    }
    if req.scopes.iter().any(|s| s == features::SCOPE) {
        let on = features::enabled_for(state, req.tenant, req.org_id).await?;
        claims.insert("features".into(), json!(on));
    }
    if let Some(n) = req.nonce {
        claims.insert("nonce".into(), json!(n));
    }
    if let Some(sid) = req.session_id {
        claims.insert("sid".into(), json!(sid));
    }
    if !req.amr.is_empty() {
        claims.insert("amr".into(), json!(req.amr));
    }
    if let Some(acr) = req.acr {
        claims.insert("acr".into(), json!(acr));
    }
    if let Some(at) = req.access_token {
        claims.insert("at_hash".into(), json!(half_hash(key.alg, at)));
    }
    if let Some(code) = req.code {
        claims.insert("c_hash".into(), json!(half_hash(key.alg, code)));
    }
    if let Some(act) = req.act {
        claims.insert("act".into(), act);
    }

    let jws = sign(state, &key, "JWT", &claims).await?;
    let token = match &req.client.id_token_encryption {
        Some(e) => jwe::encrypt(jws.as_bytes(), &e.recipient_jwk, e.alg, e.enc)?,
        None => jws,
    };
    Ok(IssuedToken {
        token,
        claims,
        kid: key.kid,
        expires_at: exp,
    })
}

/// The user an access token was issued to. `sub` is the user id for public
/// subjects; pairwise subjects cannot be reversed, so those resolve through the
/// session (`sid`) the token was issued in. `Ok(None)` for client-only tokens
/// or when the session has ended.
pub async fn subject_user_id(
    state: &AppState,
    tenant: &Tenant,
    claims: &Map<String, Value>,
) -> AppResult<Option<Uuid>> {
    if let Some(id) = claims
        .get("sub")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return Ok(Some(id));
    }
    let Some(sid) = claims
        .get("sid")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return Ok(None);
    };
    let session =
        crate::services::sessions::get(state, tenant.id, sid, &tenant.settings.session).await?;
    Ok(session.map(|s| s.user_id))
}

/// What a verified token must satisfy.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub audience: Option<String>,
    /// `at+jwt` for access tokens, `JWT` for ID tokens; `None` accepts any.
    pub typ: Option<String>,
    pub leeway_secs: u64,
    /// Accept expired tokens (introspection reports `active: false` itself).
    pub allow_expired: bool,
    /// Reject tokens whose `jti` was revoked before expiry.
    pub check_denylist: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            audience: None,
            typ: None,
            leeway_secs: 30,
            allow_expired: false,
            check_denylist: true,
        }
    }
}

/// A tenant's published keys by `kid`, parsed for verification.
type VerificationKeys = HashMap<String, (SigningAlg, DecodingKey)>;

/// The published keys, cached per node under the tenant's keys version: every
/// key change moves the version, so a revoked key stops verifying on every
/// node at once, and an entry read before the change is never looked up again.
async fn verification_keys(state: &AppState, tenant_id: Uuid) -> AppResult<Arc<VerificationKeys>> {
    let version = keys::keys_version(state, tenant_id).await?;
    let cache_key = cache_keys::verification_keys(tenant_id, &version);
    if let Some(k) = state.cache.material().get::<VerificationKeys>(&cache_key) {
        return Ok(k);
    }
    let mut parsed = VerificationKeys::new();
    for jwk in keys::published_jwks(state, tenant_id).await? {
        let (Some(kid), Some(alg)) = (
            jwk["kid"].as_str().map(str::to_string),
            jwk["alg"]
                .as_str()
                .and_then(|a| a.parse::<SigningAlg>().ok()),
        ) else {
            continue;
        };
        let Some(decoding) = serde_json::from_value::<jsonwebtoken::jwk::Jwk>(jwk)
            .ok()
            .and_then(|j| DecodingKey::from_jwk(&j).ok())
        else {
            continue;
        };
        parsed.insert(kid, (alg, decoding));
    }
    let parsed = Arc::new(parsed);
    state
        .cache
        .material()
        .insert(cache_key, parsed.clone(), MATERIAL_L1_TTL);
    Ok(parsed)
}

/// Verify a JWS issued by `tenant` and return its claims.
pub async fn verify(
    state: &AppState,
    tenant: &Tenant,
    token: &str,
    opts: &VerifyOptions,
) -> AppResult<Map<String, Value>> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| AppError::Unauthorized)?;
    let kid = header.kid.as_deref().ok_or(AppError::Unauthorized)?;
    if let Some(expected) = &opts.typ
        && header.typ.as_deref() != Some(expected)
    {
        return Err(AppError::Unauthorized);
    }
    // Only published keys verify; revoked keys are gone from this set.
    let keys = verification_keys(state, tenant.id).await?;
    let (alg, decoding) = keys.get(kid).ok_or(AppError::Unauthorized)?;
    if jwt_alg(*alg) != header.alg {
        return Err(AppError::Unauthorized);
    }

    let mut validation = Validation::new(header.alg);
    validation.leeway = opts.leeway_secs;
    validation.validate_exp = !opts.allow_expired;
    validation.validate_nbf = true;
    validation.set_issuer(&[issuer(state, tenant)]);
    match &opts.audience {
        Some(a) => validation.set_audience(&[a]),
        None => validation.validate_aud = false,
    }
    // `sub` is not universal (JARM response JWTs have none); callers that need
    // it check the claim themselves.
    validation.set_required_spec_claims(&["exp", "iss"]);
    let data =
        jsonwebtoken::decode::<Map<String, Value>>(token, decoding, &validation).map_err(|e| {
            tracing::debug!(error = %e, "jwt verification failed");
            AppError::Unauthorized
        })?;
    if opts.check_denylist
        && let Some(jti) = data.claims.get("jti").and_then(Value::as_str)
        && crate::services::denylist::is_denied(state, tenant.id, jti).await?
    {
        return Err(AppError::Unauthorized);
    }
    Ok(data.claims)
}

/// Verify an access token of `tenant`, whichever form it was issued in: a
/// JWT (`typ: at+jwt`, against the tenant's keys) or an opaque `at_` token
/// (its claims from Valkey). `opts.typ` is implied; `audience`,
/// `allow_expired` and `check_denylist` apply to both forms, so a revoked
/// `jti` refuses an opaque token exactly as it does a JWT.
pub async fn verify_access(
    state: &AppState,
    tenant: &Tenant,
    token: &str,
    opts: &VerifyOptions,
) -> AppResult<Map<String, Value>> {
    if !opaque_tokens::looks_like(token) {
        let opts = VerifyOptions {
            typ: Some("at+jwt".into()),
            ..opts.clone()
        };
        return verify(state, tenant, token, &opts).await;
    }
    let (tenant_id, claims) = opaque_tokens::lookup(state, token)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if tenant_id != tenant.id {
        return Err(AppError::Unauthorized);
    }
    check_opaque(state, tenant, claims, opts).await
}

/// An access token presented to the admin, account or feature API: the
/// tenant it belongs to, verified, and its claims. An opaque token is looked
/// up once for both. A token of another tenant than `expected` (when the
/// path names one) is `Forbidden` before anything else is checked, as its
/// issuer would not verify here anyway. `Ok(None)`: no such token, or its
/// tenant is gone; a disabled tenant is `Forbidden`.
pub async fn access_token_with_tenant(
    state: &AppState,
    token: &str,
    expected: Option<Uuid>,
    opts: &VerifyOptions,
) -> AppResult<Option<(Arc<Tenant>, Map<String, Value>)>> {
    let check = |tenant_id: Uuid| -> AppResult<()> {
        match expected {
            Some(e) if e != tenant_id => Err(AppError::Forbidden(
                "this token belongs to another tenant".into(),
            )),
            _ => Ok(()),
        }
    };
    let tenant_of = |tenant: Option<Arc<Tenant>>| -> AppResult<Option<Arc<Tenant>>> {
        match tenant {
            Some(t) if !t.is_active() => Err(AppError::Forbidden("tenant is disabled".into())),
            other => Ok(other),
        }
    };
    if opaque_tokens::looks_like(token) {
        let Some((tenant_id, claims)) = opaque_tokens::lookup(state, token).await? else {
            return Ok(None);
        };
        check(tenant_id)?;
        let Some(tenant) =
            tenant_of(crate::services::tenants::get_cached(state, tenant_id).await?)?
        else {
            return Ok(None);
        };
        let claims = check_opaque(state, &tenant, claims, opts).await?;
        return Ok(Some((tenant, claims)));
    }
    let Some(tenant_id) = unverified_tenant_id(token) else {
        return Ok(None);
    };
    check(tenant_id)?;
    let Some(tenant) = tenant_of(crate::services::tenants::get_cached(state, tenant_id).await?)?
    else {
        return Ok(None);
    };
    let opts = VerifyOptions {
        typ: Some("at+jwt".into()),
        ..opts.clone()
    };
    let claims = verify(state, &tenant, token, &opts).await?;
    Ok(Some((tenant, claims)))
}

/// The checks an opaque token's stored claims still need: expiry,
/// audience, revocation.
async fn check_opaque(
    state: &AppState,
    tenant: &Tenant,
    claims: Map<String, Value>,
    opts: &VerifyOptions,
) -> AppResult<Map<String, Value>> {
    // The entry expires with the token; the clock is checked too, so a
    // lagging expiry never stretches a token's life.
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    if !opts.allow_expired && exp + opts.leeway_secs as i64 <= Utc::now().timestamp() {
        return Err(AppError::Unauthorized);
    }
    if let Some(expected) = &opts.audience {
        let matches = match claims.get("aud") {
            Some(Value::String(a)) => a == expected,
            Some(Value::Array(list)) => list.iter().any(|a| a == expected),
            _ => false,
        };
        if !matches {
            return Err(AppError::Unauthorized);
        }
    }
    if opts.check_denylist
        && let Some(jti) = claims.get("jti").and_then(Value::as_str)
        && crate::services::denylist::is_denied(state, tenant.id, jti).await?
    {
        return Err(AppError::Unauthorized);
    }
    Ok(claims)
}

/// The `tid` claim of a JWT read without verification, only to pick the key
/// set to verify with. [`verify`] then binds the token to that tenant's
/// issuer and keys, so a forged `tid` cannot pass.
pub(crate) fn unverified_tenant_id(token: &str) -> Option<Uuid> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("tid")?.as_str()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_hash_matches_spec_example() {
        // OpenID Connect Core §A.3 example: RS256 over the sample access token.
        let at = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
        assert_eq!(half_hash(SigningAlg::RS256, at), "77QmUPtjPfzWtF2AnpK9RQ");
    }
}
