//! [`Validator`]: everything a resource server needs to decide whether an
//! access token authorises a request.

use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::{Algorithm, Validation};
use serde::Deserialize;

use crate::claims::Claims;
use crate::error::AuthError;
use crate::jwks::JwksCache;

/// The algorithms rIDM signs with (see `SigningAlg`). A validator accepts
/// these unless told otherwise, and never `none` or an HMAC: a token signed
/// with a symmetric key the issuer published would verify against the JWKS.
pub const DEFAULT_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::EdDSA,
];

/// The JOSE `typ` of an OAuth 2 access token (RFC 9068).
pub const ACCESS_TOKEN_TYPE: &str = "at+jwt";

const DEFAULT_LEEWAY: Duration = Duration::from_secs(60);
const DEFAULT_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(600);

/// Validates rIDM access tokens against one issuer.
///
/// Build one per issuer at startup, keep it in an [`Arc`], and share it: it
/// holds the key-set cache, so a per-request validator would fetch the key set
/// on every request.
///
/// ```no_run
/// # async fn f() -> Result<(), ridm_auth::AuthError> {
/// let validator = ridm_auth::Validator::builder("https://idp.example/t/acme")
///     .audience("urn:orders")
///     .discover()
///     .await?;
/// let claims = validator.validate("eyJ...").await?;
/// claims.require_permission("orders:read")?;
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct Validator {
    issuer: String,
    audiences: Vec<String>,
    jwks: JwksCache,
    leeway: Duration,
    token_type: Option<String>,
    algorithms: Vec<Algorithm>,
    allow_sender_constrained: bool,
    required: Requirements,
}

/// What a token must carry beyond being valid.
#[derive(Debug, Default, Clone)]
pub(crate) struct Requirements {
    pub(crate) scopes: Vec<String>,
    pub(crate) permissions: Vec<String>,
    pub(crate) roles: Vec<String>,
}

impl Requirements {
    pub(crate) fn check(&self, claims: &Claims) -> Result<(), AuthError> {
        for scope in &self.scopes {
            claims.require_scope(scope)?;
        }
        for permission in &self.permissions {
            claims.require_permission(permission)?;
        }
        for role in &self.roles {
            claims.require_role(role)?;
        }
        Ok(())
    }
}

impl Validator {
    /// Start configuring a validator for `issuer` — the `iss` its tokens carry,
    /// which for rIDM is `https://{host}/t/{tenant}` or the tenant's custom
    /// domain. A trailing slash is ignored.
    pub fn builder(issuer: impl Into<String>) -> ValidatorBuilder {
        ValidatorBuilder::new(issuer)
    }

    /// The issuer whose tokens this validator accepts.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The audiences a token must name one of.
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }

    /// Where this validator reads the issuer's keys.
    pub fn jwks_uri(&self) -> &str {
        self.jwks.uri()
    }

    /// Fetch the key set now, so the first request does not wait for it.
    /// Failure is reported but not fatal — the set is fetched again on demand.
    pub async fn warm(&self) -> Result<(), AuthError> {
        self.jwks.warm().await
    }

    /// Verify `token` and return its claims.
    ///
    /// Signature, `typ`, `alg`, `iss`, `aud`, `exp` and `nbf` are all checked,
    /// as are the scopes, permissions and roles the builder asked for.
    pub async fn validate(&self, token: &str) -> Result<Claims, AuthError> {
        self.validate_with_certificate(token, None).await
    }

    /// [`validate`](Self::validate) for a request that came over mutual TLS:
    /// `certificate` is the DER client certificate of the connection (or the
    /// one a TLS-terminating proxy forwarded).
    ///
    /// A token bound to a certificate (RFC 8705 `cnf.x5t#S256`) is accepted
    /// only with that certificate, and then without
    /// [`ValidatorBuilder::allow_sender_constrained`]: the binding was checked
    /// here. Without a certificate such a token is refused like any other
    /// sender-constrained one.
    pub async fn validate_with_certificate(
        &self,
        token: &str,
        certificate: Option<&[u8]>,
    ) -> Result<Claims, AuthError> {
        let token = token.trim();
        let header = jsonwebtoken::decode_header(token).map_err(|_| AuthError::Malformed)?;

        if let Some(expected) = &self.token_type {
            let found = header.typ.as_deref().unwrap_or("");
            // RFC 9068 §4: `typ` is compared case-insensitively, and the
            // `application/` prefix a JOSE header may carry is dropped first.
            let normalised = found
                .strip_prefix("application/")
                .unwrap_or(found)
                .to_ascii_lowercase();
            if normalised != expected.to_ascii_lowercase() {
                return Err(AuthError::WrongType {
                    expected: expected.clone(),
                    found: found.to_string(),
                });
            }
        }
        if !self.algorithms.contains(&header.alg) {
            return Err(AuthError::UnacceptableAlgorithm(format!(
                "{:?}",
                header.alg
            )));
        }

        let kid = header.kid.ok_or(AuthError::NoKeyId)?;
        let key = self.jwks.key(&kid).await?;
        // A key published as ES256 must not verify an RS256 token: the header
        // does not get to choose the algorithm the issuer meant.
        if let Some(alg) = key.alg
            && alg != header.alg
        {
            return Err(AuthError::UnacceptableAlgorithm(format!(
                "{:?}, but key `{kid}` is published for {alg:?}",
                header.alg
            )));
        }

        let mut validation = Validation::new(header.alg);
        validation.leeway = self.leeway.as_secs();
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&self.audiences);
        validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);

        let data = jsonwebtoken::decode::<serde_json::Value>(token, &key.decoding, &validation)
            .map_err(|e| self.refusal(e))?;
        let claims: Claims = serde_json::from_value(data.claims).map_err(|e| {
            tracing::debug!(error = %e, "a verified token carried claims of the wrong shape");
            AuthError::BadClaim("sub")
        })?;

        if let Some(cnf) = &claims.cnf {
            let other = cnf.jkt.is_some() || !cnf.extra.is_empty();
            match (cnf.x5t_s256.as_deref(), certificate) {
                (Some(expected), Some(der)) => {
                    if certificate_thumbprint(der) != expected {
                        return Err(AuthError::CertificateMismatch);
                    }
                    if other && !self.allow_sender_constrained {
                        return Err(AuthError::SenderConstrained);
                    }
                }
                _ if !self.allow_sender_constrained => {
                    return Err(AuthError::SenderConstrained);
                }
                _ => {}
            }
        }
        self.required.check(&claims)?;
        Ok(claims)
    }

    /// Verify the token in an `Authorization` header value.
    ///
    /// Only the `Bearer` scheme is accepted: a `DPoP` token presented here
    /// would lose its binding, and rIDM issues those only to clients that
    /// asked for them.
    pub async fn validate_authorization(&self, header: Option<&str>) -> Result<Claims, AuthError> {
        let token = bearer(header.ok_or(AuthError::Missing)?).ok_or(AuthError::Missing)?;
        self.validate(token).await
    }

    /// Turn a jsonwebtoken failure into the specific reason it was.
    fn refusal(&self, e: jsonwebtoken::errors::Error) -> AuthError {
        use jsonwebtoken::errors::ErrorKind;
        match e.kind() {
            ErrorKind::ExpiredSignature => AuthError::Expired,
            ErrorKind::ImmatureSignature => AuthError::NotYetValid,
            ErrorKind::InvalidSignature => AuthError::BadSignature,
            ErrorKind::InvalidAudience => AuthError::WrongAudience(quoted_list(&self.audiences)),
            ErrorKind::InvalidIssuer => AuthError::WrongIssuer {
                expected: self.issuer.clone(),
                found: "another issuer".into(),
            },
            ErrorKind::InvalidAlgorithm | ErrorKind::MissingAlgorithm => {
                AuthError::UnacceptableAlgorithm("the token's".into())
            }
            ErrorKind::MissingRequiredClaim(claim) => {
                // `&'static str` is what the error carries; the claim name is
                // one of the four asked for above.
                AuthError::BadClaim(match claim.as_str() {
                    "iss" => "iss",
                    "aud" => "aud",
                    "exp" => "exp",
                    _ => "sub",
                })
            }
            other => {
                tracing::debug!(error = ?other, "token refused");
                AuthError::BadSignature
            }
        }
    }
}

/// `Bearer <token>`, case-insensitive on the scheme, or nothing.
pub fn bearer(header: &str) -> Option<&str> {
    let (scheme, rest) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
    (!token.is_empty()).then_some(token)
}

fn quoted_list(items: &[String]) -> String {
    items
        .iter()
        .map(|a| format!("`{a}`"))
        .collect::<Vec<_>>()
        .join(" or ")
}

/// Configures a [`Validator`]. See [`Validator::builder`].
#[derive(Debug, Clone)]
pub struct ValidatorBuilder {
    issuer: String,
    audiences: Vec<String>,
    jwks_uri: Option<String>,
    http: Option<reqwest::Client>,
    leeway: Duration,
    token_type: Option<String>,
    algorithms: Vec<Algorithm>,
    allow_sender_constrained: bool,
    allow_http: bool,
    min_refresh_interval: Duration,
    max_age: Duration,
    required: Requirements,
}

impl ValidatorBuilder {
    fn new(issuer: impl Into<String>) -> Self {
        let issuer = issuer.into().trim_end_matches('/').to_string();
        Self {
            issuer,
            audiences: Vec::new(),
            jwks_uri: None,
            http: None,
            leeway: DEFAULT_LEEWAY,
            token_type: Some(ACCESS_TOKEN_TYPE.to_string()),
            algorithms: DEFAULT_ALGORITHMS.to_vec(),
            allow_sender_constrained: false,
            allow_http: false,
            min_refresh_interval: DEFAULT_MIN_REFRESH_INTERVAL,
            max_age: DEFAULT_MAX_AGE,
            required: Requirements::default(),
        }
    }

    /// An audience this API answers to — the resource server identifier the
    /// client asked for. At least one is required, and a token must name one
    /// of them; without it, any token from the tenant would open this API.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audiences.push(audience.into());
        self
    }

    /// Several audiences at once. See [`audience`](Self::audience).
    pub fn audiences<I: IntoIterator<Item = S>, S: Into<String>>(mut self, audiences: I) -> Self {
        self.audiences.extend(audiences.into_iter().map(Into::into));
        self
    }

    /// Where the issuer publishes its keys. Defaults to
    /// `{issuer}/.well-known/jwks.json`, which is where rIDM publishes them;
    /// [`discover`](Self::discover) reads it from the discovery document
    /// instead, which is the safer choice.
    pub fn jwks_uri(mut self, uri: impl Into<String>) -> Self {
        self.jwks_uri = Some(uri.into());
        self
    }

    /// The HTTP client used for discovery and for the key set. Supply your own
    /// to share a connection pool, set timeouts, or route through a proxy.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http = Some(client);
        self
    }

    /// How much clock skew to forgive on `exp` and `nbf`. Default: 60 seconds.
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// The JOSE `typ` a token must carry. Default: `at+jwt`, which is what
    /// stops an ID token being presented to this API as an access token. Pass
    /// `None` to accept any type.
    pub fn token_type(mut self, typ: Option<impl Into<String>>) -> Self {
        self.token_type = typ.map(Into::into);
        self
    }

    /// The signature algorithms to accept. Defaults to
    /// [`DEFAULT_ALGORITHMS`]. Narrow it if the tenant signs with one.
    pub fn algorithms<I: IntoIterator<Item = Algorithm>>(mut self, algorithms: I) -> Self {
        self.algorithms = algorithms.into_iter().collect();
        self
    }

    /// Accept a token that carries a `cnf` confirmation (RFC 9449).
    ///
    /// Refused by default. This crate verifies no DPoP proof, so accepting a
    /// bound token would turn a sender-constrained credential into a bearer
    /// one — anyone who captured it could spend it here. Turn this on only if
    /// something ahead of this API verifies the proof.
    pub fn allow_sender_constrained(mut self, allow: bool) -> Self {
        self.allow_sender_constrained = allow;
        self
    }

    /// Permit an `http://` issuer. Refused by default; useful against a local
    /// rIDM in development.
    pub fn allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// The floor between key-set fetches, so tokens naming keys that do not
    /// exist cannot drive traffic at the issuer. Default: 30 seconds.
    pub fn min_refresh_interval(mut self, interval: Duration) -> Self {
        self.min_refresh_interval = interval;
        self
    }

    /// How long a cached key set answers before it is fetched again — the
    /// window in which a revoked key still verifies tokens. Default: 10
    /// minutes.
    pub fn jwks_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }

    /// Require this scope of every token this validator accepts.
    pub fn require_scope(mut self, scope: impl Into<String>) -> Self {
        self.required.scopes.push(scope.into());
        self
    }

    /// Require this permission of every token this validator accepts.
    pub fn require_permission(mut self, permission: impl Into<String>) -> Self {
        self.required.permissions.push(permission.into());
        self
    }

    /// Require this role of every token this validator accepts.
    pub fn require_role(mut self, role: impl Into<String>) -> Self {
        self.required.roles.push(role.into());
        self
    }

    /// Read `jwks_uri` from the issuer's discovery document, checking that the
    /// document claims the issuer it was fetched from (OIDC Discovery §4.3).
    pub async fn discover(self) -> Result<Validator, AuthError> {
        let http = self.client()?;
        let url = format!("{}/.well-known/openid-configuration", self.issuer);
        let fail = |message: String| AuthError::Discovery {
            url: url.clone(),
            message,
        };

        let response = http
            .get(&url)
            .send()
            .await
            .map_err(|e| fail(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(fail(format!("HTTP {}", status.as_u16())));
        }
        let document: DiscoveryDocument = response.json().await.map_err(|e| fail(e.to_string()))?;

        if document.issuer.trim_end_matches('/') != self.issuer {
            return Err(fail(format!(
                "the document names issuer `{}`, not `{}`",
                document.issuer, self.issuer
            )));
        }
        self.jwks_uri(document.jwks_uri).http_client(http).build()
    }

    /// Build the validator without contacting the issuer.
    pub fn build(self) -> Result<Validator, AuthError> {
        if self.audiences.is_empty() {
            return Err(AuthError::Config(
                "a validator needs at least one audience: without it any token from the tenant \
                 would be accepted here"
                    .into(),
            ));
        }
        let http = self.client()?;
        let jwks_uri = match self.jwks_uri {
            Some(uri) => uri,
            None => format!("{}/.well-known/jwks.json", self.issuer),
        };
        if !self.allow_http && !jwks_uri.starts_with("https://") {
            return Err(AuthError::Config(format!(
                "the key set at `{jwks_uri}` is not served over https; pass \
                 `.allow_http(true)` if that is deliberate"
            )));
        }
        Ok(Validator {
            jwks: JwksCache::new(jwks_uri, http, self.min_refresh_interval, self.max_age),
            issuer: self.issuer,
            audiences: self.audiences,
            leeway: self.leeway,
            token_type: self.token_type,
            algorithms: self.algorithms,
            allow_sender_constrained: self.allow_sender_constrained,
            required: self.required,
        })
    }

    fn client(&self) -> Result<reqwest::Client, AuthError> {
        if self.issuer.is_empty() {
            return Err(AuthError::Config("the issuer is empty".into()));
        }
        if !self.allow_http && !self.issuer.starts_with("https://") {
            return Err(AuthError::Config(format!(
                "issuer `{}` is not an https URL; pass `.allow_http(true)` if that is deliberate",
                self.issuer
            )));
        }
        match &self.http {
            Some(client) => Ok(client.clone()),
            None => reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|e| AuthError::Config(format!("could not build an HTTP client: {e}"))),
        }
    }
}

/// The two fields of the discovery document this crate needs.
#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

/// Convenience: `Arc<Validator>` is what an axum state holds.
impl Validator {
    /// Wrap this validator in an [`Arc`], ready for a router state.
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

/// The RFC 8705 §3.1 thumbprint of a DER certificate: base64url(SHA-256).
pub fn certificate_thumbprint(der: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_validator_without_an_audience_is_refused() {
        let e = Validator::builder("https://idp.example/t/acme")
            .build()
            .unwrap_err();
        assert_eq!(e.status(), 500);
        assert!(e.to_string().contains("audience"), "{e}");
    }

    #[test]
    fn the_key_set_defaults_to_the_well_known_path_beside_the_issuer() {
        let v = Validator::builder("https://idp.example/t/acme/")
            .audience("urn:orders")
            .build()
            .unwrap();
        assert_eq!(v.issuer(), "https://idp.example/t/acme");
        assert_eq!(
            v.jwks_uri(),
            "https://idp.example/t/acme/.well-known/jwks.json"
        );
    }

    #[test]
    fn plain_http_needs_saying_so_on_both_the_issuer_and_the_key_set() {
        let e = Validator::builder("http://localhost:8090/t/acme")
            .audience("urn:orders")
            .build()
            .unwrap_err();
        assert!(e.to_string().contains("allow_http"), "{e}");

        Validator::builder("http://localhost:8090/t/acme")
            .audience("urn:orders")
            .allow_http(true)
            .build()
            .unwrap();

        let e = Validator::builder("https://idp.example/t/acme")
            .audience("urn:orders")
            .jwks_uri("http://idp.example/keys")
            .build()
            .unwrap_err();
        assert!(e.to_string().contains("https"), "{e}");
    }

    #[test]
    fn bearer_is_read_case_insensitively_and_nothing_else_is() {
        assert_eq!(bearer("Bearer abc"), Some("abc"));
        assert_eq!(bearer("bearer  abc "), Some("abc"));
        assert_eq!(bearer("DPoP abc"), None);
        assert_eq!(bearer("Bearer "), None);
        assert_eq!(bearer("abc"), None);
    }

    #[test]
    fn requirements_are_checked_in_the_order_they_were_asked_for() {
        let claims: Claims = serde_json::from_value(serde_json::json!({
            "iss": "https://idp.example/t/acme",
            "sub": "a1b2",
            "aud": "urn:orders",
            "exp": 4102444800i64,
            "scope": "orders:read",
            "roles": ["staff"],
        }))
        .unwrap();

        let required = Requirements {
            scopes: vec!["orders:read".into()],
            permissions: vec![],
            roles: vec!["staff".into()],
        };
        required.check(&claims).unwrap();
        Requirements::default().check(&claims).unwrap();

        let too_much = Requirements {
            roles: vec!["staff".into(), "admin".into()],
            ..Requirements::default()
        };
        let e = too_much.check(&claims).unwrap_err();
        assert!(e.to_string().contains("admin"), "{e}");
    }
}
