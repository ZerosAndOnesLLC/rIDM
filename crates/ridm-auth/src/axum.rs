//! axum integration: an extractor, a middleware, and RFC 6750 responses.
//!
//! Two ways to use it, and they compose:
//!
//! * [`RidmClaims`] as a handler argument validates the token and hands the
//!   handler its claims. The handler decides what the claims must carry.
//! * [`Guard`] as a route layer validates once for a whole subtree and refuses
//!   anything short of what the guard asks for, before a handler runs.
//!
//! Both need the [`Validator`] in the router state:
//!
//! ```no_run
//! use std::sync::Arc;
//! use axum::{Router, routing::get, middleware::from_fn_with_state};
//! use ridm_auth::{Validator, axum::{Guard, RidmClaims, guard}};
//!
//! # async fn f() -> Result<(), ridm_auth::AuthError> {
//! let validator = Validator::builder("https://idp.example/t/acme")
//!     .audience("urn:orders")
//!     .discover()
//!     .await?
//!     .shared();
//!
//! let app: Router = Router::new()
//!     .route("/orders", get(list))
//!     .route_layer(from_fn_with_state(
//!         Guard::new(validator.clone()).permission("orders:read"),
//!         guard,
//!     ))
//!     .with_state(validator);
//!
//! async fn list(RidmClaims(claims): RidmClaims) -> String {
//!     format!("hello {}", claims.sub)
//! }
//! # Ok(()) }
//! ```

use std::sync::Arc;

use ::axum::extract::{FromRef, FromRequestParts, Request, State};
use ::axum::middleware::Next;
use ::axum::response::{IntoResponse, Response};
use http::request::Parts;
use http::{HeaderValue, StatusCode, header};

use crate::claims::Claims;
use crate::error::{AuthError, Body};
use crate::validator::{Requirements, Validator};

/// The realm named in a `WWW-Authenticate` challenge when nothing else is set.
pub const DEFAULT_REALM: &str = "api";

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        self.response(DEFAULT_REALM)
    }
}

impl AuthError {
    /// The RFC 6750 response for this failure, naming `realm` in the challenge.
    pub fn response(&self, realm: &str) -> Response {
        let status = StatusCode::from_u16(self.status()).unwrap_or(StatusCode::UNAUTHORIZED);
        let mut response = (status, Body(self).to_string()).into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
            && let Ok(challenge) = HeaderValue::from_str(&self.www_authenticate(realm))
        {
            headers.insert(header::WWW_AUTHENTICATE, challenge);
        }
        if self.is_transient() {
            headers.insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        }
        response
    }
}

/// The claims of the validated access token on this request.
///
/// If a [`guard`] ran earlier it reuses what the guard validated; otherwise it
/// validates the `Authorization` header itself. Either way the handler sees a
/// token that was verified exactly once.
#[derive(Debug, Clone)]
pub struct RidmClaims(pub Claims);

impl std::ops::Deref for RidmClaims {
    type Target = Claims;

    fn deref(&self) -> &Claims {
        &self.0
    }
}

impl<S> FromRequestParts<S> for RidmClaims
where
    Arc<Validator>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, AuthError> {
        if let Some(claims) = parts.extensions.get::<Claims>() {
            return Ok(Self(claims.clone()));
        }
        let validator = Arc::<Validator>::from_ref(state);
        let claims = validate(&validator, parts).await?;
        parts.extensions.insert(claims.clone());
        Ok(Self(claims))
    }
}

/// The claims, or `None` when no token was presented — for a route that serves
/// anonymous callers too. A token that *is* presented must still be valid.
#[derive(Debug, Clone)]
pub struct OptionalRidmClaims(pub Option<Claims>);

impl<S> FromRequestParts<S> for OptionalRidmClaims
where
    Arc<Validator>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, AuthError> {
        match RidmClaims::from_request_parts(parts, state).await {
            Ok(RidmClaims(claims)) => Ok(Self(Some(claims))),
            Err(AuthError::Missing) => Ok(Self(None)),
            Err(e) => Err(e),
        }
    }
}

/// What a route subtree demands of every request that reaches it.
///
/// Build one per subtree and pass it to [`guard`] through
/// [`axum::middleware::from_fn_with_state`](::axum::middleware::from_fn_with_state).
#[derive(Debug, Clone)]
pub struct Guard {
    validator: Arc<Validator>,
    required: Requirements,
    realm: String,
}

impl Guard {
    /// Authentication only: a valid token for this API, nothing more.
    pub fn new(validator: Arc<Validator>) -> Self {
        Self {
            validator,
            required: Requirements::default(),
            realm: DEFAULT_REALM.to_string(),
        }
    }

    /// Also require this scope. Repeat for several; all must be present.
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.required.scopes.push(scope.into());
        self
    }

    /// Also require this permission. Repeat for several; all must be present.
    pub fn permission(mut self, permission: impl Into<String>) -> Self {
        self.required.permissions.push(permission.into());
        self
    }

    /// Also require this role. Repeat for several; all must be present.
    pub fn role(mut self, role: impl Into<String>) -> Self {
        self.required.roles.push(role.into());
        self
    }

    /// The realm named in the `WWW-Authenticate` challenge. Default: `api`.
    pub fn realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = realm.into();
        self
    }
}

/// Validate the request's token against a [`Guard`], then run the route.
///
/// The claims go into the request extensions, so a [`RidmClaims`] argument in
/// the handler costs nothing more.
pub async fn guard(State(guard): State<Guard>, request: Request, next: Next) -> Response {
    let (mut parts, body) = request.into_parts();
    let claims = match validate(&guard.validator, &parts).await {
        Ok(claims) => claims,
        Err(e) => return e.response(&guard.realm),
    };
    if let Err(e) = guard.required.check(&claims) {
        return e.response(&guard.realm);
    }
    parts.extensions.insert(claims);
    next.run(Request::from_parts(parts, body)).await
}

async fn validate(validator: &Validator, parts: &Parts) -> Result<Claims, AuthError> {
    let header = parts
        .headers
        .get(header::AUTHORIZATION)
        .map(|v| v.to_str().map_err(|_| AuthError::Malformed))
        .transpose()?;
    validator.validate_authorization(header).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_carries_the_challenge_and_is_never_cached() {
        let response = AuthError::Expired.response("orders");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let challenge = response.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap();
        assert!(
            challenge.starts_with("Bearer realm=\"orders\""),
            "{challenge}"
        );
        assert!(challenge.contains("error=\"invalid_token\""), "{challenge}");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[test]
    fn a_missing_token_is_challenged_without_naming_an_error() {
        let response = AuthError::Missing.response("orders");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Bearer realm=\"orders\""
        );
    }

    #[test]
    fn a_token_short_of_a_permission_is_forbidden_not_unauthorized() {
        let response = AuthError::MissingPermission("orders:write".into()).response("orders");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let challenge = response.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap();
        assert!(challenge.contains("insufficient_scope"), "{challenge}");
    }

    #[test]
    fn an_unreachable_issuer_asks_the_caller_to_come_back() {
        let response = AuthError::Jwks {
            url: "https://idp.example/jwks".into(),
            message: "connect timed out".into(),
        }
        .response("orders");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "5");
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
    }
}
