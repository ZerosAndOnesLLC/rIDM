//! Admin authentication: `AdminCtx` is an axum extractor for `/admin/...`
//! routes.
//!
//! It accepts a bearer access token (`Authorization` header only; never a
//! query or form parameter) issued by any tenant, verified with that tenant's
//! keys, whose audience includes the built-in admin resource server. The
//! subject must be a live user (or service account) of the issuing tenant, and
//! their admin permissions are resolved from their effective roles on every
//! request (cached), so revoking a role takes effect immediately.
//!
//! Tokens issued by `master` carry global scope; tokens from any other tenant
//! may only act on that tenant. Handlers call [`AdminCtx::require`] with the
//! target tenant and the permission they need.

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ridm_core::events::Actor;
use serde::Serialize;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{MASTER_TENANT_ID, Tenant, UserStatus};
use crate::services::admin_access::{self, ADMIN_AUDIENCE, PermissionSet};
use crate::services::tokens::{self, VerifyOptions};
use crate::services::{roles, tenants, users};
use crate::state::AppState;

const REALM: &str = "ridm-admin";

/// How far an administrator's permissions reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdminScope {
    /// Token issued by `master`: every tenant.
    Global,
    /// Token issued by a regular tenant: that tenant only.
    Tenant,
}

/// An authenticated administrator.
#[derive(Debug, Clone)]
pub struct AdminCtx {
    pub user_id: Uuid,
    pub username: String,
    /// The tenant that issued the token and holds the user.
    pub tenant: Arc<Tenant>,
    pub scope: AdminScope,
    pub roles: Vec<String>,
    pub permissions: Arc<PermissionSet>,
    pub client_id: String,
    pub session_id: Option<Uuid>,
    pub jti: Option<String>,
}

impl AdminCtx {
    pub fn actor(&self) -> Actor {
        Actor::Admin { id: self.user_id }
    }

    pub fn is_global(&self) -> bool {
        self.scope == AdminScope::Global
    }

    /// May this administrator act on `tenant_id` at all?
    pub fn reaches(&self, tenant_id: Uuid) -> bool {
        self.is_global() || self.tenant.id == tenant_id
    }

    /// Does this administrator hold `permission` for `tenant_id`?
    pub fn has(&self, tenant_id: Uuid, permission: &str) -> bool {
        self.reaches(tenant_id) && self.permissions.allows(permission)
    }

    /// Fail with 403 unless the administrator holds `permission` for `tenant_id`.
    pub fn require(&self, tenant_id: Uuid, permission: &str) -> AppResult<()> {
        if !self.reaches(tenant_id) {
            return Err(AppError::Forbidden(
                "this token is scoped to another tenant".into(),
            ));
        }
        self.require_permission(permission)
    }

    /// Fail with 403 unless the administrator is global and holds `permission`
    /// (tenant lifecycle operations such as creating tenants).
    pub fn require_global(&self, permission: &str) -> AppResult<()> {
        if !self.is_global() {
            return Err(AppError::Forbidden(
                "this operation requires a global administrator".into(),
            ));
        }
        self.require_permission(permission)
    }

    fn require_permission(&self, permission: &str) -> AppResult<()> {
        debug_assert!(
            admin_access::is_known(permission),
            "unknown admin permission `{permission}`"
        );
        if self.permissions.allows(permission) {
            Ok(())
        } else {
            Err(AppError::Forbidden(format!(
                "missing permission `{permission}`"
            )))
        }
    }

    /// Fail with 403 if granting `permissions` would exceed what the
    /// administrator holds (no privilege escalation through role management).
    pub fn require_can_grant<'a>(
        &self,
        permissions: impl IntoIterator<Item = &'a str>,
    ) -> AppResult<()> {
        let missing: Vec<&str> = permissions
            .into_iter()
            .filter(|p| !self.permissions.allows(p))
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(AppError::Forbidden(format!(
                "cannot grant permissions you do not hold: {}",
                missing.join(", ")
            )))
        }
    }
}

/// Rejection that adds `WWW-Authenticate` to 401 responses (RFC 6750 §3).
#[derive(Debug)]
pub struct AdminRejection {
    error: AppError,
    /// A token was presented but is not acceptable.
    invalid_token: bool,
}

impl AdminRejection {
    pub(crate) fn missing() -> Self {
        Self {
            error: AppError::Unauthorized,
            invalid_token: false,
        }
    }

    pub(crate) fn invalid() -> Self {
        Self {
            error: AppError::Unauthorized,
            invalid_token: true,
        }
    }
}

impl From<AppError> for AdminRejection {
    fn from(error: AppError) -> Self {
        Self {
            invalid_token: matches!(error, AppError::Unauthorized),
            error,
        }
    }
}

impl IntoResponse for AdminRejection {
    fn into_response(self) -> Response {
        let status = self.error.status();
        let mut res = self.error.into_response();
        if status == StatusCode::UNAUTHORIZED {
            let value = if self.invalid_token {
                format!("Bearer realm=\"{REALM}\", error=\"invalid_token\"")
            } else {
                format!("Bearer realm=\"{REALM}\"")
            };
            if let Ok(v) = HeaderValue::from_str(&value) {
                res.headers_mut().insert(header::WWW_AUTHENTICATE, v);
            }
        }
        res.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        res
    }
}

pub(crate) fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// The `tid` claim read without verification, only to pick the key set to
/// verify with. [`tokens::verify`] then binds the token to that tenant's
/// issuer and keys, so a forged `tid` cannot pass.
pub(crate) fn unverified_tenant_id(token: &str) -> Option<Uuid> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("tid")?.as_str()?.parse().ok()
}

impl FromRequestParts<AppState> for AdminCtx {
    type Rejection = AdminRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, AdminRejection> {
        let token = bearer(&parts.headers).ok_or_else(AdminRejection::missing)?;
        let tenant_id = unverified_tenant_id(&token).ok_or_else(AdminRejection::invalid)?;
        let tenant = tenants::get_cached(state, tenant_id)
            .await?
            .ok_or_else(AdminRejection::invalid)?;
        if !tenant.is_active() {
            return Err(AppError::Forbidden("tenant is disabled".into()).into());
        }
        let claims = tokens::verify(
            state,
            &tenant,
            &token,
            &VerifyOptions {
                typ: Some("at+jwt".into()),
                audience: Some(ADMIN_AUDIENCE.into()),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| match e {
            AppError::Unauthorized => AdminRejection::invalid(),
            other => other.into(),
        })?;

        // The session the token was issued in must still be alive, so signing
        // out ends admin access before the token expires.
        let session_id = claims
            .get("sid")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok());
        if let Some(sid) = session_id
            && crate::services::sessions::get(state, tenant.id, sid, &tenant.settings.session)
                .await?
                .is_none()
        {
            return Err(AdminRejection::invalid());
        }

        let user_id = tokens::subject_user_id(state, &tenant, &claims)
            .await?
            .ok_or_else(|| {
                AppError::Forbidden(
                    "admin access requires a user or service-account subject".into(),
                )
            })?;
        let user = match users::get(state, tenant.id, user_id).await {
            Ok(u) => u,
            Err(AppError::NotFound(_)) => return Err(AdminRejection::invalid()),
            Err(e) => return Err(e.into()),
        };
        if user.status != UserStatus::Active || user.is_locked_now() {
            return Err(AppError::Forbidden("user account is not active".into()).into());
        }

        let permissions = admin_access::permissions_of_user(state, tenant.id, user.id).await?;
        if permissions.is_empty() {
            return Err(AppError::Forbidden("no admin permissions".into()).into());
        }
        let roles = roles::effective_role_names(state, tenant.id, user.id).await?;
        let scope = if tenant.id == MASTER_TENANT_ID {
            AdminScope::Global
        } else {
            AdminScope::Tenant
        };
        Ok(Self {
            user_id: user.id,
            username: user.username,
            tenant,
            scope,
            roles,
            permissions,
            client_id: claims
                .get("client_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            session_id,
            jti: claims
                .get("jti")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        })
    }
}

/// The tenant named by the `{slug}` path segment of an admin route.
///
/// Unlike [`crate::middleware::TenantCtx`] this admits disabled tenants:
/// administrators must be able to inspect and re-enable them. Authorization
/// against the caller is the handler's job (`admin.require(tenant.id, ..)`).
#[derive(Debug, Clone)]
pub struct AdminTenantPath(pub Arc<Tenant>);

#[derive(serde::Deserialize)]
struct SlugPath {
    slug: String,
}

impl FromRequestParts<AppState> for AdminTenantPath {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let axum::extract::Path(SlugPath { slug }) =
            axum::extract::Path::<SlugPath>::from_request_parts(parts, state)
                .await
                .map_err(|_| AppError::NotFound("tenant"))?;
        let tenant = crate::middleware::resolve_tenant(state, &slug)
            .await?
            .ok_or(AppError::NotFound("tenant"))?;
        Ok(Self(tenant))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_header_parsing() {
        let mut h = HeaderMap::new();
        assert!(bearer(&h).is_none());
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert!(bearer(&h).is_none());
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert!(bearer(&h).is_none());
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer  tok "),
        );
        assert_eq!(bearer(&h).as_deref(), Some("tok"));
    }

    #[test]
    fn tenant_id_is_read_from_the_payload() {
        let payload =
            URL_SAFE_NO_PAD.encode(br#"{"tid":"00000000-0000-7000-8000-000000000001","sub":"x"}"#);
        let token = format!("eyJhbGciOiJSUzI1NiJ9.{payload}.sig");
        assert_eq!(unverified_tenant_id(&token), Some(MASTER_TENANT_ID));
        assert_eq!(unverified_tenant_id("not.a"), None);
        assert_eq!(unverified_tenant_id("a.!!!.c"), None);
    }
}
