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
//!
//! A token may also name the organization its sign-in acts in (`org_id`). Role
//! grants scoped to that organization are resolved into a second permission
//! set, which only [`AdminCtx::require_org`] consults — so an organization's
//! administrator reaches the routes of that one organization and nothing
//! else. Personal access tokens belong to a user rather than to a sign-in, so
//! they never carry an organization.

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ridm_core::events::Actor;
use serde::Serialize;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{MASTER_TENANT_ID, Tenant, UserStatus};
use crate::oidc::bearer::Scheme;
use crate::oidc::dpop;
use crate::services::admin_access::{self, ADMIN_AUDIENCE, OrgScope, PermissionSet};
use crate::services::personal_access_tokens as pats;
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
    /// Permissions from unscoped grants: what [`AdminCtx::require`] checks.
    pub permissions: Arc<PermissionSet>,
    /// The organization this sign-in acts in, if any.
    pub org_id: Option<Uuid>,
    /// Permissions inside [`AdminCtx::org_id`]: the unscoped ones plus those
    /// granted within that organization. Empty without an organization.
    pub org_permissions: Arc<PermissionSet>,
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

    /// Does this administrator hold `permission` inside `org_id`, whether
    /// tenant-wide or through a grant scoped to that organization?
    pub fn has_in_org(&self, tenant_id: Uuid, org_id: Uuid, permission: &str) -> bool {
        self.reaches(tenant_id)
            && (self.permissions.allows(permission)
                || (self.org_id == Some(org_id) && self.org_permissions.allows(permission)))
    }

    /// Fail with 403 unless the administrator holds `permission` for the
    /// organization `org_id` of `tenant_id` — tenant-wide, or through a role
    /// granted within that organization to the session this token came from.
    ///
    /// Only routes under `/organizations/{org}` call this; everything else
    /// uses [`AdminCtx::require`], which org-scoped grants never satisfy.
    pub fn require_org(&self, tenant_id: Uuid, org_id: Uuid, permission: &str) -> AppResult<()> {
        if !self.reaches(tenant_id) {
            return Err(AppError::Forbidden(
                "this token is scoped to another tenant".into(),
            ));
        }
        debug_assert!(
            admin_access::is_known(permission),
            "unknown admin permission `{permission}`"
        );
        if self.has_in_org(tenant_id, org_id, permission) {
            Ok(())
        } else {
            Err(AppError::Forbidden(format!(
                "missing permission `{permission}`"
            )))
        }
    }

    /// `Some(org)` when the administrator holds `permission` only through a
    /// grant scoped to `org`, so their reach ends at that organization.
    /// `None` when they hold it tenant-wide (or not at all).
    ///
    /// Handlers use it for the few operations an organization's own
    /// administrator must not perform on it: renaming its slug, enabling or
    /// disabling it, pulling an existing user into it.
    pub fn confined_to_org(&self, permission: &str) -> Option<Uuid> {
        if self.permissions.allows(permission) {
            return None;
        }
        self.org_id
            .filter(|_| self.org_permissions.allows(permission))
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
        self.can_grant(None, permissions)
    }

    /// As [`AdminCtx::require_can_grant`], for a grant that will itself be
    /// scoped to `org_id`: what the administrator holds inside that
    /// organization counts, since the grant reaches no further than they do.
    pub fn require_can_grant_in_org<'a>(
        &self,
        org_id: Uuid,
        permissions: impl IntoIterator<Item = &'a str>,
    ) -> AppResult<()> {
        self.can_grant(Some(org_id), permissions)
    }

    fn can_grant<'a>(
        &self,
        org_id: Option<Uuid>,
        permissions: impl IntoIterator<Item = &'a str>,
    ) -> AppResult<()> {
        let in_org = org_id.is_some() && org_id == self.org_id;
        let missing: Vec<&str> = permissions
            .into_iter()
            .filter(|p| !self.permissions.allows(p) && !(in_org && self.org_permissions.allows(p)))
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

/// The access token from `Authorization: Bearer|DPoP <token>` (header only,
/// never a query parameter) with the scheme it came under.
pub(crate) fn bearer_with_scheme(headers: &HeaderMap) -> Option<(Scheme, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    let scheme = if scheme.eq_ignore_ascii_case("bearer") {
        Scheme::Bearer
    } else if scheme.eq_ignore_ascii_case("dpop") {
        Scheme::Dpop
    } else {
        return None;
    };
    let token = rest.trim();
    (!token.is_empty()).then(|| (scheme, token.to_string()))
}

/// Refuse a DPoP-bound token that is not presented with a valid proof.
pub(crate) async fn require_binding(
    state: &AppState,
    tenant: &Tenant,
    scheme: Scheme,
    token: &str,
    claims: &serde_json::Map<String, serde_json::Value>,
    parts: &Parts,
) -> Result<(), AdminRejection> {
    let htu = dpop::htu_for_path(state, tenant, parts.uri.path());
    let presented = dpop::Presented {
        scheme,
        token,
        claims,
    };
    dpop::enforce_binding(
        state,
        tenant,
        presented,
        &parts.headers,
        &parts.method,
        &htu,
    )
    .await
    .map_err(|d| {
        tracing::debug!(reason = %d, "dpop binding refused");
        AdminRejection::invalid()
    })
}

impl FromRequestParts<AppState> for AdminCtx {
    type Rejection = AdminRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, AdminRejection> {
        let (scheme, token) =
            bearer_with_scheme(&parts.headers).ok_or_else(AdminRejection::missing)?;
        if pats::looks_like_pat(&token) {
            return Self::from_personal_token(state, &token).await;
        }
        // A JWT names its tenant in `tid`; an opaque token's entry knows it.
        let tenant_id = tokens::access_token_tenant_hint(state, &token)
            .await?
            .ok_or_else(AdminRejection::invalid)?;
        let tenant = tenants::get_cached(state, tenant_id)
            .await?
            .ok_or_else(AdminRejection::invalid)?;
        if !tenant.is_active() {
            return Err(AppError::Forbidden("tenant is disabled".into()).into());
        }
        let claims = tokens::verify_access(
            state,
            &tenant,
            &token,
            &VerifyOptions {
                audience: Some(ADMIN_AUDIENCE.into()),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| match e {
            AppError::Unauthorized => AdminRejection::invalid(),
            other => other.into(),
        })?;
        require_binding(state, &tenant, scheme, &token, &claims, parts).await?;
        // Administration is done as oneself. A token that acts for someone
        // else (an impersonated session, a token exchange) never reaches it,
        // even should its subject be granted an admin role meanwhile.
        if claims.get("act").is_some() {
            return Err(AppError::Forbidden(
                "a delegated or impersonated token cannot use the admin API".into(),
            )
            .into());
        }

        // The session the token was issued in must still be alive, so signing
        // out ends admin access before the token expires.
        let session_id = claims
            .get("sid")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok());
        if let Some(sid) = session_id {
            let session =
                crate::services::sessions::get(state, tenant.id, sid, &tenant.settings.session)
                    .await?
                    .ok_or_else(AdminRejection::invalid)?;
            if session.impersonator.is_some() {
                return Err(AppError::Forbidden(
                    "a delegated or impersonated token cannot use the admin API".into(),
                )
                .into());
            }
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

        let permissions =
            admin_access::permissions_of_user(state, tenant.id, user.id, OrgScope::TenantWide)
                .await?;
        // The organization the sign-in acts in (Phase 12.1). Its grants are
        // kept apart from the tenant-wide ones and only `require_org` sees
        // them.
        let org_id = claims
            .get("org_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok());
        let org_permissions = match org_id {
            Some(org) => {
                admin_access::permissions_of_user(state, tenant.id, user.id, OrgScope::In(org))
                    .await?
            }
            None => Arc::new(PermissionSet::default()),
        };
        if permissions.is_empty() && org_permissions.is_empty() {
            return Err(AppError::Forbidden("no admin permissions".into()).into());
        }
        let roles = roles::effective_role_names(state, tenant.id, user.id, org_id).await?;
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
            org_id,
            org_permissions,
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

impl AdminCtx {
    /// A personal access token: the user's admin permissions narrowed to the
    /// token's scopes (and to what the user still holds).
    async fn from_personal_token(state: &AppState, token: &str) -> Result<Self, AdminRejection> {
        let auth = pats::authenticate(state, token)
            .await?
            .ok_or_else(AdminRejection::invalid)?;
        if auth.permissions.is_empty() {
            return Err(
                AppError::Forbidden("the token carries no admin permissions".into()).into(),
            );
        }
        let roles = roles::effective_role_names(state, auth.tenant.id, auth.user.id, None).await?;
        let scope = if auth.tenant.id == MASTER_TENANT_ID {
            AdminScope::Global
        } else {
            AdminScope::Tenant
        };
        Ok(Self {
            user_id: auth.user.id,
            username: auth.user.username,
            tenant: auth.tenant,
            scope,
            roles,
            permissions: Arc::new(auth.permissions),
            // A personal token belongs to the user, not to a sign-in, so it
            // acts in no organization and carries no org-scoped grant.
            org_id: None,
            org_permissions: Arc::new(PermissionSet::default()),
            client_id: "pat".into(),
            session_id: None,
            jti: Some(format!("pat:{}", auth.token.id)),
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
        assert!(bearer_with_scheme(&h).is_none());
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert!(bearer_with_scheme(&h).is_none());
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert!(bearer_with_scheme(&h).is_none());
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer  tok "),
        );
        assert_eq!(
            bearer_with_scheme(&h),
            Some((Scheme::Bearer, "tok".to_string()))
        );
    }

    #[test]
    fn tenant_id_is_read_from_the_payload() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload =
            URL_SAFE_NO_PAD.encode(br#"{"tid":"00000000-0000-7000-8000-000000000001","sub":"x"}"#);
        let token = format!("eyJhbGciOiJSUzI1NiJ9.{payload}.sig");
        use crate::services::tokens::unverified_tenant_id;
        assert_eq!(unverified_tenant_id(&token), Some(MASTER_TENANT_ID));
        assert_eq!(unverified_tenant_id("not.a"), None);
        assert_eq!(unverified_tenant_id("a.!!!.c"), None);
    }
}
