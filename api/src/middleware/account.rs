//! Account authentication: `AccountCtx` is an axum extractor for the
//! self-service `/t/{slug}/account/...` routes.
//!
//! It accepts a bearer access token issued by the tenant in the path whose
//! audience includes the built-in account resource server (the bundled
//! account console's client is the usual source). The subject must be a live
//! user of that tenant; the token only ever acts on that user's own account.
//! Security changes additionally need a recent sign-in, see
//! [`AccountCtx::require_recent_auth`].

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::{DateTime, TimeZone as _, Utc};
use ridm_core::events::Actor;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::admin::{AdminRejection, bearer, unverified_tenant_id};
use crate::middleware::tenant::TenantCtx;
use crate::models::{Tenant, User, UserStatus};
use crate::services::account_console::ACCOUNT_AUDIENCE;
use crate::services::flows::is_mfa_acr;
use crate::services::tokens::{self, VerifyOptions};
use crate::services::{tenants, users};
use crate::state::AppState;

/// How recent a sign-in must be for a security change (adding or removing
/// a factor, revoking devices).
pub const RECENT_AUTH_SECS: i64 = 15 * 60;

/// The signed-in user of an account API call.
#[derive(Debug, Clone)]
pub struct AccountCtx {
    pub user: User,
    pub tenant: Arc<Tenant>,
    pub session_id: Option<Uuid>,
    pub auth_time: Option<DateTime<Utc>>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    pub client_id: String,
}

impl AccountCtx {
    pub fn actor(&self) -> Actor {
        Actor::User { id: self.user.id }
    }

    /// Did the sign-in behind this token happen within the last
    /// [`RECENT_AUTH_SECS`], and with a second factor when `needs_mfa`?
    /// Otherwise the client re-authorizes with `max_age=0` (and an MFA
    /// `acr_values`) and comes back.
    pub fn require_recent_auth(&self, needs_mfa: bool) -> AppResult<()> {
        let recent = self
            .auth_time
            .is_some_and(|t| (Utc::now() - t).num_seconds() <= RECENT_AUTH_SECS);
        let strong = !needs_mfa || self.acr.as_deref().is_some_and(is_mfa_acr);
        if recent && strong {
            Ok(())
        } else {
            Err(AppError::ReauthenticationRequired { mfa: needs_mfa })
        }
    }

    /// [`Self::require_recent_auth`] for a change to the account: the
    /// second step is demanded once the account has one.
    pub async fn require_recent(&self, state: &AppState) -> AppResult<()> {
        let mfa =
            crate::services::totp::has_second_factor(state, self.tenant.id, self.user.id).await?;
        self.require_recent_auth(mfa)
    }

    /// The scope enrolments started from the account console live under:
    /// the SSO session, so a reloaded page finds its pending enrolment.
    pub fn scope_id(&self) -> Uuid {
        self.session_id.unwrap_or(self.user.id)
    }
}

impl FromRequestParts<AppState> for AccountCtx {
    type Rejection = AdminRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, AdminRejection> {
        let path_tenant = TenantCtx::from_request_parts(parts, state)
            .await
            .map_err(AdminRejection::from)?;
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
                audience: Some(ACCOUNT_AUDIENCE.into()),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| match e {
            AppError::Unauthorized => AdminRejection::invalid(),
            other => other.into(),
        })?;
        if tenant.id != path_tenant.id() {
            return Err(AppError::Forbidden("this token belongs to another tenant".into()).into());
        }
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
            .ok_or_else(|| AppError::Forbidden("account access requires a user subject".into()))?;
        let user = users::get(state, tenant.id, user_id).await?;
        if user.status != UserStatus::Active && user.status != UserStatus::Pending {
            return Err(AppError::Forbidden("account is not active".into()).into());
        }
        let auth_time = claims
            .get("auth_time")
            .and_then(serde_json::Value::as_i64)
            .and_then(|t| Utc.timestamp_opt(t, 0).single());
        let acr = claims
            .get("acr")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let amr = claims
            .get("amr")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let client_id = claims
            .get("client_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        Ok(Self {
            user,
            tenant,
            session_id,
            auth_time,
            acr,
            amr,
            client_id,
        })
    }
}
