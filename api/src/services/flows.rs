//! Login flow state machine.
//!
//! A flow starts at `/authorize` and carries the validated request through
//! the static UI. Each step validates the CSRF token bound to the flow,
//! performs its action, then [`advance`] recomputes the next stage from
//! policy and user state until `Done`, when `GET /flows/{id}/finish` issues
//! the authorization code in the browser's context.

use chrono::{Duration, Utc};
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::Serialize;
use serde_json::Value;
use subtle::ConstantTimeEq as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::db;
use crate::error::{AppError, AppResult, FieldError};
use crate::middleware::TenantCtx;
use crate::models::{AttributeDef, Client, Tenant, User, UserStatus};
use crate::repos;
use crate::services::login_flows::{self, FlowStage, LoginFlow};
use crate::services::password::{self, SetPasswordOptions, VerifyOutcome};
use crate::services::sessions::{self, NewSession, SsoSession};
use crate::services::{clients, consents, profile_schema, users};
use crate::state::AppState;

/// What the UI needs to render the current step.
#[derive(Debug, Clone, Serialize)]
pub struct PublicFlow {
    pub id: Uuid,
    pub stage: FlowStage,
    pub csrf: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub client: PublicClient,
    pub methods: Vec<&'static str>,
    pub login_hint: Option<String>,
    pub ui_locales: Vec<String>,
    /// Consent stage: scopes awaiting approval with descriptions.
    pub pending_scopes: Vec<ScopeInfo>,
    /// Profile stage: attribute definitions still missing.
    pub missing_attributes: Vec<AttributeDef>,
    /// Terms stage.
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    /// Authenticated user (after the authenticate stage).
    pub user: Option<PublicUser>,
    pub attempts: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicClient {
    pub client_id: String,
    pub name: String,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicUser {
    pub username: String,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopeInfo {
    pub name: String,
    pub description: Option<String>,
}

pub fn check_csrf(flow: &LoginFlow, presented: &str) -> AppResult<()> {
    if flow.csrf.is_empty() || !bool::from(flow.csrf.as_bytes().ct_eq(presented.as_bytes())) {
        return Err(AppError::Forbidden("invalid csrf token".into()));
    }
    Ok(())
}

pub async fn load(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<LoginFlow> {
    login_flows::get(state, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("flow"))
}

async fn client_of(state: &AppState, flow: &LoginFlow) -> AppResult<std::sync::Arc<Client>> {
    clients::find_by_client_id(state, flow.tenant_id, &flow.request.client_public_id)
        .await?
        .filter(|c| c.is_active())
        .ok_or(AppError::NotFound("client"))
}

pub async fn public_state(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
) -> AppResult<PublicFlow> {
    let client = client_of(state, flow).await?;
    let auth = &tenant.settings.auth;
    let mut methods = vec![];
    if auth.password {
        methods.push("password");
    }
    if auth.magic_link {
        methods.push("magic_link");
    }
    if auth.email_otp {
        methods.push("email_otp");
    }
    if auth.sms_otp {
        methods.push("sms_otp");
    }
    if auth.passkey {
        methods.push("passkey");
    }
    let all_scopes = crate::services::scopes::list(state, tenant.id).await?;
    let pending_scopes = flow
        .pending_scopes
        .iter()
        .map(|n| ScopeInfo {
            name: n.clone(),
            description: all_scopes
                .iter()
                .find(|s| &s.name == n)
                .and_then(|s| s.description.clone()),
        })
        .collect();
    let (missing_attributes, user) = match flow.user_id {
        Some(uid) => {
            let u = users::get(state, tenant.id, uid).await?;
            let missing = if flow.stage == FlowStage::Profile {
                missing_required(state, tenant.id, &u).await?
            } else {
                vec![]
            };
            (
                missing,
                Some(PublicUser {
                    username: u.username,
                    email: u.email,
                }),
            )
        }
        None => (vec![], None),
    };
    Ok(PublicFlow {
        id: flow.id,
        stage: flow.stage,
        csrf: flow.csrf.clone(),
        expires_at: flow.expires_at,
        client: PublicClient {
            client_id: client.client_id.clone(),
            name: client.name.clone(),
            logo_uri: client.logo_uri.clone(),
            client_uri: client.client_uri.clone(),
            tos_uri: client.tos_uri.clone(),
            policy_uri: client.policy_uri.clone(),
        },
        methods,
        login_hint: flow.request.login_hint.clone(),
        ui_locales: flow.request.ui_locales.clone(),
        pending_scopes,
        missing_attributes,
        terms_url: tenant.settings.registration.terms_url.clone(),
        privacy_url: tenant.settings.registration.privacy_url.clone(),
        user,
        attempts: flow.attempts,
    })
}

async fn missing_required(
    state: &AppState,
    tenant_id: Uuid,
    user: &User,
) -> AppResult<Vec<AttributeDef>> {
    let schema = profile_schema::get(state, tenant_id).await?;
    Ok(schema
        .attributes
        .iter()
        .filter(|a| a.required && a.editable_by != crate::models::EditableBy::None)
        .filter(|a| {
            !user
                .attributes
                .get(&a.name)
                .is_some_and(|v| !v.is_null() && v.as_str().is_none_or(|s| !s.trim().is_empty()))
        })
        .cloned()
        .collect())
}

/// Recompute the stage after the user is authenticated. `must_change_password`
/// takes precedence over everything else.
pub async fn advance(
    state: &AppState,
    tenant: &Tenant,
    flow: &mut LoginFlow,
    must_change_password: bool,
) -> AppResult<()> {
    let (Some(user_id), Some(_session_id)) = (flow.user_id, flow.session_id) else {
        flow.stage = FlowStage::Authenticate;
        return Ok(());
    };
    let user = users::get(state, tenant.id, user_id).await?;
    if must_change_password {
        flow.stage = FlowStage::PasswordChange;
        return Ok(());
    }
    // Step-up: requested acr not satisfied → MFA (Phase 7 decides the method).
    if !flow.request.acr_values.is_empty()
        && !flow.amr.iter().any(|m| m == "mfa")
        && flow.request.acr_values.iter().any(|a| a.ends_with(":mfa"))
    {
        flow.stage = FlowStage::Mfa;
        return Ok(());
    }
    if !missing_required(state, tenant.id, &user).await?.is_empty() {
        flow.stage = FlowStage::Profile;
        return Ok(());
    }
    if tenant.settings.registration.require_terms && user.terms_accepted_at.is_none() {
        flow.stage = FlowStage::Terms;
        return Ok(());
    }
    let client = client_of(state, flow).await?;
    let force_consent = flow.request.prompt.iter().any(|p| p == "consent");
    let pending = if flow.request.skip_consent && !force_consent {
        vec![]
    } else if force_consent && flow.pending_scopes.is_empty() && flow.stage != FlowStage::Consent {
        flow.request.scopes.clone()
    } else {
        consents::missing_scopes(state, tenant.id, user_id, client.id, &flow.request.scopes).await?
    };
    if !pending.is_empty() && flow.stage != FlowStage::Done {
        flow.pending_scopes = pending;
        flow.stage = FlowStage::Consent;
        return Ok(());
    }
    flow.pending_scopes.clear();
    flow.stage = FlowStage::Done;
    Ok(())
}

/// Outcome of an authentication step.
pub enum AuthStep {
    /// Session cookie to set and the updated flow.
    Authenticated {
        session: Box<SsoSession>,
        flow: Box<LoginFlow>,
    },
    /// Wrong credentials; the flow (with its attempt counter) was saved.
    Rejected { flow: Box<LoginFlow>, locked: bool },
}

/// Inputs of a password authentication attempt.
pub struct PasswordAttempt {
    pub identifier: String,
    pub password: Zeroizing<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    /// An SSO session the browser already has (re-authentication).
    pub existing_session: Option<SsoSession>,
}

/// `POST /flows/{id}/password`
pub async fn password_step(
    state: &AppState,
    tenant: &TenantCtx,
    mut flow: LoginFlow,
    attempt: PasswordAttempt,
) -> AppResult<AuthStep> {
    let PasswordAttempt {
        identifier,
        password,
        ip,
        user_agent,
        existing_session,
    } = attempt;
    if flow.stage != FlowStage::Authenticate {
        return Err(AppError::BadRequest(
            "flow is not at the authenticate step".into(),
        ));
    }
    if !tenant.tenant.settings.auth.password {
        return Err(AppError::BadRequest(
            "password login is disabled for this tenant".into(),
        ));
    }
    let tid = tenant.id();
    let lockout = &tenant.tenant.settings.lockout;
    let identifier = identifier.trim().to_lowercase();
    if identifier.is_empty() || password.is_empty() {
        return Err(AppError::Validation(vec![FieldError {
            field: "identifier".into(),
            message: "identifier and password are required".into(),
        }]));
    }

    // IP throttle.
    if lockout.ip_max_failures > 0
        && let Some(ip) = &ip
    {
        let mut tx = db::tenant_tx(&state.db, tid).await?;
        let since = Utc::now() - Duration::minutes(i64::from(lockout.ip_window_minutes.max(1)));
        let n = repos::login_attempts::failures_from_ip(&mut *tx, tid, ip, since).await?;
        tx.commit().await?;
        if n >= i64::from(lockout.ip_max_failures) {
            return Err(AppError::RateLimited {
                retry_after_secs: u64::from(lockout.ip_window_minutes) * 60,
            });
        }
    }

    let user = users::find_by_identifier(state, tid, &identifier).await?;
    let verdict = match &user {
        Some(u) if u.status == UserStatus::Disabled => Err("disabled"),
        Some(u) if u.is_locked_now() => Err("locked"),
        Some(u) => match password::verify_and_upgrade(
            state,
            tid,
            &tenant.tenant.settings.password,
            u,
            password,
        )
        .await?
        {
            VerifyOutcome::Valid { must_change } => Ok(must_change),
            VerifyOutcome::Invalid => Err("invalid_credentials"),
        },
        None => {
            // Equalise timing with a real verification.
            let _ = password::verify_and_upgrade(
                state,
                tid,
                &tenant.tenant.settings.password,
                &dummy_user(tid),
                password,
            )
            .await;
            Err("invalid_credentials")
        }
    };

    match verdict {
        Ok(must_change) => {
            let user = user.expect("user present");
            let mut tx = db::tenant_tx(&state.db, tid).await?;
            repos::users::record_login_success(&mut *tx, tid, user.id).await?;
            repos::login_attempts::record(&mut *tx, tid, &identifier, ip.as_deref(), true, None)
                .await?;
            tx.commit().await?;

            let policy = &tenant.tenant.settings.session;
            let session = match existing_session {
                Some(mut s) if s.user_id == user.id => {
                    sessions::refresh_auth(state, &mut s, vec!["pwd".into()], None).await?;
                    s
                }
                _ => {
                    sessions::create(
                        state,
                        tid,
                        NewSession {
                            user_id: user.id,
                            amr: vec!["pwd".into()],
                            acr: None,
                            ip: ip.clone(),
                            user_agent,
                            policy,
                        },
                    )
                    .await?
                }
            };
            flow.user_id = Some(user.id);
            flow.session_id = Some(session.id);
            flow.amr = vec!["pwd".into()];
            advance(state, &tenant.tenant, &mut flow, must_change).await?;
            login_flows::save(state, &flow).await?;
            state.events.publish(
                Event::new(
                    Some(tid),
                    Actor::User { id: user.id },
                    EventKind::LoginSucceeded {
                        user_id: user.id,
                        method: "pwd".into(),
                    },
                )
                .with_request(ip, None),
            );
            Ok(AuthStep::Authenticated {
                session: Box::new(session),
                flow: Box::new(flow),
            })
        }
        Err(reason) => {
            let mut locked = false;
            let mut tx = db::tenant_tx(&state.db, tid).await?;
            repos::login_attempts::record(
                &mut *tx,
                tid,
                &identifier,
                ip.as_deref(),
                false,
                Some(reason),
            )
            .await?;
            if let Some(u) = &user
                && reason == "invalid_credentials"
                && lockout.max_failures > 0
            {
                let failures = repos::users::record_login_failure(
                    &mut *tx,
                    tid,
                    u.id,
                    lockout.max_failures as i32,
                    i64::from(lockout.lock_minutes) * 60,
                )
                .await?;
                if failures >= lockout.max_failures as i32 {
                    locked = true;
                    state.events.publish(Event::new(
                        Some(tid),
                        Actor::System,
                        EventKind::UserLocked {
                            user_id: u.id,
                            until_secs: i64::from(lockout.lock_minutes) * 60,
                        },
                    ));
                }
            }
            tx.commit().await?;
            flow.attempts += 1;
            login_flows::save(state, &flow).await?;
            state.events.publish(
                Event::new(
                    Some(tid),
                    Actor::System,
                    EventKind::LoginFailed {
                        identifier: identifier.clone(),
                        reason: reason.into(),
                    },
                )
                .with_request(ip, None),
            );
            Ok(AuthStep::Rejected {
                flow: Box::new(flow),
                locked: locked || reason == "locked",
            })
        }
    }
}

fn dummy_user(tenant_id: Uuid) -> User {
    User {
        id: Uuid::nil(),
        tenant_id,
        org_id: None,
        username: String::new(),
        email: None,
        email_verified: false,
        phone: None,
        phone_verified: false,
        password_hash: None,
        password_algo: None,
        must_change_password: false,
        password_expires_at: None,
        password_changed_at: None,
        status: UserStatus::Active,
        attributes: Value::Object(Default::default()),
        locale: None,
        last_login_at: None,
        failed_attempts: 0,
        locked_until: None,
        deleted_at: None,
        terms_accepted_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// `POST /flows/{id}/password-change`: set a new password at the `PasswordChange` stage.
pub async fn password_change_step(
    state: &AppState,
    tenant: &Tenant,
    mut flow: LoginFlow,
    new_password: Zeroizing<String>,
) -> AppResult<LoginFlow> {
    if flow.stage != FlowStage::PasswordChange {
        return Err(AppError::BadRequest(
            "flow is not at the password change step".into(),
        ));
    }
    let user_id = flow.user_id.ok_or(AppError::Unauthorized)?;
    password::set_password(
        state,
        tenant.id,
        &tenant.settings.password,
        Actor::User { id: user_id },
        user_id,
        new_password,
        SetPasswordOptions {
            must_change: false,
            skip_policy: false,
            by_user: true,
        },
    )
    .await?;
    advance(state, tenant, &mut flow, false).await?;
    login_flows::save(state, &flow).await?;
    Ok(flow)
}

/// `POST /flows/{id}/profile`: fill required attributes.
pub async fn profile_step(
    state: &AppState,
    tenant: &Tenant,
    mut flow: LoginFlow,
    attributes: Value,
) -> AppResult<LoginFlow> {
    if flow.stage != FlowStage::Profile {
        return Err(AppError::BadRequest(
            "flow is not at the profile step".into(),
        ));
    }
    let user_id = flow.user_id.ok_or(AppError::Unauthorized)?;
    users::update(
        state,
        tenant.id,
        Actor::User { id: user_id },
        user_id,
        crate::models::UserUpdate {
            attributes: Some(attributes),
            ..Default::default()
        },
    )
    .await?;
    advance(state, tenant, &mut flow, false).await?;
    login_flows::save(state, &flow).await?;
    Ok(flow)
}

/// `POST /flows/{id}/terms`
pub async fn terms_step(
    state: &AppState,
    tenant: &Tenant,
    mut flow: LoginFlow,
    accepted: bool,
) -> AppResult<LoginFlow> {
    if flow.stage != FlowStage::Terms {
        return Err(AppError::BadRequest("flow is not at the terms step".into()));
    }
    if !accepted {
        return Err(AppError::Forbidden(
            "terms must be accepted to continue".into(),
        ));
    }
    let user_id = flow.user_id.ok_or(AppError::Unauthorized)?;
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    repos::users::set_terms_accepted(&mut *tx, tenant.id, user_id).await?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant.id),
        Actor::User { id: user_id },
        EventKind::TermsAccepted { user_id },
    ));
    advance(state, tenant, &mut flow, false).await?;
    login_flows::save(state, &flow).await?;
    Ok(flow)
}

/// `POST /flows/{id}/consent`: approve (all pending or a subset that must
/// include every non-optional scope) or deny.
pub async fn consent_step(
    state: &AppState,
    tenant: &Tenant,
    mut flow: LoginFlow,
    approve: bool,
    granted: Option<Vec<String>>,
) -> AppResult<ConsentOutcome> {
    if flow.stage != FlowStage::Consent {
        return Err(AppError::BadRequest(
            "flow is not at the consent step".into(),
        ));
    }
    let user_id = flow.user_id.ok_or(AppError::Unauthorized)?;
    if !approve {
        return Ok(ConsentOutcome::Denied {
            redirect_to: denial_redirect(&flow),
        });
    }
    let client = client_of(state, &flow).await?;
    let granted = granted.unwrap_or_else(|| flow.pending_scopes.clone());
    // `openid` can never be dropped; anything not requested is ignored.
    let mut effective: Vec<String> = flow
        .request
        .scopes
        .iter()
        .filter(|s| *s == "openid" || granted.contains(s) || !flow.pending_scopes.contains(s))
        .cloned()
        .collect();
    effective.dedup();
    consents::grant(state, tenant.id, user_id, client.id, &effective).await?;
    flow.request.scopes = effective;
    flow.pending_scopes.clear();
    flow.stage = FlowStage::Done;
    advance(state, tenant, &mut flow, false).await?;
    login_flows::save(state, &flow).await?;
    Ok(ConsentOutcome::Granted {
        flow: Box::new(flow),
    })
}

pub enum ConsentOutcome {
    Granted { flow: Box<LoginFlow> },
    Denied { redirect_to: String },
}

/// Client-facing error redirect used by cancel and consent denial.
pub fn denial_redirect(flow: &LoginFlow) -> String {
    let mut u = url::Url::parse(&flow.request.redirect_uri).expect("validated redirect uri");
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("error", "access_denied");
        q.append_pair("error_description", "the user denied the request");
        if let Some(s) = &flow.request.state {
            q.append_pair("state", s);
        }
    }
    u.to_string()
}

/// `POST /flows/{id}/cancel`
pub async fn cancel(state: &AppState, flow: &LoginFlow) -> AppResult<String> {
    login_flows::delete(state, flow.tenant_id, flow.id).await?;
    Ok(denial_redirect(flow))
}
