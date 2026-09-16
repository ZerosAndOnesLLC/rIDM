//! `/t/{slug}/account/mfa`: the user's second factors, managed outside a
//! login flow. Enrolment mirrors the flow steps (the services are the same;
//! the ceremony scope is the SSO session instead of a flow) and every
//! change needs a recent sign-in, with the second step once one exists.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;
use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::db;
use crate::error::{AppError, AppResult, FieldError};
use crate::middleware::{AccountCtx, Json};
use crate::models::Credential;
use crate::repos;
use crate::services::otp_factors::{self, Channel};
use crate::services::{notifications, passkeys, totp};
use crate::state::AppState;

pub fn mfa_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(status))
        .routes(routes!(totp_enroll))
        .routes(routes!(totp_confirm))
        .routes(routes!(passkey_register))
        .routes(routes!(passkey_register_finish))
        .routes(routes!(email_enroll))
        .routes(routes!(email_confirm))
        .routes(routes!(sms_enroll))
        .routes(routes!(sms_confirm))
        .routes(routes!(delete_credential))
        .routes(routes!(recovery_codes))
}

/// The user's second-factor state.
#[derive(Serialize, utoipa::ToSchema)]
pub struct MfaStatus {
    /// Enrolled factors (`totp`, `webauthn`, `email_otp`, `sms_otp` rows).
    pub factors: Vec<Credential>,
    /// Unused recovery codes.
    pub recovery_codes: usize,
    /// Factor kinds the tenant offers for enrolment.
    pub methods: Vec<&'static str>,
    /// The phone an SMS enrolment would use, masked.
    pub phone: Option<String>,
    /// The tenant's policy mode (`off`, `optional`, `required`, ...).
    pub policy: String,
}

/// Answer of a completed enrolment: recovery codes when a fresh set was
/// issued (the first factor, or an authenticator app, which always renews
/// them), shown once.
#[derive(Serialize, utoipa::ToSchema)]
pub struct Enrolled {
    pub recovery_codes: Option<Vec<String>>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RecoveryCodes {
    pub recovery_codes: Vec<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CodeBody {
    pub code: String,
    /// A name for the factor (authenticator app only).
    pub label: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct PasskeyFinishBody {
    /// The browser's `navigator.credentials.create` answer.
    pub credential: Value,
    pub label: Option<String>,
}

#[derive(Deserialize, Default, utoipa::ToSchema)]
#[serde(default)]
pub struct PhoneBody {
    /// E.164 number to prove; the account's own when omitted.
    pub phone: Option<String>,
}

fn invalid_code() -> AppError {
    AppError::Validation(vec![FieldError {
        field: "code".into(),
        message: "is invalid or has expired".into(),
    }])
}

/// A security change needs a recent sign-in, with the second step once the
/// account has one.
async fn recent(state: &AppState, ctx: &AccountCtx) -> AppResult<()> {
    let mfa = totp::has_second_factor(state, ctx.tenant.id, ctx.user.id).await?;
    ctx.require_recent_auth(mfa)
}

/// Recovery codes for a user who has none yet (their first factor).
async fn first_recovery_codes(
    state: &AppState,
    ctx: &AccountCtx,
) -> AppResult<Option<Vec<String>>> {
    if totp::factors_of(state, ctx.tenant.id, ctx.user.id)
        .await?
        .recovery_codes
        == 0
    {
        Ok(Some(
            totp::regenerate_recovery_codes(state, ctx.tenant.id, ctx.user.id).await?,
        ))
    } else {
        Ok(None)
    }
}

fn otp_scope(ctx: &AccountCtx) -> otp_factors::Scope<'_> {
    otp_factors::Scope {
        id: ctx.scope_id(),
        ui_locales: &[],
    }
}

#[utoipa::path(get, path = "/t/{slug}/account/mfa", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = MfaStatus), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem)), security(("bearer" = [])))]
async fn status(State(state): State<AppState>, ctx: AccountCtx) -> AppResult<Json<MfaStatus>> {
    let f = totp::factors_of(&state, ctx.tenant.id, ctx.user.id).await?;
    let mut tx = db::tenant_tx(&state.db, ctx.tenant.id).await?;
    let rows = repos::credentials::list_for_user(&mut *tx, ctx.tenant.id, ctx.user.id).await?;
    tx.commit().await?;
    let factors = rows
        .into_iter()
        .filter(|c| totp::SECOND_FACTOR_KINDS.contains(&c.kind.as_str()))
        .collect();
    let m = &ctx.tenant.settings.mfa_methods;
    let mut methods = vec![];
    if m.totp {
        methods.push(totp::KIND_TOTP);
    }
    if ctx.tenant.settings.auth.passkey {
        methods.push(passkeys::KIND);
    }
    if m.email_otp && ctx.user.email.is_some() {
        methods.push(otp_factors::KIND_EMAIL);
    }
    if m.sms_otp {
        methods.push(otp_factors::KIND_SMS);
    }
    let policy = serde_json::to_value(&ctx.tenant.settings.mfa)
        .ok()
        .and_then(|v| v.get("mode").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| "off".into());
    Ok(Json(MfaStatus {
        factors,
        recovery_codes: f.recovery_codes,
        methods,
        phone: ctx.user.phone.as_deref().map(otp_factors::mask_phone),
        policy,
    }))
}

#[utoipa::path(post, path = "/t/{slug}/account/mfa/totp/enroll", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = totp::Enrolment), (status = 400, description = "Already enrolled or disabled", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem)), security(("bearer" = [])))]
async fn totp_enroll(
    State(state): State<AppState>,
    ctx: AccountCtx,
) -> AppResult<Json<totp::Enrolment>> {
    recent(&state, &ctx).await?;
    if !ctx.tenant.settings.mfa_methods.totp {
        return Err(AppError::BadRequest(
            "authenticator apps are disabled for this tenant".into(),
        ));
    }
    if totp::factors_of(&state, ctx.tenant.id, ctx.user.id)
        .await?
        .totp
    {
        return Err(AppError::BadRequest(
            "an authenticator app is already enrolled".into(),
        ));
    }
    Ok(Json(
        totp::begin_enrolment(&state, &ctx.tenant, ctx.scope_id(), &ctx.user).await?,
    ))
}

#[utoipa::path(post, path = "/t/{slug}/account/mfa/totp/confirm", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), request_body = CodeBody, responses((status = 200, body = Enrolled), (status = 400, description = "Wrong code or nothing pending", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem)), security(("bearer" = [])))]
async fn totp_confirm(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Json(body): Json<CodeBody>,
) -> AppResult<Json<Enrolled>> {
    recent(&state, &ctx).await?;
    let codes = totp::confirm_enrolment(
        &state,
        &ctx.tenant,
        ctx.scope_id(),
        &ctx.user,
        &body.code,
        body.label.as_deref(),
    )
    .await?
    .ok_or_else(invalid_code)?;
    Ok(Json(Enrolled {
        recovery_codes: Some(codes),
    }))
}

#[utoipa::path(post, path = "/t/{slug}/account/mfa/passkey/register", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, description = "WebAuthn creation options", body = Value), (status = 400, description = "Passkeys disabled", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem)), security(("bearer" = [])))]
async fn passkey_register(
    State(state): State<AppState>,
    ctx: AccountCtx,
) -> AppResult<Json<Value>> {
    recent(&state, &ctx).await?;
    if !ctx.tenant.settings.auth.passkey {
        return Err(AppError::BadRequest(
            "passkeys are disabled for this tenant".into(),
        ));
    }
    let options =
        passkeys::begin_registration(&state, &ctx.tenant, ctx.scope_id(), &ctx.user).await?;
    Ok(Json(serde_json::to_value(options)?))
}

#[utoipa::path(post, path = "/t/{slug}/account/mfa/passkey/register/finish", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), request_body = PasskeyFinishBody, responses((status = 200, body = Enrolled), (status = 400, description = "The passkey could not be verified", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem)), security(("bearer" = [])))]
async fn passkey_register_finish(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Json(body): Json<PasskeyFinishBody>,
) -> AppResult<Json<Enrolled>> {
    recent(&state, &ctx).await?;
    if !ctx.tenant.settings.auth.passkey {
        return Err(AppError::BadRequest(
            "passkeys are disabled for this tenant".into(),
        ));
    }
    let credential: RegisterPublicKeyCredential = serde_json::from_value(body.credential)
        .map_err(|e| AppError::BadRequest(format!("malformed credential: {e}")))?;
    passkeys::finish_registration(
        &state,
        &ctx.tenant,
        ctx.scope_id(),
        &ctx.user,
        &credential,
        body.label.as_deref(),
    )
    .await?
    .ok_or_else(|| AppError::BadRequest("the passkey could not be verified".into()))?;
    Ok(Json(Enrolled {
        recovery_codes: first_recovery_codes(&state, &ctx).await?,
    }))
}

async fn otp_enroll(
    state: &AppState,
    ctx: &AccountCtx,
    channel: Channel,
    phone: Option<&str>,
) -> AppResult<Json<otp_factors::Sent>> {
    recent(state, ctx).await?;
    Ok(Json(
        otp_factors::begin_enrolment(
            state,
            &ctx.tenant,
            otp_scope(ctx),
            &ctx.user,
            channel,
            phone,
        )
        .await?,
    ))
}

async fn otp_confirm(
    state: &AppState,
    ctx: &AccountCtx,
    channel: Channel,
    code: &str,
) -> AppResult<Json<Enrolled>> {
    recent(state, ctx).await?;
    if !otp_factors::confirm_enrolment(state, &ctx.tenant, otp_scope(ctx), &ctx.user, channel, code)
        .await?
    {
        return Err(invalid_code());
    }
    Ok(Json(Enrolled {
        recovery_codes: first_recovery_codes(state, ctx).await?,
    }))
}

#[utoipa::path(post, path = "/t/{slug}/account/mfa/email/enroll", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 202, body = otp_factors::Sent), (status = 400, description = "Already enrolled, disabled or no address", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem), (status = 429, description = "Too many codes sent", body = crate::error::Problem)), security(("bearer" = [])))]
async fn email_enroll(
    State(state): State<AppState>,
    ctx: AccountCtx,
) -> AppResult<(StatusCode, Json<otp_factors::Sent>)> {
    Ok((
        StatusCode::ACCEPTED,
        otp_enroll(&state, &ctx, Channel::Email, None).await?,
    ))
}

#[utoipa::path(post, path = "/t/{slug}/account/mfa/email/confirm", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), request_body = CodeBody, responses((status = 200, body = Enrolled), (status = 400, description = "Wrong code or nothing pending", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem)), security(("bearer" = [])))]
async fn email_confirm(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Json(body): Json<CodeBody>,
) -> AppResult<Json<Enrolled>> {
    otp_confirm(&state, &ctx, Channel::Email, &body.code).await
}

#[utoipa::path(post, path = "/t/{slug}/account/mfa/sms/enroll", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), request_body = PhoneBody, responses((status = 202, body = otp_factors::Sent), (status = 400, description = "Already enrolled, disabled or no number", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem), (status = 429, description = "Too many codes sent", body = crate::error::Problem)), security(("bearer" = [])))]
async fn sms_enroll(
    State(state): State<AppState>,
    ctx: AccountCtx,
    body: Option<Json<PhoneBody>>,
) -> AppResult<(StatusCode, Json<otp_factors::Sent>)> {
    let phone = body.and_then(|Json(b)| b.phone);
    Ok((
        StatusCode::ACCEPTED,
        otp_enroll(&state, &ctx, Channel::Sms, phone.as_deref()).await?,
    ))
}

#[utoipa::path(post, path = "/t/{slug}/account/mfa/sms/confirm", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), request_body = CodeBody, responses((status = 200, body = Enrolled), (status = 400, description = "Wrong code or nothing pending", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem)), security(("bearer" = [])))]
async fn sms_confirm(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Json(body): Json<CodeBody>,
) -> AppResult<Json<Enrolled>> {
    otp_confirm(&state, &ctx, Channel::Sms, &body.code).await
}

#[derive(Deserialize)]
struct CredentialPath {
    credential_id: Uuid,
}

/// Remove a factor. The recovery codes go with the last one.
#[utoipa::path(delete, path = "/t/{slug}/account/mfa/credentials/{credential_id}", tag = "account", params(("slug" = String, Path, description = "Tenant slug"), ("credential_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete_credential(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Path(CredentialPath { credential_id }): Path<CredentialPath>,
) -> AppResult<StatusCode> {
    recent(&state, &ctx).await?;
    let tid = ctx.tenant.id;
    let mut tx = db::tenant_tx(&state.db, tid).await?;
    let rows = repos::credentials::list_for_user(&mut *tx, tid, ctx.user.id).await?;
    let Some(row) = rows.iter().find(|c| c.id == credential_id) else {
        return Err(AppError::NotFound("credential"));
    };
    if !totp::SECOND_FACTOR_KINDS.contains(&row.kind.as_str()) {
        return Err(AppError::NotFound("credential"));
    }
    repos::credentials::delete(&mut *tx, tid, ctx.user.id, credential_id).await?;
    let others = rows
        .iter()
        .filter(|c| c.id != credential_id && totp::SECOND_FACTOR_KINDS.contains(&c.kind.as_str()))
        .count();
    if others == 0 {
        repos::credentials::delete_of_type(&mut *tx, tid, ctx.user.id, totp::KIND_RECOVERY).await?;
    }
    tx.commit().await?;
    let what = match row.kind.as_str() {
        totp::KIND_TOTP => "An authenticator app was removed",
        passkeys::KIND => "A passkey was removed",
        otp_factors::KIND_EMAIL => "Codes by email were removed as a second step",
        _ => "Codes by text message were removed as a second step",
    };
    notifications::mfa_changed(&state, tid, ctx.user.id, what).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Replace the recovery codes; the new set is shown once.
#[utoipa::path(post, path = "/t/{slug}/account/mfa/recovery-codes", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = RecoveryCodes), (status = 400, description = "No second factor enrolled", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem)), security(("bearer" = [])))]
async fn recovery_codes(
    State(state): State<AppState>,
    ctx: AccountCtx,
) -> AppResult<Json<RecoveryCodes>> {
    recent(&state, &ctx).await?;
    if !totp::has_second_factor(&state, ctx.tenant.id, ctx.user.id).await? {
        return Err(AppError::BadRequest(
            "recovery codes need a second factor to recover from".into(),
        ));
    }
    let codes = totp::regenerate_recovery_codes(&state, ctx.tenant.id, ctx.user.id).await?;
    notifications::mfa_changed(
        &state,
        ctx.tenant.id,
        ctx.user.id,
        "Recovery codes were replaced",
    )
    .await;
    Ok(Json(RecoveryCodes {
        recovery_codes: codes,
    }))
}
