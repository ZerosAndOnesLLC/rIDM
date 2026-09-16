//! Tenant statistics for the console dashboard: sign-ins and failures per
//! day, live sessions, users and second-factor adoption, and the clients
//! users authorized most. Everything is derived from what is already
//! recorded (login attempts, sessions, credentials, audit events).

use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub const MAX_DAYS: u32 = 365;

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct DayStats {
    pub date: NaiveDate,
    pub logins: i64,
    pub failed: i64,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct UserStats {
    /// Users that are not soft-deleted.
    pub total: i64,
    pub active: i64,
    /// Users holding at least one second factor (TOTP or passkey).
    pub mfa_enrolled: i64,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ClientStats {
    pub id: Uuid,
    pub client_id: String,
    pub name: String,
    /// Authorizations granted in the window.
    pub authorizations: i64,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct TenantStats {
    pub window_days: u32,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    /// One entry per day of the window, oldest first, zeros included.
    pub days: Vec<DayStats>,
    pub logins_total: i64,
    pub failed_total: i64,
    pub active_sessions: i64,
    pub users: UserStats,
    pub top_clients: Vec<ClientStats>,
}

pub async fn tenant_stats(state: &AppState, tenant_id: Uuid, days: u32) -> AppResult<TenantStats> {
    if days == 0 || days > MAX_DAYS {
        return Err(AppError::BadRequest(format!(
            "days must be between 1 and {MAX_DAYS}"
        )));
    }
    let to = Utc::now();
    let first_day = (to - Duration::days(i64::from(days) - 1)).date_naive();
    let from = first_day.and_hms_opt(0, 0, 0).expect("midnight").and_utc();
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;

    let rows = sqlx::query(
        "SELECT (created_at AT TIME ZONE 'UTC')::date AS day, \
                count(*) FILTER (WHERE success) AS logins, \
                count(*) FILTER (WHERE NOT success) AS failed \
         FROM login_attempts WHERE tenant_id = $1 AND created_at >= $2 \
         GROUP BY day ORDER BY day",
    )
    .bind(tenant_id)
    .bind(from)
    .fetch_all(&mut *tx)
    .await?;
    let mut days_out: Vec<DayStats> = (0..days)
        .map(|i| DayStats {
            date: first_day + Duration::days(i64::from(i)),
            logins: 0,
            failed: 0,
        })
        .collect();
    for r in rows {
        let day: NaiveDate = r.get("day");
        if let Some(d) = days_out.iter_mut().find(|d| d.date == day) {
            d.logins = r.get("logins");
            d.failed = r.get("failed");
        }
    }
    let logins_total = days_out.iter().map(|d| d.logins).sum();
    let failed_total = days_out.iter().map(|d| d.failed).sum();

    let active_sessions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sso_sessions \
         WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > now() AND idle_expires_at > now()",
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await?;

    let users_row = sqlx::query(
        "SELECT count(*) FILTER (WHERE deleted_at IS NULL) AS total, \
                count(*) FILTER (WHERE deleted_at IS NULL AND status = 'active') AS active, \
                (SELECT count(DISTINCT c.user_id) FROM credentials c \
                   JOIN users u ON u.tenant_id = c.tenant_id AND u.id = c.user_id \
                   WHERE c.tenant_id = $1 AND u.deleted_at IS NULL AND c.type IN ('totp', 'webauthn', 'email_otp', 'sms_otp')) AS mfa_enrolled \
         FROM users WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await?;
    let users = UserStats {
        total: users_row.get("total"),
        active: users_row.get("active"),
        mfa_enrolled: users_row.get("mfa_enrolled"),
    };

    let top = sqlx::query(
        "SELECT c.id, c.client_id, c.name, count(*) AS authorizations \
         FROM audit_events a \
         JOIN clients c ON c.tenant_id = a.tenant_id AND c.id = (a.payload->>'client_id')::uuid \
         WHERE a.tenant_id = $1 AND a.name = 'authorization.granted' AND a.occurred_at >= $2 \
         GROUP BY c.id, c.client_id, c.name ORDER BY authorizations DESC, c.name LIMIT 8",
    )
    .bind(tenant_id)
    .bind(from)
    .fetch_all(&mut *tx)
    .await?;
    let top_clients = top
        .into_iter()
        .map(|r| ClientStats {
            id: r.get("id"),
            client_id: r.get("client_id"),
            name: r.get("name"),
            authorizations: r.get("authorizations"),
        })
        .collect();
    tx.commit().await?;

    Ok(TenantStats {
        window_days: days,
        from,
        to,
        days: days_out,
        logins_total,
        failed_total,
        active_sessions,
        users,
        top_clients,
    })
}
