//! Tenant statistics for the console dashboard: sign-ins and failures per
//! day, live sessions, users and second-factor adoption, and the clients
//! users authorized most. Everything is derived from what is already
//! recorded (login attempts, sessions, credentials, audit events).
//!
//! Each figure is an aggregate over one of the tenant's largest tables, so
//! the dashboard is cached: the whole answer for a minute (the page polls
//! once a minute), the user counts, which scan every user, for ten.
//!
//! The same answer carries what the console shell shows everywhere: the
//! sidebar counts, what needs attention, and the newest audit events. One
//! cached call serves both.

use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::AuditFilter;
use crate::repos;
use crate::state::AppState;

pub const MAX_DAYS: u32 = 365;

/// How many of the newest audit events the overview shows.
const RECENT_EVENTS: i64 = 8;

/// How long a dashboard answer is served from the cache.
const STATS_TTL: std::time::Duration = std::time::Duration::from_secs(60);
/// How long the user counts are: they move slowly and cost a scan of users.
const USER_COUNTS_TTL: std::time::Duration = std::time::Duration::from_secs(600);

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DayStats {
    pub date: NaiveDate,
    pub logins: i64,
    pub failed: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UserStats {
    /// Users that are not soft-deleted.
    pub total: i64,
    pub active: i64,
    /// Users holding at least one second factor (TOTP or passkey).
    pub mfa_enrolled: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ClientStats {
    pub id: Uuid,
    pub client_id: String,
    pub name: String,
    /// Authorizations granted in the window.
    pub authorizations: i64,
}

/// The window before this one, for deltas.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WindowTotals {
    pub logins_total: i64,
    pub failed_total: i64,
}

/// How many of each the tenant has (the console sidebar).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Counts {
    pub users: i64,
    pub groups: i64,
    pub clients: i64,
    pub webhooks: i64,
    /// Pending, active and retiring signing keys.
    pub keys: i64,
    /// OIDC, SAML, LDAP and Kerberos upstream providers together.
    pub idps: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ExpiringKey {
    pub kid: String,
    pub expires_at: DateTime<Utc>,
}

/// What is waiting on an administrator.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Attention {
    /// Accounts locked by status or by a lockout still running.
    pub locked_users: i64,
    /// Invitations neither accepted, revoked nor expired.
    pub open_invitations: i64,
    pub oldest_invitation_at: Option<DateTime<Utc>>,
    /// Active or retiring keys whose publication ends within 14 days.
    pub expiring_keys: Vec<ExpiringKey>,
    /// Webhook deliveries given up on (`dead`) in the last 7 days.
    pub dead_deliveries: i64,
}

impl Attention {
    pub fn total(&self) -> i64 {
        i64::from(self.locked_users > 0)
            + i64::from(self.open_invitations > 0)
            + self.expiring_keys.len() as i64
            + i64::from(self.dead_deliveries > 0)
    }
}

/// One of the newest audit events, with its actor and subject named.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RecentEvent {
    pub id: Uuid,
    /// Dotted event name (`user.created`).
    pub name: String,
    pub occurred_at: DateTime<Utc>,
    /// `user`, `client`, `admin` or `system`.
    pub actor_type: String,
    /// The actor's username, when the actor is a user of this tenant.
    pub actor: Option<String>,
    /// The subject's username or client name, when it is one of this tenant's.
    pub subject: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TenantStats {
    pub window_days: u32,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    /// One entry per day of the window, oldest first, zeros included.
    pub days: Vec<DayStats>,
    pub logins_total: i64,
    pub failed_total: i64,
    /// The same totals for the window before this one.
    pub previous: WindowTotals,
    pub active_sessions: i64,
    pub users: UserStats,
    pub top_clients: Vec<ClientStats>,
    pub counts: Counts,
    pub attention: Attention,
    /// Things needing attention, counted for a badge.
    pub attention_total: i64,
    /// The eight newest audit events.
    pub recent: Vec<RecentEvent>,
}

pub async fn tenant_stats(state: &AppState, tenant_id: Uuid, days: u32) -> AppResult<TenantStats> {
    if days == 0 || days > MAX_DAYS {
        return Err(AppError::BadRequest(format!(
            "days must be between 1 and {MAX_DAYS}"
        )));
    }
    let loader_state = state.clone();
    let stats = state
        .cache
        .get_or_load(
            &keys::tenant_stats(tenant_id, days),
            STATS_TTL,
            || async move { compute(&loader_state, tenant_id, days).await.map(Some) },
        )
        .await?
        .ok_or_else(|| AppError::Internal("statistics were not computed".into()))?;
    Ok((*stats).clone())
}

async fn compute(state: &AppState, tenant_id: Uuid, days: u32) -> AppResult<TenantStats> {
    let to = Utc::now();
    let first_day = (to - Duration::days(i64::from(days) - 1)).date_naive();
    let from = first_day.and_hms_opt(0, 0, 0).expect("midnight").and_utc();
    // The window before, read in the same pass, gives the deltas.
    let previous_from = from - Duration::days(i64::from(days));
    let mut tx = db::read_tx(&state.db, tenant_id).await?;

    let rows = sqlx::query(
        "SELECT (created_at AT TIME ZONE 'UTC')::date AS day, \
                count(*) FILTER (WHERE success) AS logins, \
                count(*) FILTER (WHERE NOT success) AS failed \
         FROM login_attempts WHERE tenant_id = $1 AND created_at >= $2 \
         GROUP BY day ORDER BY day",
    )
    .bind(tenant_id)
    .bind(previous_from)
    .fetch_all(&mut *tx)
    .await?;
    let mut days_out: Vec<DayStats> = (0..days)
        .map(|i| DayStats {
            date: first_day + Duration::days(i64::from(i)),
            logins: 0,
            failed: 0,
        })
        .collect();
    let mut previous = WindowTotals {
        logins_total: 0,
        failed_total: 0,
    };
    for r in rows {
        let day: NaiveDate = r.get("day");
        if day < first_day {
            previous.logins_total += r.get::<i64, _>("logins");
            previous.failed_total += r.get::<i64, _>("failed");
        } else if let Some(d) = days_out.iter_mut().find(|d| d.date == day) {
            d.logins = r.get("logins");
            d.failed = r.get("failed");
        }
    }
    let logins_total = days_out.iter().map(|d| d.logins).sum();
    let failed_total = days_out.iter().map(|d| d.failed).sum();

    // Live sessions through the partial index of unrevoked ones.
    let active_sessions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sso_sessions \
         WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > now() AND idle_expires_at > now()",
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await?;

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

    // Sidebar counts: one count(*) each, all on the tenant index.
    let count = |sql: &'static str| sqlx::query_scalar::<_, i64>(sql).bind(tenant_id);
    let groups = count("SELECT count(*) FROM groups WHERE tenant_id = $1")
        .fetch_one(&mut *tx)
        .await?;
    let clients = count("SELECT count(*) FROM clients WHERE tenant_id = $1")
        .fetch_one(&mut *tx)
        .await?;
    let webhooks = count("SELECT count(*) FROM webhooks WHERE tenant_id = $1")
        .fetch_one(&mut *tx)
        .await?;
    let keys = count(
        "SELECT count(*) FROM signing_keys WHERE tenant_id = $1 AND status IN ('pending', 'active', 'retiring')",
    )
    .fetch_one(&mut *tx)
    .await?;
    let idps = count(
        "SELECT (SELECT count(*) FROM identity_providers WHERE tenant_id = $1) \
              + (SELECT count(*) FROM saml_identity_providers WHERE tenant_id = $1) \
              + (SELECT count(*) FROM ldap_identity_providers WHERE tenant_id = $1) \
              + (SELECT count(*) FROM kerberos_identity_providers WHERE tenant_id = $1)",
    )
    .fetch_one(&mut *tx)
    .await?;

    // What is waiting on an administrator.
    let locked_users = count(
        "SELECT count(*) FROM users WHERE tenant_id = $1 AND deleted_at IS NULL \
         AND (status = 'locked' OR (locked_until IS NOT NULL AND locked_until > now()))",
    )
    .fetch_one(&mut *tx)
    .await?;
    let invitations = sqlx::query(
        "SELECT count(*) AS n, min(created_at) AS oldest FROM invitations \
         WHERE tenant_id = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()",
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await?;
    let expiring = sqlx::query(
        "SELECT kid, expires_at FROM signing_keys \
         WHERE tenant_id = $1 AND status IN ('active', 'retiring') AND expires_at IS NOT NULL \
           AND expires_at < now() + interval '14 days' \
         ORDER BY expires_at LIMIT 3",
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await?;
    let dead_deliveries = count(
        "SELECT count(*) FROM webhook_deliveries \
         WHERE tenant_id = $1 AND status = 'dead' AND created_at >= now() - interval '7 days'",
    )
    .fetch_one(&mut *tx)
    .await?;
    let attention = Attention {
        locked_users,
        open_invitations: invitations.get("n"),
        oldest_invitation_at: invitations.get("oldest"),
        expiring_keys: expiring
            .into_iter()
            .map(|r| ExpiringKey {
                kid: r.get("kid"),
                expires_at: r.get("expires_at"),
            })
            .collect(),
        dead_deliveries,
    };

    // The newest events, with the users and clients they mention named.
    let events = repos::audit::list(
        &mut *tx,
        Some(tenant_id),
        &AuditFilter::default(),
        None,
        RECENT_EVENTS,
    )
    .await?;
    let ids: Vec<Uuid> = events
        .iter()
        .flat_map(|e| [e.actor_id, e.subject_id])
        .flatten()
        .collect();
    let mut names: std::collections::HashMap<Uuid, String> = std::collections::HashMap::new();
    if !ids.is_empty() {
        for r in sqlx::query(
            "SELECT id, username AS name FROM users WHERE tenant_id = $1 AND id = ANY($2) \
             UNION ALL \
             SELECT id, name FROM clients WHERE tenant_id = $1 AND id = ANY($2)",
        )
        .bind(tenant_id)
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await?
        {
            names.insert(r.get("id"), r.get("name"));
        }
    }
    let recent = events
        .into_iter()
        .take(RECENT_EVENTS as usize)
        .map(|e| RecentEvent {
            id: e.id,
            name: e.name,
            occurred_at: e.occurred_at,
            actor_type: e.actor_type,
            actor: e.actor_id.and_then(|id| names.get(&id).cloned()),
            subject: e.subject_id.and_then(|id| names.get(&id).cloned()),
        })
        .collect();
    tx.commit().await?;
    let users = (*user_counts(state, tenant_id).await?).clone();
    let counts = Counts {
        users: users.total,
        groups,
        clients,
        webhooks,
        keys,
        idps,
    };

    Ok(TenantStats {
        window_days: days,
        from,
        to,
        days: days_out,
        logins_total,
        failed_total,
        previous,
        active_sessions,
        users,
        top_clients,
        counts,
        attention_total: attention.total(),
        attention,
        recent,
    })
}

/// The user counts, cached on their own for longer.
async fn user_counts(state: &AppState, tenant_id: Uuid) -> AppResult<std::sync::Arc<UserStats>> {
    let db = state.db.clone();
    state
        .cache
        .get_or_load(
            &keys::tenant_user_counts(tenant_id),
            USER_COUNTS_TTL,
            || async move {
                let mut tx = db::read_tx(&db, tenant_id).await?;
                let row = sqlx::query(
                    "SELECT count(*) FILTER (WHERE deleted_at IS NULL) AS total, \
                            count(*) FILTER (WHERE deleted_at IS NULL AND status = 'active') AS active, \
                            (SELECT count(DISTINCT c.user_id) FROM credentials c \
                               JOIN users u ON u.tenant_id = c.tenant_id AND u.id = c.user_id \
                               WHERE c.tenant_id = $1 AND u.deleted_at IS NULL \
                                 AND c.type IN ('totp', 'webauthn', 'email_otp', 'sms_otp')) AS mfa_enrolled \
                     FROM users WHERE tenant_id = $1",
                )
                .bind(tenant_id)
                .fetch_one(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(Some(UserStats {
                    total: row.get("total"),
                    active: row.get("active"),
                    mfa_enrolled: row.get("mfa_enrolled"),
                }))
            },
        )
        .await?
        .ok_or_else(|| AppError::Internal("user counts were not computed".into()))
}
