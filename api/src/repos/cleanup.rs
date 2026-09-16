//! Cross-tenant housekeeping deletes (run in a bypass transaction by the
//! `cleanup` job). Every statement is a constant; the cutoff is the only bind.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;

/// Rows deleted per statement, so long-running deletes never hold a table.
pub const BATCH: i64 = 5000;

/// A table with the condition (over `$1`, the cutoff) that makes a row stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub table: &'static str,
    pub stale: &'static str,
    /// Stale rows are kept this long: `Retention` (the deployment setting)
    /// or `Sessions` (a week at most, since nothing lists old sessions).
    pub keep: Keep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keep {
    Retention,
    Sessions,
}

pub const TARGETS: &[Target] = &[
    Target {
        table: "sso_sessions",
        stale: "expires_at < $1 OR (revoked_at IS NOT NULL AND revoked_at < $1)",
        keep: Keep::Sessions,
    },
    Target {
        table: "refresh_tokens",
        stale: "expires_at < $1 OR (revoked_at IS NOT NULL AND revoked_at < $1) OR (consumed_at IS NOT NULL AND consumed_at < $1)",
        keep: Keep::Retention,
    },
    Target {
        table: "login_attempts",
        stale: "created_at < $1",
        keep: Keep::Retention,
    },
    Target {
        table: "outbound_messages",
        stale: "status IN ('sent', 'dead') AND created_at < $1",
        keep: Keep::Retention,
    },
    Target {
        table: "webhook_deliveries",
        stale: "status IN ('delivered', 'dead') AND created_at < $1",
        keep: Keep::Retention,
    },
    Target {
        table: "device_codes",
        stale: "created_at < $1",
        keep: Keep::Retention,
    },
    Target {
        table: "invitations",
        stale: "expires_at < $1 OR (accepted_at IS NOT NULL AND accepted_at < $1) OR (revoked_at IS NOT NULL AND revoked_at < $1)",
        keep: Keep::Retention,
    },
    Target {
        table: "trusted_devices",
        stale: "expires_at < $1 OR (revoked_at IS NOT NULL AND revoked_at < $1)",
        keep: Keep::Retention,
    },
    Target {
        table: "personal_access_tokens",
        stale: "(expires_at IS NOT NULL AND expires_at < $1) OR (revoked_at IS NOT NULL AND revoked_at < $1)",
        keep: Keep::Retention,
    },
    Target {
        table: "scim_tokens",
        stale: "(expires_at IS NOT NULL AND expires_at < $1) OR (revoked_at IS NOT NULL AND revoked_at < $1)",
        keep: Keep::Retention,
    },
];

/// Delete one batch of stale rows of `target`; returns how many went.
pub async fn purge_batch<'e>(
    exec: impl PgExecutor<'e>,
    target: &Target,
    cutoff: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    // Table and condition come from `TARGETS`, never from input.
    let sql = format!(
        "DELETE FROM {t} WHERE id IN (SELECT id FROM {t} WHERE {c} LIMIT {BATCH})",
        t = target.table,
        c = target.stale
    );
    Ok(sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(cutoff)
        .execute(exec)
        .await?
        .rows_affected())
}
