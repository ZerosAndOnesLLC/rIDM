//! Per-tenant caps on configuration collections. Their lists are read whole
//! (the console, the tenant document, token issuance), so each is bounded
//! here, at creation, rather than paginated.

use sqlx::PgExecutor;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

/// A collection and how many rows one tenant may have in it.
#[derive(Debug, Clone, Copy)]
pub struct Cap {
    table: &'static str,
    /// Extra condition on the rows that count (e.g. only live ones).
    live: &'static str,
    pub max: i64,
    what: &'static str,
}

pub const GROUPS: Cap = Cap {
    table: "groups",
    live: "",
    max: 10_000,
    what: "groups",
};
pub const ROLES: Cap = Cap {
    table: "roles",
    live: "",
    max: 5_000,
    what: "roles",
};
pub const SCOPES: Cap = Cap {
    table: "scopes",
    live: "",
    max: 1_000,
    what: "scopes",
};
pub const RESOURCE_SERVERS: Cap = Cap {
    table: "resource_servers",
    live: "",
    max: 1_000,
    what: "resource servers",
};
pub const IP_RULES: Cap = Cap {
    table: "ip_rules",
    live: "",
    max: 1_000,
    what: "IP rules",
};
pub const WEBHOOKS: Cap = Cap {
    table: "webhooks",
    live: "",
    max: 100,
    what: "webhooks",
};
/// Live (unrevoked) tokens only.
pub const SCIM_TOKENS: Cap = Cap {
    table: "scim_tokens",
    live: " AND revoked_at IS NULL",
    max: 100,
    what: "SCIM tokens",
};

/// Refuse another row of `cap` once the tenant has `cap.max` of them. Run
/// inside the creating transaction.
pub async fn ensure_room<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    cap: Cap,
) -> AppResult<()> {
    // `cap` is one of the constants above, never input.
    let sql = format!(
        "SELECT count(*) FROM {} WHERE tenant_id = $1{}",
        cap.table, cap.live
    );
    let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(tenant_id)
        .fetch_one(exec)
        .await?;
    if n >= cap.max {
        return Err(AppError::BadRequest(format!(
            "a tenant can have at most {} {}",
            cap.max, cap.what
        )));
    }
    Ok(())
}
