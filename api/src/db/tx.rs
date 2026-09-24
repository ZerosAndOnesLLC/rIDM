//! Transactions bound to a tenant for row level security.
//!
//! Every tenant-scoped table has a forced RLS policy keyed on the
//! `app.tenant_id` setting. These helpers open a transaction and bind that
//! setting with `set_config(..., is_local = true)`, so it resets at
//! commit/rollback and can never leak to the next user of the pooled connection.
//!
//! The transaction opens and its setting is bound in one round trip: the
//! `BEGIN` and the `set_config` go to the server as one simple query.
//!
//! A tenant's transactions open on the database it lives in ([`Db::locate`]);
//! a bypass transaction names its database, since cross-tenant work runs
//! over every one of them ([`Db::all`]).

use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::Db;

pub type Tx = Transaction<'static, Postgres>;

/// The statement that opens a transaction bound to `tenant_id`. A uuid
/// prints as hex digits and dashes only, so it goes into the text as is.
fn begin_bound(tenant_id: Uuid, read_only: bool) -> sqlx::AssertSqlSafe<String> {
    let mode = if read_only { " READ ONLY" } else { "" };
    sqlx::AssertSqlSafe(format!(
        "BEGIN{mode}; SELECT set_config('app.tenant_id', '{tenant_id}', true)"
    ))
}

/// Begin a transaction that can only see rows of `tenant_id`.
pub async fn tenant_tx(db: &Db, tenant_id: Uuid) -> Result<Tx, sqlx::Error> {
    db.locate(tenant_id)
        .await?
        .primary
        .begin_with(begin_bound(tenant_id, false))
        .await
}

/// Begin a read-only transaction bound to `tenant_id` — for listings and
/// statistics, on the replica pool when the deployment has one. A write
/// inside it fails, so a query routed here by mistake cannot change data.
/// Never for loading a cache: a replica behind a write would put the old
/// value back right after the write evicted it.
pub async fn read_tx(db: &Db, tenant_id: Uuid) -> Result<Tx, sqlx::Error> {
    db.locate(tenant_id)
        .await?
        .read
        .begin_with(begin_bound(tenant_id, true))
        .await
}

/// Begin a transaction on `db` that sees every tenant in it. Only for
/// explicitly global operations (bootstrap, cross-tenant admin, background
/// jobs); callers must audit what they touch.
pub async fn bypass_tx(db: &PgPool) -> Result<Tx, sqlx::Error> {
    db.begin_with("BEGIN; SELECT set_config('app.bypass_rls', 'on', true)")
        .await
}

/// Bind `tenant_id` on an already-open transaction.
pub async fn bind_tenant(conn: &mut PgConnection, tenant_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(conn)
        .await?;
    Ok(())
}
