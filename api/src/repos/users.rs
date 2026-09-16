//! Tenant-scoped user queries. Callers run these inside a tenant-bound
//! transaction (see `db::tenant_tx`); RLS hides every other tenant's rows and
//! `tenant_id` predicates are still included so indexes are used.

use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{NewUser, User, UserFilter, UserStatus, UserUpdate};
use crate::util::cursor::Cursor;

const COLUMNS: &str = "id, tenant_id, org_id, username, email, email_verified, phone, phone_verified, \
    password_hash, password_algo, must_change_password, password_expires_at, password_changed_at, \
    status, attributes, locale, last_login_at, failed_attempts, locked_until, deleted_at, \
    terms_accepted_at, created_at, updated_at";

pub async fn find_by_id<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<User>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM users WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<User>().fetch_optional(exec).await
}

/// Active (not soft-deleted) user by normalized username.
pub async fn find_by_username<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    username: &str,
) -> Result<Option<User>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM users WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND username = ")
        .push_bind(username)
        .push(" AND deleted_at IS NULL");
    qb.build_query_as::<User>().fetch_optional(exec).await
}

/// Active (not soft-deleted) user by normalized email.
pub async fn find_by_email<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    email: &str,
) -> Result<Option<User>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM users WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND email = ")
        .push_bind(email)
        .push(" AND deleted_at IS NULL");
    qb.build_query_as::<User>().fetch_optional(exec).await
}

/// Username or email, for login identifiers.
pub async fn find_by_identifier<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    identifier: &str,
) -> Result<Option<User>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM users WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND (username = ")
        .push_bind(identifier)
        .push(" OR email = ")
        .push_bind(identifier)
        .push(") AND deleted_at IS NULL LIMIT 1");
    qb.build_query_as::<User>().fetch_optional(exec).await
}

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    input: &NewUser,
) -> Result<User, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO users (id, tenant_id, org_id, username, email, email_verified, phone, \
         phone_verified, status, attributes, locale) VALUES (",
    );
    let mut sep = qb.separated(", ");
    sep.push_bind(id)
        .push_bind(tenant_id)
        .push_bind(input.org_id)
        .push_bind(&input.username)
        .push_bind(&input.email)
        .push_bind(input.email_verified)
        .push_bind(&input.phone)
        .push_bind(input.phone_verified)
        .push_bind(input.status.unwrap_or(UserStatus::Active))
        .push_bind(
            input
                .attributes
                .clone()
                .unwrap_or_else(|| serde_json::Value::Object(Default::default())),
        )
        .push_bind(&input.locale);
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<User>().fetch_one(exec).await
}

pub async fn update<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    patch: &UserUpdate,
) -> Result<Option<User>, sqlx::Error> {
    let mut qb = QueryBuilder::new("UPDATE users SET updated_at = now()");
    if let Some(v) = &patch.username {
        qb.push(", username = ").push_bind(v);
    }
    if let Some(v) = &patch.email {
        qb.push(", email = ").push_bind(v.clone());
        if v.is_none() {
            qb.push(", email_verified = false");
        }
    }
    if let Some(v) = patch.email_verified {
        qb.push(", email_verified = ").push_bind(v);
    }
    if let Some(v) = &patch.phone {
        qb.push(", phone = ").push_bind(v.clone());
        if v.is_none() {
            qb.push(", phone_verified = false");
        }
    }
    if let Some(v) = patch.phone_verified {
        qb.push(", phone_verified = ").push_bind(v);
    }
    if let Some(v) = patch.status {
        qb.push(", status = ").push_bind(v);
    }
    if let Some(v) = &patch.attributes {
        qb.push(", attributes = ").push_bind(v.clone());
    }
    if let Some(v) = &patch.locale {
        qb.push(", locale = ").push_bind(v.clone());
    }
    if let Some(v) = &patch.org_id {
        qb.push(", org_id = ").push_bind(*v);
    }
    if let Some(v) = patch.must_change_password {
        qb.push(", must_change_password = ").push_bind(v);
    }
    qb.push(" WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id)
        .push(" AND deleted_at IS NULL RETURNING ")
        .push(COLUMNS);
    qb.build_query_as::<User>().fetch_optional(exec).await
}

/// Soft delete: frees the username/email for reuse and hides the user from
/// lookups. The purge job removes the row later.
pub async fn soft_delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE users SET status = 'deleted', deleted_at = now(), updated_at = now() \
         WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Remove soft-deleted rows older than `before`; attached rows cascade.
pub async fn purge_deleted<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    before: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        "DELETE FROM users WHERE tenant_id = $1 AND deleted_at IS NOT NULL AND deleted_at < $2",
    )
    .bind(tenant_id)
    .bind(before)
    .execute(exec)
    .await?;
    Ok(res.rows_affected())
}

pub async fn hard_delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM users WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn set_password<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    hash: &str,
    algo: &str,
    must_change: bool,
    expires_at: Option<DateTime<Utc>>,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE users SET password_hash = $3, password_algo = $4, must_change_password = $5, \
         password_expires_at = $6, password_changed_at = now(), failed_attempts = 0, \
         locked_until = NULL, updated_at = now() \
         WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(hash)
    .bind(algo)
    .bind(must_change)
    .bind(expires_at)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn record_login_success<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE users SET last_login_at = now(), failed_attempts = 0, locked_until = NULL \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(())
}

/// Increment the failure counter and lock when `lock_after` is reached.
/// Returns the new failure count.
pub async fn record_login_failure<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    lock_after: i32,
    lock_for_secs: i64,
) -> Result<i32, sqlx::Error> {
    sqlx::query_scalar::<_, i32>(
        "UPDATE users SET failed_attempts = failed_attempts + 1, \
         locked_until = CASE WHEN failed_attempts + 1 >= $3 \
                             THEN now() + make_interval(secs => $4) ELSE locked_until END \
         WHERE tenant_id = $1 AND id = $2 RETURNING failed_attempts",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(lock_after)
    .bind(lock_for_secs as f64)
    .fetch_one(exec)
    .await
}

pub async fn unlock<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL, \
         status = CASE WHEN status = 'locked' THEN 'active' ELSE status END, updated_at = now() \
         WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Keyset-paginated list; fetches `limit + 1` rows.
pub async fn list<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    filter: &UserFilter,
    after: Option<Cursor>,
    limit: i64,
) -> Result<Vec<User>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM users WHERE tenant_id = ")
        .push_bind(tenant_id);
    if !filter.include_deleted {
        qb.push(" AND deleted_at IS NULL");
    }
    if let Some(status) = filter.status {
        qb.push(" AND status = ").push_bind(status);
    }
    if let Some(org) = filter.org_id {
        qb.push(" AND org_id = ").push_bind(org);
    }
    if let Some(search) = filter
        .search
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let pattern = format!("{}%", escape_like(&search.to_lowercase()));
        qb.push(" AND (username LIKE ")
            .push_bind(pattern.clone())
            .push(" OR email LIKE ")
            .push_bind(pattern)
            .push(")");
    }
    if let Some(c) = after {
        qb.push(" AND (created_at, id) > (")
            .push_bind(c.created_at)
            .push(", ")
            .push_bind(c.id)
            .push(")");
    }
    qb.push(" ORDER BY created_at, id LIMIT ")
        .push_bind(limit + 1);
    qb.build_query_as::<User>().fetch_all(exec).await
}

pub async fn count<'e>(exec: impl PgExecutor<'e>, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM users WHERE tenant_id = $1 AND deleted_at IS NULL")
        .bind(tenant_id)
        .fetch_one(exec)
        .await
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

pub async fn set_terms_accepted<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE users SET terms_accepted_at = now(), updated_at = now() \
         WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}
