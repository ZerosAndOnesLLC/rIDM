//! Where a user has signed in from before (run inside a tenant transaction).

use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::LoginLocation;

const COLUMNS: &str =
    "tenant_id, user_id, country, latitude, longitude, logins, first_seen_at, last_seen_at";

/// The user's locations, most recently seen first. The caller reads both
/// questions off this one list: whether a country is known at all, and where
/// the user was last seen.
pub async fn recent<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    limit: i64,
) -> Result<Vec<LoginLocation>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM user_login_locations WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND user_id = ")
        .push_bind(user_id)
        .push(" ORDER BY last_seen_at DESC LIMIT ")
        .push_bind(limit);
    qb.build_query_as::<LoginLocation>().fetch_all(exec).await
}

/// Record a sign-in from `country`. Coordinates overwrite the ones held for
/// that country (they are the last place the user was seen in it), and a
/// source that has none leaves what is there.
pub async fn record<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    country: &str,
    latitude: Option<f64>,
    longitude: Option<f64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO user_login_locations (tenant_id, user_id, country, latitude, longitude) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (tenant_id, user_id, country) DO UPDATE SET \
            latitude = COALESCE(EXCLUDED.latitude, user_login_locations.latitude), \
            longitude = COALESCE(EXCLUDED.longitude, user_login_locations.longitude), \
            logins = user_login_locations.logins + 1, \
            last_seen_at = now()",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(country)
    .bind(latitude)
    .bind(longitude)
    .execute(exec)
    .await?;
    Ok(())
}
