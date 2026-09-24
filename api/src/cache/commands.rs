//! Multi-command Valkey operations on one key, sent as one atomic pipeline
//! (one key: safe under tenant routing and in a cluster alike).

use crate::error::AppError;

use super::CacheConn;

/// Add `member` to the set at `key` and keep the set alive at least `ttl`
/// seconds from now, never shortening a longer life it already has.
pub async fn add_to_set_for_at_least(
    conn: &mut CacheConn,
    key: &str,
    member: &str,
    ttl: i64,
) -> Result<(), AppError> {
    let _: () = redis::pipe()
        .atomic()
        .sadd(key, member)
        .ignore()
        // NX gives a set without a lifetime one; GT only ever lengthens it.
        .cmd("EXPIRE")
        .arg(key)
        .arg(ttl)
        .arg("NX")
        .ignore()
        .cmd("EXPIRE")
        .arg(key)
        .arg(ttl)
        .arg("GT")
        .ignore()
        .query_async(conn)
        .await?;
    Ok(())
}

/// Count one more event in the fixed window at `key` (`window` seconds from
/// its first event) and return the count so far.
pub async fn count_in_window(
    conn: &mut CacheConn,
    key: &str,
    window: i64,
) -> Result<i64, AppError> {
    let (n,): (i64,) = redis::pipe()
        .atomic()
        .incr(key, 1)
        .cmd("EXPIRE")
        .arg(key)
        .arg(window)
        .arg("NX")
        .ignore()
        .query_async(conn)
        .await?;
    Ok(n)
}
