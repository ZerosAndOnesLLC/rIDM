//! Cache topologies and the read pool: `REDIS_URL` forms, the single-node
//! pool working through the topology-neutral connection, read-only
//! transactions refusing writes, and the read pool standing in for the
//! primary when no replica is configured.

mod common;

use common::TestApp;
use ridm_api::cache::{self, Topology};
use ridm_api::db;
use std::time::Duration;

#[tokio::test]
async fn the_single_node_pool_round_trips_through_the_neutral_connection() {
    let app = TestApp::spawn().await;
    assert!(matches!(
        app.state.redis.topology(),
        Topology::Single { .. }
    ));
    let key = format!("ridm:test:topology:{}", app.tenant.id);
    cache::set_ex(&app.state.redis, &key, "v", Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(
        cache::get(&app.state.redis, &key).await.unwrap().as_deref(),
        Some("v")
    );
    cache::del(&app.state.redis, &key).await.unwrap();
    assert_eq!(cache::get(&app.state.redis, &key).await.unwrap(), None);
    cache::ping(&app.state.redis).await.unwrap();
    // The cache layer's invalidation (one DEL per key) and the rate limiter
    // (one script per bucket) are exercised by every other suite.
    let client = app.state.redis.pubsub_client().await.unwrap();
    let mut pubsub = client.get_async_pubsub().await.unwrap();
    pubsub.subscribe("ridm:test:topology").await.unwrap();
}

#[tokio::test]
async fn read_transactions_refuse_writes_and_see_the_tenant() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let mut tx = db::read_tx(&app.state.db, tid).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE tenant_id = $1")
        .bind(tid)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(n, 0);
    let err = sqlx::query(
        "INSERT INTO login_attempts (tenant_id, identifier, success) VALUES ($1, 'x', false)",
    )
    .bind(tid)
    .execute(&mut *tx)
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("read-only"),
        "a write inside a read transaction must fail: {err}"
    );
    tx.rollback().await.unwrap();
    // Without DATABASE_READ_URL the read pool is the primary.
    assert!(app.state.config.database_read_url.is_none());
    db::ping(&app.state.db.all()[0].read).await.unwrap();
}
