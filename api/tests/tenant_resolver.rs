mod common;

use std::time::Duration;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use common::{TestApp, create_tenant};
use ridm_api::cache::{CacheLayer, keys};
use ridm_api::db;
use ridm_api::middleware::{TenantCtx, tenant_cache_keys};
use ridm_api::state::AppState;
use uuid::Uuid;

fn probe_routes() -> Router<AppState> {
    Router::new().route(
        "/t/{slug}/probe",
        get(|State(state): State<AppState>, ctx: TenantCtx| async move {
            Json(serde_json::json!({
                "id": ctx.id(),
                "slug": ctx.slug(),
                "issuer": ctx.issuer(&state),
            }))
        }),
    )
}

#[tokio::test]
async fn resolves_known_tenant_and_rejects_unknown() {
    let app = TestApp::spawn_with(probe_routes()).await;

    let res = app.http.get(app.tenant_url("/probe")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["id"], app.tenant.id.to_string());
    assert_eq!(body["slug"], app.tenant.slug);
    assert_eq!(
        body["issuer"],
        format!("{}/t/{}", app.base_url, app.tenant.slug)
    );

    for bad in ["nope-does-not-exist", "Bad_Slug", "-x", "a%20b"] {
        let res = app
            .http
            .get(app.url(&format!("/t/{bad}/probe")))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 404, "slug {bad:?}");
        assert_eq!(
            res.headers()["content-type"],
            "application/problem+json",
            "slug {bad:?}"
        );
    }
}

#[tokio::test]
async fn tenant_is_cached_and_invalidation_takes_effect() {
    let app = TestApp::spawn_with(probe_routes()).await;
    let key = keys::tenant_by_slug(&app.tenant.slug);

    assert!(
        app.state
            .cache
            .l1()
            .get::<ridm_api::models::Tenant>(&key)
            .is_none()
    );
    let res = app.http.get(app.tenant_url("/probe")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let cached = app
        .state
        .cache
        .l1()
        .get::<ridm_api::models::Tenant>(&key)
        .expect("tenant in L1 after first request");
    assert_eq!(cached.id, app.tenant.id);

    // Disable the tenant behind the cache's back: still served from cache.
    sqlx::query("UPDATE tenants SET status = 'disabled' WHERE id = $1")
        .bind(app.tenant.id)
        .execute(&app.state.db)
        .await
        .unwrap();
    let res = app.http.get(app.tenant_url("/probe")).send().await.unwrap();
    assert_eq!(
        res.status(),
        200,
        "stale cache is expected until invalidated"
    );

    // Invalidate the way a write path does: now the disabled state is visible.
    app.state
        .cache
        .invalidate(&tenant_cache_keys(&cached))
        .await
        .unwrap();
    let res = app.http.get(app.tenant_url("/probe")).send().await.unwrap();
    assert_eq!(res.status(), 403);
}

#[tokio::test]
async fn unknown_slug_is_negatively_cached() {
    let app = TestApp::spawn_with(probe_routes()).await;
    let slug = format!("ghost-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let url = app.url(&format!("/t/{slug}/probe"));

    assert_eq!(app.http.get(&url).send().await.unwrap().status(), 404);
    // Create it now; the negative entry still answers until invalidated.
    sqlx::query("INSERT INTO tenants (slug, display_name) VALUES ($1, $1)")
        .bind(&slug)
        .execute(&app.state.db)
        .await
        .unwrap();
    assert_eq!(app.http.get(&url).send().await.unwrap().status(), 404);
    app.state
        .cache
        .invalidate(&[keys::tenant_by_slug(&slug)])
        .await
        .unwrap();
    assert_eq!(app.http.get(&url).send().await.unwrap().status(), 200);
}

#[tokio::test]
async fn invalidation_propagates_between_nodes() {
    let app = TestApp::spawn().await;

    // Two independent "nodes" sharing one Redis.
    let node_a = app.state.cache.clone();
    let node_b = CacheLayer::new(app.state.redis.clone());
    let listener = node_a.spawn_invalidation_listener();
    // Give the subscriber time to connect before publishing.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let key = format!("ridm:test:{}", Uuid::new_v4());
    let value = node_a
        .get_or_load(&key, Duration::from_secs(60), || async {
            Ok(Some("hello".to_string()))
        })
        .await
        .unwrap();
    assert_eq!(value.as_deref(), Some(&"hello".to_string()));
    assert!(node_a.l1().get::<String>(&key).is_some());

    node_b.invalidate(std::slice::from_ref(&key)).await.unwrap();

    let mut evicted = false;
    for _ in 0..50 {
        if node_a.l1().get::<String>(&key).is_none() {
            evicted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    listener.abort();
    assert!(
        evicted,
        "node A's L1 must be evicted by node B's invalidation"
    );

    // Redis copy is gone too, so the loader runs again.
    let reloaded = node_a
        .get_or_load(&key, Duration::from_secs(60), || async {
            Ok(Some("reloaded".to_string()))
        })
        .await
        .unwrap();
    assert_eq!(reloaded.as_deref(), Some(&"reloaded".to_string()));
}

#[tokio::test]
async fn rls_transactions_isolate_tenants() {
    let app = TestApp::spawn().await;
    let other = create_tenant(&app.state.db).await;

    // Insert through a tenant-bound transaction.
    let mut tx = db::tenant_tx(&app.state.db, app.tenant.id).await.unwrap();
    sqlx::query("INSERT INTO users (tenant_id, username) VALUES ($1, 'alice')")
        .bind(app.tenant.id)
        .execute(&mut *tx)
        .await
        .unwrap();
    // A row for another tenant is rejected by the policy even inside the tx.
    let cross = sqlx::query("INSERT INTO users (tenant_id, username) VALUES ($1, 'mallory')")
        .bind(other.id)
        .execute(&mut *tx)
        .await;
    assert!(cross.is_err(), "cross-tenant insert must violate RLS");
    tx.rollback().await.unwrap();

    let mut tx = db::tenant_tx(&app.state.db, app.tenant.id).await.unwrap();
    sqlx::query("INSERT INTO users (tenant_id, username) VALUES ($1, 'alice')")
        .bind(app.tenant.id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let count_in = |tenant: Uuid| {
        let db = app.state.db.clone();
        async move {
            let mut tx = db::tenant_tx(&db, tenant).await.unwrap();
            let n: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            n
        }
    };
    assert_eq!(count_in(app.tenant.id).await, 1);
    assert_eq!(count_in(other.id).await, 0);

    // No tenant bound: the pool sees nothing at all.
    let unbound: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE tenant_id = $1")
        .bind(app.tenant.id)
        .fetch_one(&app.state.db)
        .await
        .unwrap();
    assert_eq!(unbound, 0);

    // Explicit bypass sees it.
    let mut tx = db::bypass_tx(&app.state.db).await.unwrap();
    let bypass: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE tenant_id = $1")
        .bind(app.tenant.id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(bypass, 1);

    // The binding was transaction-local: the same pool is clean afterwards.
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE tenant_id = $1")
        .bind(app.tenant.id)
        .fetch_one(&app.state.db)
        .await
        .unwrap();
    assert_eq!(after, 0);
}
