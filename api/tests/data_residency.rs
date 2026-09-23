//! Data residency (13.7): tenants placed in regional databases (and a
//! regional Valkey) keep every row and key there, and `ridm-api move-tenant`
//! moves one between databases and back without losing a row.
//!
//! Every test runs a node with two regions of its own: `eu-…` on a
//! throwaway database with its own Valkey database, `us-…` on another
//! throwaway database sharing the home Valkey. The home database is the
//! shared test database; the tenants a test registers there are removed
//! when it ends, since other test binaries walk every tenant.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use axum::http::StatusCode;
use common::admin::{admin_token, call, get_json, user_with_role};
use common::throwaway::ThrowawayDb;
use common::{TestApp, infra};
use redis::AsyncCommands as _;
use reqwest::Method;
use ridm_api::cache::keys;
use ridm_api::config::RegionConfig;
use ridm_api::db;
use ridm_api::models::{MASTER_TENANT_ID, NewGroup, NewScimToken};
use ridm_api::repos;
use ridm_api::services::admin_access::OWNER_ROLE;
use ridm_api::services::relocation::{MoveOptions, move_tenant};
use ridm_api::services::{groups, opaque_tokens, scim_tokens, tenants, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use sqlx::Connection as _;
use uuid::Uuid;

/// The Valkey database the `eu` region keeps its keys in.
const EU_VALKEY_DB: u8 = 12;

struct Fx {
    app: TestApp,
    /// Superuser URL of the shared home database.
    home_url: String,
    eu: String,
    us: String,
    prefix: String,
    eu_db: ThrowawayDb,
    us_db: ThrowawayDb,
    _registry: RegistryCleanup,
}

/// Removes the tenants a test registered in the shared home database.
struct RegistryCleanup {
    prefix: String,
}

impl Drop for RegistryCleanup {
    fn drop(&mut self) {
        let prefix = self.prefix.clone();
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let infra = infra().await;
                if let Ok(mut c) = sqlx::PgConnection::connect(&infra.admin_url).await {
                    let _ = sqlx::query("DELETE FROM tenants WHERE slug LIKE $1")
                        .bind(format!("{prefix}%"))
                        .execute(&mut c)
                        .await;
                }
            });
        })
        .join();
    }
}

async fn fixture() -> Fx {
    let infra = infra().await;
    let tag = &Uuid::new_v4().simple().to_string()[..8];
    let (eu, us) = (format!("eu-{tag}"), format!("us-{tag}"));
    let eu_db = ThrowawayDb::new(true).await;
    let us_db = ThrowawayDb::new(true).await;
    let (eu_url, us_url) = (eu_db.app_url().await, us_db.app_url().await);
    let eu_valkey = format!("{}/{EU_VALKEY_DB}", infra.redis_url.trim_end_matches('/'));
    let regions = vec![
        RegionConfig {
            name: eu.clone(),
            database_url: eu_url,
            database_read_url: None,
            redis_url: Some(eu_valkey),
        },
        RegionConfig {
            name: us.clone(),
            database_url: us_url,
            database_read_url: None,
            redis_url: None,
        },
    ];
    let app = TestApp::spawn_reconfigured(
        axum::Router::new(),
        move |c| c.data_regions = regions,
        |_| {},
    )
    .await;
    let prefix = format!("rz-{tag}-");
    Fx {
        app,
        home_url: infra.admin_url.clone(),
        eu,
        us,
        _registry: RegistryCleanup {
            prefix: prefix.clone(),
        },
        prefix,
        eu_db,
        us_db,
    }
}

impl Fx {
    fn slug(&self, name: &str) -> String {
        format!("{}{name}", self.prefix)
    }

    async fn global(&self) -> String {
        admin_token(&self.app, MASTER_TENANT_ID, OWNER_ROLE).await
    }

    /// Create a tenant through the admin API; returns its id.
    async fn tenant(&self, name: &str, region: Option<&str>) -> Uuid {
        let token = self.global().await;
        let (status, body, _) = call(
            &self.app,
            Method::POST,
            "/admin/tenants",
            Some(&token),
            Some(&json!({
                "slug": self.slug(name),
                "display_name": name,
                "data_region": region,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["data_region"], json!(region));
        body["id"].as_str().unwrap().parse().unwrap()
    }

    /// Superuser URL of a database: row level security does not hide rows.
    fn superuser_url(&self, region: Option<&str>) -> String {
        match region {
            None => self.home_url.clone(),
            Some(r) if r == self.eu => self.eu_db.url.clone(),
            Some(r) if r == self.us => self.us_db.url.clone(),
            Some(r) => panic!("no region {r}"),
        }
    }

    /// The tenant's rows per tenant-scoped table in a database.
    async fn rows(&self, region: Option<&str>, tenant_id: Uuid) -> BTreeMap<String, i64> {
        let mut c = sqlx::PgConnection::connect(&self.superuser_url(region))
            .await
            .unwrap();
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition \
               AND c.relname <> 'tenants' AND EXISTS (SELECT 1 FROM pg_attribute a \
               WHERE a.attrelid = c.oid AND a.attname = 'tenant_id') ORDER BY 1",
        )
        .fetch_all(&mut c)
        .await
        .unwrap();
        let mut out = BTreeMap::new();
        for t in tables {
            let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT count(*) FROM \"{t}\" WHERE tenant_id = $1"
            )))
            .bind(tenant_id)
            .fetch_one(&mut c)
            .await
            .unwrap();
            if n > 0 {
                out.insert(t, n);
            }
        }
        out
    }

    /// Whether a database holds a `tenants` row for the tenant, and its flags.
    async fn tenant_row(&self, region: Option<&str>, id: Uuid) -> Option<(Option<String>, bool)> {
        let mut c = sqlx::PgConnection::connect(&self.superuser_url(region))
            .await
            .unwrap();
        sqlx::query_as("SELECT data_region, registry_only FROM tenants WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut c)
            .await
            .unwrap()
    }

    /// Wait for the audit writer to land `name` for the tenant in a database.
    async fn audited(&self, region: Option<&str>, tenant_id: Uuid, name: &str) {
        let mut c = sqlx::PgConnection::connect(&self.superuser_url(region))
            .await
            .unwrap();
        for _ in 0..100 {
            let n: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND name = $2",
            )
            .bind(tenant_id)
            .bind(name)
            .fetch_one(&mut c)
            .await
            .unwrap();
            if n > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("{name} never audited for {tenant_id} in {region:?}");
    }

    async fn move_to(
        &self,
        slug: &str,
        region: Option<&str>,
    ) -> ridm_api::services::relocation::MoveReport {
        move_tenant(
            &self.app.state,
            slug,
            region,
            &MoveOptions {
                drain: Duration::ZERO,
            },
        )
        .await
        .unwrap()
    }
}

async fn valkey(db: u8) -> redis::aio::MultiplexedConnection {
    let base = infra().await.redis_url.trim_end_matches('/').to_string();
    redis::Client::open(format!("{base}/{db}"))
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap()
}

async fn has_key(db: u8, key: &str) -> bool {
    let mut c = valkey(db).await;
    c.exists(key).await.unwrap()
}

#[tokio::test]
async fn a_regional_tenant_keeps_every_row_in_its_region() {
    let fx = fixture().await;
    let id = fx.tenant("acme", Some(&fx.eu)).await;

    // The home database holds the registry row and nothing else of it.
    assert_eq!(
        fx.tenant_row(None, id).await,
        Some((Some(fx.eu.clone()), true))
    );
    assert_eq!(fx.rows(None, id).await, BTreeMap::new(), "nothing in home");
    // The region holds its copy of the row and everything seeded for it.
    assert_eq!(
        fx.tenant_row(Some(&fx.eu), id).await,
        Some((Some(fx.eu.clone()), false))
    );
    let eu = fx.rows(Some(&fx.eu), id).await;
    for seeded in ["roles", "scopes", "clients", "permission_assignments"] {
        assert!(eu.get(seeded).copied().unwrap_or(0) > 0, "{seeded}: {eu:?}");
    }
    assert_eq!(fx.tenant_row(Some(&fx.us), id).await, None);
    assert_eq!(fx.rows(Some(&fx.us), id).await, BTreeMap::new());

    // Work done through the services lands there too, audit trail included.
    let user = user_with_role(&fx.app, id, None).await;
    assert_eq!(users::get(&fx.app.state, id, user).await.unwrap().id, user);
    fx.audited(Some(&fx.eu), id, "user.created").await;
    fx.audited(Some(&fx.eu), id, "tenant.created").await;
    assert_eq!(
        fx.rows(None, id).await,
        BTreeMap::new(),
        "still nothing in home"
    );
    let eu = fx.rows(Some(&fx.eu), id).await;
    assert_eq!(eu.get("users"), Some(&1));

    // The tenant's audit chain verifies where it lives.
    let tenant_owner = admin_token(&fx.app, id, OWNER_ROLE).await;
    let (status, body, _) = get_json(
        &fx.app,
        &format!("/admin/tenants/{}/audit/verify", fx.slug("acme")),
        Some(&tenant_owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["valid"], true, "{body}");

    // A SCIM token names no tenant; its lookup finds it in the region.
    let scim = scim_tokens::create(
        &fx.app.state,
        id,
        Actor::System,
        NewScimToken {
            name: "idp".into(),
            expires_in_days: None,
        },
    )
    .await
    .unwrap();
    let res = fx
        .app
        .http
        .get(fx.app.url(&format!("/scim/v2/{}/Users", fx.slug("acme"))))
        .bearer_auth(&scim.token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn tenant_keys_go_to_the_regions_valkey() {
    let fx = fixture().await;
    let eu_tenant = fx.tenant("keys-eu", Some(&fx.eu)).await;
    let us_tenant = fx.tenant("keys-us", Some(&fx.us)).await;
    let state = &fx.app.state;
    let (eu_key, us_key) = (keys::scopes(eu_tenant), keys::scopes(us_tenant));
    for k in [&eu_key, &us_key] {
        ridm_api::cache::set_ex(&state.redis, k, "x", Duration::from_secs(60))
            .await
            .unwrap();
    }
    // `eu` has a Valkey of its own; `us` shares the home one.
    assert!(has_key(EU_VALKEY_DB, &eu_key).await);
    assert!(!has_key(0, &eu_key).await);
    assert!(has_key(0, &us_key).await);
    assert!(!has_key(EU_VALKEY_DB, &us_key).await);
    // Reads come back through the same routing.
    assert_eq!(
        ridm_api::cache::get(&state.redis, &eu_key)
            .await
            .unwrap()
            .as_deref(),
        Some("x")
    );

    // An opaque access token: the claims stay in the region, the
    // deployment-wide entry only names the tenant.
    let claims: serde_json::Map<String, Value> = serde_json::from_value(json!({
        "tid": eu_tenant.to_string(),
        "sub": "someone",
        "exp": chrono::Utc::now().timestamp() + 60,
    }))
    .unwrap();
    let token = opaque_tokens::issue(
        state,
        &claims,
        chrono::Utc::now() + chrono::Duration::seconds(60),
    )
    .await
    .unwrap();
    let mut eu_valkey = valkey(EU_VALKEY_DB).await;
    let in_region: Vec<String> = eu_valkey
        .keys(format!("ridm:t:{eu_tenant}:at:*"))
        .await
        .unwrap();
    assert_eq!(in_region.len(), 1);
    let (tid, back) = opaque_tokens::lookup(state, &token).await.unwrap().unwrap();
    assert_eq!(tid, eu_tenant);
    assert_eq!(back["sub"], "someone");
    opaque_tokens::revoke(state, &token).await.unwrap();
    assert!(
        opaque_tokens::lookup(state, &token)
            .await
            .unwrap()
            .is_none()
    );
    let left: Vec<String> = eu_valkey
        .keys(format!("ridm:t:{eu_tenant}:at:*"))
        .await
        .unwrap();
    assert!(left.is_empty());
}

#[tokio::test]
async fn regions_are_listed_checked_and_refused_when_unknown() {
    let fx = fixture().await;
    fx.tenant("listed", Some(&fx.eu)).await;
    let token = fx.global().await;
    let (status, body, _) = get_json(&fx.app, "/admin/regions", Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let regions = body.as_array().unwrap();
    assert_eq!(regions[0]["name"], "home");
    assert_eq!(regions[0]["home"], true);
    let eu = regions
        .iter()
        .find(|r| r["name"] == fx.eu.as_str())
        .unwrap();
    assert_eq!(eu["dedicated_cache"], true);
    assert_eq!(eu["tenants"], 1);
    let us = regions
        .iter()
        .find(|r| r["name"] == fx.us.as_str())
        .unwrap();
    assert_eq!(us["dedicated_cache"], false);

    // A tenant-scoped administrator may not ask.
    let own = admin_token(&fx.app, fx.app.tenant.id, OWNER_ROLE).await;
    let (status, _, _) = get_json(&fx.app, "/admin/regions", Some(&own)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A region this deployment does not have is refused, and nothing is registered.
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        "/admin/tenants",
        Some(&token),
        Some(&json!({"slug": fx.slug("nowhere"), "display_name": "x", "data_region": "mars"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        repos::tenants::find_by_slug(fx.app.state.db.home(), &fx.slug("nowhere"))
            .await
            .unwrap()
            .is_none()
    );

    // Readiness reports each region without depending on it.
    let res = fx.app.http.get(fx.app.url("/readyz")).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["checks"]["regions"][&fx.eu]["database"], "ok",
        "{body}"
    );
    assert_eq!(body["checks"]["regions"][&fx.us]["cache"], "ok", "{body}");
}

#[tokio::test]
async fn a_tenant_moves_between_regions_and_back_without_losing_anything() {
    let fx = fixture().await;
    let slug = fx.slug("mover");
    let id = fx.tenant("mover", None).await;
    let state = &fx.app.state;
    let user = user_with_role(&fx.app, id, None).await;
    // A parent and a child group: the one table that references itself.
    let parent = groups::create(
        state,
        id,
        Actor::System,
        NewGroup {
            name: "parent".into(),
            parent_id: None,
            description: None,
            attributes: None,
        },
    )
    .await
    .unwrap();
    groups::create(
        state,
        id,
        Actor::System,
        NewGroup {
            name: "child".into(),
            parent_id: Some(parent.id),
            description: None,
            attributes: None,
        },
    )
    .await
    .unwrap();
    let session_key = keys::sso_session(id, Uuid::now_v7());
    ridm_api::cache::set_ex(&state.redis, &session_key, "{}", Duration::from_secs(600))
        .await
        .unwrap();
    fx.audited(None, id, "group.created").await;
    let before = fx.rows(None, id).await;
    assert!(before.contains_key("users") && before.get("groups") == Some(&2));

    // home → eu, which has a Valkey of its own.
    let report = fx.move_to(&slug, Some(&fx.eu)).await;
    assert_eq!(report.from, "home");
    assert_eq!(report.to, fx.eu);
    assert_eq!(
        report
            .rows
            .iter()
            .filter(|(_, n)| **n > 0)
            .map(|(t, n)| (t.clone(), *n))
            .collect::<BTreeMap<_, _>>(),
        before
    );
    assert!(report.audit_rows_verified > 0);
    assert!(
        report.cache_keys >= 1,
        "the session and whatever the tenant had cached"
    );
    assert_eq!(report.cleaned, vec!["home".to_string()]);
    assert_eq!(
        fx.tenant_row(None, id).await,
        Some((Some(fx.eu.clone()), true))
    );
    assert_eq!(
        fx.rows(None, id).await,
        BTreeMap::new(),
        "home keeps only the registry row"
    );
    let eu = fx.rows(Some(&fx.eu), id).await;
    for (table, n) in &before {
        assert!(eu.get(table).copied().unwrap_or(0) >= *n, "{table}: {eu:?}");
    }
    assert!(has_key(EU_VALKEY_DB, &session_key).await);
    assert!(!has_key(0, &session_key).await);
    let mut v = valkey(EU_VALKEY_DB).await;
    let ttl: i64 = v.ttl(&session_key).await.unwrap();
    assert!(ttl > 0 && ttl <= 600, "the key keeps its lifetime: {ttl}");
    assert_eq!(users::get(state, id, user).await.unwrap().id, user);
    fx.audited(Some(&fx.eu), id, "tenant.moved").await;

    // eu → us: from one region to another, and back to the shared Valkey.
    let report = fx.move_to(&slug, Some(&fx.us)).await;
    assert_eq!(report.cleaned, vec![fx.eu.clone()]);
    assert_eq!(
        fx.tenant_row(Some(&fx.eu), id).await,
        None,
        "eu keeps nothing"
    );
    assert_eq!(fx.rows(Some(&fx.eu), id).await, BTreeMap::new());
    assert_eq!(
        fx.tenant_row(Some(&fx.us), id).await,
        Some((Some(fx.us.clone()), false))
    );
    assert!(has_key(0, &session_key).await);
    assert!(!has_key(EU_VALKEY_DB, &session_key).await);

    // us → home: the registry row holds the data again.
    let report = fx.move_to(&slug, None).await;
    assert_eq!(report.cache_keys, 0, "us and home share a Valkey");
    assert_eq!(fx.tenant_row(None, id).await, Some((None, false)));
    assert_eq!(fx.tenant_row(Some(&fx.us), id).await, None);
    let home = fx.rows(None, id).await;
    for (table, n) in &before {
        assert!(
            home.get(table).copied().unwrap_or(0) >= *n,
            "{table}: {home:?}"
        );
    }
    assert!(has_key(0, &session_key).await);
    let (status, body, _) = get_json(
        &fx.app,
        &format!("/admin/tenants/{slug}/audit/verify"),
        Some(&admin_token(&fx.app, id, OWNER_ROLE).await),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["valid"], true,
        "the chain survived three copies: {body}"
    );

    // Moving where it already is changes nothing.
    let report = fx.move_to(&slug, None).await;
    assert!(report.rows.is_empty() && report.cleaned.is_empty());
}

/// What a move does to every node's cached registry entry. Only the
/// deployment-wide keys: the tenant's own are out of reach while it moves.
async fn forget_registry_entry(fx: &Fx, tenant: &ridm_api::models::Tenant) {
    let keys: Vec<String> = ridm_api::middleware::tenant_cache_keys(tenant)
        .into_iter()
        .filter(|k| ridm_api::cache::key_tenant(k.as_bytes()).is_none())
        .collect();
    fx.app.state.cache.invalidate(&keys).await.unwrap();
}

#[tokio::test]
async fn a_moving_tenant_is_unavailable_everywhere() {
    let fx = fixture().await;
    let slug = fx.slug("frozen");
    let id = fx.tenant("frozen", Some(&fx.eu)).await;
    let state = &fx.app.state;
    let tenant = tenants::get(state, id).await.unwrap();
    repos::tenants::set_relocating(state.db.home(), id, true)
        .await
        .unwrap();
    state.db.forget(id);
    forget_registry_entry(&fx, &tenant).await;

    let err = db::tenant_tx(&state.db, id).await.unwrap_err();
    assert!(
        matches!(db::unroutable(&err), Some(db::Unroutable::Relocating)),
        "{err}"
    );
    let res = fx
        .app
        .http
        .get(
            fx.app
                .url(&format!("/t/{slug}/.well-known/openid-configuration")),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    // Neither changed nor deleted while it moves.
    let token = fx.global().await;
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("/admin/tenants/{slug}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    repos::tenants::set_relocating(state.db.home(), id, false)
        .await
        .unwrap();
    state.db.forget(id);
    forget_registry_entry(&fx, &tenant).await;
    let res = fx
        .app
        .http
        .get(
            fx.app
                .url(&format!("/t/{slug}/.well-known/openid-configuration")),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Deleting a regional tenant deletes it in its region too.
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("/admin/tenants/{slug}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(fx.tenant_row(Some(&fx.eu), id).await, None);
    assert_eq!(fx.tenant_row(None, id).await, None);
    // The audit trail outlives the tenant (it has no foreign key), in the
    // region, `tenant.deleted` included; nothing else of it is left, and
    // nothing of it ever reaches home.
    fx.audited(Some(&fx.eu), id, "tenant.deleted").await;
    let left = fx.rows(Some(&fx.eu), id).await;
    assert!(
        left.keys().all(|t| t.starts_with("audit_")),
        "only the audit trail remains: {left:?}"
    );
    assert_eq!(fx.rows(None, id).await, BTreeMap::new());
}

#[tokio::test]
async fn a_failed_move_leaves_the_tenant_where_it_was() {
    let fx = fixture().await;
    let slug = fx.slug("stays");
    let id = fx.tenant("stays", None).await;
    user_with_role(&fx.app, id, None).await;
    fx.audited(None, id, "user.created").await;
    let before = fx.rows(None, id).await;
    // The target already has another tenant under the same slug: the copy
    // of the tenant's row cannot go in, so the move must fail and undo.
    let mut us = sqlx::PgConnection::connect(&fx.us_db.url).await.unwrap();
    sqlx::query(
        "INSERT INTO tenants (slug, display_name, registry_only) VALUES ($1, 'squatter', true)",
    )
    .bind(&slug)
    .execute(&mut us)
    .await
    .unwrap();

    let err = move_tenant(
        &fx.app.state,
        &slug,
        Some(&fx.us),
        &MoveOptions {
            drain: Duration::ZERO,
        },
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("exists") || err.to_string().contains("database"),
        "{err}"
    );
    assert_eq!(fx.tenant_row(None, id).await, Some((None, false)));
    let t = tenants::get(&fx.app.state, id).await.unwrap();
    assert!(!t.relocating, "the tenant is unlocked again");
    // Audit rows may still be landing from the writer; everything else is exact.
    let no_audit = |m: BTreeMap<String, i64>| -> BTreeMap<String, i64> {
        m.into_iter()
            .filter(|(t, _)| !t.starts_with("audit_"))
            .collect()
    };
    assert_eq!(
        no_audit(fx.rows(None, id).await),
        no_audit(before),
        "nothing left the home database"
    );
    assert_eq!(fx.rows(Some(&fx.us), id).await, BTreeMap::new());
    assert!(db::tenant_tx(&fx.app.state.db, id).await.is_ok());
}

#[tokio::test]
async fn running_a_move_again_removes_a_stale_copy() {
    let fx = fixture().await;
    let slug = fx.slug("stale");
    let id = fx.tenant("stale", Some(&fx.eu)).await;
    // What a move that died after switching leaves: a copy in the old place.
    let tenant = repos::tenants::find_by_id(fx.app.state.db.home(), id)
        .await
        .unwrap()
        .unwrap();
    let mut us = sqlx::PgConnection::connect(&fx.us_db.url).await.unwrap();
    repos::tenants::insert_copy(&mut us, &tenant).await.unwrap();
    assert!(fx.rows(Some(&fx.us), id).await.contains_key("roles"));

    let report = fx.move_to(&slug, Some(&fx.eu)).await;
    assert_eq!(report.cleaned, vec![fx.us.clone()]);
    assert_eq!(fx.tenant_row(Some(&fx.us), id).await, None);
    assert_eq!(fx.rows(Some(&fx.us), id).await, BTreeMap::new());
    assert!(
        fx.rows(Some(&fx.eu), id).await.contains_key("roles"),
        "the live copy is untouched"
    );
}

/// A later migration that seeds every tenant must skip the home database's
/// registry-only rows, or it would write a regional tenant's rows at home.
#[test]
fn per_tenant_seeding_migrations_skip_registry_rows() {
    const SINCE: &str = "20260923102320";
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if name.as_str() <= SINCE {
            continue;
        }
        let sql = std::fs::read_to_string(&path).unwrap();
        for line in sql.lines().filter(|l| l.contains("FROM tenants")) {
            assert!(
                line.contains("registry_only"),
                "{name}: `{line}` must skip registry-only tenants (WHERE NOT registry_only)"
            );
        }
    }
}
