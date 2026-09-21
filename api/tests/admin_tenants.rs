//! Phase 5.2: admin API for tenants.

mod common;

use axum::http::StatusCode;
use common::admin::{admin_token, call, get_json};
use common::{TestApp, create_tenant};
use reqwest::Method;
use ridm_api::models::MASTER_TENANT_ID;
use ridm_api::services::admin_access::{
    ADMIN_ROLE, CLIENT_MANAGER_ROLE, OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
use ridm_api::services::tenants;
use serde_json::{Value, json};
use uuid::Uuid;

fn new_slug() -> String {
    format!("adm-{}", &Uuid::new_v4().simple().to_string()[..10])
}

#[tokio::test]
async fn global_owner_manages_the_tenant_lifecycle() {
    let app = TestApp::spawn().await;
    let t = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let slug = new_slug();

    // Validation.
    let (status, body, _) = call(
        &app,
        Method::POST,
        "/admin/tenants",
        Some(&t),
        Some(&json!({"slug": "Bad Slug", "display_name": "x"})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["type"], "urn:ridm:error:bad-request");
    let (status, body, _) = call(
        &app,
        Method::POST,
        "/admin/tenants",
        Some(&t),
        Some(&json!({"slug": slug, "display_name": "Acme", "settings": {"locale": {"default": "xx-not-a-locale-!!"}}})),
    )
    .await;
    assert_eq!(status, 400, "{body}");

    // Create.
    let (status, created, _) = call(
        &app,
        Method::POST,
        "/admin/tenants",
        Some(&t),
        Some(&json!({"slug": slug, "display_name": "Acme", "settings": {"password": {"min_length": 14}}})),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["slug"], slug);
    assert_eq!(created["status"], "active");
    assert_eq!(created["settings"]["password"]["min_length"], 14);
    assert!(
        created.get("pairwise_salt").is_none(),
        "secrets never leave"
    );
    let (status, dup, _) = call(
        &app,
        Method::POST,
        "/admin/tenants",
        Some(&t),
        Some(&json!({"slug": slug, "display_name": "Again"})),
    )
    .await;
    assert_eq!(status, 409, "{dup}");

    // Read, both as admin and as the public branding endpoint.
    let path = format!("/admin/tenants/{slug}");
    let (status, got, _) = get_json(&app, &path, Some(&t)).await;
    assert_eq!(status, 200, "{got}");
    assert_eq!(got["id"], created["id"]);

    // Merge patch: only the named settings change, siblings survive.
    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(&json!({
            "display_name": "Acme Corp",
            "settings": {"password": {"require_uppercase": true}, "features": {"beta": true}, "branding": {"primary_color": "#123456"}}
        })),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["display_name"], "Acme Corp");
    assert_eq!(
        patched["settings"]["password"]["min_length"], 14,
        "sibling kept"
    );
    assert_eq!(patched["settings"]["password"]["require_uppercase"], true);
    assert_eq!(patched["settings"]["features"]["beta"]["enabled"], true);
    assert_eq!(patched["settings"]["branding"]["primary_color"], "#123456");
    // `null` clears; the public branding endpoint sees the change (cache evicted).
    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(&json!({"settings": {"branding": {"primary_color": null}}})),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert!(patched["settings"]["branding"]["primary_color"].is_null());
    let branding: Value = app
        .http
        .get(app.url(&format!("/t/{slug}/branding")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(branding["display_name"], "Acme Corp");

    // Bad patches.
    for bad in [
        json!({"settings": "nope"}),
        json!({"settings": {"password": {"min_length": "twelve"}}}),
        json!({"settings": {"password": {"min_uppercase": 1}}}),
        json!({"settings": {"passwrod": {"min_length": 8}}}),
        json!({"unknown_field": 1}),
        json!({"display_name": ""}),
    ] {
        let (status, body, _) = call(&app, Method::PATCH, &path, Some(&t), Some(&bad)).await;
        assert_eq!(status, 400, "{bad} -> {body}");
        assert_eq!(body["status"], 400);
    }
    let res = app
        .http
        .patch(app.url(&path))
        .bearer_auth(&t)
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert_eq!(res.headers()["content-type"], "application/problem+json");

    // Disable: OIDC refuses the tenant, the admin API still serves it.
    let (status, disabled, _) = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(&json!({"status": "disabled"})),
    )
    .await;
    assert_eq!(status, 200, "{disabled}");
    assert_eq!(disabled["status"], "disabled");
    let discovery = app
        .http
        .get(app.url(&format!("/t/{slug}/.well-known/openid-configuration")))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(discovery, 403);
    let (status, _, _) = get_json(&app, &path, Some(&t)).await;
    assert_eq!(status, 200, "disabled tenants stay manageable");
    let (status, _, _) = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(&json!({"status": "active"})),
    )
    .await;
    assert_eq!(status, 200);

    // Delete.
    let (status, _, _) = call(&app, Method::DELETE, &path, Some(&t), None).await;
    assert_eq!(status, 204);
    let (status, _, _) = get_json(&app, &path, Some(&t)).await;
    assert_eq!(status, 404);
    let (status, _, _) = get_json(&app, "/admin/tenants/no-such-tenant", Some(&t)).await;
    assert_eq!(status, 404);

    // Master is protected.
    let (status, body, _) = call(
        &app,
        Method::PATCH,
        "/admin/tenants/master",
        Some(&t),
        Some(&json!({"status": "disabled"})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    let (status, body, _) = call(
        &app,
        Method::DELETE,
        "/admin/tenants/master",
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn listing_is_cursor_paginated_for_global_admins() {
    let app = TestApp::spawn().await;
    let t = admin_token(&app, MASTER_TENANT_ID, VIEWER_ROLE).await;
    // There are at least master + the app tenant; add two more.
    create_tenant(&app.state.db).await;
    create_tenant(&app.state.db).await;
    // `tenants` is the one table every test binary shares, and they run in
    // parallel: what matters is that paging covers everything that existed
    // when it started, not that the table stood still while it ran.
    let before: Vec<String> = sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM tenants")
        .fetch_all(&app.state.db)
        .await
        .unwrap()
        .into_iter()
        .map(|id| id.to_string())
        .collect();
    let mut seen = vec![];
    let mut cursor: Option<String> = None;
    loop {
        let path = match &cursor {
            Some(c) => format!("/admin/tenants?limit=2&cursor={c}"),
            None => "/admin/tenants?limit=2".into(),
        };
        let (status, page, _) = get_json(&app, &path, Some(&t)).await;
        assert_eq!(status, 200, "{page}");
        let items = page["items"].as_array().unwrap();
        assert!(items.len() <= 2);
        seen.extend(items.iter().map(|i| i["id"].as_str().unwrap().to_string()));
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    for id in &before {
        assert!(seen.contains(id), "tenant {id} never appeared in a page");
    }
    let mut dedup = seen.clone();
    dedup.sort();
    dedup.dedup();
    assert_eq!(dedup.len(), seen.len(), "every tenant exactly once");
    let (status, body, _) = get_json(&app, "/admin/tenants?cursor=garbage", Some(&t)).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn tenant_scoped_admins_only_reach_their_own_tenant() {
    let app = TestApp::spawn().await;
    let own = app.tenant.slug.clone();
    let other = create_tenant(&app.state.db).await;
    let t = admin_token(&app, app.tenant.id, OWNER_ROLE).await;

    // List: exactly own tenant.
    let (status, page, _) = get_json(&app, "/admin/tenants", Some(&t)).await;
    assert_eq!(status, 200, "{page}");
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["slug"], own);

    // Own tenant: read and write.
    let (status, _, _) = get_json(&app, &format!("/admin/tenants/{own}"), Some(&t)).await;
    assert_eq!(status, 200);
    let (status, body, _) = call(
        &app,
        Method::PATCH,
        &format!("/admin/tenants/{own}"),
        Some(&t),
        Some(&json!({"display_name": "Mine"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        tenants::get(&app.state, app.tenant.id)
            .await
            .unwrap()
            .display_name,
        "Mine"
    );

    // Other tenants: not even readable; existence is not confirmed either way.
    let (status, _, _) = get_json(&app, &format!("/admin/tenants/{}", other.slug), Some(&t)).await;
    assert_eq!(status, 403);
    let (status, _, _) = call(
        &app,
        Method::PATCH,
        &format!("/admin/tenants/{}", other.slug),
        Some(&t),
        Some(&json!({"display_name": "Hijacked"})),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = get_json(&app, "/admin/tenants/master", Some(&t)).await;
    assert_eq!(status, 403);

    // Lifecycle is global-only, even for a tenant owner and even on their own tenant.
    let (status, body, _) = call(
        &app,
        Method::POST,
        "/admin/tenants",
        Some(&t),
        Some(&json!({"slug": new_slug(), "display_name": "New"})),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("/admin/tenants/{own}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 403);
    assert!(tenants::get(&app.state, app.tenant.id).await.is_ok());
}

#[tokio::test]
async fn built_in_roles_map_onto_tenant_routes() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let path = format!("/admin/tenants/{slug}");
    // (role, read, write)
    for (role, read, write) in [
        (OWNER_ROLE, 200, 200),
        (ADMIN_ROLE, 200, 200),
        (USER_MANAGER_ROLE, 200, 403),
        (CLIENT_MANAGER_ROLE, 200, 403),
        (VIEWER_ROLE, 200, 403),
    ] {
        let t = admin_token(&app, app.tenant.id, role).await;
        let (status, _, _) = get_json(&app, &path, Some(&t)).await;
        assert_eq!(status, read, "{role} read");
        let (status, _, _) = call(
            &app,
            Method::PATCH,
            &path,
            Some(&t),
            Some(&json!({"settings": {"features": {"x": true}}})),
        )
        .await;
        assert_eq!(status, write, "{role} write");
        let (status, _, _) = get_json(&app, &format!("{path}/captcha"), Some(&t)).await;
        assert_eq!(
            status,
            if read == 200 { 204 } else { read },
            "{role} captcha read"
        );
    }
    // Global admin (not owner) may write settings but not create or delete.
    let t = admin_token(&app, MASTER_TENANT_ID, ADMIN_ROLE).await;
    let (status, _, _) = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(&json!({"display_name": "By global admin"})),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _, _) = call(
        &app,
        Method::POST,
        "/admin/tenants",
        Some(&t),
        Some(&json!({"slug": new_slug(), "display_name": "New"})),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = call(&app, Method::DELETE, &path, Some(&t), None).await;
    assert_eq!(status, 403);
    let (status, _, _) = get_json(&app, &path, None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn captcha_configuration_round_trips_with_the_secret_redacted() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let path = format!("/admin/tenants/{slug}/captcha");
    let t = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;

    let (status, _, _) = get_json(&app, &path, Some(&t)).await;
    assert_eq!(status, 204, "not configured");
    let (status, body, _) = call(
        &app,
        Method::PUT,
        &path,
        Some(&t),
        Some(&json!({"provider": "turnstile", "site_key": "sk", "secret": ""})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    let (status, body, _) = call(
        &app,
        Method::PUT,
        &path,
        Some(&t),
        Some(&json!({"provider": "turnstile", "site_key": "site-123", "secret": "s3cret", "verify_url": "https://verify.example/"})),
    )
    .await;
    assert_eq!(status, 204, "{body}");
    let (status, view, _) = get_json(&app, &path, Some(&t)).await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["provider"], "turnstile");
    assert_eq!(view["site_key"], "site-123");
    assert_eq!(view["secret_set"], true);
    assert!(view.get("secret").is_none(), "{view}");
    assert_eq!(view["verify_url"], "https://verify.example/");
    let (status, _, _) = call(&app, Method::DELETE, &path, Some(&t), None).await;
    assert_eq!(status, 204);
    let (status, _, _) = get_json(&app, &path, Some(&t)).await;
    assert_eq!(status, 204);
}

#[tokio::test]
async fn profile_schema_is_read_and_replaced_through_the_admin_api() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let t = admin_token(&app, MASTER_TENANT_ID, ADMIN_ROLE).await;
    let path = format!("/admin/tenants/{slug}/profile-schema");

    let (status, body, _) = call(&app, Method::GET, &path, Some(&t), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["attributes"], serde_json::json!([]));
    assert_eq!(body["allow_undeclared"], false);

    let schema = serde_json::json!({
        "attributes": [
            {"name": "department", "type": "enum", "required": true, "validation": {"values": ["eng", "sales"]}, "editable_by": "admin", "visible_in": ["id_token"], "order": 1},
            {"name": "nickname", "type": "string", "label": "Nickname"}
        ],
        "allow_undeclared": false
    });
    let (status, body, _) = call(&app, Method::PUT, &path, Some(&t), Some(&schema)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["attributes"][0]["name"], "department");
    let (status, body, _) = call(&app, Method::GET, &path, Some(&t), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["attributes"].as_array().unwrap().len(), 2);
    assert_eq!(body["attributes"][1]["label"], "Nickname");

    // Structural validation applies: an enum needs values.
    let bad = serde_json::json!({"attributes": [{"name": "level", "type": "enum"}]});
    let (status, body, _) = call(&app, Method::PUT, &path, Some(&t), Some(&bad)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Read-only roles see it but cannot change it.
    let viewer = admin_token(&app, MASTER_TENANT_ID, VIEWER_ROLE).await;
    let (status, _, _) = call(&app, Method::GET, &path, Some(&viewer), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = call(&app, Method::PUT, &path, Some(&viewer), Some(&schema)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Switching `settings.mfa` to another mode with a merge patch that names the
/// mode alone drops the old mode's fields instead of refusing them as
/// unknown; and `registration.captcha` (never read by the server) is gone,
/// the setting being `captcha.on_registration`.
#[tokio::test]
async fn settings_patches_switch_mfa_mode_and_know_the_captcha_setting() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let path = format!("/admin/tenants/{slug}");
    let t = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;
    let patch = |settings: Value| {
        let (app, path, t) = (&app, &path, &t);
        async move {
            let (status, body, _) = call(
                app,
                Method::PATCH,
                path,
                Some(t),
                Some(&json!({ "settings": settings })),
            )
            .await;
            (status, body)
        }
    };

    let (status, body) =
        patch(json!({"mfa": {"mode": "required_for_roles", "roles": ["finance"]}})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["settings"]["mfa"]["roles"], json!(["finance"]));
    let (status, body) = patch(json!({"mfa": {"mode": "optional"}})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["settings"]["mfa"], json!({"mode": "optional"}));
    // What the console sends: the mode, and the role list cleared.
    let (status, _) = patch(json!({"mfa": {"mode": "required_for_roles", "roles": ["a"]}})).await;
    assert_eq!(status, 200);
    let (status, body) = patch(json!({"mfa": {"mode": "required", "roles": null}})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["settings"]["mfa"], json!({"mode": "required"}));
    // A stray field on the same mode is still a typo.
    let (status, body) = patch(json!({"mfa": {"roles": ["x"]}})).await;
    assert_eq!(status, 400, "{body}");

    let (status, body) = patch(json!({"registration": {"captcha": true}})).await;
    assert_eq!(status, 400, "{body}");
    let (status, body) = patch(json!({"captcha": {"on_registration": false}})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["settings"]["captcha"]["on_registration"], false);
    assert!(body["settings"]["registration"].get("captcha").is_none());
}
