//! Phase 5.6: admin API for signing keys and master-key rotation status.

mod common;

use common::admin::{admin_token, call, get_json};
use common::{TestApp, create_tenant};
use reqwest::Method;
use ridm_api::models::MASTER_TENANT_ID;
use ridm_api::services::admin_access::{
    ADMIN_ROLE, CLIENT_MANAGER_ROLE, OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
use serde_json::{Value, json};
use uuid::Uuid;

async fn published_kids(app: &TestApp) -> Vec<String> {
    let doc: Value = app
        .http
        .get(app.tenant_url("/.well-known/jwks.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    doc["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn admin_runs_the_key_lifecycle() {
    let app = TestApp::spawn().await;
    let base = format!("/admin/tenants/{}/keys", app.tenant.slug);
    let t = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;

    // Validation.
    for body in [
        json!({"alg": "HS256"}),
        json!({"rsa_bits": 1024}),
        json!({"colour": "red"}),
    ] {
        let (status, err, _) = call(&app, Method::POST, &base, Some(&t), Some(&body)).await;
        assert_eq!(status, 400, "{body} -> {err}");
    }

    // Rotate: a fresh active key, published, no private material in the body.
    let (status, first, _) = call(
        &app,
        Method::POST,
        &format!("{base}/rotate"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 201, "{first}");
    assert_eq!(first["status"], "active");
    assert!(first.get("private_key_enc").is_none());
    assert!(first["public_jwk"].get("d").is_none(), "public half only");
    let first_id = first["id"].as_str().unwrap().to_string();
    let first_kid = first["kid"].as_str().unwrap().to_string();
    assert!(published_kids(&app).await.contains(&first_kid));

    // Pending key: published, not signing.
    let (status, pending, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"alg": "ES256"})),
    )
    .await;
    assert_eq!(status, 201, "{pending}");
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["alg"], "ES256");
    let pending_id = pending["id"].as_str().unwrap().to_string();
    let pending_kid = pending["kid"].as_str().unwrap().to_string();
    assert!(published_kids(&app).await.contains(&pending_kid));
    let (status, list, _) = get_json(&app, &format!("{base}?status=pending"), Some(&t)).await;
    assert_eq!(status, 200, "{list}");
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .all(|k| k["status"] == "pending")
    );
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .any(|k| k["id"] == pending_id)
    );

    // Activating a second key of the tenant's default algorithm retires the first.
    let (status, second, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"activate": true})),
    )
    .await;
    assert_eq!(status, 201, "{second}");
    assert_eq!(second["status"], "active");
    assert_eq!(second["alg"], first["alg"]);
    let (_, first_now, _) = get_json(&app, &format!("{base}/{first_id}"), Some(&t)).await;
    assert_eq!(first_now["status"], "retiring");
    assert!(first_now["expires_at"].is_string());
    assert!(
        published_kids(&app).await.contains(&first_kid),
        "still verifiable"
    );

    // Activate the pending ES256 key (different algorithm: nothing retires).
    let (status, activated, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{pending_id}/activate"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{activated}");
    assert_eq!(activated["status"], "active");
    let (_, second_now, _) = get_json(
        &app,
        &format!("{base}/{}", second["id"].as_str().unwrap()),
        Some(&t),
    )
    .await;
    assert_eq!(second_now["status"], "active");

    // Retire, then revoke: revoked keys leave the JWKS at once.
    let (status, retired, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{pending_id}/retire"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{retired}");
    assert_eq!(retired["status"], "retiring");
    let (status, revoked, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{first_id}/revoke"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{revoked}");
    assert_eq!(revoked["status"], "revoked");
    assert!(!published_kids(&app).await.contains(&first_kid));
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{first_id}/activate"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 400, "revoked keys stay revoked: {err}");
    let (status, _, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{}/revoke", Uuid::new_v4()),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
    let (_, all, _) = get_json(&app, &base, Some(&t)).await;
    assert!(all.as_array().unwrap().len() >= 3);
}

#[tokio::test]
async fn master_key_status_is_global_only() {
    let app = TestApp::spawn().await;
    let tenant_owner = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let (status, _, _) = get_json(&app, "/admin/master-key", Some(&tenant_owner)).await;
    assert_eq!(status, 403);
    let (status, _, _) = call(
        &app,
        Method::POST,
        "/admin/master-key/rotate",
        Some(&tenant_owner),
        None,
    )
    .await;
    assert_eq!(status, 403);

    let (status, report, _) = get_json(&app, "/admin/master-key", Some(&global)).await;
    assert_eq!(status, 200, "{report}");
    assert!(report["current_version"].is_number());
    assert!(report["rows_by_version"].get("signing_keys").is_some());
    assert!(report["pending_rows"].is_number());
    let (status, rotation, _) = call(
        &app,
        Method::POST,
        "/admin/master-key/rotate",
        Some(&global),
        None,
    )
    .await;
    assert_eq!(status, 200, "{rotation}");
    assert_eq!(rotation["target_version"], report["current_version"]);
    assert!(rotation["rewritten"].is_object());
}

#[tokio::test]
async fn built_in_roles_map_onto_key_routes() {
    let app = TestApp::spawn().await;
    let base = format!("/admin/tenants/{}/keys", app.tenant.slug);
    for (role, list, rotate) in [
        (OWNER_ROLE, 200, 201),
        (ADMIN_ROLE, 200, 201),
        (USER_MANAGER_ROLE, 403, 403),
        (CLIENT_MANAGER_ROLE, 403, 403),
        (VIEWER_ROLE, 200, 403),
    ] {
        let t = admin_token(&app, app.tenant.id, role).await;
        let (status, body, _) = get_json(&app, &base, Some(&t)).await;
        assert_eq!(status, list, "{role} list: {body}");
        let (status, body, _) = call(
            &app,
            Method::POST,
            &format!("{base}/rotate"),
            Some(&t),
            None,
        )
        .await;
        assert_eq!(status, rotate, "{role} rotate: {body}");
    }
    let (status, _, _) = get_json(&app, &base, None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn keys_are_confined_to_the_admins_tenant() {
    let app = TestApp::spawn().await;
    let other = create_tenant(&app.state.db).await;
    let t = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let (status, theirs, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/keys/rotate", other.slug),
        Some(&global),
        None,
    )
    .await;
    assert_eq!(status, 201, "{theirs}");
    let their_id = theirs["id"].as_str().unwrap();
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/keys/{their_id}", other.slug),
        Some(&t),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/keys/{their_id}/revoke", app.tenant.slug),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
}
