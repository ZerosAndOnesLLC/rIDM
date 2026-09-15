//! Phase 5.4: admin API for users and everything attached to them.

mod common;

use common::admin::{admin_token, assign, call, get_json, role_id, user_with_role};
use common::{TestApp, create_tenant};
use reqwest::Method;
use ridm_api::db;
use ridm_api::models::{
    MASTER_TENANT_ID, NewClient, NewGroup, NewRole, NewUser, Principal, SessionPolicy,
};
use ridm_api::services::admin_access::{
    ADMIN_ROLE, CLIENT_MANAGER_ROLE, OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::{clients, consents, groups, roles, tenants, trusted_devices, users};
use ridm_core::events::Actor;
use serde_json::json;
use uuid::Uuid;

const STRONG: &str = "Correct-Horse-Battery-9x!";

async fn plain_user(app: &TestApp, tenant_id: Uuid) -> Uuid {
    user_with_role(app, tenant_id, None).await
}

fn new_session<'a>(uid: Uuid, policy: &'a SessionPolicy) -> NewSession<'a> {
    NewSession {
        user_id: uid,
        amr: vec!["pwd".into()],
        acr: None,
        ip: Some("10.0.0.1".into()),
        user_agent: Some("UA".into()),
        policy,
    }
}

#[tokio::test]
async fn user_manager_runs_the_user_lifecycle() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let t = admin_token(&app, app.tenant.id, USER_MANAGER_ROLE).await;
    let base = format!("/admin/tenants/{slug}/users");

    // Validation.
    for (body, needle) in [
        (json!({"username": "x", "colour": "red"}), "colour"),
        (json!({"username": "x", "password": "short"}), "password"),
        (
            json!({"username": "x", "password": STRONG, "temporary_password": true}),
            "either",
        ),
        (json!({"username": "x", "email": "not-an-email"}), "email"),
    ] {
        let (status, err, _) = call(&app, Method::POST, &base, Some(&t), Some(&body)).await;
        assert_eq!(status, 400, "{body} -> {err}");
        assert!(
            err["detail"].as_str().unwrap().contains(needle),
            "{err} should mention {needle}"
        );
    }

    // Create with a temporary password: returned once, must change at login.
    let (status, created, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({
            "username": "Alice",
            "email": "alice@example.com",
            "email_verified": true,
            "temporary_password": true
        })),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["username"], "alice", "normalized");
    assert_eq!(created["must_change_password"], true);
    let temp = created["temporary_password"].as_str().unwrap();
    assert_eq!(temp.len(), 26);
    assert!(created.get("password_hash").is_none());
    let id = created["id"].as_str().unwrap().to_string();
    let (status, dup, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"username": "alice"})),
    )
    .await;
    assert_eq!(status, 409, "{dup}");
    // Explicit password, policy-checked, no forced change.
    let (status, bob, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"username": "bob", "password": STRONG})),
    )
    .await;
    assert_eq!(status, 201, "{bob}");
    assert_eq!(bob["must_change_password"], false);
    assert!(bob.get("temporary_password").is_none());

    // Detail view.
    let path = format!("{base}/{id}");
    let (status, got, _) = get_json(&app, &path, Some(&t)).await;
    assert_eq!(status, 200, "{got}");
    assert_eq!(got["password"]["set"], true);
    assert_eq!(got["password"]["must_change"], true);
    assert!(got["roles"].as_array().unwrap().is_empty());
    assert!(got["groups"].as_array().unwrap().is_empty());
    let (status, _, _) = get_json(&app, &format!("{base}/{}", Uuid::new_v4()), Some(&t)).await;
    assert_eq!(status, 404);

    // List and search.
    let (status, page, _) = get_json(&app, &format!("{base}?search=ali"), Some(&t)).await;
    assert_eq!(status, 200, "{page}");
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], id);
    let (_, page, _) = get_json(&app, &format!("{base}?limit=1"), Some(&t)).await;
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert!(page["next_cursor"].is_string());

    // Patch: partial, `null` clears, unknown fields and system statuses rejected.
    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(&json!({"email": "alice2@example.com", "locale": "de"})),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["email"], "alice2@example.com");
    assert_eq!(patched["locale"], "de");
    assert_eq!(patched["username"], "alice", "sibling kept");
    let (_, cleared, _) = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(&json!({"locale": null})),
    )
    .await;
    assert!(cleared["locale"].is_null());
    for body in [
        json!({"colour": "red"}),
        json!({"status": "locked"}),
        json!({"status": "deleted"}),
        json!({"username": "has space"}),
    ] {
        let (status, err, _) = call(&app, Method::PATCH, &path, Some(&t), Some(&body)).await;
        assert_eq!(status, 400, "{body} -> {err}");
    }

    // Disabling ends the sessions; enabling does not bring them back.
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let uid: Uuid = id.parse().unwrap();
    sessions::create(
        &app.state,
        tenant.id,
        new_session(uid, &tenant.settings.session),
    )
    .await
    .unwrap();
    let (_, s, _) = get_json(&app, &format!("{path}/sessions"), Some(&t)).await;
    assert_eq!(s.as_array().unwrap().len(), 1);
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
    let (_, s, _) = get_json(&app, &format!("{path}/sessions"), Some(&t)).await;
    assert!(s.as_array().unwrap().is_empty());
    let (_, enabled, _) = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(&json!({"status": "active"})),
    )
    .await;
    assert_eq!(enabled["status"], "active");

    // Passwords: explicit (204), temporary (returned once), forced change, unlock.
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{path}/password"),
        Some(&t),
        Some(&json!({"password": STRONG})),
    )
    .await;
    assert_eq!(status, 204);
    let (_, got, _) = get_json(&app, &path, Some(&t)).await;
    assert_eq!(got["password"]["must_change"], false);
    let (status, err, _) = call(
        &app,
        Method::PUT,
        &format!("{path}/password"),
        Some(&t),
        Some(&json!({"password": "short"})),
    )
    .await;
    assert_eq!(status, 400, "{err}");
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{path}/password"),
        Some(&t),
        Some(&json!({"password": "short", "skip_policy": true})),
    )
    .await;
    assert_eq!(status, 204, "admin override");
    let (status, temp, _) = call(
        &app,
        Method::PUT,
        &format!("{path}/password"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{temp}");
    assert!(temp["temporary_password"].is_string());
    let (_, got, _) = get_json(&app, &path, Some(&t)).await;
    assert_eq!(got["password"]["must_change"], true);
    let (status, err, _) = call(
        &app,
        Method::PUT,
        &format!("{path}/password"),
        Some(&t),
        Some(&json!({"password": STRONG, "revoke_sessions": true})),
    )
    .await;
    assert_eq!(status, 400, "history forbids reuse: {err}");
    let (status, err, _) = call(
        &app,
        Method::PUT,
        &format!("{path}/password"),
        Some(&t),
        Some(&json!({"password": "Another-Strong-Passphrase-7!", "revoke_sessions": true})),
    )
    .await;
    assert_eq!(status, 204, "{err}");
    let (status, forced, _) = call(
        &app,
        Method::POST,
        &format!("{path}/force-password-change"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{forced}");
    assert_eq!(forced["must_change_password"], true);
    let (status, unlocked, _) = call(
        &app,
        Method::POST,
        &format!("{path}/unlock"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{unlocked}");
    assert_eq!(unlocked["status"], "active");
    assert_eq!(unlocked["failed_attempts"], 0);

    // Delete: soft, gone from reads and lists unless asked for.
    let (status, _, _) = call(&app, Method::DELETE, &path, Some(&t), None).await;
    assert_eq!(status, 204);
    let (status, _, _) = get_json(&app, &path, Some(&t)).await;
    assert_eq!(status, 404);
    let (status, _, _) = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(&json!({"locale": "fr"})),
    )
    .await;
    assert_eq!(status, 404);
    let (_, page, _) = get_json(&app, &format!("{base}?search=alice"), Some(&t)).await;
    assert!(page["items"].as_array().unwrap().is_empty());
    let (_, page, _) = get_json(
        &app,
        &format!("{base}?search=alice&include_deleted=true"),
        Some(&t),
    )
    .await;
    assert_eq!(page["items"][0]["status"], "deleted");
}

#[tokio::test]
async fn sessions_devices_credentials_and_consents_are_listed_and_revoked() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let t = admin_token(&app, tenant.id, ADMIN_ROLE).await;
    let uid = plain_user(&app, tenant.id).await;
    let path = format!("/admin/tenants/{slug}/users/{uid}");

    // Sessions.
    let s1 = sessions::create(
        &app.state,
        tenant.id,
        new_session(uid, &tenant.settings.session),
    )
    .await
    .unwrap();
    sessions::create(
        &app.state,
        tenant.id,
        new_session(uid, &tenant.settings.session),
    )
    .await
    .unwrap();
    let (status, list, _) = get_json(&app, &format!("{path}/sessions"), Some(&t)).await;
    assert_eq!(status, 200, "{list}");
    assert_eq!(list.as_array().unwrap().len(), 2);
    assert_eq!(list[0]["ip"], "10.0.0.1");
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}/sessions/{}", s1.id),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}/sessions/{}", s1.id),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404, "already revoked");
    let (status, revoked, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}/sessions"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{revoked}");
    assert_eq!(revoked["revoked"], 1);
    let (_, list, _) = get_json(&app, &format!("{path}/sessions"), Some(&t)).await;
    assert!(list.as_array().unwrap().is_empty());

    // Trusted devices.
    let (d1, _) = trusted_devices::trust(&app.state, &tenant, uid, Some("laptop"), None, None)
        .await
        .unwrap();
    trusted_devices::trust(&app.state, &tenant, uid, Some("phone"), None, None)
        .await
        .unwrap();
    let (status, list, _) = get_json(&app, &format!("{path}/devices"), Some(&t)).await;
    assert_eq!(status, 200, "{list}");
    assert_eq!(list.as_array().unwrap().len(), 2);
    assert!(list[0].get("device_hash").is_none());
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}/devices/{}", d1.id),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}/devices/{}", d1.id),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
    let (_, revoked, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}/devices"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(revoked["revoked"], 1);

    // Credentials: password summary plus factor rows (metadata only).
    let cred_id = Uuid::now_v7();
    let mut tx = db::tenant_tx(&app.state.db, tenant.id).await.unwrap();
    sqlx::query(
        "INSERT INTO credentials (id, tenant_id, user_id, type, data_enc, label) \
         VALUES ($1, $2, $3, 'totp', $4, 'Authenticator')",
    )
    .bind(cred_id)
    .bind(tenant.id)
    .bind(uid)
    .bind(b"secret".as_slice())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (status, creds, _) = get_json(&app, &format!("{path}/credentials"), Some(&t)).await;
    assert_eq!(status, 200, "{creds}");
    assert_eq!(creds["password"]["set"], false);
    assert_eq!(creds["credentials"][0]["kind"], "totp");
    assert_eq!(creds["credentials"][0]["label"], "Authenticator");
    assert!(creds["credentials"][0].get("data_enc").is_none());
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}/credentials/{cred_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}/credentials/{cred_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
    let (_, creds, _) = get_json(&app, &format!("{path}/credentials"), Some(&t)).await;
    assert!(creds["credentials"].as_array().unwrap().is_empty());

    // Consents.
    let client = clients::create(
        &app.state,
        tenant.id,
        Actor::System,
        NewClient {
            name: "app".into(),
            redirect_uris: vec!["https://app.example/cb".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .client;
    consents::grant(
        &app.state,
        tenant.id,
        uid,
        client.id,
        &["openid".into(), "email".into()],
    )
    .await
    .unwrap();
    let (status, list, _) = get_json(&app, &format!("{path}/consents"), Some(&t)).await;
    assert_eq!(status, 200, "{list}");
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["client_id"], client.id.to_string());
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}/consents/{}", client.id),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}/consents/{}", client.id),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
    let (_, list, _) = get_json(&app, &format!("{path}/consents"), Some(&t)).await;
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .all(|c| c["revoked_at"].is_string())
    );

    // Deleting the user ends sessions and devices too.
    sessions::create(
        &app.state,
        tenant.id,
        new_session(uid, &tenant.settings.session),
    )
    .await
    .unwrap();
    trusted_devices::trust(&app.state, &tenant, uid, None, None, None)
        .await
        .unwrap();
    let (status, _, _) = call(&app, Method::DELETE, &path, Some(&t), None).await;
    assert_eq!(status, 204);
    assert!(
        sessions::list_live_for_user(&app.state, tenant.id, uid)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        trusted_devices::list(&app.state, tenant.id, uid)
            .await
            .unwrap()
            .is_empty()
    );
    let (status, _, _) = get_json(&app, &format!("{path}/sessions"), Some(&t)).await;
    assert_eq!(status, 404, "deleted users have no sub-resources");
}

#[tokio::test]
async fn roles_and_groups_are_granted_within_the_admins_own_reach() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let tid = app.tenant.id;
    let manager = admin_token(&app, tid, USER_MANAGER_ROLE).await;
    let admin = admin_token(&app, tid, ADMIN_ROLE).await;
    let owner = admin_token(&app, tid, OWNER_ROLE).await;
    let uid = plain_user(&app, tid).await;
    let path = format!("/admin/tenants/{slug}/users/{uid}");
    let editor = roles::create(
        &app.state,
        tid,
        Actor::System,
        NewRole {
            name: "editor".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let owner_role = role_id(&app, tid, OWNER_ROLE).await;
    let admin_role = role_id(&app, tid, ADMIN_ROLE).await;
    let viewer_role = role_id(&app, tid, VIEWER_ROLE).await;

    // A plain role is fine for a user manager.
    let (status, body, _) = call(
        &app,
        Method::PUT,
        &format!("{path}/roles/{}", editor.id),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["direct"][0]["name"], "editor");
    assert_eq!(body["effective"][0]["name"], "editor");
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{path}/roles/{}", Uuid::new_v4()),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 404);

    // Admin roles only within what the caller holds: a user manager cannot
    // hand out ridm:admin, a tenant admin cannot hand out ridm:owner
    // (tenant lifecycle permissions), the owner can.
    let (status, err, _) = call(
        &app,
        Method::PUT,
        &format!("{path}/roles/{admin_role}"),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 403, "{err}");
    assert!(err["detail"].as_str().unwrap().contains("cannot grant"));
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{path}/roles/{owner_role}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{path}/roles/{viewer_role}"),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 403, "viewer reads clients, a user manager does not");
    let (status, body, _) = call(
        &app,
        Method::PUT,
        &format!("{path}/roles/{owner_role}"),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}/roles/{owner_role}"),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 204, "taking away is never an escalation");
    let (_, listed, _) = get_json(&app, &format!("{path}/roles"), Some(&manager)).await;
    let names: Vec<&str> = listed["direct"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["editor"]);

    // Groups carry their roles (and their ancestors' roles) into membership.
    let staff = groups::create(
        &app.state,
        tid,
        Actor::System,
        NewGroup {
            name: "staff".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let helpdesk = groups::create(
        &app.state,
        tid,
        Actor::System,
        NewGroup {
            name: "helpdesk".into(),
            parent_id: Some(staff.id),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let plain = groups::create(
        &app.state,
        tid,
        Actor::System,
        NewGroup {
            name: "newsletter".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    roles::assign(
        &app.state,
        tid,
        Actor::System,
        admin_role,
        Principal::Group { id: staff.id },
    )
    .await
    .unwrap();
    let (status, body, _) = call(
        &app,
        Method::PUT,
        &format!("{path}/groups/{}", plain.id),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["direct"][0]["name"], "newsletter");
    for g in [staff.id, helpdesk.id] {
        let (status, err, _) = call(
            &app,
            Method::PUT,
            &format!("{path}/groups/{g}"),
            Some(&manager),
            None,
        )
        .await;
        assert_eq!(status, 403, "{err}");
    }
    let (status, body, _) = call(
        &app,
        Method::PUT,
        &format!("{path}/groups/{}", helpdesk.id),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let effective: Vec<&str> = body["effective"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["name"].as_str().unwrap())
        .collect();
    assert!(effective.contains(&"staff") && effective.contains(&"helpdesk"));
    let (_, r, _) = get_json(&app, &format!("{path}/roles"), Some(&manager)).await;
    assert!(
        r["effective"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["name"] == ADMIN_ROLE),
        "{r}"
    );
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}/groups/{}", helpdesk.id),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (_, g, _) = get_json(&app, &format!("{path}/groups"), Some(&manager)).await;
    assert_eq!(g["direct"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn built_in_roles_map_onto_user_routes() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let base = format!("/admin/tenants/{slug}/users");
    for (role, list, create) in [
        (OWNER_ROLE, 200, 201),
        (ADMIN_ROLE, 200, 201),
        (USER_MANAGER_ROLE, 200, 201),
        (CLIENT_MANAGER_ROLE, 403, 403),
        (VIEWER_ROLE, 200, 403),
    ] {
        let t = admin_token(&app, app.tenant.id, role).await;
        let (status, body, _) = get_json(&app, &base, Some(&t)).await;
        assert_eq!(status, list, "{role} list: {body}");
        let (status, body, _) = call(
            &app,
            Method::POST,
            &base,
            Some(&t),
            Some(&json!({"username": format!("by-{}", role.replace(':', "-"))})),
        )
        .await;
        assert_eq!(status, create, "{role} create: {body}");
    }
    let viewer = admin_token(&app, app.tenant.id, VIEWER_ROLE).await;
    let uid = plain_user(&app, app.tenant.id).await;
    let path = format!("{base}/{uid}");
    for sub in [
        "",
        "/sessions",
        "/credentials",
        "/devices",
        "/roles",
        "/groups",
        "/consents",
    ] {
        let (status, body, _) = get_json(&app, &format!("{path}{sub}"), Some(&viewer)).await;
        assert_eq!(status, 200, "viewer GET {sub}: {body}");
    }
    for (method, sub) in [
        (Method::PATCH, ""),
        (Method::DELETE, ""),
        (Method::PUT, "/password"),
        (Method::POST, "/force-password-change"),
        (Method::POST, "/unlock"),
        (Method::DELETE, "/sessions"),
        (Method::DELETE, "/devices"),
    ] {
        let body = (method == Method::PATCH).then(|| json!({"locale": "en"}));
        let (status, _, _) = call(
            &app,
            method.clone(),
            &format!("{path}{sub}"),
            Some(&viewer),
            body.as_ref(),
        )
        .await;
        assert_eq!(status, 403, "viewer {method} {sub}");
    }
    let (status, _, _) = get_json(&app, &base, None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn users_are_confined_to_the_admins_tenant() {
    let app = TestApp::spawn().await;
    let other = create_tenant(&app.state.db).await;
    let own = app.tenant.slug.clone();
    let t = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let theirs = users::create(
        &app.state,
        other.id,
        Actor::System,
        NewUser {
            username: "theirs".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/users", other.slug),
        Some(&t),
    )
    .await;
    assert_eq!(status, 403);
    let their_path = format!("/admin/tenants/{}/users/{}", other.slug, theirs.id);
    let (status, _, _) = get_json(&app, &their_path, Some(&t)).await;
    assert_eq!(status, 403);
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{their_path}/password"),
        Some(&t),
        Some(&json!({"password": STRONG})),
    )
    .await;
    assert_eq!(status, 403);
    // Their id under the owner's own tenant does not resolve.
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{own}/users/{}", theirs.id),
        Some(&t),
    )
    .await;
    assert_eq!(status, 404);
    // Nor can roles of another tenant be granted: the role lookup is tenant-bound.
    let mine = plain_user(&app, app.tenant.id).await;
    assign(&app, other.id, theirs.id, VIEWER_ROLE).await;
    let their_viewer = role_id(&app, other.id, VIEWER_ROLE).await;
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("/admin/tenants/{own}/users/{mine}/roles/{their_viewer}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
    // Global scope reaches both.
    let (status, _, _) = get_json(&app, &their_path, Some(&global)).await;
    assert_eq!(status, 200);
    let (status, _, _) =
        get_json(&app, &format!("/admin/tenants/{own}/users"), Some(&global)).await;
    assert_eq!(status, 200);
}
