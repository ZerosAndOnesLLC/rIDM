//! Phase 5.1: admin authentication and the permission model.

mod common;

use axum::Router;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::routing::get;
use common::admin::{TokenOpts, assign, get_json, role_id, token, user_with_role};
use common::{TestApp, create_tenant};
use ridm_api::middleware::AdminCtx;
use ridm_api::models::{
    ClientType, MASTER_TENANT_ID, NewClient, NewRole, Principal, RoleUpdate, UserStatus, UserUpdate,
};
use ridm_api::services::admin_access::{
    ADMIN_AUDIENCE, ADMIN_ROLE, BUILT_IN_ROLES, CATALOGUE, OWNER_ROLE, VIEWER_ROLE,
};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::tokens;
use ridm_api::services::{clients, denylist, roles, tenants, users};
use ridm_api::{db, repos};
use ridm_core::events::Actor;
use serde_json::Value;
use uuid::Uuid;

/// Test-only route exercising `AdminCtx::require` / `require_global`.
fn probe_routes() -> Router<ridm_api::state::AppState> {
    Router::new()
        .route(
            "/probe/{tenant_id}/{permission}",
            get(
                |admin: AdminCtx, Path((tenant_id, permission)): Path<(Uuid, String)>| async move {
                    admin
                        .require(tenant_id, &permission)
                        .map(|()| StatusCode::NO_CONTENT)
                },
            ),
        )
        .route(
            "/probe-global/{permission}",
            get(
                |admin: AdminCtx, Path(permission): Path<String>| async move {
                    admin
                        .require_global(&permission)
                        .map(|()| StatusCode::NO_CONTENT)
                },
            ),
        )
}

async fn probe(app: &TestApp, bearer: &str, tenant_id: Uuid, permission: &str) -> StatusCode {
    app.http
        .get(app.url(&format!("/probe/{tenant_id}/{permission}")))
        .bearer_auth(bearer)
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn global_owner_from_master_reaches_every_tenant() {
    let app = TestApp::spawn_with(probe_routes()).await;
    let master = tenants::get(&app.state, MASTER_TENANT_ID).await.unwrap();
    let owner = user_with_role(&app, MASTER_TENANT_ID, Some(OWNER_ROLE)).await;
    let t = token(&app, &master, owner, TokenOpts::default()).await;

    let (status, me, _) = get_json(&app, "/admin/me", Some(&t)).await;
    assert_eq!(status, 200, "{me}");
    assert_eq!(me["scope"], "global");
    assert_eq!(me["tenant_slug"], "master");
    assert_eq!(me["user_id"], owner.to_string());
    assert!(
        me["roles"]
            .as_array()
            .unwrap()
            .contains(&Value::from(OWNER_ROLE))
    );
    assert_eq!(
        me["permissions"].as_array().unwrap().len(),
        CATALOGUE.len(),
        "owner holds the whole catalogue"
    );

    // Any tenant, any permission.
    let other = create_tenant(&app.state.db).await;
    for p in CATALOGUE {
        assert_eq!(
            probe(&app, &t, app.tenant.id, p.name).await,
            204,
            "{}",
            p.name
        );
        assert_eq!(probe(&app, &t, other.id, p.name).await, 204, "{}", p.name);
    }
    let global = app
        .http
        .get(app.url("/probe-global/ridm:tenants:create"))
        .bearer_auth(&t)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(global, 204);

    let (status, model, _) = get_json(&app, "/admin/permissions", Some(&t)).await;
    assert_eq!(status, 200);
    assert_eq!(model["audience"], ADMIN_AUDIENCE);
    assert_eq!(
        model["permissions"].as_array().unwrap().len(),
        CATALOGUE.len()
    );
    assert_eq!(
        model["roles"].as_array().unwrap().len(),
        BUILT_IN_ROLES.len()
    );
}

#[tokio::test]
async fn tenant_admin_is_confined_to_its_tenant_and_role() {
    let app = TestApp::spawn_with(probe_routes()).await;
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let viewer = user_with_role(&app, tenant.id, Some(VIEWER_ROLE)).await;
    let t = token(&app, &tenant, viewer, TokenOpts::default()).await;

    let (status, me, _) = get_json(&app, "/admin/me", Some(&t)).await;
    assert_eq!(status, 200, "{me}");
    assert_eq!(me["scope"], "tenant");
    assert_eq!(me["tenant_id"], tenant.id.to_string());
    let perms = me["permissions"].as_array().unwrap();
    assert!(perms.iter().all(|p| p.as_str().unwrap().ends_with(":read")));

    // Own tenant: reads yes, writes no.
    assert_eq!(probe(&app, &t, tenant.id, "ridm:users:read").await, 204);
    assert_eq!(probe(&app, &t, tenant.id, "ridm:users:write").await, 403);
    // Another tenant: nothing, not even reads.
    let other = create_tenant(&app.state.db).await;
    assert_eq!(probe(&app, &t, other.id, "ridm:users:read").await, 403);
    assert_eq!(
        probe(&app, &t, MASTER_TENANT_ID, "ridm:users:read").await,
        403
    );

    // A tenant-scoped owner is still not a global administrator.
    let owner = user_with_role(&app, tenant.id, Some(OWNER_ROLE)).await;
    let to = token(&app, &tenant, owner, TokenOpts::default()).await;
    assert_eq!(
        probe(&app, &to, tenant.id, "ridm:tenants:delete").await,
        204
    );
    assert_eq!(probe(&app, &to, other.id, "ridm:tenants:read").await, 403);
    let global = app
        .http
        .get(app.url("/probe-global/ridm:tenants:create"))
        .bearer_auth(&to)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(global, 403);
}

#[tokio::test]
async fn built_in_role_matrix_matches_the_rust_catalogue() {
    let app = TestApp::spawn_with(probe_routes()).await;
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();

    // The seeded catalogue equals the Rust one, by name.
    let mut tx = db::tenant_tx(&app.state.db, tenant.id).await.unwrap();
    let rs = repos::resource_servers::find_by_identifier(&mut *tx, tenant.id, ADMIN_AUDIENCE)
        .await
        .unwrap()
        .expect("admin resource server seeded");
    assert!(rs.built_in);
    let seeded = repos::resource_servers::list_permissions(&mut *tx, tenant.id, rs.id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut seeded_names: Vec<&str> = seeded.iter().map(|p| p.name.as_str()).collect();
    seeded_names.sort_unstable();
    let mut expected: Vec<&str> = CATALOGUE.iter().map(|p| p.name).collect();
    expected.sort_unstable();
    assert_eq!(seeded_names, expected);
    for p in &seeded {
        let def = CATALOGUE.iter().find(|d| d.name == p.name).unwrap();
        assert_eq!(
            p.description.as_deref(),
            Some(def.description),
            "{}",
            p.name
        );
    }

    // Each built-in role grants exactly what the Rust definition says, and
    // the probe agrees for every catalogue permission.
    for role in BUILT_IN_ROLES {
        let user = user_with_role(&app, tenant.id, Some(role.name)).await;
        let t = token(&app, &tenant, user, TokenOpts::default()).await;
        let (status, me, _) = get_json(&app, "/admin/me", Some(&t)).await;
        assert_eq!(status, 200, "{}: {me}", role.name);
        let mut held: Vec<String> = me["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        held.sort_unstable();
        let mut expected: Vec<String> = role.permissions().iter().map(|s| s.to_string()).collect();
        expected.sort_unstable();
        assert_eq!(held, expected, "{}", role.name);
        for p in CATALOGUE {
            let want = if expected.iter().any(|e| e == p.name) {
                204
            } else {
                403
            };
            assert_eq!(
                probe(&app, &t, tenant.id, p.name).await,
                want,
                "{} × {}",
                role.name,
                p.name
            );
        }
    }
}

#[tokio::test]
async fn rejects_missing_wrong_and_dead_tokens() {
    let app = TestApp::spawn_with(probe_routes()).await;
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let admin = user_with_role(&app, tenant.id, Some(ADMIN_ROLE)).await;

    // No token.
    let (status, body, www) = get_json(&app, "/admin/me", None).await;
    assert_eq!(status, 401);
    assert_eq!(www, "Bearer realm=\"ridm-admin\"");
    assert_eq!(body["type"], "urn:ridm:error:unauthorized");
    // Garbage.
    let (status, _, www) = get_json(&app, "/admin/me", Some("nope")).await;
    assert_eq!(status, 401);
    assert!(www.contains("error=\"invalid_token\""), "{www}");
    // Unknown tenant id in `tid`.
    let forged = {
        let real = token(&app, &tenant, admin, TokenOpts::default()).await;
        let mut parts: Vec<&str> = real.split('.').collect();
        let payload = format!(r#"{{"tid":"{}"}}"#, Uuid::now_v7());
        let enc =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload);
        parts[1] = &enc;
        parts.join(".")
    };
    let (status, _, _) = get_json(&app, "/admin/me", Some(&forged)).await;
    assert_eq!(status, 401);
    // Wrong audience.
    let t = token(
        &app,
        &tenant,
        admin,
        TokenOpts {
            audiences: &["https://api.example"],
            ..Default::default()
        },
    )
    .await;
    let (status, _, www) = get_json(&app, "/admin/me", Some(&t)).await;
    assert_eq!(status, 401, "audience must include {ADMIN_AUDIENCE}");
    assert!(www.contains("invalid_token"));
    // Token from another tenant's keys claiming this tenant is caught by
    // issuer/key verification.
    let other = create_tenant(&app.state.db).await;
    let other_tenant = tenants::get(&app.state, other.id).await.unwrap();
    let other_admin = user_with_role(&app, other.id, Some(ADMIN_ROLE)).await;
    let cross = token(&app, &other_tenant, other_admin, TokenOpts::default()).await;
    let (status, me, _) = get_json(&app, "/admin/me", Some(&cross)).await;
    assert_eq!(status, 200, "{me}");
    assert_eq!(me["tenant_id"], other.id.to_string());
    assert_eq!(probe(&app, &cross, tenant.id, "ridm:users:read").await, 403);

    // Revoked `jti`.
    let t = token(&app, &tenant, admin, TokenOpts::default()).await;
    let claims = tokens::verify(&app.state, &tenant, &t, &Default::default())
        .await
        .unwrap();
    denylist::deny(
        &app.state,
        tenant.id,
        claims["jti"].as_str().unwrap(),
        chrono::Utc::now() + chrono::Duration::minutes(5),
    )
    .await
    .unwrap();
    let (status, _, _) = get_json(&app, "/admin/me", Some(&t)).await;
    assert_eq!(status, 401);

    // No admin roles at all → 403, not 401 (the token itself is fine).
    let plain = user_with_role(&app, tenant.id, None).await;
    let t = token(&app, &tenant, plain, TokenOpts::default()).await;
    let (status, body, _) = get_json(&app, "/admin/me", Some(&t)).await;
    assert_eq!(status, 403, "{body}");

    // Disabled user.
    let t = token(&app, &tenant, admin, TokenOpts::default()).await;
    users::update(
        &app.state,
        tenant.id,
        Actor::System,
        admin,
        UserUpdate {
            status: Some(UserStatus::Disabled),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (status, _, _) = get_json(&app, "/admin/me", Some(&t)).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn role_changes_and_session_end_take_effect_immediately() {
    let app = TestApp::spawn_with(probe_routes()).await;
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let user = user_with_role(&app, tenant.id, Some(VIEWER_ROLE)).await;
    let t = token(&app, &tenant, user, TokenOpts::default()).await;
    assert_eq!(probe(&app, &t, tenant.id, "ridm:users:read").await, 204);
    assert_eq!(probe(&app, &t, tenant.id, "ridm:users:write").await, 403);

    // Promote: the same token now writes.
    assign(&app, tenant.id, user, ADMIN_ROLE).await;
    assert_eq!(probe(&app, &t, tenant.id, "ridm:users:write").await, 204);

    // Demote everything: the same token is refused outright.
    for name in [VIEWER_ROLE, ADMIN_ROLE] {
        let rid = role_id(&app, tenant.id, name).await;
        roles::unassign(
            &app.state,
            tenant.id,
            Actor::System,
            rid,
            Principal::User { id: user },
        )
        .await
        .unwrap();
    }
    let (status, _, _) = get_json(&app, "/admin/me", Some(&t)).await;
    assert_eq!(status, 403);

    // A custom role with a wildcard grant works like the built-ins.
    let custom = roles::create(
        &app.state,
        tenant.id,
        Actor::System,
        NewRole {
            name: "support".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut tx = db::tenant_tx(&app.state.db, tenant.id).await.unwrap();
    let rs = repos::resource_servers::find_by_identifier(&mut *tx, tenant.id, ADMIN_AUDIENCE)
        .await
        .unwrap()
        .unwrap();
    let wildcard = repos::resource_servers::insert_permission(
        &mut *tx,
        tenant.id,
        Uuid::now_v7(),
        rs.id,
        "ridm:users:*",
        Some("everything about users"),
    )
    .await
    .unwrap();
    repos::resource_servers::assign_permission(&mut *tx, tenant.id, custom.id, wildcard.id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    roles::assign(
        &app.state,
        tenant.id,
        Actor::System,
        custom.id,
        Principal::User { id: user },
    )
    .await
    .unwrap();
    assert_eq!(probe(&app, &t, tenant.id, "ridm:users:write").await, 204);
    assert_eq!(probe(&app, &t, tenant.id, "ridm:users:read").await, 204);
    assert_eq!(probe(&app, &t, tenant.id, "ridm:clients:read").await, 403);

    // Session-bound token dies with its session.
    let session = sessions::create(
        &app.state,
        tenant.id,
        NewSession {
            user_id: user,
            amr: vec!["pwd".into()],
            acr: None,
            ip: None,
            user_agent: None,
            device_id: None,
            policy: &tenant.settings.session,
        },
    )
    .await
    .unwrap();
    let ts = token(
        &app,
        &tenant,
        user,
        TokenOpts {
            session_id: Some(session.id),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(probe(&app, &ts, tenant.id, "ridm:users:read").await, 204);
    sessions::revoke(&app.state, tenant.id, session.id)
        .await
        .unwrap();
    let (status, _, www) = get_json(&app, "/admin/me", Some(&ts)).await;
    assert_eq!(status, 401);
    assert!(www.contains("invalid_token"));
}

#[tokio::test]
async fn built_in_roles_are_immutable_but_assignable() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let owner = role_id(&app, tid, OWNER_ROLE).await;
    let err = roles::update(
        &app.state,
        tid,
        Actor::System,
        owner,
        RoleUpdate {
            name: Some("root".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.status(), 403, "{err}");
    let err = roles::delete(&app.state, tid, Actor::System, owner)
        .await
        .unwrap_err();
    assert_eq!(err.status(), 403, "{err}");
    let listed = roles::list(&app.state, tid, Some(None)).await.unwrap();
    let names: Vec<&str> = listed
        .iter()
        .filter(|r| r.built_in)
        .map(|r| r.name.as_str())
        .collect();
    for r in BUILT_IN_ROLES {
        assert!(names.contains(&r.name), "{} seeded", r.name);
    }
    // Custom roles are unaffected.
    let custom = roles::create(
        &app.state,
        tid,
        Actor::System,
        NewRole {
            name: "temp".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(!custom.built_in);
    roles::delete(&app.state, tid, Actor::System, custom.id)
        .await
        .unwrap();
}

#[tokio::test]
async fn token_endpoint_only_mints_admin_audience_for_allowed_clients() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let service_user = user_with_role(&app, tid, Some(ADMIN_ROLE)).await;

    // A client that is otherwise unrestricted must still not obtain the admin
    // audience implicitly.
    let open = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("open-svc".into()),
            name: "open".into(),
            client_type: Some(ClientType::Machine),
            allowed_scopes: Some(vec![]),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .basic_auth("open-svc", open.client_secret.as_deref())
        .form(&[
            ("grant_type", "client_credentials"),
            ("resource", ADMIN_AUDIENCE),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_target");

    // An explicitly allowed client with a service account gets a usable token.
    let allowed = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("terraform".into()),
            name: "terraform".into(),
            client_type: Some(ClientType::Machine),
            allowed_scopes: Some(vec![]),
            allowed_audiences: vec![ADMIN_AUDIENCE.into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut tx = db::tenant_tx(&app.state.db, tid).await.unwrap();
    repos::clients::set_service_account(&mut *tx, tid, allowed.client.id, Some(service_user))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .basic_auth("terraform", allowed.client_secret.as_deref())
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let at = body["access_token"].as_str().unwrap();
    let (status, me, _) = get_json(&app, "/admin/me", Some(at)).await;
    assert_eq!(status, 200, "{me}");
    assert_eq!(me["scope"], "tenant");
    assert_eq!(me["user_id"], service_user.to_string());
    assert!(
        me["roles"]
            .as_array()
            .unwrap()
            .contains(&Value::from(ADMIN_ROLE))
    );

    // Same client without a service account: valid token, but no subject to
    // derive permissions from.
    let mut tx = db::tenant_tx(&app.state.db, tid).await.unwrap();
    repos::clients::set_service_account(&mut *tx, tid, allowed.client.id, None)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    app.state
        .cache
        .invalidate(&[ridm_api::cache::keys::client_by_client_id(tid, "terraform")])
        .await
        .unwrap();
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .basic_auth("terraform", allowed.client_secret.as_deref())
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let (status, body, _) = get_json(
        &app,
        "/admin/me",
        Some(body["access_token"].as_str().unwrap()),
    )
    .await;
    assert_eq!(status, 403, "{body}");
}
