//! Phase 13.3: LDAP / Active Directory upstream. A real OpenLDAP (see
//! `common::ldap`) is the directory: its users sign in with the password
//! form (rIDM binds as them), are imported on first sign-in and by the
//! sync job, get their groups, are disabled when they leave, and — when the
//! directory is writable — have their password and profile written back.

mod common;

use common::TestApp;
use common::admin::{admin_token, call};
use common::ldap::{self as dir, ADMIN_DN, ADMIN_PASSWORD, Namespace};
use reqwest::Method;
use ridm_api::models::{
    AttributeDef, ClientType, NewClient, NewGroup, NewUser, ProfileSchema, User, UserStatus,
};
use ridm_api::services::admin_access::OWNER_ROLE;
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::tenant_config;
use ridm_api::services::{clients, groups, ldap, profile_schema, tenants, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const ALIAS: &str = "corp";
const ALICE_PW: &str = "Alice-Directory-Pw1";

struct Fx {
    app: TestApp,
    token: String,
    ns: Namespace,
}

impl Fx {
    fn base(&self) -> String {
        format!("/admin/tenants/{}/identity-providers", self.app.tenant.slug)
    }
}

async fn fixture() -> Fx {
    let app = TestApp::spawn().await;
    clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("spa".into()),
            name: "My App".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            require_consent: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    profile_schema::set(
        &app.state,
        app.tenant.id,
        Actor::System,
        ProfileSchema {
            attributes: vec![AttributeDef {
                name: "given_name".into(),
                ..Default::default()
            }],
            allow_undeclared: false,
        },
    )
    .await
    .unwrap();
    let token = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let ns = dir::namespace().await;
    Fx { app, token, ns }
}

/// The settings of a directory at the test's namespace, over plain LDAP on
/// loopback, searching as the admin.
async fn settings(fx: &Fx) -> Value {
    json!({
        "url": dir::directory().await.url(),
        "vendor": "openldap",
        "bind_dn": ADMIN_DN,
        "bind_password": ADMIN_PASSWORD,
        "users_dn": fx.ns.people,
        "groups_dn": fx.ns.groups,
        "sync_interval_minutes": 0,
    })
}

async fn create_directory(fx: &Fx, ldap: Value) -> Value {
    let (s, body, _) = call(
        &fx.app,
        Method::POST,
        &fx.base(),
        Some(&fx.token),
        Some(&json!({
            "alias": ALIAS,
            "kind": "ldap",
            "display_name": "Corp Directory",
            "trust_email": true,
            "mappers": {"attributes": {"given_name": "givenName"}},
            "ldap": ldap,
        })),
    )
    .await;
    assert_eq!(s, 201, "{body}");
    body
}

async fn patch_directory(fx: &Fx, body: Value) -> (reqwest::StatusCode, Value) {
    let (s, b, _) = call(
        &fx.app,
        Method::PATCH,
        &format!("{}/{ALIAS}", fx.base()),
        Some(&fx.token),
        Some(&body),
    )
    .await;
    (s, b)
}

async fn sync(fx: &Fx, full: bool) -> Value {
    let (s, body, _) = call(
        &fx.app,
        Method::POST,
        &format!("{}/{ALIAS}/ldap/sync", fx.base()),
        Some(&fx.token),
        Some(&json!({"full": full})),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    body
}

async fn test_connection(fx: &Fx) -> Value {
    let (s, body, _) = call(
        &fx.app,
        Method::POST,
        &format!("{}/{ALIAS}/ldap/test", fx.base()),
        Some(&fx.token),
        None,
    )
    .await;
    assert_eq!(s, 200, "{body}");
    body
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

/// Start a login flow and post the password step; returns the status and
/// the answer.
async fn sign_in(fx: &Fx, identifier: &str, password: &str) -> (u16, Value) {
    let http = client();
    let res = http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid profile"),
            ("state", "st"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let flow = loc
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    let state: Value = http
        .get(fx.app.tenant_url(&format!("/flows/{flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let res = http
        .post(fx.app.tenant_url(&format!("/flows/{flow}/password")))
        .json(&json!({
            "csrf": state["csrf"],
            "identifier": identifier,
            "password": password,
        }))
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

async fn find_user(fx: &Fx, identifier: &str) -> Option<User> {
    users::find_by_identifier(&fx.app.state, fx.app.tenant.id, identifier)
        .await
        .unwrap()
}

async fn group_members(fx: &Fx, name: &str) -> Option<Vec<String>> {
    let all = groups::list(&fx.app.state, fx.app.tenant.id).await.unwrap();
    let g = all.iter().find(|g| g.name == name)?;
    let mut names: Vec<String> =
        groups::members(&fx.app.state, fx.app.tenant.id, g.id, None, None, None)
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|m| m.user.username)
            .collect();
    names.sort();
    Some(names)
}

async fn local_user(fx: &Fx, username: &str, pw: &str) -> Uuid {
    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    let u = users::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewUser {
            username: username.into(),
            email: Some(format!("{username}@local.example")),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    password::set_password(
        &fx.app.state,
        fx.app.tenant.id,
        &tenant.settings.password,
        Actor::System,
        u.id,
        pw.to_string().into(),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    u.id
}

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_directory_user_signs_in_is_imported_and_binds_again_every_time() {
    let fx = fixture().await;
    let alice = dir::add_user(
        &fx.ns,
        "alice",
        ALICE_PW,
        Some("alice@corp.example"),
        Some("Alice"),
    )
    .await;
    dir::add_group(&fx.ns, "engineers", &[&alice]).await;
    local_user(&fx, "bob", "Bob-Local-Passw0rd").await;
    let created = create_directory(&fx, settings(&fx).await).await;
    assert_eq!(created["kind"], "ldap");
    assert_eq!(created["callback_url"], "");
    assert_eq!(created["ldap"]["bind_password_set"], true);
    assert!(created["ldap"].get("bind_password").is_none(), "{created}");
    assert_eq!(created["ldap"]["username_attribute"], "uid");
    assert_eq!(created["ldap"]["uuid_attribute"], "entryUUID");
    assert_eq!(created["mappers"]["username"], "uid");

    // Nobody signs in with a wrong password, and nobody is created by it.
    let (s, _) = sign_in(&fx, "alice", "wrong-password").await;
    assert_eq!(s, 401);
    assert!(find_user(&fx, "alice").await.is_none());

    // The first sign-in imports alice with her attributes and groups.
    let (s, after) = sign_in(&fx, "alice", ALICE_PW).await;
    assert_eq!(s, 200, "{after}");
    let user = find_user(&fx, "alice").await.expect("imported");
    assert_eq!(user.email.as_deref(), Some("alice@corp.example"));
    assert!(
        user.email_verified,
        "the provider trusts the directory's email"
    );
    assert!(
        user.password_hash.is_none(),
        "the directory owns the password"
    );
    assert_eq!(user.attributes["given_name"], "Alice");
    assert_eq!(
        group_members(&fx, "engineers").await.unwrap(),
        vec!["alice".to_string()]
    );

    // Later sign-ins bind again: a password changed in the directory
    // counts at once, by username or by email.
    dir::replace(&alice, "userPassword", &["Alice-New-Pw2"]).await;
    assert_eq!(sign_in(&fx, "alice", ALICE_PW).await.0, 401);
    assert_eq!(sign_in(&fx, "alice", "Alice-New-Pw2").await.0, 200);
    assert_eq!(
        sign_in(&fx, "alice@corp.example", "Alice-New-Pw2").await.0,
        200
    );

    // A directory change of email and name reaches rIDM at the next bind.
    dir::replace(&alice, "mail", &["alice.w@corp.example"]).await;
    dir::replace(&alice, "givenName", &["Alicia"]).await;
    assert_eq!(sign_in(&fx, "alice", "Alice-New-Pw2").await.0, 200);
    let user = find_user(&fx, "alice").await.unwrap();
    assert_eq!(user.email.as_deref(), Some("alice.w@corp.example"));
    assert_eq!(user.attributes["given_name"], "Alicia");

    // Local accounts are untouched by the directory.
    assert_eq!(sign_in(&fx, "bob", "Bob-Local-Passw0rd").await.0, 200);
    assert_eq!(sign_in(&fx, "bob", "wrong").await.0, 401);

    // The login page offers no button for a directory.
    let (s, _) = sign_in(&fx, "nobody-here", "whatever-pw").await;
    assert_eq!(s, 401);
    let offered = ridm_api::services::identity_providers::offered(&fx.app.state, fx.app.tenant.id)
        .await
        .unwrap();
    assert!(offered.iter().all(|p| p.alias != ALIAS));

    // A disabled directory signs its users in no more.
    let (s, _) = patch_directory(&fx, json!({"enabled": false})).await;
    assert_eq!(s, 200);
    assert_eq!(sign_in(&fx, "alice", "Alice-New-Pw2").await.0, 401);
}

#[tokio::test]
async fn an_unreachable_directory_is_an_outage_not_a_local_fallback() {
    let fx = fixture().await;
    dir::add_user(&fx.ns, "carl", "Carl-Directory-Pw1", None, None).await;
    create_directory(&fx, settings(&fx).await).await;
    assert_eq!(sign_in(&fx, "carl", "Carl-Directory-Pw1").await.0, 200);
    // Point it at a closed port.
    let mut s = settings(&fx).await;
    s["url"] = json!("ldap://127.0.0.1:1");
    s["timeout_secs"] = json!(2);
    let (st, body) = patch_directory(&fx, json!({"ldap": s})).await;
    assert_eq!(st, 200, "{body}");
    let (st, _) = sign_in(&fx, "carl", "Carl-Directory-Pw1").await;
    assert_eq!(st, 503, "a linked user's sign-in needs the directory");
    let (st, _) = sign_in(&fx, "someone-else", "Some-Pw-123").await;
    assert_eq!(st, 503, "an unknown identifier may be a directory user");
    let report = test_connection(&fx).await;
    assert_eq!(report["connected"], false);
    assert!(report["error"].as_str().is_some());
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sync_imports_updates_disables_and_enables_users_and_owns_its_groups() {
    let fx = fixture().await;
    let carol = dir::add_user(
        &fx.ns,
        "carol",
        "Carol-Pw-1234",
        Some("carol@corp.example"),
        None,
    )
    .await;
    let dave = dir::add_user(
        &fx.ns,
        "dave",
        "Dave-Pw-12345",
        Some("dave@corp.example"),
        None,
    )
    .await;
    let staff = dir::add_group(&fx.ns, "staff", &[&carol]).await;
    let admins = dir::add_group(&fx.ns, "admins", &[&dave]).await;
    // An administrator's own group of the same name is never taken over.
    let own = groups::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewGroup {
            name: "admins".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut s = settings(&fx).await;
    s["user_object_filter"] = json!("(&(objectClass=inetOrgPerson)(!(employeeType=gone)))");
    create_directory(&fx, s).await;

    let stats = sync(&fx, true).await;
    assert_eq!(stats["full"], true);
    assert_eq!(stats["read"], 2);
    assert_eq!(stats["created"], 2);
    assert_eq!(stats["groups_created"], 2);
    assert!(find_user(&fx, "carol").await.is_some());
    assert_eq!(group_members(&fx, "staff").await.unwrap(), vec!["carol"]);
    assert_eq!(
        group_members(&fx, "admins (corp)").await.unwrap(),
        vec!["dave"]
    );
    assert!(
        groups::members(&fx.app.state, fx.app.tenant.id, own.id, None, None, None)
            .await
            .unwrap()
            .items
            .is_empty(),
        "the administrator's group is left alone"
    );

    // An incremental pass picks up what changed.
    dir::replace(&dave, "mail", &["dave.d@corp.example"]).await;
    dir::replace(&staff, "member", &[&dave]).await;
    // modifyTimestamp has one-second resolution.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let stats = sync(&fx, false).await;
    assert_eq!(stats["full"], false);
    assert!(stats["updated"].as_u64().unwrap() >= 1, "{stats}");
    assert_eq!(
        find_user(&fx, "dave").await.unwrap().email.as_deref(),
        Some("dave.d@corp.example")
    );
    assert_eq!(group_members(&fx, "staff").await.unwrap(), vec!["dave"]);

    // A full pass disables the users whose entries it no longer reads …
    dir::replace(&carol, "employeeType", &["gone"]).await;
    let stats = sync(&fx, true).await;
    assert_eq!(stats["disabled"], 1, "{stats}");
    let c = find_user(&fx, "carol").await.unwrap();
    assert_eq!(c.status, UserStatus::Disabled);
    assert_eq!(sign_in(&fx, "carol", "Carol-Pw-1234").await.0, 401);

    // … and enables them when they are back.
    dir::replace(&carol, "employeeType", &[]).await;
    let stats = sync(&fx, true).await;
    assert_eq!(stats["enabled"], 1, "{stats}");
    assert_eq!(
        find_user(&fx, "carol").await.unwrap().status,
        UserStatus::Active
    );

    // A user an administrator disabled stays disabled.
    let d = find_user(&fx, "dave").await.unwrap();
    users::update(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        d.id,
        ridm_api::models::UserUpdate {
            status: Some(UserStatus::Disabled),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let stats = sync(&fx, true).await;
    assert_eq!(stats["enabled"], 0, "{stats}");

    // A group gone from the directory goes; its rIDM twin with it.
    dir::delete(&admins).await;
    let stats = sync(&fx, true).await;
    assert_eq!(stats["groups_deleted"], 1, "{stats}");
    assert!(group_members(&fx, "admins (corp)").await.is_none());

    // A full pass that reads nothing (a wrong base) disables nobody.
    let mut s = settings(&fx).await;
    s["users_dn"] = json!(format!("ou=groups,{}", fx.ns.base));
    let (st, body) = patch_directory(&fx, json!({"ldap": s})).await;
    assert_eq!(st, 200, "{body}");
    let stats = sync(&fx, true).await;
    assert_eq!(stats["read"], 0);
    assert_eq!(stats["disabled"], 0);
    assert_eq!(
        find_user(&fx, "carol").await.unwrap().status,
        UserStatus::Active
    );

    // The outcome is on the provider, and the job finds nothing due while
    // periodic sync is off.
    let (_, view, _) = call(
        &fx.app,
        Method::GET,
        &format!("{}/{ALIAS}", fx.base()),
        Some(&fx.token),
        None,
    )
    .await;
    assert!(view["ldap"]["last_sync_at"].is_string(), "{view}");
    assert!(view["ldap"]["last_full_sync_at"].is_string());
    assert!(view["ldap"]["last_sync_error"].is_null());
    assert_eq!(view["ldap"]["last_sync_stats"]["full"], true);
    assert!(view["ldap"].get("sync_cursor").is_none());
}

#[tokio::test]
async fn the_sync_job_runs_due_directories_once_at_a_time() {
    let fx = fixture().await;
    dir::add_user(&fx.ns, "erin", "Erin-Pw-12345", None, None).await;
    let mut s = settings(&fx).await;
    s["sync_interval_minutes"] = json!(5);
    create_directory(&fx, s).await;
    // Other tests' directories may be due too; this one must be synced.
    ldap::sync_due(&fx.app.state).await.unwrap();
    assert!(find_user(&fx, "erin").await.is_some());
    // Not due again right away.
    let idp = ridm_api::services::identity_providers::get(&fx.app.state, fx.app.tenant.id, ALIAS)
        .await
        .unwrap();
    let first = idp.ldap.unwrap().last_sync_at.unwrap();
    ldap::sync_due(&fx.app.state).await.unwrap();
    let idp = ridm_api::services::identity_providers::get(&fx.app.state, fx.app.tenant.id, ALIAS)
        .await
        .unwrap();
    assert_eq!(idp.ldap.unwrap().last_sync_at.unwrap(), first);
    // Two syncs of one directory never overlap.
    let (a, b) = tokio::join!(
        ldap::sync(&fx.app.state, fx.app.tenant.id, idp.id, true),
        ldap::sync(&fx.app.state, fx.app.tenant.id, idp.id, true),
    );
    // One ran; the other ran after it or was refused while it held the lock.
    assert!(a.is_ok() || b.is_ok());
    for r in [a, b] {
        if let Err(e) = r {
            assert!(matches!(e, ridm_api::error::AppError::Conflict(_)), "{e}");
        }
    }
    // Later runs' job passes need not visit this directory again.
    let (s, _) = patch_directory(&fx, json!({"enabled": false})).await;
    assert_eq!(s, 200);
}

// ---------------------------------------------------------------------------
// Write-back
// ---------------------------------------------------------------------------

#[tokio::test]
async fn write_back_follows_the_edit_mode() {
    let fx = fixture().await;
    let frank = dir::add_user(
        &fx.ns,
        "frank",
        "Frank-Pw-12345",
        Some("frank@corp.example"),
        Some("Frank"),
    )
    .await;
    create_directory(&fx, settings(&fx).await).await;
    assert_eq!(sign_in(&fx, "frank", "Frank-Pw-12345").await.0, 200);
    let user = find_user(&fx, "frank").await.unwrap();
    let users_path = format!("/admin/tenants/{}/users/{}", fx.app.tenant.slug, user.id);

    // Read-only: the directory is where these change.
    let (s, body, _) = call(
        &fx.app,
        Method::PUT,
        &format!("{users_path}/password"),
        Some(&fx.token),
        Some(&json!({"password": "Another-Passw0rd-1"})),
    )
    .await;
    assert_eq!(s, 400, "{body}");
    assert!(body.to_string().contains("Corp Directory"), "{body}");
    for patch in [
        json!({"email": "frank@elsewhere.example"}),
        json!({"attributes": {"given_name": "Francis"}}),
        json!({"username": "francis"}),
    ] {
        let (s, body, _) = call(
            &fx.app,
            Method::PATCH,
            &users_path,
            Some(&fx.token),
            Some(&patch),
        )
        .await;
        assert_eq!(s, 400, "{patch}: {body}");
    }
    // What the directory does not own stays editable.
    let (s, body, _) = call(
        &fx.app,
        Method::PATCH,
        &users_path,
        Some(&fx.token),
        Some(&json!({"locale": "de"})),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(dir::read(&frank, "mail").await, vec!["frank@corp.example"]);

    // Writable: rIDM writes the directory as the service account.
    let (s, body) = patch_directory(
        &fx,
        json!({"ldap": {
            "url": dir::directory().await.url(),
            "vendor": "openldap",
            "bind_dn": ADMIN_DN,
            "users_dn": fx.ns.people,
            "sync_interval_minutes": 0,
            "edit_mode": "writable",
        }}),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["ldap"]["bind_password_set"], true, "kept");
    let (s, body, _) = call(
        &fx.app,
        Method::PUT,
        &format!("{users_path}/password"),
        Some(&fx.token),
        Some(&json!({"password": "Another-Passw0rd-1"})),
    )
    .await;
    assert_eq!(s, 204, "{body}");
    let url = dir::directory().await.url();
    assert!(dir::bind_ok(&url, &frank, "Another-Passw0rd-1").await);
    assert!(!dir::bind_ok(&url, &frank, "Frank-Pw-12345").await);
    assert!(
        find_user(&fx, "frank")
            .await
            .unwrap()
            .password_hash
            .is_none()
    );
    assert_eq!(sign_in(&fx, "frank", "Another-Passw0rd-1").await.0, 200);

    // The tenant's password policy still applies.
    let (s, _, _) = call(
        &fx.app,
        Method::PUT,
        &format!("{users_path}/password"),
        Some(&fx.token),
        Some(&json!({"password": "short"})),
    )
    .await;
    assert_eq!(s, 400);

    // A temporary password is written there and must be changed here.
    let (s, body, _) = call(
        &fx.app,
        Method::PUT,
        &format!("{users_path}/password"),
        Some(&fx.token),
        None,
    )
    .await;
    assert_eq!(s, 200, "{body}");
    let temp = body["temporary_password"].as_str().unwrap();
    assert!(dir::bind_ok(&url, &frank, temp).await);
    assert!(find_user(&fx, "frank").await.unwrap().must_change_password);

    let (s, body, _) = call(
        &fx.app,
        Method::PATCH,
        &users_path,
        Some(&fx.token),
        Some(&json!({"email": "frank@new.example", "attributes": {"given_name": "Francis"}})),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(dir::read(&frank, "mail").await, vec!["frank@new.example"]);
    assert_eq!(dir::read(&frank, "givenName").await, vec!["Francis"]);
    // The username always comes from the directory.
    let (s, _, _) = call(
        &fx.app,
        Method::PATCH,
        &users_path,
        Some(&fx.token),
        Some(&json!({"username": "francis"})),
    )
    .await;
    assert_eq!(s, 400);
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ldaps_and_starttls_verify_the_directory_against_a_pinned_ca() {
    let fx = fixture().await;
    dir::add_user(&fx.ns, "gina", "Gina-Pw-123456", None, None).await;
    let d = dir::directory().await;
    let mut s = settings(&fx).await;
    s["url"] = json!(d.ldaps_url());
    s["ca_certificate"] = json!(d.ca_pem);
    create_directory(&fx, s).await;
    let report = test_connection(&fx).await;
    assert_eq!(report["connected"], true, "{report}");
    assert_eq!(report["bound"], true, "{report}");
    assert!(
        report["users"]
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["username"] == "gina"),
        "{report}"
    );
    assert_eq!(sign_in(&fx, "gina", "Gina-Pw-123456").await.0, 200);

    // StartTLS on the plain port.
    let mut s = settings(&fx).await;
    s["url"] = json!(d.starttls_url());
    s["starttls"] = json!(true);
    s["ca_certificate"] = json!(d.ca_pem);
    let (st, body) = patch_directory(&fx, json!({"ldap": s})).await;
    assert_eq!(st, 200, "{body}");
    let report = test_connection(&fx).await;
    assert_eq!(report["bound"], true, "{report}");

    // Another CA is not trusted: no connection.
    let other = rcgen::generate_simple_self_signed(vec!["other".to_string()])
        .unwrap()
        .cert
        .pem();
    let mut s = settings(&fx).await;
    s["url"] = json!(d.ldaps_url());
    s["ca_certificate"] = json!(other);
    let (st, body) = patch_directory(&fx, json!({"ldap": s})).await;
    assert_eq!(st, 200, "{body}");
    let report = test_connection(&fx).await;
    assert_eq!(report["connected"], false, "{report}");
}

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn administrators_configure_directories_and_never_see_the_bind_password() {
    let fx = fixture().await;
    dir::add_user(&fx.ns, "hank", "Hank-Pw-123456", None, None).await;
    let good = settings(&fx).await;
    let bad = |k: &str, v: Value| {
        let mut s = good.clone();
        s[k] = v;
        s
    };
    for (ldap, field) in [
        (bad("url", json!("ldap://dc1.corp.example")), "ldap.url"),
        (bad("url", json!("https://dc1.corp.example")), "ldap.url"),
        (
            bad("user_object_filter", json!("objectClass=person")),
            "ldap.user_object_filter",
        ),
        (
            bad("username_attribute", json!("user name")),
            "ldap.username_attribute",
        ),
        (bad("users_dn", json!("people")), "ldap.users_dn"),
        (
            bad("sync_interval_minutes", json!(2)),
            "ldap.sync_interval_minutes",
        ),
        (
            bad("ca_certificate", json!("not a certificate")),
            "ldap.ca_certificate",
        ),
        (
            {
                let mut s = bad("edit_mode", json!("writable"));
                s.as_object_mut().unwrap().remove("bind_dn");
                s.as_object_mut().unwrap().remove("bind_password");
                s
            },
            "ldap.edit_mode",
        ),
        (
            {
                let mut s = good.clone();
                s.as_object_mut().unwrap().remove("bind_dn");
                s
            },
            "ldap.bind_password",
        ),
    ] {
        let (s, body, _) = call(
            &fx.app,
            Method::POST,
            &fx.base(),
            Some(&fx.token),
            Some(&json!({"alias": ALIAS, "kind": "ldap", "ldap": ldap})),
        )
        .await;
        assert_eq!(s, 400, "{field}: {body}");
        assert!(body.to_string().contains(field), "{field}: {body}");
    }
    let (s, body, _) = call(
        &fx.app,
        Method::POST,
        &fx.base(),
        Some(&fx.token),
        Some(&json!({"alias": ALIAS, "kind": "ldap", "client_secret": "x", "ldap": good})),
    )
    .await;
    assert_eq!(s, 400, "{body}");
    let (s, body, _) = call(
        &fx.app,
        Method::POST,
        &fx.base(),
        Some(&fx.token),
        Some(&json!({"alias": ALIAS, "kind": "ldap"})),
    )
    .await;
    assert_eq!(s, 400, "{body}");

    create_directory(&fx, good.clone()).await;
    let (s, list, _) = call(&fx.app, Method::GET, &fx.base(), Some(&fx.token), None).await;
    assert_eq!(s, 200);
    assert!(!list.to_string().contains(ADMIN_PASSWORD), "{list}");

    // Kinds do not change to or from LDAP.
    let (s, _) = patch_directory(&fx, json!({"kind": "oidc"})).await;
    assert_eq!(s, 400);
    // A connection test binds with the stored password; clearing it makes
    // the service bind fail.
    assert_eq!(test_connection(&fx).await["bound"], true);
    let mut cleared = good.clone();
    cleared["bind_password"] = json!("");
    let (s, body) = patch_directory(&fx, json!({"ldap": cleared})).await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["ldap"]["bind_password_set"], false);
    let report = test_connection(&fx).await;
    assert_eq!(report["bound"], false, "{report}");
    let (s, body) = patch_directory(&fx, json!({"ldap": good})).await;
    assert_eq!(s, 200, "{body}");

    assert_eq!(sign_in(&fx, "hank", "Hank-Pw-123456").await.0, 200);

    // The settings travel in the tenant document (without the password),
    // and importing that document plans no change.
    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    let doc = tenant_config::export(&fx.app.state, &tenant).await.unwrap();
    let p = doc
        .identity_providers
        .iter()
        .find(|p| p.alias == ALIAS)
        .unwrap();
    let exported = serde_json::to_string(p).unwrap();
    assert!(exported.contains("\"users_dn\""), "{exported}");
    assert!(!exported.contains("bind_password"), "{exported}");
    let plan = tenant_config::plan(&fx.app.state, &tenant, doc.clone(), false)
        .await
        .unwrap();
    assert!(
        plan.changes
            .iter()
            .all(|c| c.resource != "identity_provider"),
        "{:?}",
        plan.changes
    );

    // The LDAP endpoints refuse other kinds.
    let (s, _, _) = call(
        &fx.app,
        Method::POST,
        &fx.base(),
        Some(&fx.token),
        Some(&json!({
            "alias": "oidc-one",
            "kind": "oauth2",
            "client_id": "x",
            "client_secret": "y",
            "authorization_endpoint": "https://idp.example/a",
            "token_endpoint": "https://idp.example/t",
            "userinfo_endpoint": "https://idp.example/u",
        })),
    )
    .await;
    assert_eq!(s, 201);
    for op in ["test", "sync"] {
        let (s, body, _) = call(
            &fx.app,
            Method::POST,
            &format!("{}/oidc-one/ldap/{op}", fx.base()),
            Some(&fx.token),
            Some(&json!({})),
        )
        .await;
        assert_eq!(s, 400, "{op}: {body}");
    }
    let (s, body, _) = call(
        &fx.app,
        Method::PATCH,
        &format!("{}/oidc-one", fx.base()),
        Some(&fx.token),
        Some(&json!({"ldap": good})),
    )
    .await;
    assert_eq!(s, 400, "{body}");

    // Deleting the directory leaves its users, with no password to sign in
    // with until one is set.
    let (s, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{}/{ALIAS}", fx.base()),
        Some(&fx.token),
        None,
    )
    .await;
    assert_eq!(s, 204);
    let hank = find_user(&fx, "hank").await.expect("kept");
    assert!(hank.password_hash.is_none());
    assert_eq!(sign_in(&fx, "hank", "Hank-Pw-123456").await.0, 401);
}
