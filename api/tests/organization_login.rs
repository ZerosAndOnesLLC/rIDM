//! Phase 12.1: choosing an organization while signing in, and what the tokens
//! issued from that sign-in then say.

mod common;

use common::TestApp;
use ridm_api::models::{
    ClientType, NewClient, NewOrganization, NewOrganizationDomain, NewUser, Organization,
    OrganizationStatus, OrganizationUpdate, Principal, TenantSettings,
};
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::{clients, organizations, roles, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PASSWORD: &str = "correct-horse-battery";

struct Fx {
    app: TestApp,
    user_id: Uuid,
}

async fn fixture() -> Fx {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let user = users::create(
        &app.state,
        tid,
        Actor::System,
        NewUser {
            username: "alice".into(),
            email: Some("alice@acme.example".into()),
            email_verified: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    password::set_password(
        &app.state,
        tid,
        &TenantSettings::default().password,
        Actor::System,
        user.id,
        PASSWORD.to_string().into(),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    clients::create(
        &app.state,
        tid,
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
    Fx {
        app,
        user_id: user.id,
    }
}

async fn make_org(fx: &Fx, slug: &str) -> Organization {
    organizations::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewOrganization {
            slug: slug.into(),
            display_name: slug.to_uppercase(),
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

async fn join(fx: &Fx, org: &Organization) {
    organizations::add_member(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        org.id,
        fx.user_id,
    )
    .await
    .unwrap();
}

/// `/authorize` without a session, returning the flow id and its state.
async fn start(fx: &Fx, extra: &[(&str, &str)]) -> (Uuid, Value) {
    let mut q = vec![
        ("response_type", "code"),
        ("client_id", "spa"),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "openid profile"),
        ("state", "st"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    q.extend_from_slice(extra);
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&q)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303, "authorize should start a flow");
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let id: Uuid = loc
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .unwrap()
        .1
        .parse()
        .unwrap();
    (id, flow_state(fx, id).await)
}

async fn flow_state(fx: &Fx, id: Uuid) -> Value {
    fx.app
        .http
        .get(fx.app.tenant_url(&format!("/flows/{id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn step(fx: &Fx, id: Uuid, name: &str, body: Value) -> reqwest::Response {
    fx.app
        .http
        .post(fx.app.tenant_url(&format!("/flows/{id}/{name}")))
        .json(&body)
        .send()
        .await
        .unwrap()
}

/// Sign in with the password; returns the flow state after authentication.
async fn sign_in(fx: &Fx, id: Uuid, csrf: &str) -> Value {
    let res = step(
        fx,
        id,
        "password",
        json!({"csrf": csrf, "identifier": "alice", "password": PASSWORD}),
    )
    .await;
    assert_eq!(res.status(), 200);
    res.json().await.unwrap()
}

/// Follow the flow's finish and exchange the code; returns the token response.
async fn finish_and_exchange(fx: &Fx, id: Uuid) -> Value {
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url(&format!("/flows/{id}/finish")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let code = loc
        .query_pairs()
        .find(|(k, _)| k == "code")
        .expect("a code")
        .1
        .to_string();
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://app.example/cb"),
            ("client_id", "spa"),
            ("code_verifier", VERIFIER),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    res.json().await.unwrap()
}

fn claims_of(token: &str) -> Value {
    use base64::Engine;
    let payload = token.split('.').nth(1).expect("a JWT");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    serde_json::from_slice(&raw).unwrap()
}

#[tokio::test]
async fn no_organizations_means_no_question_and_no_claim() {
    let fx = fixture().await;
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "done", "{after}");
    let tokens = finish_and_exchange(&fx, id).await;
    let access = claims_of(tokens["access_token"].as_str().unwrap());
    assert!(access.get("org_id").is_none(), "{access}");
    let id_claims = claims_of(tokens["id_token"].as_str().unwrap());
    assert!(id_claims.get("org_id").is_none(), "{id_claims}");
}

#[tokio::test]
async fn one_membership_is_chosen_without_asking() {
    let fx = fixture().await;
    let acme = make_org(&fx, "acme").await;
    join(&fx, &acme).await;

    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "done", "one organization should not ask");

    let tokens = finish_and_exchange(&fx, id).await;
    let access = claims_of(tokens["access_token"].as_str().unwrap());
    assert_eq!(access["org_id"], json!(acme.id.to_string()));
    let id_claims = claims_of(tokens["id_token"].as_str().unwrap());
    assert_eq!(id_claims["org_id"], json!(acme.id.to_string()));
}

#[tokio::test]
async fn several_memberships_ask_and_the_choice_reaches_the_tokens() {
    let fx = fixture().await;
    let tid = fx.app.tenant.id;
    let acme = make_org(&fx, "acme").await;
    let globex = make_org(&fx, "globex").await;
    join(&fx, &acme).await;
    join(&fx, &globex).await;

    // A role that only applies inside globex.
    let role = roles::create(
        &fx.app.state,
        tid,
        Actor::System,
        ridm_api::models::NewRole {
            name: "globex-admin".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    organizations::assign_role(
        &fx.app.state,
        tid,
        Actor::System,
        globex.id,
        role.id,
        Principal::User { id: fx.user_id },
    )
    .await
    .unwrap();

    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "organization", "{after}");
    let offered = after["organizations"].as_array().unwrap();
    assert_eq!(offered.len(), 2, "{offered:?}");
    assert!(offered.iter().any(|o| o["slug"] == "acme"));

    // The step refuses CSRF-less calls and organizations the user is not in.
    assert_eq!(
        step(
            &fx,
            id,
            "organization",
            json!({"csrf": "nope", "org_id": globex.id})
        )
        .await
        .status(),
        403
    );
    let outsider = organizations::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewOrganization {
            slug: "initech".into(),
            display_name: "Initech".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        step(
            &fx,
            id,
            "organization",
            json!({"csrf": csrf, "org_id": outsider.id})
        )
        .await
        .status(),
        400
    );

    let res = step(
        &fx,
        id,
        "organization",
        json!({"csrf": csrf, "org_id": globex.id}),
    )
    .await;
    assert_eq!(res.status(), 200);
    let after: Value = res.json().await.unwrap();
    assert_eq!(after["stage"], "done", "{after}");

    let tokens = finish_and_exchange(&fx, id).await;
    let access = claims_of(tokens["access_token"].as_str().unwrap());
    assert_eq!(access["org_id"], json!(globex.id.to_string()));
    // The org-scoped role is in the token, because the session acts there.
    let role_names: Vec<&str> = access["roles"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r.as_str())
        .collect();
    assert!(role_names.contains(&"globex-admin"), "{role_names:?}");

    // Refreshing keeps the organization and its roles.
    let refresh = tokens["refresh_token"].as_str().expect("a refresh token");
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", "spa"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let refreshed: Value = res.json().await.unwrap();
    let access = claims_of(refreshed["access_token"].as_str().unwrap());
    assert_eq!(access["org_id"], json!(globex.id.to_string()));
    assert!(
        access["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "globex-admin")
    );
}

#[tokio::test]
async fn the_request_may_name_the_organization() {
    let fx = fixture().await;
    let acme = make_org(&fx, "acme").await;
    let globex = make_org(&fx, "globex").await;
    join(&fx, &acme).await;
    join(&fx, &globex).await;

    // By slug, so the client does not need to know ids.
    let (id, state) = start(&fx, &[("organization", "globex")]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "done", "{after}");
    let tokens = finish_and_exchange(&fx, id).await;
    let access = claims_of(tokens["access_token"].as_str().unwrap());
    assert_eq!(access["org_id"], json!(globex.id.to_string()));

    // One the user does not belong to is not silently swapped: they are asked.
    let fx2 = fixture().await;
    let a = make_org(&fx2, "acme").await;
    let b = make_org(&fx2, "globex").await;
    join(&fx2, &a).await;
    join(&fx2, &b).await;
    make_org(&fx2, "initech").await;
    let (id, state) = start(&fx2, &[("organization", "initech")]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx2, id, &csrf).await;
    assert_eq!(after["stage"], "organization", "{after}");
}

#[tokio::test]
async fn a_disabled_organization_is_not_offered() {
    let fx = fixture().await;
    let acme = make_org(&fx, "acme").await;
    let globex = make_org(&fx, "globex").await;
    join(&fx, &acme).await;
    join(&fx, &globex).await;
    organizations::update(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        globex.id,
        OrganizationUpdate {
            status: Some(OrganizationStatus::Disabled),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Only one is left to act in, so nothing is asked.
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "done", "{after}");
    let tokens = finish_and_exchange(&fx, id).await;
    let access = claims_of(tokens["access_token"].as_str().unwrap());
    assert_eq!(access["org_id"], json!(acme.id.to_string()));
}

#[tokio::test]
async fn auto_join_happens_at_sign_in() {
    let fx = fixture().await;
    let tid = fx.app.tenant.id;
    let acme = make_org(&fx, "acme").await;
    let domain = organizations::add_domain(
        &fx.app.state,
        tid,
        Actor::System,
        acme.id,
        NewOrganizationDomain {
            domain: "acme.example".into(),
            auto_join: true,
        },
    )
    .await
    .unwrap();
    // As a passing DNS lookup would.
    let mut tx = ridm_api::db::tenant_tx(&fx.app.state.db, tid)
        .await
        .unwrap();
    ridm_api::repos::organizations::mark_domain_verified(&mut *tx, tid, acme.id, domain.id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // As the service does after a verification.
    fx.app
        .state
        .cache
        .invalidate(&[ridm_api::cache::keys::org_auto_join_domains(tid)])
        .await
        .unwrap();

    // The user is not a member yet; signing in makes them one, and the token
    // names the organization they were just put in.
    assert!(
        organizations::of_user(&fx.app.state, tid, fx.user_id)
            .await
            .unwrap()
            .is_empty()
    );
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "done", "{after}");
    let tokens = finish_and_exchange(&fx, id).await;
    let access = claims_of(tokens["access_token"].as_str().unwrap());
    assert_eq!(access["org_id"], json!(acme.id.to_string()));
    assert_eq!(
        organizations::of_user(&fx.app.state, tid, fx.user_id)
            .await
            .unwrap()
            .len(),
        1
    );
}
