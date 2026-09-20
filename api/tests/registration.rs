mod common;

use std::sync::Arc;

use async_trait::async_trait;
use common::TestApp;
use ridm_api::messaging::SenderFactory;
use ridm_api::models::{
    ClientType, NewClient, NewInvitation, NewRole, RegistrationPolicy, TenantSettings, UserStatus,
};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{clients, invitations, roles, users};
use ridm_api::state::AppState;
use ridm_core::events::Actor;
use ridm_core::providers::{EmailSender, SmsSender};
use ridm_core::test_support::{MockEmailSender, MockSmsSender};
use serde_json::{Value, json};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Mocks(Arc<MockEmailSender>);
#[async_trait]
impl SenderFactory for Mocks {
    async fn email(
        &self,
        _: &AppState,
        _: Uuid,
    ) -> ridm_api::error::AppResult<Option<Arc<dyn EmailSender>>> {
        Ok(Some(self.0.clone()))
    }
    async fn sms(
        &self,
        _: &AppState,
        _: Uuid,
    ) -> ridm_api::error::AppResult<Option<Arc<dyn SmsSender>>> {
        Ok(Some(Arc::new(MockSmsSender::new())))
    }
}

async fn fixture(registration: RegistrationPolicy) -> (TestApp, Arc<MockEmailSender>) {
    let email = Arc::new(MockEmailSender::new());
    let e2 = email.clone();
    let app = TestApp::spawn_configured(axum::Router::new(), move |st| {
        st.senders = Arc::new(Mocks(e2))
    })
    .await;
    let tid = app.tenant.id;
    tenants::update(
        &app.state,
        Actor::System,
        tid,
        TenantUpdate {
            settings: Some(TenantSettings {
                registration,
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("spa".into()),
            name: "spa".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            require_consent: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (app, email)
}

async fn start(app: &TestApp, prompt: &str) -> (Uuid, String) {
    let res = app
        .http
        .get(app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid"),
            ("prompt", prompt),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let id: Uuid = loc
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .unwrap()
        .1
        .parse()
        .unwrap();
    let state: Value = app
        .http
        .get(app.tenant_url(&format!("/flows/{id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (id, state["csrf"].as_str().unwrap().to_string())
}

fn link_token(text: &str, param: &str) -> String {
    let line = text
        .lines()
        .find(|l| l.contains(&format!("{param}=")))
        .expect("link line");
    url::Url::parse(line.trim())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == param)
        .unwrap()
        .1
        .into_owned()
}

#[tokio::test]
async fn registration_with_email_verification_continues_the_flow() {
    let (app, email) = fixture(RegistrationPolicy {
        enabled: true,
        require_email_verification: true,
        require_terms: true,
        terms_url: Some("https://x/tos".into()),
        allowed_email_domains: vec!["example.com".into()],
        ..Default::default()
    })
    .await;
    let (id, csrf) = start(&app, "create").await;
    let reg = |body: Value| {
        let app = &app;
        async move {
            app.http
                .post(app.tenant_url(&format!("/flows/{id}/register")))
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };
    // Policy: domain allowlist, terms, password required.
    let res = reg(json!({"csrf": csrf, "email": "eve@evil.example", "password": "correct-horse-battery", "terms_accepted": true})).await;
    assert_eq!(res.status(), 400);
    let res = reg(json!({"csrf": csrf, "email": "alice@example.com", "password": "correct-horse-battery", "terms_accepted": false})).await;
    assert_eq!(res.status(), 400);
    let res =
        reg(json!({"csrf": csrf, "email": "alice@example.com", "terms_accepted": true})).await;
    assert_eq!(res.status(), 400);
    let res = reg(json!({"csrf": csrf, "email": "alice@example.com", "password": "short", "terms_accepted": true})).await;
    assert_eq!(res.status(), 400, "password policy applies");
    assert!(
        users::find_by_identifier(&app.state, app.tenant.id, "alice@example.com")
            .await
            .unwrap()
            .is_none(),
        "no half-created account"
    );

    let res = reg(json!({"csrf": csrf, "email": "Alice@Example.com", "password": "correct-horse-battery", "terms_accepted": true})).await;
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "verify_email");
    assert!(res_has_no_cookie(&body));
    let user = users::find_by_identifier(&app.state, app.tenant.id, "alice@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.status, UserStatus::Pending);
    assert!(!user.email_verified);
    assert!(user.terms_accepted_at.is_some());
    assert_eq!(
        user.username, "alice@example.com",
        "email doubles as username when none given"
    );
    // Duplicate registration is a conflict.
    let (id2, csrf2) = start(&app, "create").await;
    let res = app
        .http
        .post(app.tenant_url(&format!("/flows/{id2}/register")))
        .json(&json!({"csrf": csrf2, "email": "alice@example.com", "password": "correct-horse-battery", "terms_accepted": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 409);

    // Pending users cannot log in with the password yet? They can once verified; before that
    // the flow waits. Open the verification link: account activated and the flow completes.
    let mail = email.last().unwrap();
    assert_eq!(mail.to[0].email, "alice@example.com");
    let token = link_token(&mail.text, "token");
    let flow_in_link = link_token(&mail.text, "flow");
    assert_eq!(flow_in_link, id.to_string());
    let res = app
        .http
        .post(app.tenant_url("/verification/email/confirm"))
        .json(&json!({"token": token}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let cookie = res.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["verified"], true);
    assert_eq!(body["stage"], "done", "{body}");
    let res = app
        .http
        .get(body["finish_url"].as_str().unwrap())
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    assert!(
        res.headers()["location"]
            .to_str()
            .unwrap()
            .contains("code=")
    );
    let user = users::get(&app.state, app.tenant.id, user.id)
        .await
        .unwrap();
    assert_eq!(user.status, UserStatus::Active);
    assert!(user.email_verified);
    // Token is single use.
    let res = app
        .http
        .post(app.tenant_url("/verification/email/confirm"))
        .json(&json!({"token": token}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

fn res_has_no_cookie(body: &Value) -> bool {
    body.get("finish_url").is_none()
}

#[tokio::test]
async fn registration_without_verification_signs_in_and_disabled_registration_is_refused() {
    let (app, _email) = fixture(RegistrationPolicy {
        enabled: true,
        require_email_verification: false,
        ..Default::default()
    })
    .await;
    let (id, csrf) = start(&app, "login").await;
    // Registration can also be started from the login page (authenticate stage).
    let res = app.http.post(app.tenant_url(&format!("/flows/{id}/register"))).json(&json!({"csrf": csrf, "username": "bob", "email": "bob@example.org", "password": "correct-horse-battery", "terms_accepted": true})).send().await.unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    assert!(res.headers().get("set-cookie").is_some());
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "done");
    let user = users::find_by_identifier(&app.state, app.tenant.id, "bob")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.status, UserStatus::Active);

    let (app2, _) = fixture(RegistrationPolicy {
        enabled: false,
        ..Default::default()
    })
    .await;
    let (id, csrf) = start(&app2, "create").await;
    let res = app2
        .http
        .post(app2.tenant_url(&format!("/flows/{id}/register")))
        .json(&json!({"csrf": csrf, "email": "x@example.com", "password": "correct-horse-battery"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
}

#[tokio::test]
async fn invitation_lifecycle() {
    let (app, email) = fixture(RegistrationPolicy {
        enabled: false,
        ..Default::default()
    })
    .await;
    let tid = app.tenant.id;
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    let admin = users::create(
        &app.state,
        tid,
        Actor::System,
        ridm_api::models::NewUser {
            username: "admin".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let role = roles::create(
        &app.state,
        tid,
        Actor::System,
        NewRole {
            name: "member".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let inv = invitations::create(
        &app.state,
        &tenant,
        Actor::Admin { id: admin.id },
        NewInvitation {
            email: "Carol@Example.com".into(),
            roles: vec![role.id],
            expires_days: Some(3),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(inv.email, "carol@example.com");
    assert!(inv.is_open(chrono::Utc::now()));
    let mail = email.last().unwrap();
    assert!(mail.text.contains("admin invited you"));
    let token = link_token(&mail.text, "token");

    // Public lookup, then accept (invitations work even with self-registration disabled).
    let res = app
        .http
        .get(app.tenant_url(&format!("/invitations/{token}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let public: Value = res.json().await.unwrap();
    assert_eq!(public["email"], "carol@example.com");
    assert_eq!(public["invited_by"], "admin");
    assert_eq!(
        app.http
            .get(app.tenant_url("/invitations/nope"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    let (flow_id, _csrf) = start(&app, "login").await;
    let res = app
        .http
        .post(app.tenant_url(&format!("/invitations/{token}")))
        .json(&json!({"username": "carol", "password": "correct-horse-battery", "flow": flow_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "{}", res.text().await.unwrap());
    let cookie = res.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["username"], "carol");
    assert_eq!(body["flow"]["stage"], "done", "{body}");
    let res = app
        .http
        .get(body["flow"]["finish_url"].as_str().unwrap())
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let carol = users::find_by_identifier(&app.state, tid, "carol")
        .await
        .unwrap()
        .unwrap();
    assert!(carol.email_verified);
    assert_eq!(
        roles::effective_role_names(&app.state, tid, carol.id, None)
            .await
            .unwrap(),
        vec!["member"]
    );

    // Single use; revoke/resend on a used invitation is refused; a new invitation for an existing user is a conflict.
    assert_eq!(
        app.http
            .post(app.tenant_url(&format!("/invitations/{token}")))
            .json(&json!({"password": "correct-horse-battery"}))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert!(
        invitations::resend(&app.state, &tenant, Actor::System, inv.id)
            .await
            .is_err()
    );
    assert!(matches!(
        invitations::create(
            &app.state,
            &tenant,
            Actor::System,
            NewInvitation {
                email: "carol@example.com".into(),
                ..Default::default()
            }
        )
        .await,
        Err(ridm_api::error::AppError::Conflict(_))
    ));

    // Resend rotates the token; revoke closes it.
    let inv2 = invitations::create(
        &app.state,
        &tenant,
        Actor::System,
        NewInvitation {
            email: "dave@example.com".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let t1 = link_token(&email.last().unwrap().text, "token");
    invitations::resend(&app.state, &tenant, Actor::System, inv2.id)
        .await
        .unwrap();
    let t2 = link_token(&email.last().unwrap().text, "token");
    assert_ne!(t1, t2);
    assert_eq!(
        app.http
            .get(app.tenant_url(&format!("/invitations/{t1}")))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        app.http
            .get(app.tenant_url(&format!("/invitations/{t2}")))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    invitations::revoke(&app.state, tid, Actor::System, inv2.id)
        .await
        .unwrap();
    assert_eq!(
        app.http
            .get(app.tenant_url(&format!("/invitations/{t2}")))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let open = invitations::list(&app.state, tid, None, true, None, None)
        .await
        .unwrap();
    assert!(open.items.is_empty());
    assert_eq!(
        invitations::list(&app.state, tid, None, false, None, None)
            .await
            .unwrap()
            .items
            .len(),
        2
    );
}
