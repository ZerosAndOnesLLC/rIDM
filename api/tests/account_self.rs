//! Phase 8.2: the self-service account API beyond second factors — the
//! profile by schema, changing the password, proving a new email address or
//! phone number with a code, sessions, consented applications, the data
//! export, and deleting one's own account (soft delete, then the purge job).

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use common::TestApp;
use common::admin::{assign, call};
use reqwest::Method;
use ridm_api::messaging::SenderFactory;
use ridm_api::models::{
    AccountPolicy, AttributeDef, AttributeType, AttributeValidation, EditableBy, NewClient,
    NewUser, ProfileSchema, Tenant, TenantSettings,
};
use ridm_api::services::account_console::{ACCOUNT_AUDIENCE, ACCOUNT_CLIENT_ID};
use ridm_api::services::password::{self, SetPasswordOptions, VerifyOutcome};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::tokens::{self, AccessTokenRequest, TokenClient};
use ridm_api::services::{account, clients, consents, profile_schema, users};
use ridm_api::state::AppState;
use ridm_core::events::Actor;
use ridm_core::providers::{EmailSender, SmsSender};
use ridm_core::test_support::{MockEmailSender, MockSmsSender};
use serde_json::{Value, json};
use uuid::Uuid;

const PASSWORD: &str = "Correct-Horse-Battery-9";
const NEW_PASSWORD: &str = "Staple-Bulb-Orbit-42";

struct Mocks {
    email: Arc<MockEmailSender>,
    sms: Arc<MockSmsSender>,
}

#[async_trait]
impl SenderFactory for Mocks {
    async fn email(
        &self,
        _: &AppState,
        _: Uuid,
    ) -> ridm_api::error::AppResult<Option<Arc<dyn EmailSender>>> {
        Ok(Some(self.email.clone()))
    }
    async fn sms(
        &self,
        _: &AppState,
        _: Uuid,
    ) -> ridm_api::error::AppResult<Option<Arc<dyn SmsSender>>> {
        Ok(Some(self.sms.clone()))
    }
}

struct Fx {
    app: TestApp,
    tenant: Tenant,
    email: Arc<MockEmailSender>,
    sms: Arc<MockSmsSender>,
    user_id: Uuid,
}

fn schema() -> ProfileSchema {
    ProfileSchema {
        attributes: vec![
            AttributeDef {
                name: "department".into(),
                kind: AttributeType::Enum,
                required: true,
                validation: AttributeValidation {
                    values: vec!["eng".into(), "sales".into()],
                    ..Default::default()
                },
                order: 1,
                ..Default::default()
            },
            AttributeDef {
                name: "badge".into(),
                editable_by: EditableBy::Admin,
                order: 3,
                ..Default::default()
            },
            AttributeDef {
                name: "nickname".into(),
                order: 2,
                ..Default::default()
            },
        ],
        allow_undeclared: false,
    }
}

async fn fixture_with(settings: TenantSettings) -> Fx {
    let email = Arc::new(MockEmailSender::new());
    let sms = Arc::new(MockSmsSender::new());
    let (e2, s2) = (email.clone(), sms.clone());
    let app = TestApp::spawn_configured(axum::Router::new(), move |st| {
        st.senders = Arc::new(Mocks { email: e2, sms: s2 });
    })
    .await;
    let tid = app.tenant.id;
    tenants::update(
        &app.state,
        Actor::System,
        tid,
        TenantUpdate {
            settings: Some(settings),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    profile_schema::set(&app.state, tid, Actor::System, schema())
        .await
        .unwrap();
    let user = users::create(
        &app.state,
        tid,
        Actor::System,
        NewUser {
            username: "alice".into(),
            email: Some("alice@example.com".into()),
            email_verified: true,
            attributes: Some(json!({"department": "eng", "badge": "b-1"})),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    password::set_password(
        &app.state,
        tid,
        &tenant.settings.password,
        Actor::System,
        user.id,
        PASSWORD.to_string().into(),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    email.clear();
    Fx {
        app,
        tenant,
        email,
        sms,
        user_id: user.id,
    }
}

async fn fixture() -> Fx {
    fixture_with(TenantSettings::default()).await
}

/// An access token as the account console would hold, with its own
/// session. `age_secs` is how long ago the sign-in happened.
async fn token(fx: &Fx, user_id: Uuid, age_secs: i64) -> (String, Uuid) {
    let user = users::get(&fx.app.state, fx.tenant.id, user_id)
        .await
        .unwrap();
    let auth_time = Utc::now() - chrono::Duration::seconds(age_secs);
    let session = sessions::create(
        &fx.app.state,
        fx.tenant.id,
        NewSession {
            user_id,
            amr: vec!["pwd".into()],
            acr: None,
            ip: Some("203.0.113.9".into()),
            user_agent: Some("Test/1.0".into()),
            policy: &fx.tenant.settings.session,
        },
    )
    .await
    .unwrap();
    let mut client = TokenClient::public(ACCOUNT_CLIENT_ID);
    client.access_token_ttl = Duration::from_secs(300);
    let t = tokens::issue_access_token(
        &fx.app.state,
        AccessTokenRequest {
            tenant: &fx.tenant,
            client: &client,
            user: Some(&user),
            scopes: &["openid".into()],
            audiences: &[ACCOUNT_AUDIENCE.to_string()],
            roles: &[],
            groups: &[],
            session_id: Some(session.id),
            org_id: None,
            auth_time: Some(auth_time),
            amr: &["pwd".into()],
            acr: None,
            cnf_jkt: None,
            act: None,
        },
    )
    .await
    .unwrap()
    .token;
    (t, session.id)
}

fn path(fx: &Fx, rest: &str) -> String {
    format!("/t/{}/account{rest}", fx.tenant.slug)
}

/// The code in a message: the run of exactly six digits after the word
/// "code" (the tenant's name before it and the expiry after it carry
/// digits of their own).
fn six_digits(text: &str) -> String {
    let after = text
        .split_once("code")
        .map(|(_, rest)| rest)
        .unwrap_or(text);
    after
        .split(|c: char| !c.is_ascii_digit())
        .find(|run| run.len() == 6)
        .map(str::to_string)
        .unwrap_or_else(|| panic!("no code in {text:?}"))
}

fn field_error(body: &Value, field: &str) -> String {
    body["errors"]
        .as_array()
        .and_then(|e| e.iter().find(|e| e["field"] == field))
        .map(|e| e["message"].as_str().unwrap_or_default().to_string())
        .unwrap_or_else(|| panic!("no error for field {field} in {body}"))
}

#[tokio::test]
async fn the_profile_follows_the_schema_and_only_user_editable_attributes_change() {
    let fx = fixture().await;
    let (t, _) = token(&fx, fx.user_id, 0).await;
    let p = path(&fx, "/profile");

    let (status, body, _) = call(&fx.app, Method::GET, &p, Some(&t), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["username"], "alice");
    assert_eq!(body["email"], "alice@example.com");
    let names: Vec<&str> = body["schema"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["department", "nickname", "badge"],
        "form order, then name"
    );
    assert_eq!(
        body["attributes"],
        json!({"department": "eng", "badge": "b-1"})
    );
    assert_eq!(body["pending"], json!({"email": null, "phone": null}));
    assert!(body["locales"].as_array().unwrap().contains(&json!("en")));

    let (status, body, _) = call(
        &fx.app,
        Method::PATCH,
        &p,
        Some(&t),
        Some(&json!({"attributes": {"department": "sales", "nickname": "Al"}})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["attributes"],
        json!({"department": "sales", "nickname": "Al", "badge": "b-1"}),
        "the admin-only attribute the user did not send is kept"
    );

    let (status, body, _) = call(
        &fx.app,
        Method::PATCH,
        &p,
        Some(&t),
        Some(&json!({"attributes": {"department": "sales", "badge": "b-2"}})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(field_error(&body, "attributes.badge"), "not editable");

    let (status, body, _) = call(
        &fx.app,
        Method::PATCH,
        &p,
        Some(&t),
        Some(&json!({"attributes": {"department": "ops"}})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        field_error(&body, "attributes.department").contains("one of"),
        "{body}"
    );

    let (status, body, _) = call(
        &fx.app,
        Method::PATCH,
        &p,
        Some(&t),
        Some(&json!({"locale": "xx-Unsupported"})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    let (status, body, _) = call(
        &fx.app,
        Method::PATCH,
        &p,
        Some(&t),
        Some(&json!({"locale": "en"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["locale"], "en");
    let (status, body, _) = call(
        &fx.app,
        Method::PATCH,
        &p,
        Some(&t),
        Some(&json!({"locale": null})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["locale"].is_null());

    let (status, body, _) = call(
        &fx.app,
        Method::PATCH,
        &p,
        Some(&t),
        Some(&json!({"username": "bob"})),
    )
    .await;
    assert_eq!(
        status, 400,
        "the username is not the user's to change: {body}"
    );
}

#[tokio::test]
async fn changing_the_password_checks_the_current_one_and_can_sign_out_elsewhere() {
    let fx = fixture().await;
    let p = path(&fx, "/password");
    let (t, own_session) = token(&fx, fx.user_id, 0).await;

    let (status, body, _) = call(&fx.app, Method::GET, &p, Some(&t), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["set"], true);
    assert_eq!(body["enabled"], true);
    assert!(body["policy"]["min_length"].is_number());

    let (old, _) = token(&fx, fx.user_id, 20 * 60).await;
    let (status, body, _) = call(
        &fx.app,
        Method::PUT,
        &p,
        Some(&old),
        Some(&json!({"current_password": PASSWORD, "new_password": NEW_PASSWORD})),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["type"], "urn:ridm:error:reauthentication-required");

    let (status, body, _) = call(
        &fx.app,
        Method::PUT,
        &p,
        Some(&t),
        Some(&json!({"current_password": "nope", "new_password": NEW_PASSWORD})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(field_error(&body, "current_password"), "is incorrect");

    let (status, body, _) = call(
        &fx.app,
        Method::PUT,
        &p,
        Some(&t),
        Some(&json!({"current_password": PASSWORD, "new_password": "short"})),
    )
    .await;
    assert_eq!(status, 400, "the policy applies: {body}");
    assert!(body["errors"][0]["field"] == "password", "{body}");

    // The old-token session above is a second session: signing out
    // elsewhere ends it and keeps this one.
    let (status, body, _) = call(
        &fx.app,
        Method::PUT,
        &p,
        Some(&t),
        Some(&json!({"current_password": PASSWORD, "new_password": NEW_PASSWORD, "sign_out_others": true})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["signed_out"], 1);
    assert_eq!(body["password"]["set"], true);
    assert!(body["password"]["changed_at"].is_string());
    let live = sessions::list_live_for_user(&fx.app.state, fx.tenant.id, fx.user_id)
        .await
        .unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].id, own_session);

    let user = users::get(&fx.app.state, fx.tenant.id, fx.user_id)
        .await
        .unwrap();
    let outcome = password::verify_and_upgrade(
        &fx.app.state,
        fx.tenant.id,
        &fx.tenant.settings.password,
        &user,
        NEW_PASSWORD.to_string().into(),
    )
    .await
    .unwrap();
    assert!(matches!(outcome, VerifyOutcome::Valid { .. }));
    let notices = fx.email.sent_to("alice@example.com");
    assert!(
        notices
            .iter()
            .any(|m| m.subject.to_lowercase().contains("password")),
        "the user is told: {notices:?}"
    );
}

#[tokio::test]
async fn an_email_change_is_proven_by_a_code_and_the_old_address_is_told() {
    let fx = fixture().await;
    let (t, _) = token(&fx, fx.user_id, 0).await;
    let change = path(&fx, "/email/change");
    let confirm = path(&fx, "/email/confirm");

    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &change,
        Some(&t),
        Some(&json!({"email": "alice@example.com"})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(field_error(&body, "email").contains("already"), "{body}");

    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &change,
        Some(&t),
        Some(&json!({"email": "not-an-address"})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(field_error(&body, "email"), "invalid email address");

    users::create(
        &fx.app.state,
        fx.tenant.id,
        Actor::System,
        NewUser {
            username: "bob".into(),
            email: Some("bob@example.com".into()),
            attributes: Some(json!({"department": "eng"})),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &change,
        Some(&t),
        Some(&json!({"email": "bob@example.com"})),
    )
    .await;
    assert_eq!(status, 409, "{body}");

    let (old, _) = token(&fx, fx.user_id, 20 * 60).await;
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &change,
        Some(&old),
        Some(&json!({"email": "alice.new@example.com"})),
    )
    .await;
    assert_eq!(status, 403, "{body}");

    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &change,
        Some(&t),
        Some(&json!({"email": " Alice.New@Example.com "})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["destination"], "a•••@example.com");
    let sent = fx.email.sent_to("alice.new@example.com");
    assert_eq!(sent.len(), 1, "one code to the new address");
    let code = six_digits(&sent[0].text);

    // Asking again within the cooldown does not send twice.
    let (status, _, _) = call(
        &fx.app,
        Method::POST,
        &change,
        Some(&t),
        Some(&json!({"email": "alice.new@example.com"})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(fx.email.sent_to("alice.new@example.com").len(), 1);

    let (status, body, _) =
        call(&fx.app, Method::GET, &path(&fx, "/profile"), Some(&t), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["pending"]["email"], "a•••@example.com");
    assert_eq!(body["email"], "alice@example.com", "nothing moved yet");

    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &confirm,
        Some(&t),
        Some(&json!({"code": "000000"})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(field_error(&body, "code").contains("incorrect"));

    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &confirm,
        Some(&t),
        Some(&json!({"code": code})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["email"], "alice.new@example.com");
    assert_eq!(body["email_verified"], true);
    assert!(body["pending"]["email"].is_null());
    let user = users::get(&fx.app.state, fx.tenant.id, fx.user_id)
        .await
        .unwrap();
    assert_eq!(user.email.as_deref(), Some("alice.new@example.com"));
    assert!(user.email_verified);
    let old_address = fx.email.sent_to("alice@example.com");
    assert!(
        old_address
            .iter()
            .any(|m| m.subject.to_lowercase().contains("email")),
        "the previous address is told: {old_address:?}"
    );

    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &confirm,
        Some(&t),
        Some(&json!({"code": code})),
    )
    .await;
    assert_eq!(status, 400, "a code works once: {body}");
    assert!(
        body["detail"].as_str().unwrap().contains("pending"),
        "{body}"
    );

    // A change can be dropped before it is proven.
    let (status, _, _) = call(
        &fx.app,
        Method::POST,
        &change,
        Some(&t),
        Some(&json!({"email": "third@example.com"})),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _, _) = call(&fx.app, Method::DELETE, &change, Some(&t), None).await;
    assert_eq!(status, 204);
    let (_, body, _) = call(&fx.app, Method::GET, &path(&fx, "/profile"), Some(&t), None).await;
    assert!(body["pending"]["email"].is_null());
}

#[tokio::test]
async fn a_phone_change_is_proven_by_a_text_and_the_number_can_be_removed() {
    let fx = fixture().await;
    let (t, _) = token(&fx, fx.user_id, 0).await;
    let change = path(&fx, "/phone/change");
    let confirm = path(&fx, "/phone/confirm");

    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &change,
        Some(&t),
        Some(&json!({"phone": "5550100001"})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(field_error(&body, "phone"), "phone must be in E.164 format");

    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &change,
        Some(&t),
        Some(&json!({"phone": "+1 555 010 0001"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["destination"], "•••••••••01");
    let texts = fx.sms.sent_to("+15550100001");
    assert_eq!(texts.len(), 1);
    let code = six_digits(&texts[0].body);

    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &confirm,
        Some(&t),
        Some(&json!({"code": code})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["phone"], "+15550100001");
    assert_eq!(body["phone_verified"], true);

    let (status, body, _) = call(
        &fx.app,
        Method::DELETE,
        &path(&fx, "/phone"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["phone"].is_null());
    assert_eq!(body["phone_verified"], false);
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &path(&fx, "/phone"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn sessions_are_listed_with_the_current_one_first_and_can_be_ended() {
    let fx = fixture().await;
    let (t, own) = token(&fx, fx.user_id, 0).await;
    let (_, other) = token(&fx, fx.user_id, 60).await;
    let p = path(&fx, "/sessions");

    let (status, body, _) = call(&fx.app, Method::GET, &p, Some(&t), None).await;
    assert_eq!(status, 200, "{body}");
    let list = body.as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0]["id"], own.to_string());
    assert_eq!(list[0]["current"], true);
    assert_eq!(list[0]["ip"], "203.0.113.9");
    assert_eq!(list[0]["user_agent"], "Test/1.0");
    assert_eq!(list[1]["current"], false);

    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{p}/{}", Uuid::now_v7()),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{p}/{other}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (_, body, _) = call(&fx.app, Method::GET, &p, Some(&t), None).await;
    assert_eq!(body.as_array().unwrap().len(), 1);

    token(&fx, fx.user_id, 0).await;
    token(&fx, fx.user_id, 0).await;
    let (status, body, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{p}?keep_current=true"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["revoked"], 2);
    let (_, body, _) = call(&fx.app, Method::GET, &p, Some(&t), None).await;
    assert_eq!(body.as_array().unwrap().len(), 1, "this session stays");

    let (status, body, _) = call(&fx.app, Method::DELETE, &p, Some(&t), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["revoked"], 1);
    let (status, _, _) = call(&fx.app, Method::GET, &p, Some(&t), None).await;
    assert_eq!(status, 401, "signing out everywhere ends this session too");
}

#[tokio::test]
async fn consented_applications_are_listed_and_their_access_withdrawn() {
    let fx = fixture().await;
    let (t, _) = token(&fx, fx.user_id, 0).await;
    let p = path(&fx, "/apps");
    let client = clients::create(
        &fx.app.state,
        fx.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("photos".into()),
            name: "Photos".into(),
            logo_uri: Some("https://photos.example/logo.png".into()),
            redirect_uris: vec!["https://photos.example/cb".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .client;
    let (_, body, _) = call(&fx.app, Method::GET, &p, Some(&t), None).await;
    assert_eq!(body, json!([]));

    consents::grant(
        &fx.app.state,
        fx.tenant.id,
        fx.user_id,
        client.id,
        &["openid".into(), "email".into()],
    )
    .await
    .unwrap();
    let (status, body, _) = call(&fx.app, Method::GET, &p, Some(&t), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body[0]["client_id"], client.id.to_string());
    assert_eq!(body[0]["client"], "photos");
    assert_eq!(body[0]["name"], "Photos");
    assert_eq!(body[0]["logo_uri"], "https://photos.example/logo.png");
    assert_eq!(body[0]["scopes"], json!(["openid", "email"]));

    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{p}/{}", client.id),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (_, body, _) = call(&fx.app, Method::GET, &p, Some(&t), None).await;
    assert_eq!(body, json!([]));
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{p}/{}", client.id),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
    let missing = consents::missing_scopes(
        &fx.app.state,
        fx.tenant.id,
        fx.user_id,
        client.id,
        &["openid".into()],
    )
    .await
    .unwrap();
    assert_eq!(missing, ["openid"], "the next sign-in asks again");
}

#[tokio::test]
async fn the_export_is_a_download_of_everything_held_and_needs_a_recent_sign_in() {
    let fx = fixture().await;
    let p = path(&fx, "/export");
    let (old, _) = token(&fx, fx.user_id, 20 * 60).await;
    let (status, body, _) = call(&fx.app, Method::GET, &p, Some(&old), None).await;
    assert_eq!(status, 403, "{body}");

    let (t, _) = token(&fx, fx.user_id, 0).await;
    let res = fx
        .app
        .http
        .get(format!("{}{}", fx.app.base_url, p))
        .bearer_auth(&t)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let disposition = res
        .headers()
        .get("content-disposition")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        disposition.starts_with("attachment; filename=\"") && disposition.contains("alice"),
        "{disposition}"
    );
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["tenant"]["slug"], fx.tenant.slug);
    assert_eq!(body["user"]["username"], "alice");
    assert_eq!(body["user"]["attributes"]["badge"], "b-1");
    assert!(body["user"].get("password_hash").is_none(), "{body}");
    assert!(body["exported_at"].is_string());
    for key in [
        "credentials",
        "trusted_devices",
        "sessions",
        "consents",
        "personal_access_tokens",
        "identities",
        "roles",
        "groups",
        "audit_events",
    ] {
        assert!(body[key].is_array(), "{key} missing in {body}");
    }
    assert_eq!(
        body["sessions"].as_array().unwrap().len(),
        2,
        "both sessions opened above are live"
    );
    let text = body.to_string();
    assert!(!text.contains("$argon2"), "no secret material leaves");
}

#[tokio::test]
async fn deleting_the_account_ends_everything_and_the_purge_job_removes_it_later() {
    let fx = fixture().await;
    let p = path(&fx, "/me");
    let (t, session) = token(&fx, fx.user_id, 0).await;

    let (status, body, _) = call(
        &fx.app,
        Method::DELETE,
        &p,
        Some(&t),
        Some(&json!({"confirm": "someone-else"})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(field_error(&body, "confirm"), "must be your username");

    let (old, _) = token(&fx, fx.user_id, 20 * 60).await;
    let (status, body, _) = call(
        &fx.app,
        Method::DELETE,
        &p,
        Some(&old),
        Some(&json!({"confirm": "alice"})),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["type"], "urn:ridm:error:reauthentication-required");

    let admin = users::create(
        &fx.app.state,
        fx.tenant.id,
        Actor::System,
        NewUser {
            username: "owner".into(),
            attributes: Some(json!({"department": "eng"})),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .id;
    assign(&fx.app, fx.tenant.id, admin, "ridm:owner").await;
    let (ta, _) = token(&fx, admin, 0).await;
    let admin_name = "owner";
    let (status, body, _) = call(
        &fx.app,
        Method::DELETE,
        &p,
        Some(&ta),
        Some(&json!({"confirm": admin_name})),
    )
    .await;
    assert_eq!(
        status, 403,
        "an administrator cannot delete themselves: {body}"
    );
    assert!(body["detail"].as_str().unwrap().contains("administrator"));

    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &p,
        Some(&t),
        Some(&json!({"confirm": " Alice "})),
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = call(&fx.app, Method::GET, &path(&fx, "/me"), Some(&t), None).await;
    assert_eq!(status, 401, "the session is gone with the account");
    assert!(
        sessions::get(
            &fx.app.state,
            fx.tenant.id,
            session,
            &fx.tenant.settings.session
        )
        .await
        .unwrap()
        .is_none()
    );
    assert!(matches!(
        users::get(&fx.app.state, fx.tenant.id, fx.user_id).await,
        Err(ridm_api::error::AppError::NotFound(_))
    ));
    // The username frees up at once.
    users::create(
        &fx.app.state,
        fx.tenant.id,
        Actor::System,
        NewUser {
            username: "alice".into(),
            attributes: Some(json!({"department": "eng"})),
            ..Default::default()
        },
    )
    .await
    .expect("the name is free again");

    // Still there for the retention period, then purged.
    assert_eq!(
        account::purge_deleted(&fx.app.state, fx.tenant.id, 30)
            .await
            .unwrap(),
        0
    );
    let mut tx = ridm_api::db::tenant_tx(&fx.app.state.db, fx.tenant.id)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE users SET deleted_at = now() - interval '40 days' WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fx.tenant.id)
    .bind(fx.user_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        account::purge_deleted(&fx.app.state, fx.tenant.id, 30)
            .await
            .unwrap(),
        1
    );
    let mut tx = ridm_api::db::tenant_tx(&fx.app.state.db, fx.tenant.id)
        .await
        .unwrap();
    let left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM users WHERE tenant_id = $1 AND id = $2")
            .bind(fx.tenant.id)
            .bind(fx.user_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(left, 0);
    // The scheduled pass runs the same purge for every tenant.
    ridm_api::jobs::user_purge::run_once(&fx.app.state)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_tenant_can_keep_users_from_deleting_their_own_account() {
    let fx = fixture_with(TenantSettings {
        account: AccountPolicy {
            self_deletion: false,
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    let (t, _) = token(&fx, fx.user_id, 0).await;
    let (status, body, _) = call(
        &fx.app,
        Method::DELETE,
        &path(&fx, "/me"),
        Some(&t),
        Some(&json!({"confirm": "alice"})),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(body["detail"].as_str().unwrap().contains("not allow"));
    assert!(
        users::get(&fx.app.state, fx.tenant.id, fx.user_id)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn an_account_token_only_ever_reaches_its_own_user() {
    let fx = fixture().await;
    let bob = users::create(
        &fx.app.state,
        fx.tenant.id,
        Actor::System,
        NewUser {
            username: "bob".into(),
            email: Some("bob@example.com".into()),
            email_verified: true,
            attributes: Some(json!({"department": "sales"})),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (ta, alice_session) = token(&fx, fx.user_id, 0).await;
    let (tb, bob_session) = token(&fx, bob.id, 0).await;
    let bob_client = clients::create(
        &fx.app.state,
        fx.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("bobs-app".into()),
            name: "Bob's app".into(),
            redirect_uris: vec!["https://bob.example/cb".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .client;
    consents::grant(
        &fx.app.state,
        fx.tenant.id,
        bob.id,
        bob_client.id,
        &["openid".into()],
    )
    .await
    .unwrap();

    // Every read is the token holder's own.
    let (_, body, _) = call(
        &fx.app,
        Method::GET,
        &path(&fx, "/profile"),
        Some(&ta),
        None,
    )
    .await;
    assert_eq!(body["username"], "alice");
    let (_, body, _) = call(
        &fx.app,
        Method::GET,
        &path(&fx, "/profile"),
        Some(&tb),
        None,
    )
    .await;
    assert_eq!(body["username"], "bob");
    assert_eq!(body["attributes"]["department"], "sales");
    let (_, body, _) = call(
        &fx.app,
        Method::GET,
        &path(&fx, "/sessions"),
        Some(&ta),
        None,
    )
    .await;
    let ids: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [alice_session.to_string().as_str()]);
    let (_, body, _) = call(&fx.app, Method::GET, &path(&fx, "/apps"), Some(&ta), None).await;
    assert_eq!(body, json!([]), "Bob's consents are not Alice's");
    let (_, body, _) = call(&fx.app, Method::GET, &path(&fx, "/apps"), Some(&tb), None).await;
    assert_eq!(body[0]["name"], "Bob's app");

    // Nor can a write name someone else's record.
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &path(&fx, &format!("/sessions/{bob_session}")),
        Some(&ta),
        None,
    )
    .await;
    assert_eq!(status, 404, "Bob's session is not Alice's to end");
    assert!(
        sessions::get(
            &fx.app.state,
            fx.tenant.id,
            bob_session,
            &fx.tenant.settings.session
        )
        .await
        .unwrap()
        .is_some()
    );
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &path(&fx, &format!("/apps/{}", bob_client.id)),
        Some(&ta),
        None,
    )
    .await;
    assert_eq!(status, 404, "Bob's consent is not Alice's to withdraw");
    let (_, body, _) = call(&fx.app, Method::GET, &path(&fx, "/apps"), Some(&tb), None).await;
    assert_eq!(body.as_array().unwrap().len(), 1);
}
