//! Phase 12.6: client-initiated backchannel authentication (OpenID CIBA
//! Core 1.0). A client names the user at `/bc-authorize`, the user is told
//! by email and answers on the account console's approvals, and the client
//! collects the tokens from `/token` by polling or after a ping.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use common::TestApp;
use ridm_api::db;
use ridm_api::messaging::SenderFactory;
use ridm_api::models::{BackchannelDeliveryMode, ClientType, NewClient, NewUser, Tenant, grants};
use ridm_api::services::account_console::{ACCOUNT_AUDIENCE, ACCOUNT_CLIENT_ID};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::tokens::{self, AccessTokenRequest, IdTokenRequest, TokenClient};
use ridm_api::services::{clients, tenants, users};
use ridm_api::state::AppState;
use ridm_core::events::Actor;
use ridm_core::providers::{EmailSender, SmsSender};
use ridm_core::test_support::{MockEmailSender, MockSmsSender};
use serde_json::Value;
use uuid::Uuid;

const CIBA: &str = grants::CIBA;

/// A form to post, and the status and `error` it must earn.
type Case<'a> = (Vec<(&'a str, &'a str)>, u16, &'a str);
/// What the notification endpoint received: `Authorization`, and the body.
type Pings = Arc<Mutex<Vec<(Option<String>, Value)>>>;

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
    alice: Uuid,
    bob: Uuid,
    /// `(client_id, secret)` of the poll-mode client.
    poll: (String, String),
}

async fn fixture() -> Fx {
    let email = Arc::new(MockEmailSender::new());
    let sms = Arc::new(MockSmsSender::new());
    let (e2, s2) = (email.clone(), sms.clone());
    let app = TestApp::spawn_configured(axum::Router::new(), move |st| {
        st.senders = Arc::new(Mocks { email: e2, sms: s2 });
    })
    .await;
    let tid = app.tenant.id;
    let mut ids = vec![];
    for name in ["alice", "bob"] {
        let u = users::create(
            &app.state,
            tid,
            Actor::System,
            NewUser {
                username: name.into(),
                email: Some(format!("{name}@example.com")),
                email_verified: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        ids.push(u.id);
    }
    let poll = ciba_client(&app, "bank", BackchannelDeliveryMode::Poll, None).await;
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    Fx {
        app,
        tenant,
        email,
        alice: ids[0],
        bob: ids[1],
        poll,
    }
}

async fn ciba_client(
    app: &TestApp,
    id: &str,
    mode: BackchannelDeliveryMode,
    endpoint: Option<String>,
) -> (String, String) {
    let c = clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some(id.into()),
            name: "Example Bank".into(),
            client_type: Some(ClientType::Machine),
            allowed_grants: Some(vec![CIBA.into(), grants::REFRESH_TOKEN.into()]),
            allowed_scopes: Some(vec![
                "openid".into(),
                "profile".into(),
                "email".into(),
                "offline_access".into(),
            ]),
            backchannel_token_delivery_mode: Some(mode),
            backchannel_client_notification_endpoint: endpoint,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (
        c.client.client_id.clone(),
        c.client_secret.as_deref().unwrap().to_string(),
    )
}

async fn bc_authorize(fx: &Fx, creds: &(String, String), form: &[(&str, &str)]) -> (u16, Value) {
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/bc-authorize"))
        .basic_auth(&creds.0, Some(&creds.1))
        .form(form)
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

async fn collect(fx: &Fx, creds: &(String, String), auth_req_id: &str) -> (u16, Value) {
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .basic_auth(&creds.0, Some(&creds.1))
        .form(&[("grant_type", CIBA), ("auth_req_id", auth_req_id)])
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

/// An account-console token for `user_id`, from a live session.
async fn account_token(fx: &Fx, user_id: Uuid) -> String {
    account_token_in(fx, user_id, true).await
}

/// An account-console token, with or without a sign-in session behind it.
async fn account_token_in(fx: &Fx, user_id: Uuid, with_session: bool) -> String {
    let user = users::get(&fx.app.state, fx.tenant.id, user_id)
        .await
        .unwrap();
    let s = sessions::create(
        &fx.app.state,
        fx.tenant.id,
        NewSession {
            user_id,
            amr: vec!["pwd".into(), "otp".into()],
            acr: None,
            ip: None,
            user_agent: None,
            policy: &fx.tenant.settings.session,
        },
    )
    .await
    .unwrap();
    let mut client = TokenClient::public(ACCOUNT_CLIENT_ID);
    client.access_token_ttl = Duration::from_secs(300);
    tokens::issue_access_token(
        &fx.app.state,
        AccessTokenRequest {
            tenant: &fx.tenant,
            client: &client,
            user: Some(&user),
            scopes: &["openid".into()],
            audiences: &[ACCOUNT_AUDIENCE.to_string()],
            roles: &[],
            groups: &[],
            session_id: with_session.then_some(s.id),
            auth_time: Some(Utc::now()),
            amr: &["pwd".into(), "otp".into()],
            acr: None,
            org_id: None,
            cnf_jkt: None,
            cnf_x5t: None,
            act: None,
        },
    )
    .await
    .unwrap()
    .token
}

async fn account(fx: &Fx, token: &str, method: reqwest::Method, rest: &str) -> (u16, Value) {
    let res = fx
        .app
        .http
        .request(
            method,
            fx.app.url(&format!(
                "/t/{}/account/backchannel-requests{rest}",
                fx.tenant.slug
            )),
        )
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

/// The one request waiting on the holder of `token`.
async fn only_pending(fx: &Fx, token: &str) -> Value {
    let (status, list) = account(fx, token, reqwest::Method::GET, "").await;
    assert_eq!(status, 200, "{list}");
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 1, "{list:?}");
    list[0].clone()
}

/// Move the live (Valkey) record of `auth_req_id` past its expiry.
async fn age_live_record(fx: &Fx, auth_req_id: &str) {
    let key = ridm_api::cache::keys::ciba_request(
        fx.tenant.id,
        &URL_SAFE_NO_PAD.encode(<sha2::Sha256 as sha2::Digest>::digest(
            auth_req_id.as_bytes(),
        )),
    );
    let mut conn = fx.app.state.redis.get().await.unwrap();
    let raw: String = redis::cmd("GET")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .unwrap();
    let mut rec: Value = serde_json::from_str(&raw).unwrap();
    rec["expires_at"] = serde_json::json!(Utc::now() - chrono::Duration::seconds(1));
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(rec.to_string())
        .arg("KEEPTTL")
        .query_async(&mut conn)
        .await
        .unwrap();
}

/// Open a request for alice from the poll client: `(auth_req_id, row id)`.
async fn open_for_alice(fx: &Fx, alice: &str) -> (String, String) {
    let (status, ack) = bc_authorize(
        fx,
        &fx.poll,
        &[("scope", "openid offline_access"), ("login_hint", "alice")],
    )
    .await;
    assert_eq!(status, 200, "{ack}");
    let (_, list) = account(fx, alice, reqwest::Method::GET, "").await;
    let row = list.as_array().unwrap().first().expect("listed")["id"]
        .as_str()
        .unwrap()
        .to_string();
    (ack["auth_req_id"].as_str().unwrap().to_string(), row)
}

async fn answer(fx: &Fx, token: &str, row: &str, verb: &str) -> u16 {
    account(fx, token, reqwest::Method::POST, &format!("/{row}/{verb}"))
        .await
        .0
}

fn claims_of(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

/// Audit rows named `name`, once there is one: the audit writer runs in the
/// background, so a row lands a moment after the request that raised it
/// (long enough, under the coverage build, for a single read to miss it).
async fn audit_count(app: &TestApp, name: &str) -> i64 {
    for _ in 0..100 {
        let mut tx = db::bypass_tx(app.state.db.home()).await.unwrap();
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND name = $2",
        )
        .bind(app.tenant.id)
        .bind(name)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        if n > 0 {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    0
}

#[tokio::test]
async fn discovery_advertises_ciba() {
    let fx = fixture().await;
    let doc: Value = fx
        .app
        .http
        .get(fx.app.tenant_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        doc["backchannel_authentication_endpoint"],
        fx.app.tenant_url("/bc-authorize")
    );
    assert_eq!(
        doc["backchannel_token_delivery_modes_supported"],
        serde_json::json!(["poll", "ping"])
    );
    assert_eq!(doc["backchannel_user_code_parameter_supported"], false);
    assert!(
        doc["grant_types_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g == CIBA)
    );
}

#[tokio::test]
async fn poll_mode_from_request_to_tokens() {
    let fx = fixture().await;
    let (status, ack) = bc_authorize(
        &fx,
        &fx.poll,
        &[
            ("scope", "openid profile offline_access"),
            ("login_hint", "alice@example.com"),
            ("binding_message", "K7 R2"),
        ],
    )
    .await;
    assert_eq!(status, 200, "{ack}");
    let auth_req_id = ack["auth_req_id"].as_str().unwrap().to_string();
    assert_eq!(ack["expires_in"], 600);
    assert_eq!(ack["interval"], 5);

    // The user is told, with a link to the request (never the auth_req_id).
    common::settle(&fx.app.state).await;
    let mail = fx.email.sent_to("alice@example.com");
    assert_eq!(mail.len(), 1);
    assert!(
        mail[0].subject.contains("Example Bank"),
        "{}",
        mail[0].subject
    );
    assert!(mail[0].text.contains("K7 R2"));
    assert!(mail[0].text.contains("account/approvals"));
    assert!(!mail[0].text.contains(&auth_req_id));

    // Waiting, then too eager.
    let (status, body) = collect(&fx, &fx.poll, &auth_req_id).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("authorization_pending"))
    );
    let (_, body) = collect(&fx, &fx.poll, &auth_req_id).await;
    assert_eq!(body["error"], "slow_down");

    // Only alice sees it; bob cannot answer it.
    let bob = account_token(&fx, fx.bob).await;
    let (_, list) = account(&fx, &bob, reqwest::Method::GET, "").await;
    assert_eq!(list, serde_json::json!([]));
    let alice = account_token(&fx, fx.alice).await;
    let req = only_pending(&fx, &alice).await;
    assert_eq!(req["client_name"], "Example Bank");
    assert_eq!(req["binding_message"], "K7 R2");
    let id = req["id"].as_str().unwrap();
    let (status, _) = account(&fx, &bob, reqwest::Method::POST, &format!("/{id}/approve")).await;
    assert_eq!(status, 404);

    let (status, body) = account(
        &fx,
        &alice,
        reqwest::Method::POST,
        &format!("/{id}/approve"),
    )
    .await;
    assert_eq!(status, 204, "{body}");
    // Answered once only.
    let (status, _) = account(&fx, &alice, reqwest::Method::POST, &format!("/{id}/deny")).await;
    assert_eq!(status, 404);

    // A decided request is handed over at once, whatever the interval.
    let (status, tokens) = collect(&fx, &fx.poll, &auth_req_id).await;
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(tokens["token_type"], "Bearer");
    let id_token = claims_of(tokens["id_token"].as_str().unwrap());
    assert_eq!(id_token["sub"], fx.alice.to_string());
    assert_eq!(id_token["aud"], "bank");
    assert!(
        id_token["sid"].is_string(),
        "bound to the approving session"
    );
    let access = claims_of(tokens["access_token"].as_str().unwrap());
    assert_eq!(access["amr"], serde_json::json!(["pwd", "otp"]));
    assert!(tokens["refresh_token"].is_string());

    // Spent.
    let (status, body) = collect(&fx, &fx.poll, &auth_req_id).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_grant"))
    );

    // Remembered as consent: the bank is a connected application now.
    let apps: Value = fx
        .app
        .http
        .get(fx.app.url(&format!("/t/{}/account/apps", fx.tenant.slug)))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        apps.as_array()
            .unwrap()
            .iter()
            .any(|a| a["name"] == "Example Bank"),
        "{apps}"
    );
    assert_eq!(audit_count(&fx.app, "backchannel.requested").await, 1);
    assert!(audit_count(&fx.app, "authorization.granted").await >= 1);
}

#[tokio::test]
async fn a_denial_reaches_the_client_once() {
    let fx = fixture().await;
    let (_, ack) = bc_authorize(
        &fx,
        &fx.poll,
        &[("scope", "openid"), ("login_hint", "alice")],
    )
    .await;
    let auth_req_id = ack["auth_req_id"].as_str().unwrap();
    let alice = account_token(&fx, fx.alice).await;
    let id = only_pending(&fx, &alice).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, _) = account(&fx, &alice, reqwest::Method::POST, &format!("/{id}/deny")).await;
    assert_eq!(status, 204);
    let (status, body) = collect(&fx, &fx.poll, auth_req_id).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("access_denied"))
    );
    let (_, body) = collect(&fx, &fx.poll, auth_req_id).await;
    assert_eq!(body["error"], "invalid_grant", "the answer is given once");
    assert_eq!(audit_count(&fx.app, "backchannel.denied").await, 1);
    let (_, list) = account(&fx, &alice, reqwest::Method::GET, "").await;
    assert_eq!(list, serde_json::json!([]));
}

#[tokio::test]
async fn approving_needs_a_sign_in_session() {
    let fx = fixture().await;
    let (_, ack) = bc_authorize(
        &fx,
        &fx.poll,
        &[("scope", "openid"), ("login_hint", "alice")],
    )
    .await;
    // A token with no session behind it (as a personal access token has none).
    let sessionless = account_token_in(&fx, fx.alice, false).await;
    let id = only_pending(&fx, &sessionless).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = account(
        &fx,
        &sessionless,
        reqwest::Method::POST,
        &format!("/{id}/approve"),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    let (_, body) = collect(&fx, &fx.poll, ack["auth_req_id"].as_str().unwrap()).await;
    assert_eq!(body["error"], "authorization_pending", "still undecided");
    // Denying needs nothing more than the account token.
    let (status, _) = account(
        &fx,
        &sessionless,
        reqwest::Method::POST,
        &format!("/{id}/deny"),
    )
    .await;
    assert_eq!(status, 204);
}

#[tokio::test]
async fn an_expired_request_is_expired_token() {
    let fx = fixture().await;
    let (_, ack) = bc_authorize(
        &fx,
        &fx.poll,
        &[
            ("scope", "openid"),
            ("login_hint", "alice"),
            ("requested_expiry", "30"),
        ],
    )
    .await;
    assert_eq!(ack["expires_in"], 30);
    let auth_req_id = ack["auth_req_id"].as_str().unwrap();
    age_live_record(&fx, auth_req_id).await;
    let (status, body) = collect(&fx, &fx.poll, auth_req_id).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("expired_token"))
    );
    // Nor can the user still answer it.
    let alice = account_token(&fx, fx.alice).await;
    let (_, list) = account(&fx, &alice, reqwest::Method::GET, "").await;
    let id = list[0]["id"].as_str().map(str::to_string);
    if let Some(id) = id {
        let (status, _) = account(
            &fx,
            &alice,
            reqwest::Method::POST,
            &format!("/{id}/approve"),
        )
        .await;
        assert_eq!(status, 404);
    }
}

#[tokio::test]
async fn requests_are_validated() {
    let fx = fixture().await;
    let cases: Vec<Case> = vec![
        (vec![("login_hint", "alice")], 400, "invalid_request"),
        (
            vec![("scope", "profile"), ("login_hint", "alice")],
            400,
            "invalid_scope",
        ),
        (vec![("scope", "openid")], 400, "invalid_request"),
        (
            vec![
                ("scope", "openid"),
                ("login_hint", "alice"),
                ("id_token_hint", "x.y.z"),
            ],
            400,
            "invalid_request",
        ),
        (
            vec![("scope", "openid"), ("login_hint_token", "x.y.z")],
            400,
            "invalid_request",
        ),
        (
            vec![("scope", "openid"), ("login_hint", "nobody")],
            400,
            "unknown_user_id",
        ),
        (
            vec![("scope", "openid"), ("id_token_hint", "not-a-jwt")],
            400,
            "invalid_request",
        ),
        (
            vec![
                ("scope", "openid"),
                ("login_hint", "alice"),
                ("binding_message", "see https://evil.example"),
            ],
            400,
            "invalid_binding_message",
        ),
        (
            vec![
                ("scope", "openid"),
                ("login_hint", "alice"),
                ("requested_expiry", "86400"),
            ],
            400,
            "invalid_request",
        ),
        (
            vec![
                ("scope", "openid"),
                ("login_hint", "alice"),
                ("request", "x.y.z"),
            ],
            400,
            "invalid_request",
        ),
    ];
    for (form, want_status, want_error) in cases {
        let (status, body) = bc_authorize(&fx, &fx.poll, &form).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (want_status, Some(want_error)),
            "{form:?}: {body}"
        );
    }
    // No credentials, wrong credentials.
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/bc-authorize"))
        .form(&[
            ("client_id", "bank"),
            ("scope", "openid"),
            ("login_hint", "alice"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    // A disabled or locked user cannot be asked.
    users::update(
        &fx.app.state,
        fx.tenant.id,
        Actor::System,
        fx.bob,
        ridm_api::models::UserUpdate {
            status: Some(ridm_api::models::UserStatus::Disabled),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (_, body) =
        bc_authorize(&fx, &fx.poll, &[("scope", "openid"), ("login_hint", "bob")]).await;
    assert_eq!(body["error"], "unknown_user_id");
    common::settle(&fx.app.state).await;
    assert!(fx.email.sent().is_empty(), "no request, no notice");
}

#[tokio::test]
async fn only_ciba_clients_may_ask_and_only_confidential_ones_can_be() {
    let fx = fixture().await;
    let other = clients::create(
        &fx.app.state,
        fx.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("svc".into()),
            name: "svc".into(),
            client_type: Some(ClientType::Machine),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let creds = (
        "svc".to_string(),
        other.client_secret.as_deref().unwrap().to_string(),
    );
    let (status, body) =
        bc_authorize(&fx, &creds, &[("scope", "openid"), ("login_hint", "alice")]).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("unauthorized_client"))
    );

    // Registration rules.
    let refused = |input: NewClient| {
        let st = fx.app.state.clone();
        let tid = fx.tenant.id;
        async move {
            clients::create(&st, tid, Actor::System, input)
                .await
                .is_err()
        }
    };
    let base = || NewClient {
        name: "x".into(),
        client_type: Some(ClientType::Machine),
        allowed_grants: Some(vec![CIBA.into()]),
        ..Default::default()
    };
    assert!(
        refused(NewClient {
            token_endpoint_auth_method: Some(ridm_api::models::TokenEndpointAuthMethod::None),
            ..base()
        })
        .await,
        "public"
    );
    assert!(
        refused(NewClient {
            backchannel_token_delivery_mode: Some(BackchannelDeliveryMode::Ping),
            ..base()
        })
        .await,
        "ping without an endpoint"
    );
    assert!(
        refused(NewClient {
            backchannel_token_delivery_mode: Some(BackchannelDeliveryMode::Ping),
            backchannel_client_notification_endpoint: Some("http://203.0.113.9/cb".into()),
            ..base()
        })
        .await,
        "plain http"
    );
    assert!(
        refused(NewClient {
            allowed_grants: Some(vec![grants::CLIENT_CREDENTIALS.into()]),
            backchannel_token_delivery_mode: Some(BackchannelDeliveryMode::Poll),
            ..base()
        })
        .await,
        "a delivery mode without the grant"
    );
    let ok = clients::create(&fx.app.state, fx.tenant.id, Actor::System, base())
        .await
        .unwrap();
    assert_eq!(
        ok.client.backchannel_token_delivery_mode,
        Some(BackchannelDeliveryMode::Poll),
        "poll is the default"
    );
}

#[tokio::test]
async fn an_id_token_hint_names_the_user_it_was_issued_for() {
    let fx = fixture().await;
    let alice = users::get(&fx.app.state, fx.tenant.id, fx.alice)
        .await
        .unwrap();
    let hint_for = |client: &'static str| {
        let (st, tenant, alice) = (fx.app.state.clone(), fx.tenant.clone(), alice.clone());
        async move {
            tokens::issue_id_token(
                &st,
                IdTokenRequest {
                    tenant: &tenant,
                    client: &TokenClient::public(client),
                    user: &alice,
                    scopes: &["openid".into()],
                    roles: &[],
                    groups: &[],
                    session_id: None,
                    org_id: None,
                    auth_time: Utc::now() - chrono::Duration::hours(2),
                    nonce: None,
                    amr: &[],
                    acr: None,
                    access_token: None,
                    code: None,
                    act: None,
                },
            )
            .await
            .unwrap()
            .token
        }
    };
    let mine = hint_for("bank").await;
    let (status, body) = bc_authorize(
        &fx,
        &fx.poll,
        &[("scope", "openid"), ("id_token_hint", &mine)],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    common::settle(&fx.app.state).await;
    assert_eq!(fx.email.sent_to("alice@example.com").len(), 1);
    let theirs = hint_for("someone-else").await;
    let (_, body) = bc_authorize(
        &fx,
        &fx.poll,
        &[("scope", "openid"), ("id_token_hint", &theirs)],
    )
    .await;
    assert_eq!(body["error"], "invalid_request", "{body}");
}

#[tokio::test]
async fn a_user_can_only_be_asked_so_often_at_once() {
    let fx = fixture().await;
    for i in 0..5 {
        let (status, body) = bc_authorize(
            &fx,
            &fx.poll,
            &[("scope", "openid"), ("login_hint", "alice")],
        )
        .await;
        assert_eq!(status, 200, "request {i}: {body}");
    }
    let (_, body) = bc_authorize(
        &fx,
        &fx.poll,
        &[("scope", "openid"), ("login_hint", "alice")],
    )
    .await;
    assert_eq!(body["error"], "access_denied", "{body}");
    // Someone else is still reachable.
    let (status, _) =
        bc_authorize(&fx, &fx.poll, &[("scope", "openid"), ("login_hint", "bob")]).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn ping_mode_calls_the_client_back() {
    let fx = fixture().await;
    let received: Pings = Arc::new(Mutex::new(vec![]));
    let sink = received.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/cb",
            axum::routing::post(
                move |headers: axum::http::HeaderMap, axum::Json(body): axum::Json<Value>| {
                    let sink = sink.clone();
                    async move {
                        let auth = headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string);
                        sink.lock().unwrap().push((auth, body));
                        axum::http::StatusCode::NO_CONTENT
                    }
                },
            ),
        );
        axum::serve(listener, app).await.unwrap();
    });
    let creds = ciba_client(
        &fx.app,
        "pinged",
        BackchannelDeliveryMode::Ping,
        Some(format!("http://127.0.0.1:{port}/cb")),
    )
    .await;
    let (status, body) =
        bc_authorize(&fx, &creds, &[("scope", "openid"), ("login_hint", "alice")]).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_request")),
        "token required"
    );
    let (status, ack) = bc_authorize(
        &fx,
        &creds,
        &[
            ("scope", "openid"),
            ("login_hint", "alice"),
            ("client_notification_token", "note-8f2a"),
        ],
    )
    .await;
    assert_eq!(status, 200, "{ack}");
    let auth_req_id = ack["auth_req_id"].as_str().unwrap().to_string();
    let alice = account_token(&fx, fx.alice).await;
    let id = only_pending(&fx, &alice).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, _) = account(
        &fx,
        &alice,
        reqwest::Method::POST,
        &format!("/{id}/approve"),
    )
    .await;
    assert_eq!(status, 204);
    let mut got = vec![];
    for _ in 0..100 {
        got = received.lock().unwrap().clone();
        if !got.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(got.len(), 1, "one ping");
    assert_eq!(got[0].0.as_deref(), Some("Bearer note-8f2a"));
    assert_eq!(got[0].1, serde_json::json!({ "auth_req_id": auth_req_id }));
    let (status, tokens) = collect(&fx, &creds, &auth_req_id).await;
    assert_eq!(status, 200, "{tokens}");
    // Another client cannot collect it.
    let (_, body) = collect(&fx, &fx.poll, &auth_req_id).await;
    assert_eq!(body["error"], "invalid_grant");
}

/// Phase 12.7: the CIBA state machine. Each terminal answer is given once
/// and the request is gone after it; an undecided request that outlives its
/// expiry can be neither collected nor answered; an approval not collected
/// in time expires too; a stranger's poll never spends the grant; two
/// collections racing for one approval get one set of tokens between them.
#[tokio::test]
async fn every_state_answers_once() {
    let fx = fixture().await;
    let alice = account_token(&fx, fx.alice).await;
    let other = ciba_client(&fx.app, "other", BackchannelDeliveryMode::Poll, None).await;

    // pending → slow_down stays pending, and the interval keeps growing.
    let (id, row) = open_for_alice(&fx, &alice).await;
    let (_, b) = collect(&fx, &fx.poll, &id).await;
    assert_eq!(b["error"], "authorization_pending");
    for _ in 0..2 {
        let (_, b) = collect(&fx, &fx.poll, &id).await;
        assert_eq!(b["error"], "slow_down");
    }
    // A stranger learns nothing and spends nothing.
    let (_, b) = collect(&fx, &other, &id).await;
    assert_eq!(b["error"], "invalid_grant");
    // Approved → handed over at once despite the slow_downs, then gone.
    assert_eq!(answer(&fx, &alice, &row, "approve").await, 204);
    assert_eq!(
        answer(&fx, &alice, &row, "approve").await,
        404,
        "answered once"
    );
    assert_eq!(
        answer(&fx, &alice, &row, "deny").await,
        404,
        "and not undone"
    );
    let (_, b) = collect(&fx, &other, &id).await;
    assert_eq!(b["error"], "invalid_grant", "still not the stranger's");
    let (status, b) = collect(&fx, &fx.poll, &id).await;
    assert_eq!(status, 200, "{b}");
    assert!(b["refresh_token"].is_string(), "offline_access was granted");
    let (_, b) = collect(&fx, &fx.poll, &id).await;
    assert_eq!(b["error"], "invalid_grant");

    // Denied → access_denied once, then gone.
    let (id, row) = open_for_alice(&fx, &alice).await;
    assert_eq!(answer(&fx, &alice, &row, "deny").await, 204);
    assert_eq!(answer(&fx, &alice, &row, "approve").await, 404);
    let (_, b) = collect(&fx, &fx.poll, &id).await;
    assert_eq!(b["error"], "access_denied");
    let (_, b) = collect(&fx, &fx.poll, &id).await;
    assert_eq!(b["error"], "invalid_grant");

    // Approved but not collected in time → expired_token, then gone.
    let (id, row) = open_for_alice(&fx, &alice).await;
    assert_eq!(answer(&fx, &alice, &row, "approve").await, 204);
    age_live_record(&fx, &id).await;
    let (_, b) = collect(&fx, &fx.poll, &id).await;
    assert_eq!(b["error"], "expired_token");
    let (_, b) = collect(&fx, &fx.poll, &id).await;
    assert_eq!(b["error"], "invalid_grant");

    // Past its expiry in the database: no longer listed, cannot be answered.
    let (_, row) = open_for_alice(&fx, &alice).await;
    let mut tx = db::bypass_tx(fx.app.state.db.home()).await.unwrap();
    sqlx::query("UPDATE ciba_requests SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(row.parse::<Uuid>().unwrap())
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let (_, list) = account(&fx, &alice, reqwest::Method::GET, "").await;
    assert_eq!(list, serde_json::json!([]));
    assert_eq!(answer(&fx, &alice, &row, "approve").await, 404);

    // Two collections racing for one approval: one set of tokens.
    let (id, row) = open_for_alice(&fx, &alice).await;
    assert_eq!(answer(&fx, &alice, &row, "approve").await, 204);
    let (a, b) = tokio::join!(collect(&fx, &fx.poll, &id), collect(&fx, &fx.poll, &id));
    let mut statuses = [a.0, b.0];
    statuses.sort();
    assert_eq!(statuses, [200, 400], "{a:?} {b:?}");

    // Every request ended up with its outcome in the audit trail.
    let mut tx = db::bypass_tx(fx.app.state.db.home()).await.unwrap();
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status, count(*) FROM ciba_requests WHERE tenant_id = $1 GROUP BY status ORDER BY status",
    )
    .bind(fx.tenant.id)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        rows,
        vec![
            ("approved".to_string(), 1),
            ("consumed".to_string(), 2),
            ("denied".to_string(), 1),
            ("pending".to_string(), 1),
        ],
        "the uncollected approval stays approved, the aged one pending"
    );
}

#[tokio::test]
async fn only_the_user_themselves_can_answer() {
    let fx = fixture().await;
    let alice = account_token(&fx, fx.alice).await;
    let (id, row) = open_for_alice(&fx, &alice).await;
    // A token acting for alice (an impersonation or an exchange) cannot.
    let user = users::get(&fx.app.state, fx.tenant.id, fx.alice)
        .await
        .unwrap();
    let mut client = TokenClient::public(ACCOUNT_CLIENT_ID);
    client.access_token_ttl = Duration::from_secs(300);
    let acting = tokens::issue_access_token(
        &fx.app.state,
        AccessTokenRequest {
            tenant: &fx.tenant,
            client: &client,
            user: Some(&user),
            scopes: &["openid".into()],
            audiences: &[ACCOUNT_AUDIENCE.to_string()],
            roles: &[],
            groups: &[],
            session_id: None,
            auth_time: Some(Utc::now()),
            amr: &[],
            acr: None,
            org_id: None,
            cnf_jkt: None,
            cnf_x5t: None,
            act: Some(serde_json::json!({"sub": fx.bob.to_string(), "iss": "x"})),
        },
    )
    .await
    .unwrap()
    .token;
    for verb in ["approve", "deny"] {
        let (status, body) = account(
            &fx,
            &acting,
            reqwest::Method::POST,
            &format!("/{row}/{verb}"),
        )
        .await;
        assert_eq!(status, 403, "{verb}: {body}");
        assert_eq!(body["type"], "urn:ridm:error:impersonation-forbidden");
    }
    // Alice can, and a user disabled after approving gets no tokens.
    assert_eq!(answer(&fx, &alice, &row, "approve").await, 204);
    users::update(
        &fx.app.state,
        fx.tenant.id,
        Actor::System,
        fx.alice,
        ridm_api::models::UserUpdate {
            status: Some(ridm_api::models::UserStatus::Disabled),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (status, body) = collect(&fx, &fx.poll, &id).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_grant")),
        "{body}"
    );
}
