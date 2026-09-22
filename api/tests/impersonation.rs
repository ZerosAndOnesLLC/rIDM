//! Phase 12.4: administrators signing in as users — who may, whom, what the
//! session and its tokens carry (`act`), what it may not do, how it ends, and
//! the audit trail it leaves.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::TestApp;
use common::admin::{TokenOpts, call, token, user_with_role};
use reqwest::Method;
use ridm_api::db;
use ridm_api::models::{
    ClientType, ImpersonationPolicy, MfaPolicy, NewClient, NewUser, TenantSettings, UserStatus,
};
use ridm_api::services::account_console::ACCOUNT_AUDIENCE;
use ridm_api::services::admin_access::{ADMIN_AUDIENCE, ADMIN_ROLE, OWNER_ROLE, VIEWER_ROLE};
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::tokens::{self, AccessTokenRequest, TokenClient};
use ridm_api::services::{clients, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PASSWORD: &str = "correct-horse-battery";
const REDIRECT: &str = "https://app.example/cb";

struct Fx {
    app: TestApp,
    settings: TenantSettings,
    /// The user administrators sign in as.
    ada: Uuid,
    /// An owner of the tenant and a token for them.
    owner: Uuid,
    owner_token: String,
}

/// A tenant allowing impersonation (unless `enabled` is false), with a
/// client that needs no consent, one user and an owner.
async fn fixture(enabled: bool) -> Fx {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let settings = TenantSettings {
        impersonation: ImpersonationPolicy {
            enabled,
            max_minutes: 30,
        },
        // The user's own sign-ins need a second step; an administrator's
        // session as them must not.
        mfa: MfaPolicy::Required,
        ..Default::default()
    };
    set_settings(&app, settings.clone()).await;
    for (id, consent) in [("spa", false), ("asks", true)] {
        clients::create(
            &app.state,
            tid,
            Actor::System,
            NewClient {
                client_id: Some(id.into()),
                name: format!("App {id}"),
                client_type: Some(ClientType::Spa),
                redirect_uris: vec![REDIRECT.into()],
                require_consent: Some(consent),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    let ada = users::create(
        &app.state,
        tid,
        Actor::System,
        NewUser {
            username: "ada".into(),
            email: Some("ada@example.com".into()),
            status: Some(UserStatus::Active),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .id;
    let owner = user_with_role(&app, tid, Some(OWNER_ROLE)).await;
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    let owner_token = token(&app, &tenant, owner, TokenOpts::default()).await;
    Fx {
        app,
        settings,
        ada,
        owner,
        owner_token,
    }
}

async fn set_settings(app: &TestApp, settings: TenantSettings) {
    tenants::update(
        &app.state,
        Actor::System,
        app.tenant.id,
        TenantUpdate {
            settings: Some(settings),
            ..Default::default()
        },
    )
    .await
    .unwrap();
}

fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

fn payload(jwt: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

fn param(u: &url::Url, k: &str) -> Option<String> {
    u.query_pairs()
        .find(|(a, _)| a == k)
        .map(|(_, v)| v.into_owned())
}

fn location(res: &reqwest::Response) -> url::Url {
    url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap()
}

/// `POST …/users/{user}/impersonate` as `bearer`.
async fn ask(fx: &Fx, bearer: &str, user: Uuid, reason: &str) -> (u16, Value) {
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &format!(
            "/admin/tenants/{}/users/{user}/impersonate",
            fx.app.tenant.slug
        ),
        Some(bearer),
        Some(&json!({ "reason": reason })),
    )
    .await;
    (status.as_u16(), body)
}

/// Ask as the owner and open the ticket in `http`; returns the redirect.
async fn impersonate(fx: &Fx, http: &reqwest::Client) -> url::Url {
    let (status, body) = ask(fx, &fx.owner_token, fx.ada, "ticket 4711: login loop").await;
    assert_eq!(status, 200, "{body}");
    let url = body["url"].as_str().unwrap();
    assert!(
        url.starts_with(&fx.app.tenant_url("/impersonate?ticket=")),
        "{url}"
    );
    let res = http.get(url).send().await.unwrap();
    assert_eq!(res.status(), 303);
    location(&res)
}

/// `/authorize` for `client` in `http`; returns the redirect.
async fn authorize(fx: &Fx, http: &reqwest::Client, client: &str) -> url::Url {
    let q = [
        ("response_type", "code"),
        ("client_id", client),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("state", "st"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    let res = http
        .get(fx.app.tenant_url("/authorize"))
        .query(&q)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303, "authorize");
    location(&res)
}

async fn token_request(fx: &Fx, form: &[(&str, &str)]) -> (u16, Value) {
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .form(form)
        .send()
        .await
        .unwrap();
    (res.status().as_u16(), res.json().await.unwrap())
}

/// Sign in to `spa` through the browser's session and redeem the code.
async fn tokens_via(fx: &Fx, http: &reqwest::Client) -> Value {
    let back = authorize(fx, http, "spa").await;
    let code = param(&back, "code").unwrap_or_else(|| panic!("no code: {back}"));
    let (status, body) = token_request(
        fx,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("client_id", "spa"),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    body
}

/// The live impersonated session of `user`, straight from the mirror table.
async fn impersonated_session(app: &TestApp, user: Uuid) -> (Uuid, Option<Uuid>, Option<String>) {
    let mut tx = db::bypass_tx(&app.state.db).await.unwrap();
    let row = sqlx::query_as::<_, (Uuid, Option<Uuid>, Option<String>)>(
        "SELECT id, impersonator_id, impersonation_reason FROM sso_sessions \
         WHERE tenant_id = $1 AND user_id = $2 AND impersonator_id IS NOT NULL \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(app.tenant.id)
    .bind(user)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    row
}

/// `(payload, impersonator_id, actor_type)` of one event name, newest first.
/// The writer records from the bus in the background, so the read retries.
async fn audit(app: &TestApp, name: &str) -> Vec<(Value, Option<Uuid>, String)> {
    let mut rows = Vec::new();
    for _ in 0..100 {
        let mut tx = db::bypass_tx(&app.state.db).await.unwrap();
        rows = sqlx::query_as::<_, (Value, Option<Uuid>, String)>(
            "SELECT payload, impersonator_id, actor_type FROM audit_events \
             WHERE tenant_id = $1 AND name = $2 ORDER BY occurred_at DESC",
        )
        .bind(app.tenant.id)
        .bind(name)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        if !rows.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    rows
}

/// An account-audience token, as the account console holds for a session.
async fn account_token(fx: &Fx, user: Uuid, session: Option<Uuid>, act: Option<Value>) -> String {
    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    let u = users::get(&fx.app.state, tenant.id, user).await.unwrap();
    tokens::issue_access_token(
        &fx.app.state,
        AccessTokenRequest {
            tenant: &tenant,
            client: &TokenClient::public("ridm-account-console"),
            user: Some(&u),
            scopes: &["openid".into()],
            audiences: &[ACCOUNT_AUDIENCE.into()],
            roles: &[],
            groups: &[],
            session_id: session,
            org_id: None,
            auth_time: Some(chrono::Utc::now()),
            amr: &[],
            acr: None,
            cnf_jkt: None,
            cnf_x5t: None,
            act,
        },
    )
    .await
    .unwrap()
    .token
}

async fn account_call(
    fx: &Fx,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut req = fx
        .app
        .http
        .request(method, fx.app.tenant_url(&format!("/account{path}")))
        .bearer_auth(bearer);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let res = req.send().await.unwrap();
    (
        res.status().as_u16(),
        res.json().await.unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn impersonation_is_off_until_the_tenant_enables_it() {
    let fx = fixture(false).await;
    let (status, body) = ask(&fx, &fx.owner_token, fx.ada, "support").await;
    assert_eq!(status, 403, "{body}");
    assert!(
        body["detail"].as_str().unwrap().contains("not enabled"),
        "{body}"
    );
}

#[tokio::test]
async fn only_owners_may_and_never_as_an_administrator_or_themselves() {
    let fx = fixture(true).await;
    let tid = fx.app.tenant.id;
    let tenant = tenants::get(&fx.app.state, tid).await.unwrap();

    // `ridm:admin` is everything but tenant lifecycle and this.
    let admin = user_with_role(&fx.app, tid, Some(ADMIN_ROLE)).await;
    let admin_token = token(&fx.app, &tenant, admin, TokenOpts::default()).await;
    let (status, body) = ask(&fx, &admin_token, fx.ada, "support").await;
    assert_eq!(status, 403, "{body}");
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("ridm:users:impersonate")
    );

    // A user holding any admin permission is off limits, however little.
    let viewer = user_with_role(&fx.app, tid, Some(VIEWER_ROLE)).await;
    let (status, body) = ask(&fx, &fx.owner_token, viewer, "support").await;
    assert_eq!(status, 403, "{body}");
    assert!(body["detail"].as_str().unwrap().contains("administrators"));

    // Not oneself, not without a reason, not an inactive user.
    let (status, _) = ask(&fx, &fx.owner_token, fx.owner, "support").await;
    assert_eq!(status, 400);
    let (status, _) = ask(&fx, &fx.owner_token, fx.ada, "   ").await;
    assert_eq!(status, 400);
    let (status, _) = ask(&fx, &fx.owner_token, fx.ada, &"x".repeat(501)).await;
    assert_eq!(status, 400);
    let (status, _) = ask(&fx, &fx.owner_token, Uuid::now_v7(), "support").await;
    assert_eq!(status, 404);
    users::update(
        &fx.app.state,
        tid,
        Actor::System,
        fx.ada,
        ridm_api::models::UserUpdate {
            status: Some(UserStatus::Disabled),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (status, _) = ask(&fx, &fx.owner_token, fx.ada, "support").await;
    assert_eq!(status, 409);
}

#[tokio::test]
async fn the_session_mints_tokens_that_name_the_administrator() {
    let fx = fixture(true).await;
    let http = browser();
    let landed = impersonate(&fx, &http).await;
    assert_eq!(landed.path(), "/account/");
    assert_eq!(param(&landed, "impersonate").as_deref(), Some("1"));

    // No password, and no second step although the policy requires one:
    // the session goes straight to a code.
    let body = tokens_via(&fx, &http).await;
    let at = payload(body["access_token"].as_str().unwrap());
    let issuer = format!("{}/t/{}", fx.app.base_url, fx.app.tenant.slug);
    assert_eq!(at["sub"], fx.ada.to_string());
    assert_eq!(
        at["act"],
        json!({ "sub": fx.owner.to_string(), "iss": issuer })
    );
    let id = payload(body["id_token"].as_str().unwrap());
    assert_eq!(id["act"], at["act"], "the ID token tells the client too");

    // Nothing outlives the session (30 minutes here), refresh included.
    let limit = chrono::Utc::now().timestamp() + 30 * 60 + 5;
    assert!(at["exp"].as_i64().unwrap() <= limit);
    let refresh = body["refresh_token"].as_str().expect("a refresh token");
    let (status, again) = token_request(
        &fx,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", "spa"),
        ],
    )
    .await;
    assert_eq!(status, 200, "{again}");
    let at2 = payload(again["access_token"].as_str().unwrap());
    assert_eq!(at2["act"], at["act"], "every refresh repeats act");
    let mut tx = db::bypass_tx(&fx.app.state.db).await.unwrap();
    let family_end: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT max(expires_at) FROM refresh_tokens WHERE tenant_id = $1 AND act IS NOT NULL",
    )
    .bind(fx.app.tenant.id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(family_end.timestamp() <= limit, "{family_end}");

    // The session says who opened it and why.
    let (_, by, reason) = impersonated_session(&fx.app, fx.ada).await;
    assert_eq!(by, Some(fx.owner));
    assert_eq!(reason.as_deref(), Some("ticket 4711: login loop"));

    // And the audit log says it three ways: the request, the start, and
    // everything done in the session carries the administrator.
    let requested = audit(&fx.app, "impersonation.requested").await;
    assert_eq!(requested[0].0["reason"], "ticket 4711: login loop");
    assert_eq!(requested[0].2, "admin");
    let started = audit(&fx.app, "impersonation.started").await;
    assert_eq!(started[0].0["impersonator_id"], fx.owner.to_string());
    assert_eq!(started[0].1, Some(fx.owner));
    let granted = audit(&fx.app, "authorization.granted").await;
    assert_eq!(granted[0].1, Some(fx.owner), "the grant names the admin");
    assert_eq!(granted[0].2, "user", "while the user remains the actor");
}

#[tokio::test]
async fn a_ticket_opens_one_session_once() {
    let fx = fixture(true).await;
    let (_, body) = ask(&fx, &fx.owner_token, fx.ada, "support").await;
    let url = body["url"].as_str().unwrap();
    assert_eq!(browser().get(url).send().await.unwrap().status(), 303);
    let res = browser().get(url).send().await.unwrap();
    let to = location(&res);
    assert_eq!(to.path(), "/error/");
    assert_eq!(param(&to, "error").as_deref(), Some("impersonation_failed"));
    // A redeemed ticket is gone even if the policy is switched off after.
    let (_, body) = ask(&fx, &fx.owner_token, fx.ada, "support").await;
    set_settings(
        &fx.app,
        TenantSettings {
            impersonation: ImpersonationPolicy::default(),
            ..fx.settings.clone()
        },
    )
    .await;
    let res = browser()
        .get(body["url"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(location(&res).path(), "/error/", "switched off since");
}

#[tokio::test]
async fn consent_is_the_users_to_give() {
    let fx = fixture(true).await;
    let http = browser();
    impersonate(&fx, &http).await;
    let back = authorize(&fx, &http, "asks").await;
    assert_eq!(
        back.as_str().split('?').next(),
        Some(REDIRECT),
        "sent back, not to a consent page"
    );
    assert_eq!(param(&back, "error").as_deref(), Some("access_denied"));
}

#[tokio::test]
async fn the_account_api_refuses_what_only_the_user_may_do() {
    let fx = fixture(true).await;
    impersonate(&fx, &browser()).await;
    let (session, _, _) = impersonated_session(&fx.app, fx.ada).await;
    let bearer = account_token(&fx, fx.ada, Some(session), None).await;

    let (status, me) = account_call(&fx, Method::GET, "/me", &bearer, None).await;
    assert_eq!(status, 200);
    let owner = users::get(&fx.app.state, fx.app.tenant.id, fx.owner)
        .await
        .unwrap();
    assert_eq!(me["impersonation"]["impersonator"], owner.username);

    // Looking and ordinary profile edits work.
    let (status, _) = account_call(
        &fx,
        Method::PATCH,
        "/profile",
        &bearer,
        Some(json!({"locale": "en"})),
    )
    .await;
    assert_eq!(status, 200);

    // Credentials, tokens, the account itself: refused, however recent the
    // sign-in looks.
    for (method, path, body) in [
        (
            Method::PUT,
            "/password",
            Some(json!({"current_password": PASSWORD, "new_password": "a-whole-new-secret-1"})),
        ),
        (Method::POST, "/mfa/totp/enroll", None),
        (
            Method::POST,
            "/email/change",
            Some(json!({"email": "someone@example.com"})),
        ),
        (
            Method::POST,
            "/tokens",
            Some(json!({"name": "mine", "scopes": ["account"]})),
        ),
        (Method::DELETE, "/me", Some(json!({"confirm": "ada"}))),
    ] {
        let (status, problem) = account_call(&fx, method.clone(), path, &bearer, body).await;
        assert_eq!(status, 403, "{method} {path}: {problem}");
        assert_eq!(
            problem["type"], "urn:ridm:error:impersonation-forbidden",
            "{method} {path}"
        );
    }

    // The user sees the session among their own, with the administrator's
    // address and browser withheld.
    let (_, sessions) = account_call(&fx, Method::GET, "/sessions", &bearer, None).await;
    let mine = sessions
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == session.to_string())
        .expect("listed");
    assert_eq!(mine["impersonated_by"], owner.username);
    assert!(mine["ip"].is_null() && mine["user_agent"].is_null());
}

#[tokio::test]
async fn a_token_acting_for_someone_never_administers() {
    let fx = fixture(true).await;
    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    let owner = users::get(&fx.app.state, tenant.id, fx.owner)
        .await
        .unwrap();
    let roles =
        ridm_api::services::roles::effective_roles(&fx.app.state, tenant.id, owner.id, None)
            .await
            .unwrap();
    let delegated = tokens::issue_access_token(
        &fx.app.state,
        AccessTokenRequest {
            tenant: &tenant,
            client: &TokenClient::public("admin-ui"),
            user: Some(&owner),
            scopes: &["openid".into()],
            audiences: &[ADMIN_AUDIENCE.into()],
            roles: &roles,
            groups: &[],
            session_id: None,
            org_id: None,
            auth_time: None,
            amr: &["pwd".into()],
            acr: None,
            cnf_jkt: None,
            cnf_x5t: None,
            act: Some(json!({"sub": Uuid::now_v7().to_string()})),
        },
    )
    .await
    .unwrap()
    .token;
    let (status, body, _) = call(
        &fx.app,
        Method::GET,
        &format!("/admin/tenants/{}/users", tenant.slug),
        Some(&delegated),
        None,
    )
    .await;
    assert_eq!(status, 403, "{body}");

    // And a token exchanged for the user (no impersonated session behind
    // it) is refused credential changes like an impersonation.
    let exchanged = account_token(
        &fx,
        fx.ada,
        None,
        Some(json!({"sub": "someone", "client_id": "svc"})),
    )
    .await;
    let (status, _) = account_call(
        &fx,
        Method::DELETE,
        "/me",
        &exchanged,
        Some(json!({"confirm": "ada"})),
    )
    .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn ending_it_puts_the_browsers_own_session_back() {
    let fx = fixture(true).await;
    // The owner signs in in this browser first: a tenant administrator
    // impersonating in their own tenant shares the tenant's cookie.
    let tid = fx.app.tenant.id;
    password::set_password(
        &fx.app.state,
        tid,
        &fx.settings.password,
        Actor::System,
        fx.owner,
        PASSWORD.to_string().into(),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    // Their own sign-in is not the subject here; the policy's MFA would
    // stand in the way of opening it through a flow.
    set_settings(
        &fx.app,
        TenantSettings {
            mfa: MfaPolicy::Off,
            ..fx.settings.clone()
        },
    )
    .await;
    let http = browser();
    let to_login = authorize(&fx, &http, "spa").await;
    let flow: Uuid = param(&to_login, "flow").unwrap().parse().unwrap();
    let csrf = http
        .get(fx.app.tenant_url(&format!("/flows/{flow}")))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["csrf"]
        .as_str()
        .unwrap()
        .to_string();
    let owner = users::get(&fx.app.state, tid, fx.owner).await.unwrap();
    let res = http
        .post(fx.app.tenant_url(&format!("/flows/{flow}/password")))
        .json(&json!({"identifier": owner.username, "password": PASSWORD, "csrf": csrf}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let own = payload(tokens_via(&fx, &http).await["id_token"].as_str().unwrap());
    assert_eq!(own["sub"], fx.owner.to_string());

    // Impersonate in the same browser, then end it from the banner.
    impersonate(&fx, &http).await;
    let as_ada = payload(tokens_via(&fx, &http).await["id_token"].as_str().unwrap());
    assert_eq!(as_ada["sub"], fx.ada.to_string());
    let (session, _, _) = impersonated_session(&fx.app, fx.ada).await;
    let res = http
        .post(fx.app.tenant_url("/impersonation/end"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    assert_eq!(location(&res).path(), "/console/");

    // The owner is themselves again, with the session they had before.
    let back = payload(tokens_via(&fx, &http).await["id_token"].as_str().unwrap());
    assert_eq!(back["sub"], fx.owner.to_string());
    assert_eq!(back["sid"], own["sid"]);
    assert!(back.get("act").is_none());

    // The impersonated session is over, and the log says who ended it.
    let mut tx = db::bypass_tx(&fx.app.state.db).await.unwrap();
    let revoked: bool = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM sso_sessions WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tid)
    .bind(session)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(revoked);
    let ended = audit(&fx.app, "impersonation.ended").await;
    assert_eq!(ended[0].0["session_id"], session.to_string());
    assert_eq!(ended[0].2, "admin");
    assert_eq!(ended[0].1, Some(fx.owner));
}

#[tokio::test]
async fn revoking_it_from_the_admin_api_also_records_the_end() {
    let fx = fixture(true).await;
    impersonate(&fx, &browser()).await;
    let (session, _, _) = impersonated_session(&fx.app, fx.ada).await;
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!(
            "/admin/tenants/{}/users/{}/sessions/{session}",
            fx.app.tenant.slug, fx.ada
        ),
        Some(&fx.owner_token),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let ended = audit(&fx.app, "impersonation.ended").await;
    assert_eq!(ended[0].0["impersonator_id"], fx.owner.to_string());
    assert_eq!(ended[0].2, "system", "not ended from inside the session");
}

/// Phase 12.7: the whole trail of one impersonation, read back from the
/// chain. Everything recorded from `impersonation.started` until the session
/// ends names the administrator; nothing after it does,
/// though the same administrator keeps working; and the chain, with the
/// `impersonator_id` rows folded into their hashes, still verifies.
#[tokio::test]
async fn the_trail_names_the_administrator_from_start_to_end_and_the_chain_holds() {
    let fx = fixture(true).await;
    let http = browser();
    impersonate(&fx, &http).await;
    let tokens = tokens_via(&fx, &http).await;
    assert!(payload(tokens["access_token"].as_str().unwrap())["act"].is_object());
    let (session, _, _) = impersonated_session(&fx.app, fx.ada).await;
    let bearer = account_token(&fx, fx.ada, Some(session), None).await;
    let (status, _) = account_call(
        &fx,
        Method::PATCH,
        "/profile",
        &bearer,
        Some(json!({"locale": "en"})),
    )
    .await;
    assert_eq!(status, 200);
    // Ended by the administrator from the admin API.
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!(
            "/admin/tenants/{}/users/{}/sessions/{session}",
            fx.app.tenant.slug, fx.ada
        ),
        Some(&fx.owner_token),
        None,
    )
    .await;
    assert_eq!(status, 204);
    assert!(!audit(&fx.app, "impersonation.ended").await.is_empty());
    // The same administrator, as themselves, afterwards.
    let (status, body, _) = call(
        &fx.app,
        Method::PATCH,
        &format!("/admin/tenants/{}/users/{}", fx.app.tenant.slug, fx.ada),
        Some(&fx.owner_token),
        Some(&json!({"locale": "de"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // Read the chain in order once the writer has caught up.
    let mut rows: Vec<(i64, String, Option<Uuid>)> = vec![];
    for _ in 0..100 {
        let mut tx = db::bypass_tx(&fx.app.state.db).await.unwrap();
        rows = sqlx::query_as(
            "SELECT seq, name, impersonator_id FROM audit_events \
             WHERE tenant_id = $1 ORDER BY seq",
        )
        .bind(fx.app.tenant.id)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        if rows.iter().filter(|r| r.1 == "user.updated").count() >= 1
            && rows.iter().any(|r| r.1 == "impersonation.ended")
            && rows
                .iter()
                .rev()
                .take_while(|r| r.1 != "impersonation.ended")
                .any(|r| r.1 == "user.updated")
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let start = rows
        .iter()
        .position(|r| r.1 == "impersonation.started")
        .expect("started");
    let end = rows
        .iter()
        .position(|r| r.1 == "impersonation.ended")
        .expect("ended");
    assert!(start < end);
    // The end itself was recorded outside the session (the administrator
    // revoked it from the admin API), so it is not part of the window.
    let during = &rows[start..end];
    assert!(
        during.iter().any(|r| r.1 == "authorization.granted"),
        "{during:?}"
    );
    for (seq, name, by) in during {
        assert_eq!(*by, Some(fx.owner), "#{seq} {name} inside the session");
    }
    let after = &rows[end + 1..];
    assert!(after.iter().any(|r| r.1 == "user.updated"), "{after:?}");
    for (seq, name, by) in after {
        assert_eq!(*by, None, "#{seq} {name} after the session");
    }
    // Before it, the request itself is the administrator's own act.
    let requested = rows
        .iter()
        .find(|r| r.1 == "impersonation.requested")
        .unwrap();
    assert_eq!(requested.2, None);

    let (status, verification, _) = call(
        &fx.app,
        Method::GET,
        &format!("/admin/tenants/{}/audit/verify", fx.app.tenant.slug),
        Some(&fx.owner_token),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(verification["valid"], true, "{verification}");
    assert!(verification["checked"].as_u64().unwrap() >= rows.len() as u64);
}
