//! Phase 7.6: the self-service account API — who may call it (an
//! `urn:ridm:account` token of the path's tenant, alive session, own account
//! only), the recent-authentication rule for security changes, managing
//! second factors and recovery codes, and trusted devices.

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use common::TestApp;
use common::admin::call;
use reqwest::Method;
use ridm_api::messaging::SenderFactory;
use ridm_api::models::{MfaMethods, NewUser, Tenant, TenantSettings};
use ridm_api::services::account_console::{ACCOUNT_AUDIENCE, ACCOUNT_CLIENT_ID};
use ridm_api::services::admin_access::ADMIN_AUDIENCE;
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::tokens::{self, AccessTokenRequest, TokenClient};
use ridm_api::services::{clients, totp, trusted_devices, users};
use ridm_api::state::AppState;
use ridm_core::events::Actor;
use ridm_core::providers::{EmailSender, SmsSender};
use ridm_core::test_support::{MockEmailSender, MockSmsSender};
use serde_json::json;
use totp_rs::{Algorithm, Builder, Secret};
use uuid::Uuid;

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
    user_id: Uuid,
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
    tenants::update(
        &app.state,
        Actor::System,
        tid,
        TenantUpdate {
            settings: Some(TenantSettings {
                mfa_methods: MfaMethods {
                    totp: true,
                    email_otp: true,
                    sms_otp: false,
                },
                ..Default::default()
            }),
            ..Default::default()
        },
    )
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
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    Fx {
        app,
        tenant,
        email,
        user_id: user.id,
    }
}

struct Auth {
    audience: &'static str,
    /// Seconds ago the sign-in happened.
    age_secs: i64,
    acr: Option<&'static str>,
    session: bool,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            audience: ACCOUNT_AUDIENCE,
            age_secs: 0,
            acr: None,
            session: true,
        }
    }
}

/// An access token for `user_id` as the account console would hold.
async fn token(fx: &Fx, user_id: Uuid, auth: Auth) -> String {
    let user = users::get(&fx.app.state, fx.tenant.id, user_id)
        .await
        .unwrap();
    let auth_time = Utc::now() - chrono::Duration::seconds(auth.age_secs);
    let session_id = if auth.session {
        let s = sessions::create(
            &fx.app.state,
            fx.tenant.id,
            NewSession {
                user_id,
                amr: vec!["pwd".into()],
                acr: auth.acr.map(str::to_string),
                ip: None,
                user_agent: None,
                policy: &fx.tenant.settings.session,
            },
        )
        .await
        .unwrap();
        Some(s.id)
    } else {
        None
    };
    let mut client = TokenClient::public(ACCOUNT_CLIENT_ID);
    client.access_token_ttl = Duration::from_secs(300);
    tokens::issue_access_token(
        &fx.app.state,
        AccessTokenRequest {
            tenant: &fx.tenant,
            client: &client,
            user: Some(&user),
            scopes: &["openid".into()],
            audiences: &[auth.audience.to_string()],
            roles: &[],
            groups: &[],
            session_id,
            auth_time: Some(auth_time),
            amr: &["pwd".into()],
            acr: auth.acr,
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

fn path(fx: &Fx, rest: &str) -> String {
    format!("/t/{}/account{rest}", fx.tenant.slug)
}

fn code_for(secret_b32: &str, offset: i64) -> String {
    let now = (Utc::now().timestamp() + offset) as u64;
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(Secret::try_from_base32(secret_b32).unwrap())
        .with_issuer(Some("x"))
        .with_account_name("y")
        .build()
        .unwrap()
        .generate(now)
        .to_string()
}

#[tokio::test]
async fn only_a_live_account_token_of_the_path_tenant_gets_in() {
    let fx = fixture().await;
    let me = path(&fx, "/me");
    let (status, _, www) = call(&fx.app, Method::GET, &me, None, None).await;
    assert_eq!(status, 401);
    assert!(www.starts_with("Bearer realm="), "{www}");

    let admin = token(
        &fx,
        fx.user_id,
        Auth {
            audience: ADMIN_AUDIENCE,
            ..Default::default()
        },
    )
    .await;
    let (status, _, _) = call(&fx.app, Method::GET, &me, Some(&admin), None).await;
    assert_eq!(status, 401, "an admin token has the wrong audience");

    let ok = token(&fx, fx.user_id, Auth::default()).await;
    let (status, body, _) = call(&fx.app, Method::GET, &me, Some(&ok), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["username"], "alice");
    assert_eq!(body["tenant"]["slug"], fx.tenant.slug);
    assert_eq!(body["amr"], json!(["pwd"]));
    assert!(body["auth_time"].is_string());

    // Another tenant's path: refused even with a valid token.
    let other = common::create_tenant(&fx.app.state.db).await;
    let (status, _, _) = call(
        &fx.app,
        Method::GET,
        &format!("/t/{}/account/me", other.slug),
        Some(&ok),
        None,
    )
    .await;
    assert_eq!(status, 403);

    // The session behind the token ended: the token is dead with it.
    let dead = token(&fx, fx.user_id, Auth::default()).await;
    for s in sessions::list_live_for_user(&fx.app.state, fx.tenant.id, fx.user_id)
        .await
        .unwrap()
    {
        sessions::revoke(&fx.app.state, fx.tenant.id, s.id)
            .await
            .unwrap();
    }
    let (status, _, _) = call(&fx.app, Method::GET, &me, Some(&dead), None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn factors_are_managed_with_a_recent_sign_in() {
    let fx = fixture().await;
    let fresh = token(&fx, fx.user_id, Auth::default()).await;
    let stale = token(
        &fx,
        fx.user_id,
        Auth {
            age_secs: 20 * 60,
            ..Default::default()
        },
    )
    .await;

    let (status, body, _) =
        call(&fx.app, Method::GET, &path(&fx, "/mfa"), Some(&stale), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["factors"], json!([]));
    assert_eq!(body["recovery_codes"], 0);
    assert_eq!(body["methods"], json!(["totp", "email_otp"]));
    assert_eq!(body["policy"], "off");

    // Reading is fine on an old sign-in; changing is not.
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &path(&fx, "/mfa/totp/enroll"),
        Some(&stale),
        None,
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(body["type"], "urn:ridm:error:reauthentication-required");
    assert!(!body["detail"].as_str().unwrap().contains("second step"));

    // Enrol an authenticator app.
    let (status, e, _) = call(
        &fx.app,
        Method::POST,
        &path(&fx, "/mfa/totp/enroll"),
        Some(&fresh),
        None,
    )
    .await;
    assert_eq!(status, 200, "{e}");
    let secret = e["secret"].as_str().unwrap().to_string();
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &path(&fx, "/mfa/totp/confirm"),
        Some(&fresh),
        Some(&json!({"code": "000000"})),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["errors"][0]["field"], "code");
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &path(&fx, "/mfa/totp/confirm"),
        Some(&fresh),
        Some(&json!({"code": code_for(&secret, 0), "label": "Phone"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let codes = body["recovery_codes"].as_array().unwrap();
    assert_eq!(codes.len(), totp::RECOVERY_CODE_COUNT);

    // With a factor enrolled, changes need a sign-in that passed it.
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &path(&fx, "/mfa/recovery-codes"),
        Some(&fresh),
        None,
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(body["detail"].as_str().unwrap().contains("second step"));
    let strong = token(
        &fx,
        fx.user_id,
        Auth {
            acr: Some("urn:ridm:acr:mfa"),
            ..Default::default()
        },
    )
    .await;
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &path(&fx, "/mfa/recovery-codes"),
        Some(&strong),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let renewed = body["recovery_codes"].as_array().unwrap();
    assert_eq!(renewed.len(), totp::RECOVERY_CODE_COUNT);
    assert_ne!(renewed, codes);

    // Codes by email as a second factor: the enrolment code goes to the address.
    let (status, sent, _) = call(
        &fx.app,
        Method::POST,
        &path(&fx, "/mfa/email/enroll"),
        Some(&strong),
        None,
    )
    .await;
    assert_eq!(status, 202, "{sent}");
    assert_eq!(sent["destination"], "a•••@example.com");
    let mails = fx.email.sent();
    let mail = mails
        .iter()
        .rev()
        .find(|m| m.subject.contains("code:"))
        .unwrap_or_else(|| {
            panic!(
                "no code email among {:?}",
                mails.iter().map(|m| m.subject.clone()).collect::<Vec<_>>()
            )
        });
    let code: String = mail
        .text
        .split("code")
        .nth(1)
        .unwrap()
        .chars()
        .filter(|c| c.is_ascii_digit())
        .take(6)
        .collect();
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &path(&fx, "/mfa/email/confirm"),
        Some(&strong),
        Some(&json!({"code": code})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["recovery_codes"].is_null(), "codes exist already");

    let (_, body, _) = call(&fx.app, Method::GET, &path(&fx, "/mfa"), Some(&stale), None).await;
    let kinds: Vec<&str> = body["factors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, vec!["totp", "email_otp"]);
    assert_eq!(body["factors"][0]["label"], "Phone");
    let totp_id = body["factors"][0]["id"].as_str().unwrap().to_string();
    let email_id = body["factors"][1]["id"].as_str().unwrap().to_string();

    // Remove both; the recovery codes go with the last factor. Password and
    // recovery rows are not reachable here.
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &path(&fx, &format!("/mfa/credentials/{totp_id}")),
        Some(&fresh),
        None,
    )
    .await;
    assert_eq!(
        status, 403,
        "the single-factor token may not remove a factor"
    );
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &path(&fx, &format!("/mfa/credentials/{totp_id}")),
        Some(&strong),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let f = totp::factors_of(&fx.app.state, fx.tenant.id, fx.user_id)
        .await
        .unwrap();
    assert!(!f.totp && f.email_otp && f.recovery_codes == totp::RECOVERY_CODE_COUNT);
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &path(&fx, &format!("/mfa/credentials/{email_id}")),
        Some(&strong),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let f = totp::factors_of(&fx.app.state, fx.tenant.id, fx.user_id)
        .await
        .unwrap();
    assert!(!f.any() && f.recovery_codes == 0);
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &path(&fx, &format!("/mfa/credentials/{email_id}")),
        Some(&strong),
        None,
    )
    .await;
    assert_eq!(status, 404);
    let (status, _, _) = call(
        &fx.app,
        Method::POST,
        &path(&fx, "/mfa/recovery-codes"),
        Some(&fresh),
        None,
    )
    .await;
    assert_eq!(status, 400, "nothing to recover from");
}

#[tokio::test]
async fn a_user_only_ever_sees_their_own_devices_and_may_revoke_them() {
    let fx = fixture().await;
    let tid = fx.tenant.id;
    let bob = users::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewUser {
            username: "bob".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    for (user, ua) in [
        (fx.user_id, "Firefox"),
        (fx.user_id, "Safari"),
        (bob.id, "Chrome"),
    ] {
        trusted_devices::trust(&fx.app.state, &fx.tenant, user, None, Some(ua), None)
            .await
            .unwrap();
    }
    let alice = token(&fx, fx.user_id, Auth::default()).await;
    let (status, body, _) = call(
        &fx.app,
        Method::GET,
        &path(&fx, "/devices"),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let devices = body.as_array().unwrap();
    assert_eq!(devices.len(), 2);
    let bobs = trusted_devices::list(&fx.app.state, tid, bob.id)
        .await
        .unwrap();
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &path(&fx, &format!("/devices/{}", bobs[0].id)),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(status, 404, "another user's device is invisible");
    let first = devices[0]["id"].as_str().unwrap();
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &path(&fx, &format!("/devices/{first}")),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(status, 204);
    assert_eq!(
        trusted_devices::list(&fx.app.state, tid, fx.user_id)
            .await
            .unwrap()
            .len(),
        1
    );
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &path(&fx, "/devices"),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(status, 204);
    assert!(
        trusted_devices::list(&fx.app.state, tid, fx.user_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        trusted_devices::list(&fx.app.state, tid, bob.id)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn every_tenant_carries_the_account_client_and_audience() {
    let fx = fixture().await;
    let created = tenants::create(
        &fx.app.state,
        Actor::System,
        tenants::NewTenant {
            slug: format!("acct-{}", &Uuid::new_v4().simple().to_string()[..8]),
            display_name: "Account tenant".into(),
            settings: None,
        },
    )
    .await
    .unwrap();
    let client = clients::find_by_client_id(&fx.app.state, created.id, ACCOUNT_CLIENT_ID)
        .await
        .unwrap()
        .expect("account client");
    assert_eq!(client.allowed_audiences, vec![ACCOUNT_AUDIENCE.to_string()]);
    assert!(client.require_pkce);
    assert!(
        client
            .redirect_uris
            .iter()
            .any(|u| u.ends_with("/account/callback/"))
    );
}
