mod common;

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::TestApp;
use ridm_api::models::{ClientType, NewClient, NewUser};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::{clients, tenants, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Fx {
    app: TestApp,
    user_id: Uuid,
    cookie: String,
    session_id: Uuid,
}

async fn fixture() -> Fx {
    let app = TestApp::spawn().await;
    let user = users::create(
        &app.state,
        app.tenant.id,
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
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let s = sessions::create(
        &app.state,
        tenant.id,
        NewSession {
            user_id: user.id,
            amr: vec!["pwd".into()],
            acr: None,
            ip: None,
            user_agent: None,
            policy: &tenant.settings.session,
        },
    )
    .await
    .unwrap();
    let cookie = format!("{}={}", sessions::cookie_name(&app.state), s.id);
    Fx {
        app,
        user_id: user.id,
        cookie,
        session_id: s.id,
    }
}

/// Full code flow for `client_id`; returns the token response.
async fn login_and_get_tokens(fx: &Fx, client_id: &str, scope: &str) -> Value {
    let q = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", scope),
        ("nonce", "n"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&q)
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let code = loc
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| panic!("{loc}"));
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "https://app.example/cb"),
            ("code_verifier", VERIFIER),
            ("client_id", client_id),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    res.json().await.unwrap()
}

async fn public_client(fx: &Fx, id: &str, extra: NewClient) -> String {
    clients::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some(id.into()),
            name: id.into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            require_consent: Some(false),
            ..extra
        },
    )
    .await
    .unwrap()
    .client
    .client_id
}

#[tokio::test]
async fn userinfo_returns_claims_by_scope_and_rejects_bad_tokens() {
    let fx = fixture().await;
    let cid = public_client(&fx, "app", NewClient::default()).await;
    let tokens = login_and_get_tokens(&fx, &cid, "openid email").await;
    let at = tokens["access_token"].as_str().unwrap();

    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/userinfo"))
        .bearer_auth(at)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["cache-control"], "no-store");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["sub"], fx.user_id.to_string());
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["email_verified"], true);
    assert!(
        body.get("preferred_username").is_none(),
        "profile scope not granted"
    );

    // POST form works too.
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/userinfo"))
        .form(&[("access_token", at)])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // No token / garbage / id token instead of access token / token without openid.
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/userinfo"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    assert!(
        res.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .starts_with("Bearer")
    );
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/userinfo"))
        .bearer_auth("garbage")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    assert!(
        res.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("invalid_token")
    );
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/userinfo"))
        .bearer_auth(tokens["id_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let plain = login_and_get_tokens(&fx, &cid, "profile").await;
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/userinfo"))
        .bearer_auth(plain["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    assert!(
        res.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("insufficient_scope")
    );
}

#[tokio::test]
async fn introspection_and_revocation() {
    let fx = fixture().await;
    let cid = public_client(&fx, "app", NewClient::default()).await;
    let tokens = login_and_get_tokens(&fx, &cid, "openid").await;
    let at = tokens["access_token"].as_str().unwrap().to_string();
    let rt = tokens["refresh_token"].as_str().unwrap().to_string();

    // A confidential client that is an audience-less introspector of its own tokens is
    // the common case; here a separate resource server client introspects via basic auth.
    let rs = clients::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("rs".into()),
            name: "rs".into(),
            client_type: Some(ClientType::Machine),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let rs_secret = rs.client_secret.unwrap();
    let introspect = |token: &str| {
        let fx = &fx;
        let secret = rs_secret.clone();
        let token = token.to_string();
        async move {
            let res = fx
                .app
                .http
                .post(fx.app.tenant_url("/introspect"))
                .basic_auth("rs", Some(&*secret))
                .form(&[("token", token.as_str())])
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), 200);
            res.json::<Value>().await.unwrap()
        }
    };
    // The rs client is neither azp nor audience of the SPA's token → inactive (no leak).
    assert_eq!(introspect(&at).await["active"], false);
    // Make rs an allowed audience-holder by introspecting a token issued to itself.
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .basic_auth("rs", Some(&*rs_secret))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    let own: Value = res.json().await.unwrap();
    let own_at = own["access_token"].as_str().unwrap().to_string();
    let info = introspect(&own_at).await;
    assert_eq!(info["active"], true);
    assert_eq!(info["client_id"], "rs");
    assert_eq!(info["token_type"], "Bearer");
    assert!(info["exp"].is_number());
    assert_eq!(introspect("garbage").await, json!({"active": false}));
    assert_eq!(introspect("rt_nope").await, json!({"active": false}));

    // Public clients cannot introspect; a wrong secret is invalid_client.
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/introspect"))
        .form(&[("token", at.as_str()), ("client_id", cid.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/introspect"))
        .basic_auth("rs", Some("cs_wrong"))
        .form(&[("token", at.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    // Revocation by the owning (public) client: refresh token family and access token.
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/revoke"))
        .form(&[("token", rt.as_str()), ("client_id", cid.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt.as_str()),
            ("client_id", cid.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/userinfo"))
        .bearer_auth(&at)
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        200,
        "access token still valid before revocation"
    );
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/revoke"))
        .form(&[
            ("token", at.as_str()),
            ("client_id", "rs"),
            ("client_secret", &*rs_secret),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        401,
        "rs is registered for basic auth, not post"
    );
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/revoke"))
        .basic_auth("rs", Some(&*rs_secret))
        .form(&[("token", at.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/userinfo"))
        .bearer_auth(&at)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "another client cannot revoke it");
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/revoke"))
        .form(&[("token", at.as_str()), ("client_id", cid.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/userinfo"))
        .bearer_auth(&at)
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        401,
        "revoked access token is rejected before expiry"
    );
    // Unknown tokens are fine (RFC 7009).
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/revoke"))
        .form(&[("token", "whatever"), ("client_id", cid.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn rp_initiated_logout_with_hint_and_backchannel_notification() {
    let fx = fixture().await;
    // Local receiver for back-channel logout tokens.
    let received: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let sink = received.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/bc",
            axum::routing::post(move |body: String| {
                let sink = sink.clone();
                async move {
                    let token = body
                        .strip_prefix("logout_token=")
                        .unwrap_or(&body)
                        .to_string();
                    sink.lock().unwrap().push(urlencoding_decode(&token));
                    axum::http::StatusCode::OK
                }
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });
    let cid = public_client(
        &fx,
        "rp",
        NewClient {
            post_logout_redirect_uris: vec!["https://app.example/bye".into()],
            backchannel_logout_uri: Some(format!("http://127.0.0.1:{port}/bc")),
            frontchannel_logout_uri: Some("https://app.example/fc-logout".into()),
            ..Default::default()
        },
    )
    .await;
    let tokens = login_and_get_tokens(&fx, &cid, "openid").await;
    let id_token = tokens["id_token"].as_str().unwrap();
    let rt = tokens["refresh_token"].as_str().unwrap();

    // Unregistered post_logout_redirect_uri is refused (page, no redirect).
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/end_session"))
        .query(&[
            ("id_token_hint", id_token),
            ("post_logout_redirect_uri", "https://evil.example/"),
        ])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);

    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/end_session"))
        .query(&[
            ("id_token_hint", id_token),
            ("post_logout_redirect_uri", "https://app.example/bye"),
            ("state", "st"),
        ])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    // Front-channel URIs exist → an HTML page with the iframe, then a refresh to the RP.
    assert_eq!(res.status(), 200);
    // The page's policy must admit the relying party it frames; the API's
    // blanket `default-src 'none'` would block the logout altogether.
    let csp = res.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        csp.contains("frame-src https://app.example;"),
        "front-channel page CSP: {csp}"
    );
    let set_cookie = res.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(
        set_cookie.contains("Max-Age=0"),
        "session cookie cleared: {set_cookie}"
    );
    let html = res.text().await.unwrap();
    assert!(
        html.contains("https://app.example/fc-logout?iss="),
        "{html}"
    );
    assert!(html.contains(&format!("sid={}", fx.session_id)));
    assert!(html.contains("https://app.example/bye?state=st"));

    // Session and its refresh tokens are gone.
    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    assert!(
        sessions::get(
            &fx.app.state,
            tenant.id,
            fx.session_id,
            &tenant.settings.session
        )
        .await
        .unwrap()
        .is_none()
    );
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt),
            ("client_id", cid.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);

    // Back-channel logout token arrived and is well formed.
    let mut got = None;
    for _ in 0..50 {
        if let Some(t) = received.lock().unwrap().first().cloned() {
            got = Some(t);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let logout_token = got.expect("back-channel logout token delivered");
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(logout_token.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(header["typ"], "logout+jwt");
    let claims = ridm_api::services::tokens::verify(
        &fx.app.state,
        &tenant,
        &logout_token,
        &ridm_api::services::tokens::VerifyOptions {
            audience: Some(cid.clone()),
            typ: Some("logout+jwt".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(claims["sub"], fx.user_id.to_string());
    assert_eq!(claims["sid"], fx.session_id.to_string());
    assert!(claims["events"]["http://schemas.openid.net/event/backchannel-logout"].is_object());
    assert!(claims.get("nonce").is_none());
}

#[tokio::test]
async fn logout_without_hint_asks_for_confirmation() {
    let fx = fixture().await;
    let cid = public_client(
        &fx,
        "rp",
        NewClient {
            post_logout_redirect_uris: vec!["https://app.example/bye".into()],
            ..Default::default()
        },
    )
    .await;
    login_and_get_tokens(&fx, &cid, "openid").await;

    // No hint, but a session: UI confirmation flow.
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/end_session"))
        .query(&[
            ("client_id", cid.as_str()),
            ("post_logout_redirect_uri", "https://app.example/bye"),
            ("state", "s1"),
        ])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    assert!(loc.path().ends_with("/logout/"), "{loc}");
    let flow_id: Uuid = loc
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .unwrap()
        .1
        .parse()
        .unwrap();
    // The session is untouched until confirmed.
    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    assert!(
        sessions::get(
            &fx.app.state,
            tenant.id,
            fx.session_id,
            &tenant.settings.session
        )
        .await
        .unwrap()
        .is_some()
    );

    // Wrong csrf → 403; correct → logged out with redirect_to carrying state.
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/end_session/confirm"))
        .header("Cookie", &fx.cookie)
        .json(&json!({"flow": flow_id, "csrf": "nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    // The flow was consumed by the attempt; start another.
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/end_session"))
        .query(&[
            ("client_id", cid.as_str()),
            ("post_logout_redirect_uri", "https://app.example/bye"),
            ("state", "s1"),
        ])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let flow_id: Uuid = loc
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .unwrap()
        .1
        .parse()
        .unwrap();
    // The logout page reads the flow (client, csrf) without consuming it.
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url(&format!("/end_session/{flow_id}")))
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["cache-control"], "no-store");
    let view: Value = res.json().await.unwrap();
    assert_eq!(view["client"]["client_id"], cid);
    assert_eq!(view["signed_in"], true);
    assert_eq!(view["returns_to_client"], true);
    assert_eq!(view["dir"], "ltr");
    let csrf = view["csrf"].as_str().unwrap().to_string();
    assert!(!csrf.is_empty());
    // Still there after reading.
    assert_eq!(
        fx.app
            .http
            .get(fx.app.tenant_url(&format!("/end_session/{flow_id}")))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/end_session/confirm"))
        .header("Cookie", &fx.cookie)
        .json(&json!({"flow": flow_id, "csrf": csrf}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["logged_out"], true);
    assert_eq!(body["redirect_to"], "https://app.example/bye?state=s1");
    assert!(
        sessions::get(
            &fx.app.state,
            tenant.id,
            fx.session_id,
            &tenant.settings.session
        )
        .await
        .unwrap()
        .is_none()
    );

    // No session at all: immediate redirect to the UI signed-out page.
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/end_session"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    assert!(
        res.headers()["location"]
            .to_str()
            .unwrap()
            .contains("/logout/?")
    );
}

fn urlencoding_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("v={s}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}
