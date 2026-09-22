//! Security suite: named negative cases. Every finding from reviews, fuzzing,
//! conformance runs or external reports gets a regression test here.

#[path = "../common/mod.rs"]
mod common;

mod broker_binding;
mod bulk_import;
mod custom_domains;
mod kerberos;
mod ldap;
mod legacy_hash_cost;
mod mfa_policy;
mod org_admin;
mod outbound;
mod resource_indicators;
mod saml_upstream;
mod scim_membership;
mod session_cookies;
mod session_revocation;
mod support;
mod token_claims;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::TestApp;
use ridm_api::models::{ClientType, IpRuleAction, NewClient, NewIpRule, NewUser};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::{clients, ip_rules, tenants, users};
use ridm_core::events::Actor;
use serde_json::Value;
use uuid::Uuid;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Fx {
    app: TestApp,
    cookie: String,
}

async fn fixture() -> Fx {
    let app = TestApp::spawn().await;
    let user = users::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewUser {
            username: "alice".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    clients::create(
        &app.state,
        app.tenant.id,
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
    let cookie = format!(
        "{}={}",
        sessions::cookie_name(&app.state, &app.tenant.slug),
        s.id
    );
    Fx { app, cookie }
}

async fn code_for(fx: &Fx, nonce: &str) -> String {
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid"),
            ("nonce", nonce),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    loc.query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
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

/// Every endpoint the discovery document advertises must be routed.
#[tokio::test]
async fn discovery_endpoints_are_all_served() {
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
    for (k, v) in doc.as_object().unwrap() {
        if !(k.ends_with("_endpoint") || k == "jwks_uri") {
            continue;
        }
        let url = v.as_str().unwrap();
        let get = fx.app.http.get(url).send().await.unwrap().status().as_u16();
        let post = fx
            .app
            .http
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body("")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();
        assert!(
            get != 404 || post != 404,
            "{k} = {url} is advertised but unrouted (GET {get}, POST {post})"
        );
        assert!(
            !(get == 405 && post == 405),
            "{k} = {url} accepts neither GET nor POST"
        );
    }
}

#[tokio::test]
async fn nonce_is_bound_to_the_authorization_request() {
    let fx = fixture().await;
    let code_a = code_for(&fx, "nonce-A").await;
    let code_b = code_for(&fx, "nonce-B").await;
    let exchange = |code: String| {
        let fx = &fx;
        async move {
            let res = fx
                .app
                .http
                .post(fx.app.tenant_url("/token"))
                .form(&[
                    ("grant_type", "authorization_code"),
                    ("code", code.as_str()),
                    ("redirect_uri", "https://app.example/cb"),
                    ("code_verifier", VERIFIER),
                    ("client_id", "spa"),
                ])
                .send()
                .await
                .unwrap();
            res.json::<Value>().await.unwrap()
        }
    };
    let a = exchange(code_a).await;
    let b = exchange(code_b).await;
    assert_eq!(payload(a["id_token"].as_str().unwrap())["nonce"], "nonce-A");
    assert_eq!(payload(b["id_token"].as_str().unwrap())["nonce"], "nonce-B");
    // Without a nonce in the request, no nonce appears (never a stale one).
    let code = {
        let res = fx
            .app
            .http
            .get(fx.app.tenant_url("/authorize"))
            .query(&[
                ("response_type", "code"),
                ("client_id", "spa"),
                ("redirect_uri", "https://app.example/cb"),
                ("scope", "openid"),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
            ])
            .header("Cookie", &fx.cookie)
            .send()
            .await
            .unwrap();
        let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
        loc.query_pairs()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.into_owned())
            .unwrap()
    };
    let c = exchange(code).await;
    assert!(
        payload(c["id_token"].as_str().unwrap())
            .get("nonce")
            .is_none()
    );
}

#[tokio::test]
async fn id_token_hint_from_another_tenant_is_rejected() {
    let fx = fixture().await;
    let code = code_for(&fx, "n").await;
    let tokens: Value = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "https://app.example/cb"),
            ("code_verifier", VERIFIER),
            ("client_id", "spa"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let idt = tokens["id_token"].as_str().unwrap();
    let other = common::create_tenant(&fx.app.state.db).await;
    let res = fx
        .app
        .http
        .get(fx.app.url(&format!("/t/{}/end_session", other.slug)))
        .query(&[("id_token_hint", idt)])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    // ... and the access token is useless at the other tenant's userinfo.
    let res = fx
        .app
        .http
        .get(fx.app.url(&format!("/t/{}/userinfo", other.slug)))
        .bearer_auth(tokens["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn code_bound_to_pkce_and_redirect_cannot_be_downgraded() {
    let fx = fixture().await;
    // A public client can never opt out of PKCE at /authorize.
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid"),
        ])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    assert_eq!(
        loc.query_pairs().find(|(k, _)| k == "error").unwrap().1,
        "invalid_request"
    );
    // plain method is refused even though RFC 7636 allows it.
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid"),
            ("code_challenge", VERIFIER),
            ("code_challenge_method", "plain"),
        ])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    assert_eq!(
        loc.query_pairs().find(|(k, _)| k == "error").unwrap().1,
        "invalid_request"
    );
    // The verifier itself presented as a challenge (plain-style) does not verify under S256.
    let code = code_for(&fx, "n").await;
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "https://app.example/cb"),
            ("code_verifier", CHALLENGE),
            ("client_id", "spa"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn open_redirect_and_injection_attempts_are_refused() {
    let fx = fixture().await;
    for redirect in [
        "https://app.example/cb/../admin",
        "https://app.example/cb%2F..%2Fadmin",
        "https://app.example@evil.example/cb",
        "https://evil.example/cb#https://app.example/cb",
        "https://app.example:443/cb",
        "https://APP.example/cb",
        "//app.example/cb",
        "data:text/html,x",
    ] {
        let res = fx
            .app
            .http
            .get(fx.app.tenant_url("/authorize"))
            .query(&[
                ("response_type", "code"),
                ("client_id", "spa"),
                ("redirect_uri", redirect),
                ("scope", "openid"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400, "{redirect}");
        assert!(
            res.headers().get("location").is_none(),
            "{redirect} must not redirect"
        );
    }
    // Error descriptions are HTML-escaped on the error page.
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("client_id", "<script>alert(1)</script>"),
            ("redirect_uri", "https://app.example/cb"),
        ])
        .send()
        .await
        .unwrap();
    let html = res.text().await.unwrap();
    assert!(!html.contains("<script>"));
}

/// Phase 9.12 review finding. The request guard read the tenant from the raw
/// URI path while the handlers read axum's percent-decoded path parameter, so
/// `/t/%61cme/...` reached the tenant with its IP rules and rate-limit buckets
/// skipped. A slug is `[a-z0-9-]` and never needs escaping, so anything the
/// guard cannot read as a slug is refused instead of passed on.
#[tokio::test]
async fn an_escaped_tenant_slug_cannot_dodge_the_guard() {
    let app = TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        config.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
        state.config = std::sync::Arc::new(config);
    })
    .await;
    ip_rules::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewIpRule {
            client_id: None,
            action: Some(IpRuleAction::Deny),
            cidr: "198.51.100.0/24".into(),
            description: None,
        },
    )
    .await
    .unwrap();

    let slug = &app.tenant.slug;
    // The escape spells the same slug: the first byte, percent-encoded.
    let first = slug.as_bytes()[0];
    let escaped = format!("%{first:02x}{}", &slug[1..]);
    let url = |s: &str| format!("{}/t/{}/flows/{}", app.base_url, s, Uuid::new_v4());

    let refused = app
        .http
        .get(url(slug))
        .header("x-forwarded-for", "198.51.100.7")
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403, "the rule refuses the plain slug");

    let escaped_res = app
        .http
        .get(url(&escaped))
        .header("x-forwarded-for", "198.51.100.7")
        .send()
        .await
        .unwrap();
    assert_ne!(
        escaped_res.status(),
        200,
        "an escaped slug must not reach the tenant past its IP rules"
    );
    assert!(
        escaped_res.status() == 403 || escaped_res.status() == 404,
        "unexpected status {} for an escaped slug",
        escaped_res.status()
    );
}

/// Phase 9.12 review finding. The client address came from the leftmost
/// `X-Forwarded-For` entry, which is whatever the caller sent when the proxy
/// appends rather than overwrites (an AWS load balancer, nginx's
/// `$proxy_add_x_forwarded_for`). The chain is now read from the right, past
/// our own proxies, so a caller cannot choose the address a rule matches.
#[tokio::test]
async fn a_forged_forwarded_entry_cannot_choose_the_client_address() {
    let app = TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        config.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
        state.config = std::sync::Arc::new(config);
    })
    .await;
    // The tenant admits its office range only.
    ip_rules::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewIpRule {
            client_id: None,
            action: Some(IpRuleAction::Allow),
            cidr: "203.0.113.0/24".into(),
            description: None,
        },
    )
    .await
    .unwrap();
    let flow = |ip: &str| {
        let app = &app;
        let value = ip.to_string();
        async move {
            app.http
                .get(app.tenant_url(&format!("/flows/{}", Uuid::new_v4())))
                .header("x-forwarded-for", value)
                .send()
                .await
                .unwrap()
                .status()
        }
    };

    // The office address is admitted; an outside one is not.
    assert_ne!(flow("203.0.113.9").await, 403);
    assert_eq!(flow("198.51.100.7").await, 403);

    // The attacker prepends the office address; the proxy appends their real
    // one. The rightmost untrusted entry is what counts, so the rule holds.
    assert_eq!(
        flow("203.0.113.9, 198.51.100.7").await,
        403,
        "a forged leftmost entry must not pass the allow list"
    );
    // A chain ending in our own proxy still reports the address before it.
    assert_eq!(flow("198.51.100.7, 127.0.0.1").await, 403);
    assert_ne!(flow("203.0.113.9, 127.0.0.1").await, 403);
}
