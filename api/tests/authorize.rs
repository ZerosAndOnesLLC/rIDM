mod common;

use common::TestApp;
use ridm_api::models::{ClientType, NewClient, NewUser, TokenEndpointAuthMethod};
use ridm_api::services::login_flows::{self, FlowStage};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::{clients, consents, tenants, users};
use ridm_core::events::Actor;
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Fx {
    app: TestApp,
    client_id: String,
    client_uuid: Uuid,
    user_id: Uuid,
}

async fn fixture(client_type: ClientType, require_consent: bool) -> Fx {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let created = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("web-app".into()),
            name: "Web".into(),
            client_type: Some(client_type),
            redirect_uris: vec![
                "https://app.example/cb".into(),
                "http://127.0.0.1/cb".into(),
            ],
            require_consent: Some(require_consent),
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
            ..Default::default()
        },
    )
    .await
    .unwrap();
    Fx {
        app,
        client_id: created.client.client_id,
        client_uuid: created.client.id,
        user_id: user.id,
    }
}

async fn login(fx: &Fx) -> String {
    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    let session = sessions::create(
        &fx.app.state,
        tenant.id,
        NewSession {
            user_id: fx.user_id,
            amr: vec!["pwd".into()],
            acr: None,
            ip: None,
            user_agent: None,
            policy: &tenant.settings.session,
        },
    )
    .await
    .unwrap();
    format!(
        "{}={}",
        sessions::cookie_name(&fx.app.state, &fx.app.tenant.slug),
        session.id
    )
}

fn params(fx: &Fx, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut p: Vec<(String, String)> = vec![
        ("response_type".into(), "code".into()),
        ("client_id".into(), fx.client_id.clone()),
        ("redirect_uri".into(), "https://app.example/cb".into()),
        ("scope".into(), "openid profile".into()),
        ("state".into(), "xyz".into()),
        ("code_challenge".into(), CHALLENGE.into()),
        ("code_challenge_method".into(), "S256".into()),
    ];
    for (k, v) in extra {
        p.retain(|(pk, _)| pk != k);
        if !v.is_empty() {
            p.push(((*k).into(), (*v).into()));
        }
    }
    p
}

async fn authorize(fx: &Fx, p: &[(String, String)], cookie: Option<&str>) -> reqwest::Response {
    let mut req = fx.app.http.get(fx.app.tenant_url("/authorize")).query(p);
    if let Some(c) = cookie {
        req = req.header("Cookie", c);
    }
    req.send().await.unwrap()
}

fn location(res: &reqwest::Response) -> url::Url {
    url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap()
}

fn query(u: &url::Url, key: &str) -> Option<String> {
    u.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

#[tokio::test]
async fn without_a_session_the_browser_is_sent_to_the_login_flow() {
    let fx = fixture(ClientType::Spa, true).await;
    let res = authorize(&fx, &params(&fx, &[]), None).await;
    assert_eq!(res.status(), 303);
    let loc = location(&res);
    assert!(loc.path().ends_with("/login/"), "{loc}");
    assert_eq!(
        query(&loc, "tenant").as_deref(),
        Some(fx.app.tenant.slug.as_str())
    );
    let flow_id: Uuid = query(&loc, "flow").unwrap().parse().unwrap();
    let flow = login_flows::get(&fx.app.state, fx.app.tenant.id, flow_id)
        .await
        .unwrap()
        .expect("flow stored");
    assert_eq!(flow.stage, FlowStage::Authenticate);
    assert_eq!(flow.request.client_public_id, fx.client_id);
    assert_eq!(flow.request.scopes, vec!["openid", "profile"]);
    assert_eq!(flow.request.state.as_deref(), Some("xyz"));
    assert_eq!(flow.request.code_challenge.as_deref(), Some(CHALLENGE));
    assert!(!flow.csrf.is_empty());
    assert_eq!(res.headers()["cache-control"], "no-store");

    // prompt=create goes to registration instead.
    let res = authorize(&fx, &params(&fx, &[("prompt", "create")]), None).await;
    assert!(location(&res).path().ends_with("/register/"));
}

#[tokio::test]
async fn with_a_session_a_code_is_issued_or_consent_is_requested() {
    let fx = fixture(ClientType::Spa, true).await;
    let cookie = login(&fx).await;
    let issuer = format!("{}/t/{}", fx.app.base_url, fx.app.tenant.slug);

    // Consent required first.
    let res = authorize(&fx, &params(&fx, &[]), Some(&cookie)).await;
    let loc = location(&res);
    assert!(loc.path().ends_with("/consent/"), "{loc}");
    let flow = login_flows::get(
        &fx.app.state,
        fx.app.tenant.id,
        query(&loc, "flow").unwrap().parse().unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(flow.stage, FlowStage::Consent);
    assert_eq!(flow.pending_scopes, vec!["openid", "profile"]);
    assert_eq!(flow.user_id, Some(fx.user_id));

    // Grant consent, then a code comes back to the redirect URI.
    consents::grant(
        &fx.app.state,
        fx.app.tenant.id,
        fx.user_id,
        fx.client_uuid,
        &["openid".into(), "profile".into()],
    )
    .await
    .unwrap();
    let res = authorize(&fx, &params(&fx, &[]), Some(&cookie)).await;
    assert_eq!(res.status(), 303);
    let loc = location(&res);
    assert_eq!(loc.origin().ascii_serialization(), "https://app.example");
    assert_eq!(loc.path(), "/cb");
    let code = query(&loc, "code").expect("code");
    assert!(code.len() >= 40);
    assert_eq!(query(&loc, "state").as_deref(), Some("xyz"));
    assert_eq!(query(&loc, "iss").as_deref(), Some(issuer.as_str()));
    assert_eq!(res.headers()["cache-control"], "no-store");

    // The code is stored (single use).
    let rec = ridm_api::services::auth_codes::consume(&fx.app.state, fx.app.tenant.id, &code)
        .await
        .unwrap()
        .expect("code record");
    assert_eq!(rec.user_id, fx.user_id);
    assert_eq!(rec.client_public_id, fx.client_id);
    assert_eq!(rec.redirect_uri, "https://app.example/cb");
    assert_eq!(rec.code_challenge.as_deref(), Some(CHALLENGE));
    assert!(
        ridm_api::services::auth_codes::consume(&fx.app.state, fx.app.tenant.id, &code)
            .await
            .unwrap()
            .is_none(),
        "single use"
    );

    // prompt=consent forces the consent screen again; prompt=login forces re-auth.
    let res = authorize(&fx, &params(&fx, &[("prompt", "consent")]), Some(&cookie)).await;
    assert!(location(&res).path().ends_with("/consent/"));
    let res = authorize(&fx, &params(&fx, &[("prompt", "login")]), Some(&cookie)).await;
    assert!(location(&res).path().ends_with("/login/"));
    // max_age=0 always re-authenticates; a large max_age does not.
    let res = authorize(&fx, &params(&fx, &[("max_age", "0")]), Some(&cookie)).await;
    assert!(location(&res).path().ends_with("/login/"));
    let res = authorize(&fx, &params(&fx, &[("max_age", "3600")]), Some(&cookie)).await;
    assert!(query(&location(&res), "code").is_some());
    // An MFA class the session does not satisfy → step-up straight to the
    // second factor; a class that is not an MFA one is voluntary.
    let res = authorize(
        &fx,
        &params(&fx, &[("acr_values", "urn:ridm:acr:mfa")]),
        Some(&cookie),
    )
    .await;
    assert!(location(&res).path().ends_with("/mfa/"));
    let res = authorize(
        &fx,
        &params(&fx, &[("acr_values", "urn:example:acr:gold")]),
        Some(&cookie),
    )
    .await;
    assert!(query(&location(&res), "code").is_some());

    // Fragment and form_post response modes.
    let res = authorize(
        &fx,
        &params(&fx, &[("response_mode", "fragment")]),
        Some(&cookie),
    )
    .await;
    let loc = location(&res);
    assert!(loc.query().is_none());
    assert!(loc.fragment().unwrap().contains("code="));
    let res = authorize(
        &fx,
        &params(&fx, &[("response_mode", "form_post")]),
        Some(&cookie),
    )
    .await;
    assert_eq!(res.status(), 200);
    assert!(
        res.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    let html = res.text().await.unwrap();
    assert!(html.contains("action=\"https://app.example/cb\""));
    assert!(html.contains("name=\"code\""));
    assert!(html.contains("name=\"state\" value=\"xyz\""));
}

#[tokio::test]
async fn first_party_clients_skip_consent_and_prompt_none_reports_requirements() {
    let fx = fixture(ClientType::Spa, false).await;
    let res = authorize(&fx, &params(&fx, &[("prompt", "none")]), None).await;
    let loc = location(&res);
    assert_eq!(loc.path(), "/cb");
    assert_eq!(query(&loc, "error").as_deref(), Some("login_required"));
    assert_eq!(query(&loc, "state").as_deref(), Some("xyz"));
    assert!(query(&loc, "iss").is_some());

    let cookie = login(&fx).await;
    let res = authorize(&fx, &params(&fx, &[("prompt", "none")]), Some(&cookie)).await;
    assert!(
        query(&location(&res), "code").is_some(),
        "no consent screen for first-party clients"
    );

    // consent_required with prompt=none for a client that requires consent.
    let strict = fixture(ClientType::Spa, true).await;
    let cookie = login(&strict).await;
    let res = authorize(
        &strict,
        &params(&strict, &[("prompt", "none")]),
        Some(&cookie),
    )
    .await;
    assert_eq!(
        query(&location(&res), "error").as_deref(),
        Some("consent_required")
    );
}

#[tokio::test]
async fn client_and_redirect_problems_never_redirect() {
    let fx = fixture(ClientType::Web, false).await;
    let page = |p: Vec<(String, String)>| {
        let fx = &fx;
        async move {
            let res = authorize(fx, &p, None).await;
            assert_eq!(res.status(), 400, "{p:?}");
            assert!(
                res.headers()["content-type"]
                    .to_str()
                    .unwrap()
                    .starts_with("text/html")
            );
            assert!(res.headers().get("location").is_none());
            res.text().await.unwrap()
        }
    };
    assert!(
        page(params(&fx, &[("client_id", "")]))
            .await
            .contains("client_id is required")
    );
    assert!(
        page(params(&fx, &[("client_id", "ghost")]))
            .await
            .contains("unknown client")
    );
    assert!(
        page(params(&fx, &[("redirect_uri", "")]))
            .await
            .contains("redirect_uri is required")
    );
    for bad in [
        "https://app.example/cb/",
        "https://app.example/cb?x=1",
        "https://app.example.evil/cb",
        "https://evil.example/?u=https://app.example/cb",
        "http://127.0.0.1:8080/cb", // port flexibility is for native clients only
        "javascript:alert(1)",
    ] {
        assert!(
            page(params(&fx, &[("redirect_uri", bad)]))
                .await
                .contains("not registered"),
            "{bad}"
        );
    }
    let mut dup = params(&fx, &[]);
    dup.push(("client_id".into(), fx.client_id.clone()));
    assert!(page(dup).await.contains("must not be repeated"));

    // Disabled client.
    clients::set_status(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        fx.client_uuid,
        ridm_api::models::ClientStatus::Disabled,
    )
    .await
    .unwrap();
    assert!(page(params(&fx, &[])).await.contains("disabled"));
}

#[tokio::test]
async fn other_problems_are_reported_to_the_client_with_state_and_iss() {
    let fx = fixture(ClientType::Spa, false).await;
    let cookie = login(&fx).await;
    let err = |p: Vec<(String, String)>| {
        let fx = &fx;
        let cookie = cookie.clone();
        async move {
            let res = authorize(fx, &p, Some(&cookie)).await;
            assert_eq!(res.status(), 303, "{p:?}");
            let loc = location(&res);
            assert_eq!(loc.path(), "/cb");
            assert_eq!(query(&loc, "state").as_deref(), Some("xyz"), "{p:?}");
            assert!(query(&loc, "iss").is_some());
            (
                query(&loc, "error").unwrap(),
                query(&loc, "error_description").unwrap_or_default(),
            )
        }
    };
    assert_eq!(
        err(params(&fx, &[("response_type", "token")])).await.0,
        "unsupported_response_type"
    );
    assert_eq!(
        err(params(&fx, &[("response_type", "")])).await.0,
        "invalid_request"
    );
    // An empty scope is given the default scopes (`openid` here); see
    // `a_request_without_scope_gets_the_default_scopes`.
    assert_eq!(
        err(params(&fx, &[("scope", "openid nope")])).await.0,
        "invalid_scope"
    );
    let (e, d) = err(params(
        &fx,
        &[("code_challenge", ""), ("code_challenge_method", "")],
    ))
    .await;
    assert_eq!(e, "invalid_request");
    assert!(d.contains("PKCE"), "{d}");
    assert!(
        err(params(&fx, &[("code_challenge", "")]))
            .await
            .1
            .contains("required with code_challenge_method")
    );
    assert!(
        err(params(&fx, &[("code_challenge_method", "plain")]))
            .await
            .1
            .contains("plain")
    );
    assert!(
        err(params(&fx, &[("code_challenge_method", "")]))
            .await
            .1
            .contains("S256")
    );
    assert!(
        err(params(&fx, &[("code_challenge", "short")]))
            .await
            .1
            .contains("malformed")
    );
    assert_eq!(
        err(params(&fx, &[("prompt", "none login")])).await.0,
        "invalid_request"
    );
    assert_eq!(
        err(params(&fx, &[("prompt", "banana")])).await.0,
        "invalid_request"
    );
    assert_eq!(
        err(params(&fx, &[("max_age", "-1")])).await.0,
        "invalid_request"
    );
    // A malformed request object is a client-side problem: shown, not redirected.
    let res = authorize(&fx, &params(&fx, &[("request", "eyJ...")]), Some(&cookie)).await;
    assert_eq!(res.status(), 400);
    assert!(res.text().await.unwrap().contains("invalid_request_object"));
    assert_eq!(
        err(params(&fx, &[("request_uri", "https://x")])).await.0,
        "request_uri_not_supported"
    );
    assert_eq!(
        err(params(&fx, &[("claims", "not json")])).await.0,
        "invalid_request"
    );
    assert_eq!(
        err(params(&fx, &[("claims", r#"{"bogus":{}}"#)])).await.0,
        "invalid_request"
    );
    assert_eq!(
        err(params(&fx, &[("resource", "https://unknown.api")]))
            .await
            .0,
        "invalid_target"
    );

    // Valid claims and a registered resource are accepted and carried into the code.
    let mut tx = ridm_api::db::tenant_tx(&fx.app.state.db, fx.app.tenant.id)
        .await
        .unwrap();
    ridm_api::repos::resource_servers::insert(
        &mut *tx,
        fx.app.tenant.id,
        Uuid::now_v7(),
        "https://api.example",
        "API",
        None,
        None,
        true,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let res = authorize(
        &fx,
        &params(
            &fx,
            &[
                ("resource", "https://api.example"),
                ("claims", r#"{"id_token":{"email":{"essential":true}}}"#),
            ],
        ),
        Some(&cookie),
    )
    .await;
    let code = query(&location(&res), "code").expect("code");
    let rec = ridm_api::services::auth_codes::consume(&fx.app.state, fx.app.tenant.id, &code)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rec.audiences, vec!["https://api.example"]);
    assert_eq!(rec.claims.unwrap()["id_token"]["email"]["essential"], true);
}

#[tokio::test]
async fn native_clients_may_vary_loopback_ports_and_confidential_clients_may_skip_pkce() {
    let fx = fixture(ClientType::Native, false).await;
    let cookie = login(&fx).await;
    let res = authorize(
        &fx,
        &params(&fx, &[("redirect_uri", "http://127.0.0.1:53211/cb")]),
        Some(&cookie),
    )
    .await;
    assert_eq!(res.status(), 303);
    let loc = location(&res);
    assert_eq!(loc.port(), Some(53211));
    assert!(query(&loc, "code").is_some());

    // A confidential client with require_pkce=false may omit PKCE; public clients never may.
    let web = fixture(ClientType::Web, false).await;
    let created = clients::create(
        &web.app.state,
        web.app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("legacy".into()),
            name: "legacy".into(),
            client_type: Some(ClientType::Web),
            redirect_uris: vec!["https://app.example/cb".into()],
            require_pkce: Some(false),
            require_consent: Some(false),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::ClientSecretPost),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let cookie = login(&web).await;
    let mut p = params(
        &web,
        &[("code_challenge", ""), ("code_challenge_method", "")],
    );
    p.retain(|(k, _)| k != "client_id");
    p.push(("client_id".into(), created.client.client_id.clone()));
    let res = authorize(&web, &p, Some(&cookie)).await;
    assert!(
        query(&location(&res), "code").is_some(),
        "{}",
        location(&res)
    );

    // POST form works the same as GET.
    let res = web
        .app
        .http
        .post(web.app.tenant_url("/authorize"))
        .form(&p)
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    assert!(query(&location(&res), "code").is_some());
    let res = web
        .app
        .http
        .post(web.app.tenant_url("/authorize"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 415);
}
