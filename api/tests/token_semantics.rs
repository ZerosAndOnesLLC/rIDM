//! What the stored configuration means for the tokens rIDM issues: opaque
//! access tokens, a resource server's signing algorithm and offline access,
//! a scope's released claims, default flag and resource-server binding, the
//! profile schema's `visible_in`, and how claim mappers meet the claims the
//! token service sets itself.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::TestApp;
use redis::AsyncCommands as _;
use ridm_api::cache::keys as cache_keys;
use ridm_api::models::{
    AccessTokenFormat, AttributeDef, ClientType, Exposure, NewClaimMapper, NewClient, NewGroup,
    NewResourceServer, NewRole, NewScope, NewUser, Principal, ProfileSchema, SigningAlg, grants,
};
use ridm_api::services::account_console::ACCOUNT_AUDIENCE;
use ridm_api::services::admin_access::{ADMIN_AUDIENCE, VIEWER_ROLE};
use ridm_api::services::admin_console::CONSOLE_CLIENT_ID;
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::tokens::{self, AccessTokenRequest, TokenClient, VerifyOptions};
use ridm_api::services::{
    claim_mappers, clients, groups, keys, profile_schema, resource_servers, roles, scopes, tenants,
    users,
};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT: &str = "https://app.example/cb";

struct Fx {
    app: TestApp,
    user_id: Uuid,
}

impl Fx {
    fn tid(&self) -> Uuid {
        self.app.tenant.id
    }
}

/// A tenant whose profile schema declares `department` (ID token and
/// userinfo) and `level` (access token), and a user holding both.
async fn fixture() -> Fx {
    let app = TestApp::spawn().await;
    profile_schema::set(
        &app.state,
        app.tenant.id,
        Actor::System,
        ProfileSchema {
            attributes: vec![
                AttributeDef {
                    name: "department".into(),
                    visible_in: vec![Exposure::IdToken, Exposure::Userinfo],
                    ..Default::default()
                },
                AttributeDef {
                    name: "level".into(),
                    visible_in: vec![Exposure::AccessToken],
                    ..Default::default()
                },
            ],
            allow_undeclared: false,
        },
    )
    .await
    .unwrap();
    let user = users::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewUser {
            username: "alice".into(),
            email: Some("alice@example.com".into()),
            email_verified: true,
            attributes: Some(json!({"department": "eng", "level": "7"})),
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

/// A browser client; returns its secret when it is confidential.
async fn web_client(fx: &Fx, id: &str, extra: NewClient) -> Option<String> {
    let created = clients::create(
        &fx.app.state,
        fx.tid(),
        Actor::System,
        NewClient {
            client_id: Some(id.into()),
            name: id.into(),
            client_type: Some(ClientType::Web),
            redirect_uris: vec![REDIRECT.into()],
            require_consent: Some(false),
            ..extra
        },
    )
    .await
    .unwrap();
    created.client_secret.map(|s| s.to_string())
}

async fn resource_server(fx: &Fx, identifier: &str, alg: Option<&str>, offline: bool) -> Uuid {
    resource_servers::create(
        &fx.app.state,
        fx.tid(),
        Actor::System,
        NewResourceServer {
            identifier: identifier.into(),
            name: identifier.into(),
            signing_alg: alg.map(str::to_string),
            allow_offline_access: Some(offline),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .id
}

async fn scope(fx: &Fx, name: &str, claims: &[&str], rs: Option<Uuid>, is_default: bool) {
    scopes::create(
        &fx.app.state,
        fx.tid(),
        Actor::System,
        NewScope {
            name: name.into(),
            description: None,
            claims: claims.iter().map(|c| c.to_string()).collect(),
            resource_server_id: rs,
            is_default,
        },
    )
    .await
    .unwrap();
}

/// A fresh SSO session for the user; returns its id and cookie.
async fn session(fx: &Fx) -> (Uuid, String) {
    let tenant = tenants::get(&fx.app.state, fx.tid()).await.unwrap();
    let s = sessions::create(
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
    let cookie = format!(
        "{}={}",
        sessions::cookie_name(&fx.app.state, &fx.app.tenant.slug),
        s.id
    );
    (s.id, cookie)
}

/// `/authorize` on `cookie`'s session; returns the code or the error.
async fn authorize(
    fx: &Fx,
    cookie: &str,
    client_id: &str,
    scope: &str,
    extra: &[(&str, &str)],
) -> Result<String, String> {
    let mut q = vec![
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", REDIRECT),
        ("scope", scope),
        ("state", "s"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    q.extend_from_slice(extra);
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&q)
        .header("Cookie", cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let get = |k: &str| {
        loc.query_pairs()
            .find(|(a, _)| a == k)
            .map(|(_, v)| v.into_owned())
    };
    match get("code") {
        Some(code) => Ok(code),
        None => Err(get("error").unwrap_or_else(|| loc.to_string())),
    }
}

async fn token(fx: &Fx, form: &[(&str, &str)], basic: Option<(&str, &str)>) -> (u16, Value) {
    let mut req = fx.app.http.post(fx.app.tenant_url("/token")).form(form);
    if let Some((id, secret)) = basic {
        req = req.basic_auth(id, Some(secret));
    }
    let res = req.send().await.unwrap();
    (res.status().as_u16(), res.json().await.unwrap())
}

/// Code flow end to end on a new session: the token response and the session.
async fn code_flow(
    fx: &Fx,
    client_id: &str,
    secret: Option<&str>,
    scope: &str,
    extra: &[(&str, &str)],
) -> (Value, Uuid) {
    let (sid, cookie) = session(fx).await;
    let code = authorize(fx, &cookie, client_id, scope, extra)
        .await
        .unwrap_or_else(|e| panic!("authorize: {e}"));
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
    ];
    if secret.is_none() {
        form.push(("client_id", client_id));
    }
    let (status, body) = token(fx, &form, secret.map(|s| (client_id, s))).await;
    assert_eq!(status, 200, "{body}");
    (body, sid)
}

fn part(jwt: &str, i: usize) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(i).unwrap())
            .unwrap(),
    )
    .unwrap()
}

fn scopes_of(v: &Value) -> Vec<String> {
    v.as_str()
        .unwrap_or_default()
        .split(' ')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

async fn userinfo(fx: &Fx, at: &str) -> (u16, Value) {
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/userinfo"))
        .bearer_auth(at)
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

async fn introspect(fx: &Fx, client: (&str, &str), t: &str) -> Value {
    fx.app
        .http
        .post(fx.app.tenant_url("/introspect"))
        .basic_auth(client.0, Some(client.1))
        .form(&[("token", t)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

// --- opaque access tokens ---------------------------------------------------

#[tokio::test]
async fn opaque_access_tokens_work_wherever_a_jwt_does() {
    let fx = fixture().await;
    let secret = web_client(
        &fx,
        "opaque-web",
        NewClient {
            access_token_format: Some(AccessTokenFormat::Opaque),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (body, _) = code_flow(&fx, "opaque-web", Some(&secret), "openid email", &[]).await;
    let at = body["access_token"].as_str().unwrap().to_string();
    assert!(at.starts_with("at_"), "{at}");
    assert_eq!(at.split('.').count(), 1, "no JWT structure");
    assert_eq!(body["token_type"], "Bearer");
    // The ID token's at_hash covers the opaque string like any other token.
    let idt = body["id_token"].as_str().unwrap();
    let alg: SigningAlg = part(idt, 0)["alg"].as_str().unwrap().parse().unwrap();
    assert_eq!(part(idt, 1)["at_hash"], tokens::half_hash(alg, &at));

    // Userinfo.
    let (status, info) = userinfo(&fx, &at).await;
    assert_eq!(status, 200, "{info}");
    assert_eq!(info["email"], "alice@example.com");
    assert_eq!(info["sub"], fx.user_id.to_string());

    // Introspection: what a resource server learns the token stands for.
    let active = introspect(&fx, ("opaque-web", &secret), &at).await;
    assert_eq!(active["active"], true, "{active}");
    assert_eq!(active["client_id"], "opaque-web");
    assert_eq!(active["sub"], fx.user_id.to_string());
    assert_eq!(scopes_of(&active["scope"]), ["openid", "email"]);
    assert!(
        active.get("typ").is_none(),
        "no JOSE type for an opaque token"
    );
    // Another client, not an audience, learns nothing.
    let other = web_client(&fx, "other-web", NewClient::default())
        .await
        .unwrap();
    assert_eq!(
        introspect(&fx, ("other-web", &other), &at).await["active"],
        false
    );

    // A refresh mints another opaque token.
    let (status, refreshed) = token(
        &fx,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", body["refresh_token"].as_str().unwrap()),
        ],
        Some(("opaque-web", &secret)),
    )
    .await;
    assert_eq!(status, 200, "{refreshed}");
    let at2 = refreshed["access_token"].as_str().unwrap();
    assert!(at2.starts_with("at_") && at2 != at);

    // Revocation ends it everywhere at once.
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/revoke"))
        .basic_auth("opaque-web", Some(&secret))
        .form(&[("token", at.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(userinfo(&fx, &at).await.0, 401);
    assert_eq!(
        introspect(&fx, ("opaque-web", &secret), &at).await["active"],
        false
    );
    // An unknown opaque-shaped token is simply inactive.
    assert_eq!(
        introspect(&fx, ("opaque-web", &secret), "at_nope").await["active"],
        false
    );
    assert_eq!(userinfo(&fx, "at_nope").await.0, 401);
}

/// Issue an access token the way the token endpoint does, in `format`.
async fn direct_token(fx: &Fx, user_id: Uuid, audience: &str, format: AccessTokenFormat) -> String {
    let tenant = tenants::get(&fx.app.state, fx.tid()).await.unwrap();
    let user = users::get(&fx.app.state, fx.tid(), user_id).await.unwrap();
    let role_list = roles::effective_roles(&fx.app.state, fx.tid(), user_id, None)
        .await
        .unwrap();
    let client = TokenClient {
        access_token_format: format,
        ..TokenClient::public("direct")
    };
    tokens::issue_access_token(
        &fx.app.state,
        AccessTokenRequest {
            tenant: &tenant,
            client: &client,
            user: Some(&user),
            scopes: &["openid".into()],
            audiences: &[audience.to_string()],
            roles: &role_list,
            groups: &[],
            session_id: None,
            auth_time: None,
            amr: &["pwd".into()],
            acr: None,
            cnf_jkt: None,
            act: None,
        },
    )
    .await
    .unwrap()
    .token
}

#[tokio::test]
async fn the_account_and_admin_apis_accept_opaque_tokens() {
    let fx = fixture().await;
    // Account API.
    let at = direct_token(&fx, fx.user_id, ACCOUNT_AUDIENCE, AccessTokenFormat::Opaque).await;
    assert!(at.starts_with("at_"));
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/account/me"))
        .bearer_auth(&at)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());

    // Admin API, for a viewer.
    let viewer = common::admin::user_with_role(&fx.app, fx.tid(), Some(VIEWER_ROLE)).await;
    let at = direct_token(&fx, viewer, ADMIN_AUDIENCE, AccessTokenFormat::Opaque).await;
    let path = format!("/admin/tenants/{}/clients", fx.app.tenant.slug);
    let res = fx
        .app
        .http
        .get(fx.app.url(&path))
        .bearer_auth(&at)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    // Its audience still matters: an account token is no admin token.
    let account = direct_token(&fx, viewer, ACCOUNT_AUDIENCE, AccessTokenFormat::Opaque).await;
    let res = fx
        .app
        .http
        .get(fx.app.url(&path))
        .bearer_auth(&account)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    // The consoles' own clients stay on JWTs.
    let refused = clients::resolve(
        fx.tid(),
        NewClient {
            client_id: Some(CONSOLE_CLIENT_ID.into()),
            name: "console".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec![REDIRECT.into()],
            access_token_format: Some(AccessTokenFormat::Opaque),
            ..Default::default()
        },
    );
    assert!(refused.is_err());
}

#[tokio::test]
async fn an_opaque_token_can_be_exchanged_but_not_as_a_jwt() {
    let fx = fixture().await;
    let api = "https://api.example";
    resource_server(&fx, api, None, true).await;
    let subject = direct_token(&fx, fx.user_id, "subject-app", AccessTokenFormat::Opaque).await;
    let created = clients::create(
        &fx.app.state,
        fx.tid(),
        Actor::System,
        NewClient {
            client_id: Some("exchanger".into()),
            name: "exchanger".into(),
            client_type: Some(ClientType::Machine),
            allowed_grants: Some(vec![grants::TOKEN_EXCHANGE.into()]),
            allowed_scopes: Some(vec!["openid".into()]),
            allowed_audiences: vec![api.into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let secret = created.client_secret.unwrap().to_string();
    let exchange = |kind: &'static str| {
        let fx = &fx;
        let subject = subject.clone();
        let secret = secret.clone();
        async move {
            token(
                fx,
                &[
                    ("grant_type", grants::TOKEN_EXCHANGE),
                    ("subject_token", subject.as_str()),
                    ("subject_token_type", kind),
                    ("resource", api),
                ],
                Some(("exchanger", &secret)),
            )
            .await
        }
    };
    let (status, body) = exchange("urn:ietf:params:oauth:token-type:access_token").await;
    assert_eq!(status, 200, "{body}");
    let exchanged = body["access_token"].as_str().unwrap();
    assert_eq!(part(exchanged, 1)["sub"], fx.user_id.to_string());
    assert_eq!(part(exchanged, 1)["aud"], api);
    // An opaque token is not a JWT.
    let (status, body) = exchange("urn:ietf:params:oauth:token-type:jwt").await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_request");
}

// --- resource server signing algorithm ------------------------------------------

#[tokio::test]
async fn a_resource_servers_algorithm_signs_its_tokens() {
    let fx = fixture().await;
    let es = "https://es.example";
    let ed = "https://ed.example";
    let plain = "https://plain.example";
    resource_server(&fx, es, Some("ES256"), true).await;
    // Saving the setting made sure a key of that algorithm exists.
    let es_key = keys::active(&fx.app.state, fx.tid(), SigningAlg::ES256)
        .await
        .unwrap()
        .expect("an ES256 key");
    resource_server(&fx, ed, Some("EdDSA"), true).await;
    resource_server(&fx, plain, None, true).await;
    let created = clients::create(
        &fx.app.state,
        fx.tid(),
        Actor::System,
        NewClient {
            client_id: Some("m2m".into()),
            name: "m2m".into(),
            client_type: Some(ClientType::Machine),
            allowed_audiences: vec![es.into(), ed.into(), plain.into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let secret = created.client_secret.unwrap().to_string();
    let cc = |resources: Vec<&'static str>| {
        let fx = &fx;
        let secret = secret.clone();
        async move {
            let mut form = vec![("grant_type", "client_credentials")];
            form.extend(resources.into_iter().map(|r| ("resource", r)));
            token(fx, &form, Some(("m2m", &secret))).await
        }
    };

    let (status, body) = cc(vec![es]).await;
    assert_eq!(status, 200, "{body}");
    let at = body["access_token"].as_str().unwrap();
    assert_eq!(part(at, 0)["alg"], "ES256");
    assert_eq!(part(at, 0)["kid"], es_key.kid);
    let tenant = tenants::get(&fx.app.state, fx.tid()).await.unwrap();
    tokens::verify_access(&fx.app.state, &tenant, at, &VerifyOptions::default())
        .await
        .expect("verifies against the published keys");

    // A server that names none, alone or next to one that does.
    let (_, body) = cc(vec![plain]).await;
    assert_eq!(
        part(body["access_token"].as_str().unwrap(), 0)["alg"],
        tenant.settings.keys.default_alg.as_str()
    );
    let (status, body) = cc(vec![plain, es]).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        part(body["access_token"].as_str().unwrap(), 0)["alg"],
        "ES256"
    );

    // Two that disagree cannot share a token.
    let (status, body) = cc(vec![es, ed]).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_target");

    // Every algorithm rIDM signs with may be named; nothing else.
    let rs = resource_server(&fx, "https://rs384.example", Some("RS384"), true).await;
    let err = resource_servers::update(
        &fx.app.state,
        fx.tid(),
        Actor::System,
        rs,
        ridm_api::models::ResourceServerUpdate {
            signing_alg: Some(Some("HS256".into())),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, ridm_api::error::AppError::BadRequest(m) if m.contains("unsupported signing_alg")),
        "{err}"
    );
}

// --- offline access ---------------------------------------------------------------

#[tokio::test]
async fn offline_access_outlives_the_session_and_only_where_allowed() {
    let fx = fixture().await;
    let offline_api = "https://offline.example";
    let online_api = "https://online.example";
    resource_server(&fx, offline_api, None, true).await;
    resource_server(&fx, online_api, None, false).await;
    let secret = web_client(
        &fx,
        "web",
        NewClient {
            allowed_audiences: vec![offline_api.into(), online_api.into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let refresh = |rt: String| {
        let fx = &fx;
        let secret = secret.clone();
        async move {
            token(
                fx,
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", rt.as_str()),
                ],
                Some(("web", &secret)),
            )
            .await
        }
    };
    let end_session_quietly = |sid: Uuid| {
        let fx = &fx;
        async move {
            // The session expires (its entry is gone) without a sign-out.
            let mut conn = fx.app.state.redis.get().await.unwrap();
            let _: () = conn
                .del(cache_keys::sso_session(fx.tid(), sid))
                .await
                .unwrap();
        }
    };

    // Allowed: granted, and the refresh token survives the session's end.
    let (body, sid) = code_flow(
        &fx,
        "web",
        Some(&secret),
        "openid offline_access",
        &[("resource", offline_api)],
    )
    .await;
    assert_eq!(scopes_of(&body["scope"]), ["openid", "offline_access"]);
    end_session_quietly(sid).await;
    let (status, refreshed) = refresh(body["refresh_token"].as_str().unwrap().into()).await;
    assert_eq!(status, 200, "{refreshed}");
    assert_eq!(scopes_of(&refreshed["scope"]), ["openid", "offline_access"]);

    // Not allowed by the audience: dropped; the refresh token is still
    // issued, but lives only as long as the session.
    let (body, sid) = code_flow(
        &fx,
        "web",
        Some(&secret),
        "openid offline_access",
        &[("resource", online_api)],
    )
    .await;
    assert_eq!(scopes_of(&body["scope"]), ["openid"]);
    let rt = body["refresh_token"].as_str().unwrap().to_string();
    let (status, next) = refresh(rt).await;
    assert_eq!(status, 200, "a live session refreshes: {next}");
    end_session_quietly(sid).await;
    let (status, refused) = refresh(next["refresh_token"].as_str().unwrap().into()).await;
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"], "invalid_grant");
    // Both audiences at once: one refusing is enough to drop it.
    let (body, _) = code_flow(
        &fx,
        "web",
        Some(&secret),
        "openid offline_access",
        &[("resource", offline_api), ("resource", online_api)],
    )
    .await;
    assert_eq!(scopes_of(&body["scope"]), ["openid"]);
}

// --- scopes -----------------------------------------------------------------------

#[tokio::test]
async fn a_scope_releases_its_claims_and_defaults_fill_an_empty_request() {
    let fx = fixture().await;
    scope(&fx, "hr", &["department", "username"], None, true).await;
    let secret = web_client(
        &fx,
        "web",
        NewClient {
            allowed_scopes: Some(vec!["openid".into(), "email".into(), "hr".into()]),
            id_token_scope_claims: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let (body, _) = code_flow(&fx, "web", Some(&secret), "openid hr", &[]).await;
    let (status, info) = userinfo(&fx, body["access_token"].as_str().unwrap()).await;
    assert_eq!(status, 200, "{info}");
    assert_eq!(info["username"], "alice");
    assert_eq!(info["department"], "eng");
    assert!(info.get("email").is_none(), "email was not granted");
    // This client asked for scope claims in the ID token as well.
    let id = part(body["id_token"].as_str().unwrap(), 1);
    assert_eq!(id["username"], "alice");

    // No scope at all: the defaults this client may hold (openid, hr).
    let (body, _) = code_flow(&fx, "web", Some(&secret), "", &[]).await;
    let mut granted = scopes_of(&body["scope"]);
    granted.sort();
    assert_eq!(granted, ["hr", "openid"]);
}

#[tokio::test]
async fn a_bound_scope_targets_its_resource_server_and_needs_it() {
    let fx = fixture().await;
    let orders = "https://orders.example";
    let billing = "https://billing.example";
    let orders_id = resource_server(&fx, orders, None, true).await;
    resource_server(&fx, billing, None, true).await;
    scope(&fx, "orders:read", &[], Some(orders_id), false).await;
    let everything = Some(vec!["openid".into(), "orders:read".into()]);
    // An unrestricted client.
    let secret = web_client(
        &fx,
        "web",
        NewClient {
            allowed_scopes: everything.clone(),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Requesting the scope targets the orders API.
    let (body, _) = code_flow(&fx, "web", Some(&secret), "openid orders:read", &[]).await;
    let claims = part(body["access_token"].as_str().unwrap(), 1);
    assert_eq!(claims["aud"], orders, "{claims}");
    assert_eq!(scopes_of(&claims["scope"]), ["openid", "orders:read"]);

    // Named next to another resource, it joins it; narrowing the refresh to
    // the other one drops the scope with its audience.
    let (body, _) = code_flow(
        &fx,
        "web",
        Some(&secret),
        "openid orders:read",
        &[("resource", billing)],
    )
    .await;
    assert_eq!(
        part(body["access_token"].as_str().unwrap(), 1)["aud"],
        json!([billing, orders])
    );
    let (status, narrowed) = token(
        &fx,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", body["refresh_token"].as_str().unwrap()),
            ("resource", billing),
        ],
        Some(("web", &secret)),
    )
    .await;
    assert_eq!(status, 200, "{narrowed}");
    assert_eq!(scopes_of(&narrowed["scope"]), ["openid"]);
    let claims = part(narrowed["access_token"].as_str().unwrap(), 1);
    assert_eq!(claims["aud"], billing);
    assert_eq!(scopes_of(&claims["scope"]), ["openid"]);

    // A client that may not target the orders API may not ask for it.
    web_client(
        &fx,
        "billing-only",
        NewClient {
            allowed_scopes: everything,
            allowed_audiences: vec![billing.into()],
            ..Default::default()
        },
    )
    .await;
    let (_, cookie) = session(&fx).await;
    let err = authorize(&fx, &cookie, "billing-only", "openid orders:read", &[])
        .await
        .unwrap_err();
    assert_eq!(err, "invalid_scope");
}

// --- profile schema -----------------------------------------------------------------

#[tokio::test]
async fn profile_attributes_appear_where_the_schema_says() {
    let fx = fixture().await;
    let secret = web_client(&fx, "web", NewClient::default()).await.unwrap();
    let (body, _) = code_flow(&fx, "web", Some(&secret), "openid", &[]).await;
    let at = body["access_token"].as_str().unwrap();
    let access = part(at, 1);
    let id = part(body["id_token"].as_str().unwrap(), 1);
    let (_, info) = userinfo(&fx, at).await;
    // `department`: ID token and userinfo; `level`: access token.
    assert_eq!(id["department"], "eng");
    assert_eq!(info["department"], "eng");
    assert!(access.get("department").is_none());
    assert_eq!(access["level"], "7");
    assert!(id.get("level").is_none() && info.get("level").is_none());
}

// --- claim mappers ------------------------------------------------------------------

#[tokio::test]
async fn roles_and_groups_mappers_reshape_the_built_in_claims() {
    let fx = fixture().await;
    let secret = web_client(&fx, "web", NewClient::default()).await.unwrap();
    web_client(&fx, "other", NewClient::default()).await;
    let web = clients::find_by_client_id(&fx.app.state, fx.tid(), "web")
        .await
        .unwrap()
        .unwrap();
    let other = clients::find_by_client_id(&fx.app.state, fx.tid(), "other")
        .await
        .unwrap()
        .unwrap();
    for (name, client) in [
        ("editor", None),
        ("web-admin", Some(web.id)),
        ("auditor", Some(other.id)),
    ] {
        let r = roles::create(
            &fx.app.state,
            fx.tid(),
            Actor::System,
            NewRole {
                name: name.into(),
                client_id: client,
                description: None,
            },
        )
        .await
        .unwrap();
        roles::assign(
            &fx.app.state,
            fx.tid(),
            Actor::System,
            r.id,
            Principal::User { id: fx.user_id },
        )
        .await
        .unwrap();
    }
    let staff = groups::create(
        &fx.app.state,
        fx.tid(),
        Actor::System,
        NewGroup {
            name: "staff".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let eng = groups::create(
        &fx.app.state,
        fx.tid(),
        Actor::System,
        NewGroup {
            name: "eng".into(),
            parent_id: Some(staff.id),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    groups::add_member(&fx.app.state, fx.tid(), Actor::System, eng.id, fx.user_id)
        .await
        .unwrap();

    // Without mappers: every role, bare group names.
    let (body, _) = code_flow(&fx, "web", Some(&secret), "openid", &[]).await;
    let claims = part(body["access_token"].as_str().unwrap(), 1);
    let mut all: Vec<String> = serde_json::from_value(claims["roles"].clone()).unwrap();
    all.sort();
    assert_eq!(all, ["auditor", "editor", "web-admin"]);

    for (name, config) in [
        (
            "client-roles",
            json!({"type": "roles", "claim": "roles", "client_id": "web", "include_in": ["access"]}),
        ),
        (
            "group-paths",
            json!({"type": "groups", "claim": "groups", "full_path": true, "include_in": ["access"]}),
        ),
    ] {
        claim_mappers::create(
            &fx.app.state,
            fx.tid(),
            Actor::System,
            NewClaimMapper {
                name: name.into(),
                client_id: None,
                config,
            },
        )
        .await
        .unwrap();
    }
    // With them, the mapper output stands: this client's roles only, and
    // group paths.
    let (body, _) = code_flow(&fx, "web", Some(&secret), "openid", &[]).await;
    let claims = part(body["access_token"].as_str().unwrap(), 1);
    assert_eq!(claims["roles"], json!(["web-admin"]), "{claims}");
    assert_eq!(claims["groups"], json!(["staff", "staff/eng"]), "{claims}");

    // Any other mapper aimed at those claims (or `permissions`) is refused.
    for claim in ["roles", "groups", "permissions", "cnf"] {
        let err = claim_mappers::create(
            &fx.app.state,
            fx.tid(),
            Actor::System,
            NewClaimMapper {
                name: format!("forge-{claim}"),
                client_id: None,
                config: json!({"type": "hardcoded", "claim": claim, "value": ["admin"], "include_in": ["access"]}),
            },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ridm_api::error::AppError::BadRequest(_)),
            "{claim}: {err}"
        );
    }
    // A user attribute mapper reads top-level fields.
    claim_mappers::create(
        &fx.app.state,
        fx.tid(),
        Actor::System,
        NewClaimMapper {
            name: "mail".into(),
            client_id: None,
            config: json!({"type": "user_attribute", "attribute": "email", "claim": "mail", "include_in": ["access"]}),
        },
    )
    .await
    .unwrap();
    let (body, _) = code_flow(&fx, "web", Some(&secret), "openid", &[]).await;
    assert_eq!(
        part(body["access_token"].as_str().unwrap(), 1)["mail"],
        "alice@example.com"
    );
}
