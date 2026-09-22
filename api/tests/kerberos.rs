//! Phase 13.4: Kerberos / SPNEGO desktop sign-in. A miniature KDC
//! (`ridm_api::kerberos::testing::Kdc`) holds the service key and issues
//! the AP-REQs a browser would send; the login flow's `/kerberos` step
//! challenges, accepts the ticket, answers with the mutual-authentication
//! token and signs the principal in: a local account by name, a new
//! account, or a directory user through an LDAP provider (a real OpenLDAP,
//! `common::ldap`). The interoperability test against MIT Kerberos is
//! `kerberos_mit.rs`.
#![cfg(feature = "kerberos")]

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use common::TestApp;
use common::admin::{admin_token, call};
use common::ldap::{self as dir, ADMIN_DN, ADMIN_PASSWORD};
use reqwest::Method;
use reqwest::header::HeaderMap;
use ridm_api::kerberos::testing::{Kdc, verify_ap_rep};
use ridm_api::kerberos::{KeytabEntry, Principal, spnego, write_keytab};
use ridm_api::models::{ClientType, NewClient, NewUser, UserStatus, UserUpdate};
use ridm_api::services::admin_access::OWNER_ROLE;
use ridm_api::services::{broker, clients, tenant_config, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use zeroize::Zeroizing;

const SPN: &str = "HTTP/sso.example.com@EXAMPLE.COM";
const ALIAS: &str = "desktop";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Fx {
    app: TestApp,
    token: String,
    kdc: Kdc,
}

impl Fx {
    fn base(&self) -> String {
        format!("/admin/tenants/{}/identity-providers", self.app.tenant.slug)
    }
}

async fn fixture() -> Fx {
    let app = TestApp::spawn().await;
    clients::create(
        &app.state,
        app.tenant.id,
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
    let token = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    Fx {
        app,
        token,
        kdc: Kdc::new(SPN),
    }
}

async fn create_realm(fx: &Fx, kerberos: Value) -> Value {
    let (s, body, _) = call(
        &fx.app,
        Method::POST,
        &fx.base(),
        Some(&fx.token),
        Some(&json!({
            "alias": ALIAS,
            "kind": "kerberos",
            "display_name": "Windows sign-in",
            "kerberos": kerberos,
        })),
    )
    .await;
    assert_eq!(s, 201, "{body}");
    body
}

async fn patch_realm(fx: &Fx, body: Value) -> (u16, Value) {
    let (s, b, _) = call(
        &fx.app,
        Method::PATCH,
        &format!("{}/{ALIAS}", fx.base()),
        Some(&fx.token),
        Some(&body),
    )
    .await;
    (s.as_u16(), b)
}

fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

struct Flow {
    id: String,
    csrf: String,
    state: Value,
}

async fn start_flow(fx: &Fx, http: &reqwest::Client, extra: &[(&str, &str)]) -> Flow {
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
    let res = http
        .get(fx.app.tenant_url("/authorize"))
        .query(&q)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let id = loc
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    let state: Value = http
        .get(fx.app.tenant_url(&format!("/flows/{id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    Flow {
        id,
        csrf: state["csrf"].as_str().unwrap().to_string(),
        state,
    }
}

/// Post the flow's Kerberos step, with a Negotiate token or without.
async fn negotiate(
    fx: &Fx,
    http: &reqwest::Client,
    flow: &Flow,
    token: Option<&[u8]>,
    auto: bool,
) -> (u16, HeaderMap, Value) {
    let mut req = http
        .post(fx.app.tenant_url(&format!("/flows/{}/kerberos", flow.id)))
        .json(&json!({"csrf": flow.csrf, "auto": auto}));
    if let Some(t) = token {
        req = req.header("Authorization", format!("Negotiate {}", B64.encode(t)));
    }
    let res = req.send().await.unwrap();
    let status = res.status().as_u16();
    let headers = res.headers().clone();
    (status, headers, res.json().await.unwrap_or(Value::Null))
}

/// The whole sign-in as a browser does it: challenged, then the token.
async fn sign_in(fx: &Fx, client: &str) -> (u16, HeaderMap, Value) {
    let http = browser();
    let flow = start_flow(fx, &http, &[]).await;
    let (s, h, _) = negotiate(fx, &http, &flow, None, false).await;
    assert_eq!(s, 401);
    assert_eq!(h["www-authenticate"], "Negotiate");
    let (token, _) = fx.kdc.negotiate_token(&fx.kdc.request(client)).unwrap();
    negotiate(fx, &http, &flow, Some(&token), false).await
}

async fn local_user(fx: &Fx, username: &str) -> uuid::Uuid {
    users::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewUser {
            username: username.into(),
            email: (!username.contains('@')).then(|| format!("{username}@local.example")),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .id
}

fn keytab_b64(fx: &Fx) -> String {
    B64.encode(fx.kdc.keytab())
}

async fn id_token_claims(fx: &Fx, http: &reqwest::Client, after: &Value) -> Value {
    let res = http
        .get(after["finish_url"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let code = loc
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
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
    let payload = tokens["id_token"]
        .as_str()
        .unwrap()
        .split('.')
        .nth(1)
        .unwrap();
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_desktop_ticket_signs_in_the_local_account_it_names() {
    let fx = fixture().await;
    let alice = local_user(&fx, "alice").await;
    let created = create_realm(&fx, json!({"keytab": keytab_b64(&fx)})).await;
    assert_eq!(created["kind"], "kerberos");
    assert_eq!(created["callback_url"], "");
    let k = &created["kerberos"];
    assert_eq!(k["service_principal"], SPN, "taken from the keytab");
    assert_eq!(k["realms"], json!(["EXAMPLE.COM"]));
    assert_eq!(k["keytab_set"], true);
    assert_eq!(k["supported"], true);
    assert!(k.get("keytab").is_none(), "write-only: {created}");
    assert_eq!(
        k["keytab_entries"][0]["etype_name"],
        "aes256-cts-hmac-sha1-96"
    );
    assert_eq!(k["keytab_entries"][0]["kvno"], 2);

    // The login page offers the button, not a redirect provider.
    let http = browser();
    let flow = start_flow(&fx, &http, &[]).await;
    assert_eq!(flow.state["kerberos"]["display_name"], "Windows sign-in");
    assert!(
        flow.state["identity_providers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["alias"] != ALIAS)
    );

    // Challenged, then signed in with the mutual-authentication answer.
    let (s, h, _) = negotiate(&fx, &http, &flow, None, false).await;
    assert_eq!(s, 401);
    assert_eq!(h["www-authenticate"], "Negotiate");
    let (token, issued) = fx
        .kdc
        .negotiate_token(&fx.kdc.request("alice@EXAMPLE.COM"))
        .unwrap();
    let (s, h, after) = negotiate(&fx, &http, &flow, Some(&token), false).await;
    assert_eq!(s, 200, "{after}");
    assert_eq!(after["stage"], "done", "{after}");
    assert!(h.get("set-cookie").is_some());
    let answer = h["www-authenticate"].to_str().unwrap();
    let answer = B64
        .decode(
            answer
                .strip_prefix("Negotiate ")
                .expect("a Negotiate answer"),
        )
        .unwrap();
    let rep = spnego::ap_rep_of_answer(&answer)
        .unwrap()
        .expect("an AP-REP");
    assert!(
        verify_ap_rep(&rep, &issued),
        "the AP-REP proves the service"
    );

    // The principal is linked to the account, and the tokens say how.
    let linked = broker::identities_of(&fx.app.state, fx.app.tenant.id, alice)
        .await
        .unwrap();
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].external_subject, "alice@EXAMPLE.COM");
    let claims = id_token_claims(&fx, &http, &after).await;
    assert_eq!(claims["amr"], json!(["kerberos"]));

    // The same authenticator is good once.
    let http2 = browser();
    let flow2 = start_flow(&fx, &http2, &[]).await;
    let (s, _, body) = negotiate(&fx, &http2, &flow2, Some(&token), false).await;
    assert_eq!(s, 403);
    assert_eq!(body["error"], "kerberos_replay");

    // Signing in again goes through the link, even after a rename.
    users::update(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        alice,
        UserUpdate {
            username: Some("alice.w".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (s, _, after) = sign_in(&fx, "alice@EXAMPLE.COM").await;
    assert_eq!(s, 200, "{after}");
    assert_eq!(after["user"]["username"], "alice.w");

    // Nobody is called zed; a disabled account signs in no more.
    let (s, _, body) = sign_in(&fx, "zed@EXAMPLE.COM").await;
    assert_eq!(
        (s, body["error"].as_str()),
        (403, Some("kerberos_no_account"))
    );
    assert!(
        users::find_by_identifier(&fx.app.state, fx.app.tenant.id, "zed")
            .await
            .unwrap()
            .is_none()
    );
    users::update(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        alice,
        UserUpdate {
            status: Some(UserStatus::Disabled),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (s, _, body) = sign_in(&fx, "alice@EXAMPLE.COM").await;
    assert_eq!((s, body["error"].as_str()), (403, Some("account_disabled")));
}

#[tokio::test]
async fn unknown_principals_get_accounts_only_when_the_provider_creates_them() {
    let fx = fixture().await;
    local_user(&fx, "bob").await;
    create_realm(
        &fx,
        json!({"keytab": keytab_b64(&fx), "match_username": false, "create_users": true}),
    )
    .await;
    // No matching by name: bob's principal gets an account of its own.
    let (s, _, after) = sign_in(&fx, "bob@EXAMPLE.COM").await;
    assert_eq!(s, 200, "{after}");
    let name = after["user"]["username"].as_str().unwrap().to_string();
    assert_ne!(name, "bob", "the local bob is not taken over");
    assert!(name.starts_with("desktop-"), "{name}");
    // Carol is new: her account is named after her principal, and the next
    // sign-in finds it through the link.
    let (s, _, after) = sign_in(&fx, "carol@EXAMPLE.COM").await;
    assert_eq!(
        (s, after["user"]["username"].as_str()),
        (200, Some("carol"))
    );
    let (s, _, after) = sign_in(&fx, "carol@EXAMPLE.COM").await;
    assert_eq!(
        (s, after["user"]["username"].as_str()),
        (200, Some("carol"))
    );
    let carol = users::find_by_identifier(&fx.app.state, fx.app.tenant.id, "carol")
        .await
        .unwrap()
        .unwrap();
    assert!(carol.password_hash.is_none());
    assert!(carol.email.is_none());

    // The whole principal as the name.
    let (s, _) = patch_realm(
        &fx,
        json!({"kerberos": {"service_principal": SPN, "name_form": "principal", "match_username": true}}),
    )
    .await;
    assert_eq!(s, 200);
    let dora = local_user(&fx, "dora@example.com").await;
    let (s, _, after) = sign_in(&fx, "dora@EXAMPLE.COM").await;
    assert_eq!(s, 200, "{after}");
    let linked = broker::identities_of(&fx.app.state, fx.app.tenant.id, dora)
        .await
        .unwrap();
    assert_eq!(linked[0].external_subject, "dora@EXAMPLE.COM");
}

#[tokio::test]
async fn the_login_page_asks_on_its_own_only_from_trusted_networks() {
    let fx = fixture().await;
    local_user(&fx, "erin").await;
    let http = browser();

    // No provider: nothing to ask.
    let flow = start_flow(&fx, &http, &[]).await;
    assert!(flow.state["kerberos"].is_null());
    assert_eq!(negotiate(&fx, &http, &flow, None, true).await.0, 404);

    create_realm(
        &fx,
        json!({"keytab": keytab_b64(&fx), "trusted_networks": ["10.0.0.0/8"]}),
    )
    .await;
    // The test client is on loopback, not 10/8: an automatic attempt is
    // not for it, a click still is.
    let flow = start_flow(&fx, &http, &[]).await;
    let (s, h, _) = negotiate(&fx, &http, &flow, None, true).await;
    assert_eq!(s, 204);
    assert!(h.get("www-authenticate").is_none());
    assert_eq!(negotiate(&fx, &http, &flow, None, false).await.0, 401);

    let (s, body) = patch_realm(
        &fx,
        json!({"kerberos": {"service_principal": SPN, "trusted_networks": ["127.0.0.1", "10.0.0.0/8"]}}),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(
        body["kerberos"]["trusted_networks"],
        json!(["127.0.0.1/32", "10.0.0.0/8"])
    );
    let flow = start_flow(&fx, &http, &[]).await;
    assert_eq!(negotiate(&fx, &http, &flow, None, true).await.0, 401);
    // A flow that wants a fresh sign-in is not answered automatically.
    let flow = start_flow(&fx, &http, &[("prompt", "login")]).await;
    assert_eq!(negotiate(&fx, &http, &flow, None, true).await.0, 204);

    // Hidden: automatic attempts go on, the button is gone.
    let (s, _) = patch_realm(&fx, json!({"hidden": true})).await;
    assert_eq!(s, 200);
    let flow = start_flow(&fx, &http, &[]).await;
    assert!(flow.state["kerberos"]["display_name"].is_null());
    assert_eq!(negotiate(&fx, &http, &flow, None, true).await.0, 401);
    // Disabled: gone altogether.
    let (s, _) = patch_realm(&fx, json!({"enabled": false})).await;
    assert_eq!(s, 200);
    let flow = start_flow(&fx, &http, &[]).await;
    assert!(flow.state["kerberos"].is_null());
    assert_eq!(negotiate(&fx, &http, &flow, None, false).await.0, 404);
}

#[tokio::test]
async fn refused_tickets_sign_nobody_in() {
    let fx = fixture().await;
    local_user(&fx, "alice").await;
    create_realm(&fx, json!({"keytab": keytab_b64(&fx)})).await;
    let refused = |token: Vec<u8>| {
        let fx = &fx;
        async move {
            let http = browser();
            let flow = start_flow(fx, &http, &[]).await;
            let (s, h, body) = negotiate(fx, &http, &flow, Some(&token), false).await;
            assert!(h.get("set-cookie").is_none());
            assert!(h.get("www-authenticate").is_none(), "no second challenge");
            (s, body["error"].as_str().unwrap_or_default().to_string())
        }
    };
    let bad = ("kerberos_invalid".to_string(), 403);
    let t = |edit: &dyn Fn(&mut ridm_api::kerberos::testing::Request)| {
        let mut req = fx.kdc.request("alice@EXAMPLE.COM");
        edit(&mut req);
        fx.kdc.negotiate_token(&req).unwrap().0
    };
    let now = chrono::Utc::now();
    for token in [
        t(&|r| r.end_time = now - chrono::Duration::hours(1)),
        t(&|r| r.ctime = now - chrono::Duration::minutes(10)),
        t(&|r| r.client = Principal::parse("alice@EVIL.EXAMPLE").unwrap()),
        t(&|r| r.ticket_key = Some(vec![3; 32])),
        t(&|r| r.sname = Some(Principal::parse("HTTP/other.example.com@EXAMPLE.COM").unwrap())),
        b"not a token".to_vec(),
    ] {
        let (s, e) = refused(token).await;
        assert_eq!((e, s), bad);
    }
    // A browser without a ticket offers NTLM.
    let (s, e) = refused(b"NTLMSSP\0\x01\0\0\0\x07\x82\x08\xa2".to_vec()).await;
    assert_eq!((s, e.as_str()), (403, "kerberos_ntlm"));
    // Another realm's user is accepted once the realm is.
    let (s, body) = patch_realm(
        &fx,
        json!({"kerberos": {"service_principal": SPN, "realms": ["example.com", "evil.example"]}}),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(
        body["kerberos"]["realms"],
        json!(["EXAMPLE.COM", "EVIL.EXAMPLE"])
    );
    let (s, _, after) = sign_in(&fx, "alice@EVIL.EXAMPLE").await;
    assert_eq!(s, 200, "{after}");
}

// ---------------------------------------------------------------------------
// A directory owns the users
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_directory_user_is_found_by_name_and_imported_through_ldap() {
    let fx = fixture().await;
    let ns = dir::namespace().await;
    let dave = dir::add_user(
        &ns,
        "dave",
        "Dave-Dir-Pw1",
        Some("dave@corp.example"),
        Some("Dave"),
    )
    .await;
    dir::add_group(&ns, "ops", &[&dave]).await;
    let (s, ldap, _) = call(
        &fx.app,
        Method::POST,
        &fx.base(),
        Some(&fx.token),
        Some(&json!({
            "alias": "corp",
            "kind": "ldap",
            "display_name": "Corp Directory",
            "trust_email": true,
            "ldap": {
                "url": dir::directory().await.url(),
                "vendor": "openldap",
                "bind_dn": ADMIN_DN,
                "bind_password": ADMIN_PASSWORD,
                "users_dn": ns.people,
                "groups_dn": ns.groups,
                "sync_interval_minutes": 0,
            },
        })),
    )
    .await;
    assert_eq!(s, 201, "{ldap}");
    let ldap_id = ldap["id"].as_str().unwrap();
    create_realm(
        &fx,
        json!({"keytab": keytab_b64(&fx), "ldap_idp_id": ldap_id, "create_users": true}),
    )
    .await;

    // Dave is imported from the directory (uid, the OpenLDAP default for a
    // local part) with its email and groups; no password is kept.
    let (s, _, after) = sign_in(&fx, "dave@EXAMPLE.COM").await;
    assert_eq!(s, 200, "{after}");
    let user = users::find_by_identifier(&fx.app.state, fx.app.tenant.id, "dave")
        .await
        .unwrap()
        .expect("imported");
    assert_eq!(user.email.as_deref(), Some("dave@corp.example"));
    assert!(user.password_hash.is_none());
    let linked = broker::identities_of(&fx.app.state, fx.app.tenant.id, user.id)
        .await
        .unwrap();
    assert_eq!(linked.len(), 1);
    assert_eq!(
        linked[0].alias, "corp",
        "the directory's identity, not the ticket's"
    );
    // The directory decides: someone it does not have is nobody, whatever
    // `create_users` says.
    let (s, _, body) = sign_in(&fx, "zed@EXAMPLE.COM").await;
    assert_eq!(
        (s, body["error"].as_str()),
        (403, Some("kerberos_no_account"))
    );
    // A changed email reaches rIDM at the next Kerberos sign-in.
    dir::replace(&dave, "mail", &["dave.o@corp.example"]).await;
    assert_eq!(sign_in(&fx, "dave@EXAMPLE.COM").await.0, 200);
    let user = users::find_by_identifier(&fx.app.state, fx.app.tenant.id, "dave")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.email.as_deref(), Some("dave.o@corp.example"));
    // Gone from the directory: no sign-in.
    dir::delete(&dave).await;
    let (s, _, body) = sign_in(&fx, "dave@EXAMPLE.COM").await;
    assert_eq!(
        (s, body["error"].as_str()),
        (403, Some("kerberos_no_account"))
    );

    // The tenant document names the directory by alias.
    let tenant = ridm_api::services::tenants::get(&fx.app.state, fx.app.tenant.id)
        .await
        .unwrap();
    let doc = tenant_config::export(&fx.app.state, &tenant).await.unwrap();
    let krb = doc
        .identity_providers
        .iter()
        .find(|p| p.alias == ALIAS)
        .unwrap()
        .kerberos
        .clone()
        .unwrap();
    assert_eq!(krb.ldap_provider.as_deref(), Some("corp"));
    assert_eq!(krb.service_principal, SPN);

    // Deleting the directory leaves the realm matching local accounts.
    let (s, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{}/corp", fx.base()),
        Some(&fx.token),
        None,
    )
    .await;
    assert_eq!(s, 204);
    let (_, body, _) = call(
        &fx.app,
        Method::GET,
        &format!("{}/{ALIAS}", fx.base()),
        Some(&fx.token),
        None,
    )
    .await;
    assert!(body["kerberos"]["ldap_idp_id"].is_null(), "{body}");
}

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_admin_api_checks_keytabs_and_principals_and_documents_round_trip() {
    let fx = fixture().await;
    let post = |body: Value| {
        let fx = &fx;
        async move {
            let (s, b, _) = call(
                &fx.app,
                Method::POST,
                &fx.base(),
                Some(&fx.token),
                Some(&body),
            )
            .await;
            (s.as_u16(), b)
        }
    };
    let realm = |k: Value| json!({"alias": ALIAS, "kind": "kerberos", "kerberos": k});

    // The preview reads a keytab and stores nothing.
    let other = Kdc::new("HTTP/two.example.com@EXAMPLE.COM");
    let rc4 = KeytabEntry {
        principal: Principal::parse(SPN).unwrap(),
        kvno: 1,
        etype: 23,
        key: Zeroizing::new(vec![1; 16]),
    };
    let two = B64.encode(write_keytab(&[fx.kdc.entry(), other.entry(), rc4.clone()]));
    let (s, report, _) = call(
        &fx.app,
        Method::POST,
        &format!("{}/kerberos-keytab", fx.base()),
        Some(&fx.token),
        Some(&json!({"keytab": two})),
    )
    .await;
    assert_eq!(s, 200, "{report}");
    assert_eq!(report["entries"].as_array().unwrap().len(), 3);
    assert_eq!(report["entries"][2]["supported"], false);
    assert_eq!(
        report["service_principals"],
        json!([
            "HTTP/sso.example.com@EXAMPLE.COM",
            "HTTP/two.example.com@EXAMPLE.COM"
        ])
    );

    for (body, field) in [
        (realm(json!({})), "kerberos.service_principal"),
        (realm(json!({"keytab": "!!!"})), "kerberos.keytab"),
        (
            realm(json!({"keytab": B64.encode(b"nope")})),
            "kerberos.keytab",
        ),
        (
            realm(json!({"keytab": B64.encode(write_keytab(&[rc4]))})),
            "kerberos.keytab",
        ),
        (realm(json!({"keytab": two})), "kerberos.service_principal"),
        (
            realm(
                json!({"keytab": keytab_b64(&fx), "service_principal": "HTTP/x.example.com@EXAMPLE.COM"}),
            ),
            "kerberos.keytab",
        ),
        (
            realm(json!({"service_principal": "host/sso.example.com@EXAMPLE.COM"})),
            "kerberos.service_principal",
        ),
        (
            realm(json!({"service_principal": SPN, "trusted_networks": ["nope"]})),
            "kerberos.trusted_networks",
        ),
        (
            realm(json!({"service_principal": SPN, "max_skew_seconds": 5})),
            "kerberos.max_skew_seconds",
        ),
        (
            realm(json!({"service_principal": SPN, "ldap_attribute": "uid"})),
            "kerberos.ldap_attribute",
        ),
        (
            realm(json!({"service_principal": SPN, "ldap_idp_id": uuid::Uuid::now_v7()})),
            "kerberos.ldap_idp_id",
        ),
        (
            json!({"alias": ALIAS, "kind": "kerberos", "client_id": "x", "client_secret": "s", "kerberos": {"service_principal": SPN}}),
            "client_secret",
        ),
        (json!({"alias": ALIAS, "kind": "kerberos"}), "kerberos"),
        (
            json!({"alias": "o", "kind": "oidc", "client_id": "x", "issuer": "https://op.example", "kerberos": {}}),
            "kerberos",
        ),
    ] {
        let (s, b) = post(body.clone()).await;
        assert_eq!(s, 400, "{body} → {b}");
        let fields: Vec<&str> = b["errors"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["field"].as_str())
            .collect();
        assert!(fields.contains(&field), "{body} → {b}");
    }

    // A keytab naming two services, with the one to use.
    let (s, created) = post(realm(
        json!({"keytab": two, "service_principal": "http/sso.example.com@EXAMPLE.COM"}),
    ))
    .await;
    assert_eq!(s, 201, "{created}");
    assert_eq!(
        created["kerberos"]["keytab_entries"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    // A second provider for the same service is a conflict.
    let (s, _) =
        post(json!({"alias": "again", "kind": "kerberos", "kerberos": {"service_principal": SPN}}))
            .await;
    assert_eq!(s, 409);
    // Settings change without the keytab: it is kept.
    let (s, body) = patch_realm(
        &fx,
        json!({"kerberos": {"service_principal": SPN, "max_skew_seconds": 120}}),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["kerberos"]["keytab_set"], true);
    assert_eq!(
        body["kerberos"]["keytab_entries"].as_array().unwrap().len(),
        3
    );
    assert_eq!(body["kerberos"]["max_skew_seconds"], 120);
    // A new keytab replaces it (and must fit the service).
    let (s, body) = patch_realm(
        &fx,
        json!({"kerberos": {"service_principal": SPN, "keytab": B64.encode(other.keytab())}}),
    )
    .await;
    assert_eq!(s, 400, "{body}");
    let (s, body) = patch_realm(&fx, json!({"kerberos": {"keytab": keytab_b64(&fx)}})).await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(
        body["kerberos"]["keytab_entries"].as_array().unwrap().len(),
        1
    );
    // Kinds do not change to or from Kerberos.
    let (s, _) = patch_realm(&fx, json!({"kind": "oidc"})).await;
    assert_eq!(s, 400);
    // An empty keytab clears it: the login page no longer offers Kerberos.
    let (s, body) = patch_realm(
        &fx,
        json!({"kerberos": {"service_principal": SPN, "keytab": ""}}),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["kerberos"]["keytab_set"], false);
    assert_eq!(body["kerberos"]["keytab_entries"], json!([]));
    let http = browser();
    let flow = start_flow(&fx, &http, &[]).await;
    assert!(flow.state["kerberos"].is_null());

    // The tenant document: no keytab out, the provider created on import
    // and reported as needing its secret.
    let tenant = ridm_api::services::tenants::get(&fx.app.state, fx.app.tenant.id)
        .await
        .unwrap();
    let doc = tenant_config::export(&fx.app.state, &tenant).await.unwrap();
    let json_doc = serde_json::to_value(&doc).unwrap();
    let krb = json_doc["identity_providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["alias"] == ALIAS)
        .unwrap();
    assert!(krb["kerberos"].get("keytab").is_none(), "{krb}");
    // Settings are replaced as a whole: the last change left the skew out.
    assert_eq!(krb["kerberos"]["max_skew_seconds"], 300);
    let fresh = common::create_tenant(&fx.app.state.db).await;
    let fresh_tenant = ridm_api::services::tenants::get(&fx.app.state, fresh.id)
        .await
        .unwrap();
    let report = tenant_config::apply(
        &fx.app.state,
        &fresh_tenant,
        Actor::System,
        doc.clone(),
        false,
        &|_: &[String]| Ok(()),
    )
    .await
    .unwrap();
    assert!(
        report
            .secrets
            .identity_providers
            .contains(&ALIAS.to_string()),
        "{report:?}"
    );
    let again = tenant_config::export(&fx.app.state, &fresh_tenant)
        .await
        .unwrap();
    let plan = tenant_config::plan(&fx.app.state, &fresh_tenant, again, false)
        .await
        .unwrap();
    let plan_doc = tenant_config::plan(&fx.app.state, &fresh_tenant, doc, false)
        .await
        .unwrap();
    assert!(plan.changes.is_empty(), "{plan:?}");
    assert!(
        plan_doc
            .changes
            .iter()
            .all(|c| c.resource != "identity_provider"),
        "{plan_doc:?}"
    );
}
