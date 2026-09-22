//! Phase 13.3 (design review): the ways an LDAP upstream is classically
//! broken, each pinned against a real OpenLDAP.
//!
//! * **Filter injection.** The identifier typed at the login page goes into
//!   a search filter. Unescaped, `*` matches every entry and `x)(uid=*`
//!   rewrites the filter; with a password that is right for *some* entry,
//!   that signs in as it. rIDM escapes every value (RFC 4515), so an
//!   identifier matches only an entry that has exactly that value.
//! * **Unauthenticated bind.** A simple bind with a DN and an empty
//!   password succeeds without proving anything (RFC 4513 5.1.2). An empty
//!   password is never sent.
//! * **A local hash beside the directory.** The directory owns a directory
//!   user's password; a local hash would be checked instead and outlive a
//!   password change or a disabled account there. A bulk hash import is
//!   refused for them.

use ridm_api::models::{
    ClientType, IdpKind, LdapSettings, LdapVendor, NewClient, NewIdentityProvider, WriteOnly,
};
use ridm_api::services::{clients, identity_providers, ldap, password, tenants, users};
use ridm_core::events::Actor;

use crate::common::TestApp;
use crate::common::ldap::{self as dir, ADMIN_DN, ADMIN_PASSWORD};

const PASSWORD: &str = "Victim-Directory-Pw1";

async fn fixture() -> (TestApp, dir::Namespace) {
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
    let ns = dir::namespace().await;
    identity_providers::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewIdentityProvider {
            alias: "corp".into(),
            kind: Some(IdpKind::Ldap),
            ldap: Some(LdapSettings {
                url: dir::directory().await.url(),
                vendor: LdapVendor::Openldap,
                bind_dn: Some(ADMIN_DN.into()),
                bind_password: Some(WriteOnly(ADMIN_PASSWORD.into())),
                users_dn: ns.people.clone(),
                sync_interval_minutes: 0,
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (app, ns)
}

async fn password_step(app: &TestApp, identifier: &str, password: &str) -> u16 {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let res = http
        .get(app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid"),
            (
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            ),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    let flow = url::Url::parse(res.headers()["location"].to_str().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .unwrap()
        .1
        .into_owned();
    let state: serde_json::Value = http
        .get(app.tenant_url(&format!("/flows/{flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    http.post(app.tenant_url(&format!("/flows/{flow}/password")))
        .json(&serde_json::json!({
            "csrf": state["csrf"],
            "identifier": identifier,
            "password": password,
        }))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn an_identifier_with_filter_syntax_matches_only_itself() {
    let (app, ns) = fixture().await;
    dir::add_user(&ns, "victim", PASSWORD, Some("victim@corp.example"), None).await;
    for identifier in ["*", "vic*", "victim)(uid=*", "*)(|(uid=*", "victim\\2a"] {
        assert_eq!(
            password_step(&app, identifier, PASSWORD).await,
            401,
            "`{identifier}` must not sign in as the victim"
        );
    }
    assert!(
        users::find_by_identifier(&app.state, app.tenant.id, "victim")
            .await
            .unwrap()
            .is_none(),
        "nobody was imported"
    );
    // The victim's own identifier still works.
    assert_eq!(password_step(&app, "victim", PASSWORD).await, 200);
}

#[tokio::test]
async fn an_empty_password_is_never_sent_as_an_unauthenticated_bind() {
    let (app, ns) = fixture().await;
    let dn = dir::add_user(&ns, "victim", PASSWORD, None, None).await;
    // Some directories take a DN with an empty password as a successful
    // unauthenticated bind (OpenLDAP only with `allow bind_anon_cred`);
    // rIDM's client never sends one, whatever the server would say.
    let mut conn = ridm_api::ldap::Conn::open(&ridm_api::ldap::ConnectOptions {
        url: dir::directory().await.url(),
        starttls: false,
        ca_certificate: None,
        timeout: std::time::Duration::from_secs(5),
    })
    .await
    .unwrap();
    assert!(!conn.bind(&dn, "").await.unwrap());
    conn.close().await;
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    assert!(
        ldap::sign_in_unknown(&app.state, &tenant, "victim", "")
            .await
            .unwrap()
            .is_none()
    );
    // Once imported, the empty password fails for the linked user too.
    assert_eq!(password_step(&app, "victim", PASSWORD).await, 200);
    let user = users::find_by_identifier(&app.state, app.tenant.id, "victim")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ldap::verify_password(&app.state, app.tenant.id, &user, "")
            .await
            .unwrap(),
        Some(false)
    );
}

#[tokio::test]
async fn a_bulk_hash_import_cannot_give_a_directory_user_a_local_password() {
    let (app, ns) = fixture().await;
    dir::add_user(&ns, "victim", PASSWORD, None, None).await;
    assert_eq!(password_step(&app, "victim", PASSWORD).await, 200);
    let user = users::find_by_identifier(&app.state, app.tenant.id, "victim")
        .await
        .unwrap()
        .unwrap();
    // A bcrypt-format hash, as a migration file would carry.
    let hash = "$2b$04$KjbNcXHk5BkvaRZpUHG3AOEBRMlr8uW/xh0sT8JfMEbTLflMnYBUa";
    let err = password::import_hash(&app.state, app.tenant.id, user.id, hash)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("directory"), "{err}");
    let user = users::get(&app.state, app.tenant.id, user.id)
        .await
        .unwrap();
    assert!(user.password_hash.is_none());
}
