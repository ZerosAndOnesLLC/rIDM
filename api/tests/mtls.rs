//! Phase 13.5: mutual-TLS client authentication and certificate-bound tokens
//! (RFC 8705). Client certificates arrive in a trusted proxy's header or on
//! rIDM's own mTLS listener; `tls_client_auth` clients prove a certificate
//! from one of the tenant's trust anchors carrying their registered subject,
//! `self_signed_tls_client_auth` clients one registered in their JWK Set,
//! and a client registered for bound tokens gets `cnf.x5t#S256` in every
//! access token, which the resources then insist on.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::TestApp;
use common::admin::{admin_token, call};
use reqwest::Method;
use ridm_api::models::{
    ClientType, DcrMode, DcrPolicy, NewClient, NewMtlsTrustAnchor, NewUser, SecurityProfile,
    TenantSettings, TokenEndpointAuthMethod, grants,
};
use ridm_api::oidc::mtls;
use ridm_api::services::refresh_tokens::{self, IssueRequest};
use ridm_api::services::tokens::{self, AccessTokenRequest, TokenClient};
use ridm_api::services::{clients, mtls_trust_anchors, tenants, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

const HEADER: &str = "x-client-cert";

/// A test PKI: one CA and the leaf certificates it issues.
struct Ca {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    pem: String,
}

/// A client certificate and its key.
struct Leaf {
    der: Vec<u8>,
    pem: String,
    key_pem: String,
}

impl Leaf {
    fn header(&self) -> String {
        STANDARD.encode(&self.der)
    }

    fn x5t(&self) -> String {
        mtls::thumbprint(&self.der)
    }
}

fn ca(name: &str) -> Ca {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    // The defaults carry a CN of their own.
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    let pem = params.self_signed(&key).unwrap().pem();
    Ca { params, key, pem }
}

impl Ca {
    fn issue(
        &self,
        cn: &str,
        sans: Vec<rcgen::SanType>,
        eku: rcgen::ExtendedKeyUsagePurpose,
    ) -> Leaf {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        // The defaults carry a CN of their own.
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Acme");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.subject_alt_names = sans;
        params.extended_key_usages = vec![eku];
        let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
        let cert = params.signed_by(&key, &issuer).unwrap();
        Leaf {
            der: cert.der().to_vec(),
            pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    fn client(&self, cn: &str) -> Leaf {
        self.issue(cn, vec![], rcgen::ExtendedKeyUsagePurpose::ClientAuth)
    }
}

fn self_signed(cn: &str) -> Leaf {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    // The defaults carry a CN of their own.
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let cert = params.self_signed(&key).unwrap();
    Leaf {
        der: cert.der().to_vec(),
        pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

/// Loopback is a trusted proxy that forwards client certificates in
/// `X-Client-Cert`, and mTLS aliases live on `mtls.example`.
async fn app() -> TestApp {
    app_with(true).await
}

async fn app_with(trusted: bool) -> TestApp {
    TestApp::spawn_configured(axum::Router::new(), move |state| {
        let mut config = (*state.config).clone();
        if trusted {
            config.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
        }
        config.mtls.cert_header = Some(HEADER.into());
        config.mtls.public_url = Some("https://mtls.example".parse().unwrap());
        state.config = Arc::new(config);
    })
    .await
}

async fn trust(app: &TestApp, ca: &Ca) {
    mtls_trust_anchors::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewMtlsTrustAnchor {
            name: "Acme CA".into(),
            certificate_pem: ca.pem.clone(),
        },
    )
    .await
    .unwrap();
}

fn machine(id: &str) -> NewClient {
    NewClient {
        client_id: Some(id.into()),
        name: id.into(),
        client_type: Some(ClientType::Machine),
        allowed_grants: Some(vec![grants::CLIENT_CREDENTIALS.into()]),
        ..Default::default()
    }
}

async fn register(app: &TestApp, input: NewClient) {
    clients::create(&app.state, app.tenant.id, Actor::System, input)
        .await
        .unwrap();
}

/// `client_credentials` for `client_id`, the certificate in the proxy header.
async fn client_credentials(app: &TestApp, client_id: &str, cert: Option<&Leaf>) -> (u16, Value) {
    let mut req = app.http.post(app.tenant_url("/token")).form(&[
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
    ]);
    if let Some(c) = cert {
        req = req.header(HEADER, c.header());
    }
    let res = req.send().await.unwrap();
    (
        res.status().as_u16(),
        res.json().await.unwrap_or(Value::Null),
    )
}

fn claims_of(jwt: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn discovery_offers_mtls_only_when_certificates_can_arrive() {
    let plain = TestApp::spawn().await;
    let doc: Value = plain
        .http
        .get(plain.tenant_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let methods = doc["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap();
    assert!(!methods.iter().any(|m| m == "tls_client_auth"));
    assert!(doc.get("mtls_endpoint_aliases").is_none());
    assert!(
        doc.get("tls_client_certificate_bound_access_tokens")
            .is_none()
    );

    let app = app().await;
    let doc: Value = app
        .http
        .get(app.tenant_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    for key in [
        "token_endpoint_auth_methods_supported",
        "introspection_endpoint_auth_methods_supported",
        "revocation_endpoint_auth_methods_supported",
    ] {
        let methods = doc[key].as_array().unwrap();
        assert!(methods.iter().any(|m| m == "tls_client_auth"), "{key}");
        assert!(
            methods.iter().any(|m| m == "self_signed_tls_client_auth"),
            "{key}"
        );
    }
    assert_eq!(doc["tls_client_certificate_bound_access_tokens"], true);
    let base = format!("https://mtls.example/t/{}", app.tenant.slug);
    let aliases = &doc["mtls_endpoint_aliases"];
    assert_eq!(aliases["token_endpoint"], format!("{base}/token"));
    assert_eq!(
        aliases["pushed_authorization_request_endpoint"],
        format!("{base}/par")
    );
    assert_eq!(
        aliases["introspection_endpoint"],
        format!("{base}/introspect")
    );
    assert_eq!(aliases["userinfo_endpoint"], format!("{base}/userinfo"));
    // Browser endpoints stay where they are.
    assert!(aliases.get("authorization_endpoint").is_none());
}

#[tokio::test]
async fn tls_client_auth_needs_a_trusted_chain_and_the_registered_subject() {
    let app = app().await;
    let acme = ca("Acme Issuing CA");
    trust(&app, &acme).await;
    register(
        &app,
        NewClient {
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::TlsClientAuth),
            tls_client_auth_subject_dn: Some("CN=billing,O=Acme".into()),
            ..machine("billing")
        },
    )
    .await;
    register(
        &app,
        NewClient {
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::TlsClientAuth),
            tls_client_auth_san_dns: Some("orders.acme.example".into()),
            ..machine("orders")
        },
    )
    .await;

    let good = acme.client("billing");
    let (status, body) = client_credentials(&app, "billing", Some(&good)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    // Not registered for bound tokens: no binding.
    assert!(
        claims_of(body["access_token"].as_str().unwrap())
            .get("cnf")
            .is_none()
    );

    // A DNS SAN, matched without regard to case.
    let orders = acme.issue(
        "whatever",
        vec![rcgen::SanType::DnsName(
            "Orders.Acme.Example".try_into().unwrap(),
        )],
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    );
    let (status, body) = client_credentials(&app, "orders", Some(&orders)).await;
    assert_eq!(status, 200, "{body}");

    // Each of these is `invalid_client`.
    let evil = ca("Acme Issuing CA");
    for (why, cert) in [
        ("no certificate", None),
        ("another subject", Some(acme.client("payroll"))),
        (
            "another CA with the same name",
            Some(evil.client("billing")),
        ),
        ("self-signed with the subject", Some(self_signed("billing"))),
        (
            "not for client authentication",
            Some(acme.issue(
                "billing",
                vec![],
                rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            )),
        ),
    ] {
        let (status, body) = client_credentials(&app, "billing", cert.as_ref()).await;
        assert_eq!(status, 401, "{why}: {body}");
        assert_eq!(body["error"], "invalid_client", "{why}");
    }
    // The orders certificate does not authenticate billing.
    let (status, _) = client_credentials(&app, "billing", Some(&orders)).await;
    assert_eq!(status, 401);

    // Without a trust anchor nothing chains.
    let anchors = mtls_trust_anchors::list(&app.state, app.tenant.id)
        .await
        .unwrap();
    mtls_trust_anchors::delete(&app.state, app.tenant.id, Actor::System, anchors[0].id)
        .await
        .unwrap();
    let (status, body) = client_credentials(&app, "billing", Some(&good)).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn a_certificate_header_is_believed_only_from_a_trusted_proxy() {
    let app = app_with(false).await;
    let acme = ca("Acme CA");
    trust(&app, &acme).await;
    register(
        &app,
        NewClient {
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::TlsClientAuth),
            tls_client_auth_subject_dn: Some("CN=billing,O=Acme".into()),
            ..machine("billing")
        },
    )
    .await;
    let (status, body) = client_credentials(&app, "billing", Some(&acme.client("billing"))).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn self_signed_tls_client_auth_matches_the_registered_certificate() {
    let app = app().await;
    let mine = self_signed("svc");
    register(
        &app,
        NewClient {
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::SelfSignedTlsClientAuth),
            jwks: Some(json!({"keys": [{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA", "x5c": [STANDARD.encode(&mine.der)]}]})),
            ..machine("svc")
        },
    )
    .await;
    let (status, body) = client_credentials(&app, "svc", Some(&mine)).await;
    assert_eq!(status, 200, "{body}");
    let (status, _) = client_credentials(&app, "svc", Some(&self_signed("svc"))).await;
    assert_eq!(status, 401);
    // A secret is not what it registered.
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .basic_auth("svc", Some("guess"))
        .form(&[("grant_type", "client_credentials")])
        .header(HEADER, mine.header())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn bound_tokens_carry_the_thumbprint_and_need_the_certificate() {
    let app = app().await;
    let acme = ca("Acme CA");
    trust(&app, &acme).await;
    register(
        &app,
        NewClient {
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::TlsClientAuth),
            tls_client_auth_subject_dn: Some("CN=billing,O=Acme".into()),
            tls_client_certificate_bound_access_tokens: Some(true),
            ..machine("billing")
        },
    )
    .await;
    let cert = acme.client("billing");
    let (status, body) = client_credentials(&app, "billing", Some(&cert)).await;
    assert_eq!(status, 200, "{body}");
    // Still a bearer token by scheme (RFC 8705 §3).
    assert_eq!(body["token_type"], "Bearer");
    let at = body["access_token"].as_str().unwrap().to_string();
    assert_eq!(claims_of(&at)["cnf"]["x5t#S256"], cert.x5t());

    // Introspection shows the binding and keeps the scheme.
    let res = app
        .http
        .post(app.tenant_url("/introspect"))
        .header(HEADER, cert.header())
        .form(&[("token", at.as_str()), ("client_id", "billing")])
        .send()
        .await
        .unwrap();
    let intro: Value = res.json().await.unwrap();
    assert_eq!(intro["active"], true, "{intro}");
    assert_eq!(intro["token_type"], "Bearer");
    assert_eq!(intro["cnf"]["x5t#S256"], cert.x5t());

    // A client certificate authentication method is no prerequisite: a
    // secret client can have its tokens bound too, and without the
    // certificate it gets none.
    let secret_client = clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewClient {
            tls_client_certificate_bound_access_tokens: Some(true),
            ..machine("reports")
        },
    )
    .await
    .unwrap();
    let secret = secret_client.client_secret.unwrap().to_string();
    let form = [("grant_type", "client_credentials")];
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .basic_auth("reports", Some(&secret))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .basic_auth("reports", Some(&secret))
        .header(HEADER, cert.header())
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        claims_of(body["access_token"].as_str().unwrap())["cnf"]["x5t#S256"],
        cert.x5t()
    );
}

/// A user token bound to `x5t`, minted the way the token endpoint would.
async fn bound_user_token(app: &TestApp, x5t: &str) -> String {
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let user = users::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewUser {
            username: format!("u-{}", &Uuid::new_v4().simple().to_string()[..8]),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    tokens::issue_access_token(
        &app.state,
        AccessTokenRequest {
            tenant: &tenant,
            client: &TokenClient::public("spa"),
            user: Some(&user),
            scopes: &["openid".into(), "profile".into()],
            audiences: &["spa".to_string()],
            roles: &[],
            groups: &[],
            session_id: None,
            org_id: None,
            auth_time: None,
            amr: &["pwd".into()],
            acr: None,
            cnf_jkt: None,
            cnf_x5t: Some(x5t),
            act: None,
        },
    )
    .await
    .unwrap()
    .token
}

#[tokio::test]
async fn resources_refuse_a_bound_token_without_its_certificate() {
    let app = app().await;
    register(
        &app,
        NewClient {
            client_id: Some("spa".into()),
            name: "spa".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            ..Default::default()
        },
    )
    .await;
    let mine = self_signed("phone");
    let at = bound_user_token(&app, &mine.x5t()).await;
    let get = |cert: Option<&Leaf>| {
        let mut req = app.http.get(app.tenant_url("/userinfo")).bearer_auth(&at);
        if let Some(c) = cert {
            req = req.header(HEADER, c.header());
        }
        req.send()
    };
    let res = get(None).await.unwrap();
    assert_eq!(res.status(), 401);
    assert!(
        res.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("invalid_token")
    );
    assert_eq!(
        get(Some(&self_signed("phone"))).await.unwrap().status(),
        401
    );
    let res = get(Some(&mine)).await.unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
}

#[tokio::test]
async fn a_public_clients_refresh_token_is_bound_to_its_certificate() {
    let app = app().await;
    register(
        &app,
        NewClient {
            client_id: Some("app".into()),
            name: "app".into(),
            client_type: Some(ClientType::Native),
            redirect_uris: vec!["com.example.app:/cb".into()],
            tls_client_certificate_bound_access_tokens: Some(true),
            ..Default::default()
        },
    )
    .await;
    let mine = self_signed("device");
    let x5t = mine.x5t();
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
    let issued = refresh_tokens::issue(
        &app.state,
        app.tenant.id,
        IssueRequest {
            client_id: "app",
            user_id: Some(user.id),
            session_id: None,
            scopes: &["openid".into(), "offline_access".into()],
            audiences: &[],
            ttl: chrono::Duration::hours(1),
            dpop_jkt: None,
            mtls_x5t: Some(&x5t),
            auth_time: None,
            amr: &[],
            acr: None,
            org_id: None,
            act: None,
        },
    )
    .await
    .unwrap();
    let refresh = |cert: Option<&Leaf>| {
        let mut req = app.http.post(app.tenant_url("/token")).form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "app"),
            ("refresh_token", issued.token.as_str()),
        ]);
        if let Some(c) = cert {
            req = req.header(HEADER, c.header());
        }
        req.send()
    };
    // Without a certificate the client may not even ask.
    assert_eq!(refresh(None).await.unwrap().status(), 400);
    let res = refresh(Some(&self_signed("device"))).await.unwrap();
    assert_eq!(res.status(), 400);
    assert_eq!(res.json::<Value>().await.unwrap()["error"], "invalid_grant");
    // The refused attempts left the token unspent.
    let res = refresh(Some(&mine)).await.unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        claims_of(body["access_token"].as_str().unwrap())["cnf"]["x5t#S256"],
        x5t
    );
    // And the rotated one stays bound.
    let rotated = body["refresh_token"].as_str().unwrap();
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .header(HEADER, self_signed("other").header())
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "app"),
            ("refresh_token", rotated),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn registration_checks_the_mtls_metadata() {
    let app = app().await;
    let tid = app.tenant.id;
    let refused = |input: NewClient| {
        let state = app.state.clone();
        async move {
            match clients::create(&state, tid, Actor::System, input).await {
                Ok(c) => panic!("registered {}", c.client.client_id),
                Err(e) => e.to_string(),
            }
        }
    };
    let tls = || NewClient {
        token_endpoint_auth_method: Some(TokenEndpointAuthMethod::TlsClientAuth),
        ..machine("x")
    };
    let e = refused(tls()).await;
    assert!(e.contains("exactly one"), "{e}");
    let e = refused(NewClient {
        tls_client_auth_subject_dn: Some("CN=a".into()),
        tls_client_auth_san_dns: Some("a.example".into()),
        ..tls()
    })
    .await;
    assert!(e.contains("exactly one"), "{e}");
    let e = refused(NewClient {
        tls_client_auth_subject_dn: Some("NOPE=a".into()),
        ..tls()
    })
    .await;
    assert!(e.contains("attribute type"), "{e}");
    let e = refused(NewClient {
        tls_client_auth_san_ip: Some("not-an-ip".into()),
        ..tls()
    })
    .await;
    assert!(e.contains("tls_client_auth_san_ip"), "{e}");
    let e = refused(NewClient {
        tls_client_auth_subject_dn: Some("CN=a".into()),
        ..machine("x")
    })
    .await;
    assert!(e.contains("only used with tls_client_auth"), "{e}");
    let e = refused(NewClient {
        token_endpoint_auth_method: Some(TokenEndpointAuthMethod::SelfSignedTlsClientAuth),
        ..machine("x")
    })
    .await;
    assert!(e.contains("x5c"), "{e}");

    // Dynamic registration takes the RFC 8705 metadata.
    tenants::update(
        &app.state,
        Actor::System,
        tid,
        ridm_api::services::tenants::TenantUpdate {
            settings: Some(TenantSettings {
                dcr: DcrPolicy {
                    mode: DcrMode::Open,
                    allowed_grants: vec![],
                    require_pkce: true,
                },
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let res = app
        .http
        .post(app.tenant_url("/register"))
        .json(&json!({
            "client_name": "dcr",
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "tls_client_auth",
            "tls_client_auth_san_uri": "spiffe://acme.example/billing",
            "tls_client_certificate_bound_access_tokens": true,
        }))
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["token_endpoint_auth_method"], "tls_client_auth",
        "{body}"
    );
    assert_eq!(
        body["tls_client_auth_san_uri"],
        "spiffe://acme.example/billing"
    );
    assert_eq!(body["tls_client_certificate_bound_access_tokens"], true);
    assert!(body.get("client_secret").is_none());
}

#[tokio::test]
async fn a_fapi_client_may_be_sender_constrained_by_its_certificate() {
    let app = app().await;
    let acme = ca("Acme CA");
    trust(&app, &acme).await;
    let fapi = |bound: Option<bool>, dpop: Option<bool>| NewClient {
        token_endpoint_auth_method: Some(TokenEndpointAuthMethod::TlsClientAuth),
        tls_client_auth_subject_dn: Some("CN=bank,O=Acme".into()),
        security_profile: Some(SecurityProfile::Fapi2),
        tls_client_certificate_bound_access_tokens: bound,
        dpop_bound_access_tokens: dpop,
        ..machine("bank")
    };
    // Neither binding: outside the profile.
    let e = clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        fapi(None, Some(false)),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(e.contains("certificate-bound"), "{e}");
    let c = clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        fapi(Some(true), None),
    )
    .await
    .unwrap()
    .client;
    // The certificate binds instead of DPoP, which is off by default here.
    assert!(!c.dpop_bound_access_tokens);
    let cert = acme.client("bank");
    let (status, body) = client_credentials(&app, "bank", Some(&cert)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        claims_of(body["access_token"].as_str().unwrap())["cnf"]["x5t#S256"],
        cert.x5t()
    );
}

#[tokio::test]
async fn trust_anchors_are_managed_through_the_admin_api() {
    let app = app().await;
    let slug = app.tenant.slug.clone();
    let token = admin_token(&app, app.tenant.id, "ridm:admin").await;
    let path = format!("/admin/tenants/{slug}/mtls/trust-anchors");
    let acme = ca("Acme Root");

    let (status, created, _) = call(
        &app,
        Method::POST,
        &path,
        Some(&token),
        Some(&json!({"name": "Acme", "certificate_pem": acme.pem})),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["subject"], "CN=Acme Root");
    let der = mtls::parse_header(&acme.pem).unwrap().remove(0);
    assert_eq!(created["fingerprint"], mtls::thumbprint(&der));

    let (status, _, _) = call(
        &app,
        Method::POST,
        &path,
        Some(&token),
        Some(&json!({"name": "Again", "certificate_pem": acme.pem})),
    )
    .await;
    assert_eq!(status, 409);
    // A leaf is no certificate authority.
    let leaf = acme.client("billing");
    let (status, body, _) = call(
        &app,
        Method::POST,
        &path,
        Some(&token),
        Some(&json!({"name": "Leaf", "certificate_pem": leaf.pem})),
    )
    .await;
    assert_eq!(status, 400);
    assert!(body.to_string().contains("not a CA"), "{body}");
    let (status, _, _) = call(
        &app,
        Method::POST,
        &path,
        Some(&token),
        Some(&json!({"name": "Junk", "certificate_pem": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"})),
    )
    .await;
    assert_eq!(status, 400);

    let (status, list, _) = call(&app, Method::GET, &path, Some(&token), None).await;
    assert_eq!(status, 200);
    assert_eq!(list.as_array().unwrap().len(), 1);
    let id = created["id"].as_str().unwrap();
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}/{id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (_, list, _) = call(&app, Method::GET, &path, Some(&token), None).await;
    assert!(list.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn the_native_listener_proves_the_certificate_in_the_handshake() {
    let app = TestApp::spawn().await;
    let mine = self_signed("svc");
    register(
        &app,
        NewClient {
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::SelfSignedTlsClientAuth),
            jwks: Some(json!({"keys": [{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA", "x5c": [STANDARD.encode(&mine.der)]}]})),
            tls_client_certificate_bound_access_tokens: Some(true),
            ..machine("svc")
        },
    )
    .await;

    // The listener, with a certificate for `localhost`.
    let server_key = rcgen::KeyPair::generate().unwrap();
    let server_cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&server_key)
        .unwrap();
    let config = ridm_api::tls::server_config(
        vec![server_cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::try_from(server_key.serialize_der()).unwrap(),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let router = ridm_api::build_router(app.state.clone());
    tokio::spawn(async move {
        axum_server::from_tcp(listener)
            .unwrap()
            .acceptor(ridm_api::tls::PeerCertAcceptor::new(
                axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config)),
            ))
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    let client = |identity: Option<&Leaf>| {
        let mut b = reqwest::Client::builder()
            .tls_certs_only([reqwest::Certificate::from_der(server_cert.der()).unwrap()])
            .resolve("localhost", addr);
        if let Some(leaf) = identity {
            b = b.identity(
                reqwest::Identity::from_pem(format!("{}{}", leaf.pem, leaf.key_pem).as_bytes())
                    .unwrap(),
            );
        }
        b.build().unwrap()
    };
    let url = format!(
        "https://localhost:{}/t/{}/token",
        addr.port(),
        app.tenant.slug
    );
    let form = [("grant_type", "client_credentials"), ("client_id", "svc")];

    let res = client(Some(&mine))
        .post(&url)
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        claims_of(body["access_token"].as_str().unwrap())["cnf"]["x5t#S256"],
        mine.x5t()
    );
    // No certificate is fine for the connection, not for this client.
    let res = client(None).post(&url).form(&form).send().await.unwrap();
    assert_eq!(res.status(), 401);
    // A header here is not believed: loopback is no trusted proxy of this app.
    let res = client(None)
        .post(&url)
        .header(HEADER, mine.header())
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}
