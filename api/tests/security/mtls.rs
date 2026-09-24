//! Design review (Phase 13.5): token exchange must not loosen a
//! certificate-bound token. Exchanging one with the gateway's secret alone,
//! or with another certificate, would hand back a token anyone holding it
//! could spend; and a gateway not registered for bound tokens would get an
//! unbound one even with the right certificate. All three are refused.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ridm_api::models::{ClientType, NewClient, NewResourceServer, NewUser, grants};
use ridm_api::oidc::mtls;
use ridm_api::services::tokens::{self, AccessTokenRequest, TokenClient};
use ridm_api::services::{clients, resource_servers, tenants, users};
use ridm_core::events::Actor;
use serde_json::Value;
use uuid::Uuid;

use crate::common::TestApp;

const GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const TT_ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";
const HEADER: &str = "x-client-cert";
const ORDERS: &str = "https://orders.example";

fn certificate() -> Vec<u8> {
    let key = rcgen::KeyPair::generate().unwrap();
    rcgen::CertificateParams::default()
        .self_signed(&key)
        .unwrap()
        .der()
        .to_vec()
}

async fn gateway(app: &TestApp, id: &str, bound: bool) -> String {
    clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some(id.into()),
            name: id.into(),
            client_type: Some(ClientType::Machine),
            allowed_grants: Some(vec![grants::CLIENT_CREDENTIALS.into(), GRANT.into()]),
            allowed_scopes: Some(vec!["openid".into()]),
            allowed_audiences: vec![ORDERS.into()],
            tls_client_certificate_bound_access_tokens: Some(bound),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .client_secret
    .unwrap()
    .to_string()
}

#[tokio::test]
async fn a_certificate_bound_token_is_not_exchanged_into_a_looser_one() {
    let app = TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        config.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
        config.mtls.cert_header = Some(HEADER.into());
        state.config = Arc::new(config);
    })
    .await;
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
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
    let cert = certificate();
    let x5t = mtls::thumbprint(&cert);
    let subject = tokens::issue_access_token(
        &app.state,
        AccessTokenRequest {
            tenant: &tenant,
            client: &TokenClient::public("frontend"),
            user: Some(&user),
            scopes: &["openid".into()],
            audiences: &["https://frontend.example".to_string()],
            roles: &[],
            groups: &[],
            session_id: Some(Uuid::new_v4()),
            org_id: None,
            auth_time: None,
            amr: &["pwd".into()],
            acr: None,
            cnf_jkt: None,
            cnf_x5t: Some(&x5t),
            act: None,
        },
    )
    .await
    .unwrap()
    .token;
    resource_servers::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewResourceServer {
            identifier: ORDERS.into(),
            name: "Orders".into(),
            token_ttl_secs: None,
            signing_alg: None,
            allow_offline_access: None,
        },
    )
    .await
    .unwrap();
    let bound_secret = gateway(&app, "bound-gw", true).await;
    let loose_secret = gateway(&app, "loose-gw", false).await;
    let exchange = |id: &'static str, secret: String, with: Option<Vec<u8>>| {
        let mut req = app
            .http
            .post(app.tenant_url("/token"))
            .basic_auth(id, Some(secret))
            .form(&[
                ("grant_type", GRANT),
                ("subject_token", subject.as_str()),
                ("subject_token_type", TT_ACCESS),
                ("resource", ORDERS),
            ]);
        if let Some(c) = with {
            req = req.header(HEADER, STANDARD.encode(c));
        }
        req.send()
    };

    // The secret alone, and another certificate.
    for with in [None, Some(certificate())] {
        let res = exchange("bound-gw", bound_secret.clone(), with)
            .await
            .unwrap();
        assert_eq!(res.status(), 400);
        let body: Value = res.json().await.unwrap();
        assert!(
            body["error"] == "invalid_grant" || body["error"] == "invalid_request",
            "{body}"
        );
    }
    // The right certificate at a client that would not bind the result.
    let res = exchange("loose-gw", loose_secret, Some(cert.clone()))
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant", "{body}");
    // The right certificate at a binding client: bound again.
    let res = exchange("bound-gw", bound_secret, Some(cert))
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let body: Value = res.json().await.unwrap();
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(
                body["access_token"]
                    .as_str()
                    .unwrap()
                    .split('.')
                    .nth(1)
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["cnf"]["x5t#S256"], x5t);
}

/// Fuzzing (`client_cert`) found a certificate whose subject attribute type
/// is not a usable OID: rIDM printed its subject as `=`, a DN that cannot
/// match the certificate it came from. A subject is offered for registration
/// only when what rIDM prints of it names it again.
#[test]
fn a_printed_subject_names_its_certificate_again() {
    let der = include_bytes!("../fixtures/mtls/fuzz-subject-dn-roundtrip.der").to_vec();
    let cert = mtls::ClientCert::from_chain(der, vec![]).expect("parses");
    if cert.subject_is_textual() {
        assert!(
            mtls::subject_matches(&cert, cert.subject_dn()),
            "the subject `{}` does not match its own certificate",
            cert.subject_dn()
        );
    }
}
