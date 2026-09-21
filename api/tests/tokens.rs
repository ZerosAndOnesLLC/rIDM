mod common;

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::TestApp;
use ridm_api::error::AppError;
use ridm_api::models::{
    ClaimMapper, KeyPolicy, KeyStatus, MapperKind, NewGroup, NewRole, NewUser, Principal, RsaBits,
    SigningAlg, TenantSettings, TokenKind,
};
use ridm_api::services::tokens::{
    self, AccessTokenRequest, IdTokenEncryption, IdTokenRequest, SubjectType, TokenClient,
    VerifyOptions,
};
use ridm_api::services::{groups, jwe, keys, roles, tenants, users};
use ridm_core::events::Actor;
use serde_json::json;

struct Fx {
    app: TestApp,
    tenant: ridm_api::models::Tenant,
    user: ridm_api::models::User,
    roles: Vec<ridm_api::models::Role>,
    groups: Vec<ridm_api::models::Group>,
}

async fn fixture(alg: SigningAlg) -> Fx {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let settings = TenantSettings {
        keys: KeyPolicy {
            default_alg: alg,
            rsa_bits: RsaBits::B2048,
            ..Default::default()
        },
        ..Default::default()
    };
    let tenant = tenants::update(
        &app.state,
        Actor::System,
        tid,
        ridm_api::services::tenants::TenantUpdate {
            settings: Some(settings),
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
    let role = roles::create(
        &app.state,
        tid,
        Actor::System,
        NewRole {
            name: "editor".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    roles::assign(
        &app.state,
        tid,
        Actor::System,
        role.id,
        Principal::User { id: user.id },
    )
    .await
    .unwrap();
    let group = groups::create(
        &app.state,
        tid,
        Actor::System,
        NewGroup {
            name: "staff".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    groups::add_member(&app.state, tid, Actor::System, group.id, user.id)
        .await
        .unwrap();
    let roles = roles::effective_roles(&app.state, tid, user.id, None)
        .await
        .unwrap()
        .to_vec();
    let groups = groups::groups_of_user(&app.state, tid, user.id, true)
        .await
        .unwrap();
    Fx {
        app,
        tenant,
        user,
        roles,
        groups,
    }
}

fn decode_payload(jwt: &str) -> serde_json::Value {
    let payload = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

fn decode_header(jwt: &str) -> serde_json::Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn access_and_id_tokens_sign_and_verify_for_every_algorithm() {
    for alg in [SigningAlg::RS256, SigningAlg::ES256, SigningAlg::EdDSA] {
        let fx = fixture(alg).await;
        // Opted in, so one ID token carries every claim shape this test signs.
        let client = TokenClient {
            id_token_scope_claims: true,
            ..TokenClient::public("web-app")
        };
        let scopes: Vec<String> = ["openid", "profile", "email"].map(String::from).to_vec();
        let issuer = format!("{}/t/{}", fx.app.base_url, fx.tenant.slug);

        let at = tokens::issue_access_token(
            &fx.app.state,
            AccessTokenRequest {
                tenant: &fx.tenant,
                client: &client,
                user: Some(&fx.user),
                scopes: &scopes,
                audiences: &["https://api.example".into()],
                roles: &fx.roles,
                groups: &fx.groups,
                session_id: None,
                org_id: None,
                auth_time: None,
                amr: &["pwd".into()],
                acr: None,
                cnf_jkt: None,
                act: None,
            },
        )
        .await
        .unwrap();
        let header = decode_header(&at.token);
        assert_eq!(header["typ"], "at+jwt", "{alg}");
        assert_eq!(header["alg"], alg.as_str());
        assert_eq!(header["kid"], at.kid);
        let payload = decode_payload(&at.token);
        assert_eq!(payload["iss"], issuer);
        assert_eq!(payload["sub"], fx.user.id.to_string());
        assert_eq!(payload["aud"], "https://api.example");
        assert_eq!(payload["azp"], "web-app");
        assert_eq!(payload["client_id"], "web-app");
        assert_eq!(payload["scope"], "openid profile email");
        assert_eq!(payload["roles"], json!(["editor"]));
        assert_eq!(payload["groups"], json!(["staff"]));
        assert_eq!(payload["amr"], json!(["pwd"]));
        assert_eq!(payload["tid"], fx.tenant.id.to_string());
        assert!(payload["jti"].is_string());
        assert!(
            payload.get("email").is_none(),
            "profile claims belong in the id token / userinfo"
        );

        let id = tokens::issue_id_token(
            &fx.app.state,
            IdTokenRequest {
                tenant: &fx.tenant,
                client: &client,
                user: &fx.user,
                scopes: &scopes,
                roles: &fx.roles,
                groups: &fx.groups,
                session_id: None,
                org_id: None,
                auth_time: chrono::Utc::now(),
                nonce: Some("n-0S6_WzA2Mj"),
                amr: &["pwd".into()],
                acr: Some("urn:ridm:acr:1"),
                access_token: Some(&at.token),
                code: Some("SplxlOBeZQQYbYS6WxSbIA"),
                act: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(decode_header(&id.token)["typ"], "JWT");
        let payload = decode_payload(&id.token);
        assert_eq!(payload["aud"], "web-app");
        assert_eq!(payload["nonce"], "n-0S6_WzA2Mj");
        assert_eq!(payload["acr"], "urn:ridm:acr:1");
        assert_eq!(payload["email"], "alice@example.com");
        assert_eq!(payload["email_verified"], true);
        assert_eq!(payload["preferred_username"], "alice");
        assert_eq!(payload["at_hash"], tokens::half_hash(alg, &at.token));
        assert_eq!(
            payload["c_hash"],
            tokens::half_hash(alg, "SplxlOBeZQQYbYS6WxSbIA")
        );
        assert!(payload["auth_time"].is_number());

        // Verification through the published JWKS.
        let claims = tokens::verify(
            &fx.app.state,
            &fx.tenant,
            &at.token,
            &VerifyOptions {
                audience: Some("https://api.example".into()),
                typ: Some("at+jwt".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(claims["sub"], fx.user.id.to_string());
        let claims = tokens::verify(
            &fx.app.state,
            &fx.tenant,
            &id.token,
            &VerifyOptions {
                audience: Some("web-app".into()),
                typ: Some("JWT".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(claims["nonce"], "n-0S6_WzA2Mj");

        // Wrong audience / wrong typ / tampered payload / other tenant → rejected.
        let wrong_aud = tokens::verify(
            &fx.app.state,
            &fx.tenant,
            &at.token,
            &VerifyOptions {
                audience: Some("other".into()),
                ..Default::default()
            },
        )
        .await;
        assert!(matches!(wrong_aud, Err(AppError::Unauthorized)), "{alg}");
        let wrong_typ = tokens::verify(
            &fx.app.state,
            &fx.tenant,
            &at.token,
            &VerifyOptions {
                typ: Some("JWT".into()),
                ..Default::default()
            },
        )
        .await;
        assert!(matches!(wrong_typ, Err(AppError::Unauthorized)));
        let mut parts: Vec<String> = at.token.split('.').map(String::from).collect();
        parts[1] = URL_SAFE_NO_PAD.encode(r#"{"sub":"mallory"}"#);
        assert!(
            tokens::verify(
                &fx.app.state,
                &fx.tenant,
                &parts.join("."),
                &VerifyOptions::default()
            )
            .await
            .is_err()
        );
        let other = tenants::get(
            &fx.app.state,
            common::create_tenant(&fx.app.state.db).await.id,
        )
        .await
        .unwrap();
        assert!(
            tokens::verify(&fx.app.state, &other, &at.token, &VerifyOptions::default())
                .await
                .is_err(),
            "another tenant's keys must not verify it"
        );
    }
}

#[tokio::test]
async fn expired_tokens_and_revoked_keys_are_rejected() {
    let fx = fixture(SigningAlg::EdDSA).await;
    let mut client = TokenClient::public("cli");
    client.access_token_ttl = Duration::from_secs(1);
    let at = tokens::issue_access_token(
        &fx.app.state,
        AccessTokenRequest {
            tenant: &fx.tenant,
            client: &client,
            user: None,
            scopes: &["api".into()],
            audiences: &[],
            roles: &[],
            groups: &[],
            session_id: None,
            org_id: None,
            auth_time: None,
            amr: &[],
            acr: None,
            cnf_jkt: None,
            act: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        decode_payload(&at.token)["sub"],
        "cli",
        "client credentials use the client id as subject"
    );
    assert_eq!(decode_payload(&at.token)["aud"], "cli");
    // `exp` has second granularity and a token is still valid during its
    // expiry second, so wait comfortably past it.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let strict = VerifyOptions {
        leeway_secs: 0,
        ..Default::default()
    };
    assert!(matches!(
        tokens::verify(&fx.app.state, &fx.tenant, &at.token, &strict).await,
        Err(AppError::Unauthorized)
    ));
    // Introspection-style verification of expired tokens still checks the signature.
    let lenient = VerifyOptions {
        leeway_secs: 0,
        allow_expired: true,
        ..Default::default()
    };
    assert!(
        tokens::verify(&fx.app.state, &fx.tenant, &at.token, &lenient)
            .await
            .is_ok()
    );

    // Rotate then revoke the old key: its tokens stop verifying at once.
    let fresh = tokens::issue_access_token(
        &fx.app.state,
        AccessTokenRequest {
            tenant: &fx.tenant,
            client: &TokenClient::public("cli"),
            user: None,
            scopes: &[],
            audiences: &[],
            roles: &[],
            groups: &[],
            session_id: None,
            org_id: None,
            auth_time: None,
            amr: &[],
            acr: None,
            cnf_jkt: None,
            act: None,
        },
    )
    .await
    .unwrap();
    keys::rotate(
        &fx.app.state,
        fx.tenant.id,
        &fx.tenant.settings.keys,
        Actor::System,
    )
    .await
    .unwrap();
    assert!(
        tokens::verify(
            &fx.app.state,
            &fx.tenant,
            &fresh.token,
            &VerifyOptions::default()
        )
        .await
        .is_ok(),
        "retiring keys still verify"
    );
    for k in keys::list(&fx.app.state, fx.tenant.id, Some(KeyStatus::Retiring))
        .await
        .unwrap()
    {
        keys::revoke(&fx.app.state, fx.tenant.id, Actor::System, k.id)
            .await
            .unwrap();
    }
    assert!(matches!(
        tokens::verify(
            &fx.app.state,
            &fx.tenant,
            &fresh.token,
            &VerifyOptions::default()
        )
        .await,
        Err(AppError::Unauthorized)
    ));
}

#[tokio::test]
async fn pairwise_subjects_are_stable_per_sector_and_differ_across_sectors() {
    let fx = fixture(SigningAlg::ES256).await;
    let mut a = TokenClient::public("a");
    a.subject_type = SubjectType::Pairwise;
    a.sector_identifier = Some("apps.example".into());
    let mut b = a.clone();
    b.client_id = "b".into();
    let mut c = a.clone();
    c.client_id = "c".into();
    c.sector_identifier = Some("other.example".into());

    let sa = tokens::subject_for(&fx.tenant, &a, &fx.user);
    assert_ne!(sa, fx.user.id.to_string());
    assert_eq!(
        sa,
        tokens::subject_for(&fx.tenant, &b, &fx.user),
        "same sector → same sub"
    );
    assert_ne!(
        sa,
        tokens::subject_for(&fx.tenant, &c, &fx.user),
        "different sector → different sub"
    );
    let other_tenant = tenants::get(
        &fx.app.state,
        common::create_tenant(&fx.app.state.db).await.id,
    )
    .await
    .unwrap();
    assert_ne!(
        sa,
        tokens::subject_for(&other_tenant, &a, &fx.user),
        "salt is per tenant"
    );
    // Stable across reads.
    let again = tenants::get(&fx.app.state, fx.tenant.id).await.unwrap();
    assert_eq!(sa, tokens::subject_for(&again, &a, &fx.user));
}

#[tokio::test]
async fn mappers_and_encrypted_id_tokens() {
    let fx = fixture(SigningAlg::RS256).await;
    let recipient = keys::generate(SigningAlg::RS256, RsaBits::B2048).unwrap();
    let mut client = TokenClient::public("secure-app");
    client.mappers = vec![
        ClaimMapper {
            name: "dept".into(),
            kind: MapperKind::Hardcoded {
                claim: "department".into(),
                value: json!("eng"),
            },
            include_in: vec![TokenKind::Id, TokenKind::Access],
        },
        ClaimMapper {
            name: "aud".into(),
            kind: MapperKind::Audience {
                audience: "https://extra.example".into(),
            },
            include_in: vec![TokenKind::Access],
        },
    ];
    client.id_token_encryption = Some(IdTokenEncryption {
        alg: jwe::KeyAlg::RsaOaep256,
        enc: jwe::ContentEnc::A256Gcm,
        recipient_jwk: recipient.public_jwk.clone(),
    });
    let at = tokens::issue_access_token(
        &fx.app.state,
        AccessTokenRequest {
            tenant: &fx.tenant,
            client: &client,
            user: Some(&fx.user),
            scopes: &["openid".into()],
            audiences: &[],
            roles: &fx.roles,
            groups: &fx.groups,
            session_id: None,
            org_id: None,
            auth_time: None,
            amr: &[],
            acr: None,
            cnf_jkt: None,
            act: None,
        },
    )
    .await
    .unwrap();
    let p = decode_payload(&at.token);
    assert_eq!(p["department"], "eng");
    assert_eq!(
        p["aud"], "https://extra.example",
        "mapper audience replaces the client-id default"
    );

    let id = tokens::issue_id_token(
        &fx.app.state,
        IdTokenRequest {
            tenant: &fx.tenant,
            client: &client,
            user: &fx.user,
            scopes: &["openid".into()],
            roles: &fx.roles,
            groups: &fx.groups,
            session_id: None,
            org_id: None,
            auth_time: chrono::Utc::now(),
            nonce: None,
            amr: &[],
            acr: None,
            access_token: None,
            code: None,
            act: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        id.token.split('.').count(),
        5,
        "encrypted id token is a compact JWE"
    );
    let jws = String::from_utf8(jwe::decrypt(&id.token, &recipient.private_der).unwrap()).unwrap();
    assert_eq!(jws.split('.').count(), 3);
    assert_eq!(decode_payload(&jws)["department"], "eng");
    let claims = tokens::verify(
        &fx.app.state,
        &fx.tenant,
        &jws,
        &VerifyOptions {
            audience: Some("secure-app".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(claims["sub"], fx.user.id.to_string());
}

/// An access token never expires after the caller's `not_after`, which is an
/// instant, not a TTL: token exchange once turned the subject token's remaining
/// life into a TTL a second before signing, and a clock tick in between issued
/// a token outliving its subject by a second.
#[tokio::test]
async fn access_token_expiry_is_capped_at_not_after() {
    let fx = fixture(SigningAlg::ES256).await;
    let limit = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp() + 7, 0).unwrap();
    let issue = |client: TokenClient| {
        let fx = &fx;
        async move {
            tokens::issue_access_token(
                &fx.app.state,
                AccessTokenRequest {
                    tenant: &fx.tenant,
                    client: &client,
                    user: Some(&fx.user),
                    scopes: &[],
                    audiences: &[],
                    roles: &[],
                    groups: &[],
                    session_id: None,
                    org_id: None,
                    auth_time: None,
                    amr: &[],
                    acr: None,
                    cnf_jkt: None,
                    act: None,
                },
            )
            .await
            .unwrap()
        }
    };
    // A five-minute TTL is cut back to the limit.
    let capped = issue(TokenClient {
        not_after: Some(limit),
        ..TokenClient::public("web-app")
    })
    .await;
    assert_eq!(capped.expires_at, limit);
    assert_eq!(decode_payload(&capped.token)["exp"], limit.timestamp());
    // A limit beyond the TTL changes nothing.
    let far = limit + chrono::Duration::hours(1);
    let uncapped = issue(TokenClient {
        not_after: Some(far),
        ..TokenClient::public("web-app")
    })
    .await;
    assert!(uncapped.expires_at < far);
    assert!(uncapped.expires_at > limit);
}
