//! Property and negative tests for everything that parses untrusted input on
//! the token path: JWT verification, JWE decrypt, encrypted blobs, cursors,
//! and legacy password hashes. None of it may panic, and no malformed or
//! forged token may verify.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::TestApp;
use proptest::prelude::*;
use ridm_api::error::AppError;
use ridm_api::services::password::legacy;
use ridm_api::services::tokens::{self, AccessTokenRequest, TokenClient, VerifyOptions};
use ridm_api::services::{jwe, tenants};
use ridm_api::util::cursor::Cursor;
use ridm_core::providers::Encrypted;
use serde_json::json;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn encrypted_blob_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = Encrypted::from_bytes(&bytes);
    }

    #[test]
    fn encrypted_blob_round_trips(version in any::<u32>(), nonce in proptest::collection::vec(any::<u8>(), 0..=255), ct in proptest::collection::vec(any::<u8>(), 0..512)) {
        let e = Encrypted { key_version: version, nonce, ciphertext: ct };
        prop_assert_eq!(Encrypted::from_bytes(&e.to_bytes()).unwrap(), e);
    }

    #[test]
    fn cursor_decoder_never_panics(s in "\\PC{0,200}") {
        let _ = Cursor::decode(&s);
    }

    #[test]
    fn legacy_hash_verifier_never_panics_and_never_accepts_garbage(stored in "\\PC{0,120}", pw in "\\PC{0,40}") {
        let r = legacy::verify(pw.as_bytes(), &stored);
        // Random strings are not valid hashes of `pw`.
        prop_assert!(!matches!(r, Ok(true)), "accepted {stored:?}");
    }

    #[test]
    fn jwe_decrypt_never_panics(s in "[A-Za-z0-9_.-]{0,300}") {
        let _ = jwe::decrypt(&s, &[0u8; 64]);
    }
}

#[tokio::test]
async fn jwt_verifier_rejects_malformed_forged_and_confused_tokens() {
    let app = TestApp::spawn().await;
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let client = TokenClient::public("cli");
    let good = tokens::issue_access_token(
        &app.state,
        AccessTokenRequest {
            tenant: &tenant,
            client: &client,
            user: None,
            scopes: &[],
            audiences: &[],
            roles: &[],
            groups: &[],
            session_id: None,
            auth_time: None,
            amr: &[],
            acr: None,
            cnf_jkt: None,
            act: None,
        },
    )
    .await
    .unwrap();
    let opts = VerifyOptions::default();
    assert!(
        tokens::verify(&app.state, &tenant, &good.token, &opts)
            .await
            .is_ok()
    );

    let parts: Vec<&str> = good.token.split('.').collect();
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let payload = parts[1];
    let rejects = |token: String, what: &'static str| {
        let st = app.state.clone();
        let t = tenant.clone();
        let o = opts.clone();
        async move {
            let r = tokens::verify(&st, &t, &token, &o).await;
            assert!(matches!(r, Err(AppError::Unauthorized)), "{what}: {r:?}");
        }
    };

    // alg=none, with and without signature.
    let none = URL_SAFE_NO_PAD
        .encode(json!({"alg": "none", "kid": header["kid"], "typ": "at+jwt"}).to_string());
    rejects(format!("{none}.{payload}."), "alg none").await;
    rejects(
        format!("{none}.{payload}.{}", parts[2]),
        "alg none with sig",
    )
    .await;
    // Algorithm confusion: claim HS256 with the public key as the HMAC secret.
    let hs = URL_SAFE_NO_PAD
        .encode(json!({"alg": "HS256", "kid": header["kid"], "typ": "at+jwt"}).to_string());
    rejects(format!("{hs}.{payload}.{}", parts[2]), "HS256 confusion").await;
    // Switching the declared alg to another asymmetric family with the same kid.
    let es = URL_SAFE_NO_PAD
        .encode(json!({"alg": "ES256", "kid": header["kid"], "typ": "at+jwt"}).to_string());
    rejects(
        format!("{es}.{payload}.{}", parts[2]),
        "alg mismatch for kid",
    )
    .await;
    // Unknown / missing kid.
    let nokid = URL_SAFE_NO_PAD.encode(json!({"alg": header["alg"], "typ": "at+jwt"}).to_string());
    rejects(format!("{nokid}.{payload}.{}", parts[2]), "missing kid").await;
    let badkid = URL_SAFE_NO_PAD
        .encode(json!({"alg": header["alg"], "kid": "nope", "typ": "at+jwt"}).to_string());
    rejects(format!("{badkid}.{payload}.{}", parts[2]), "unknown kid").await;
    // Structure.
    for garbage in [
        "",
        ".",
        "..",
        "a.b",
        "a.b.c.d",
        &good.token[..good.token.len() - 5],
        &format!("{}x", good.token),
    ] {
        rejects(garbage.to_string(), "structure").await;
    }
    // Claims tampering with an intact signature.
    let forged = URL_SAFE_NO_PAD
        .encode(json!({"iss": "x", "sub": "mallory", "exp": 4102444800u64}).to_string());
    rejects(
        format!("{}.{forged}.{}", parts[0], parts[2]),
        "forged payload",
    )
    .await;
    // Signature from another tenant's key over the same payload.
    let other = tenants::get(&app.state, common::create_tenant(&app.state.db).await.id)
        .await
        .unwrap();
    let foreign = tokens::issue_access_token(
        &app.state,
        AccessTokenRequest {
            tenant: &other,
            client: &client,
            user: None,
            scopes: &[],
            audiences: &[],
            roles: &[],
            groups: &[],
            session_id: None,
            auth_time: None,
            amr: &[],
            acr: None,
            cnf_jkt: None,
            act: None,
        },
    )
    .await
    .unwrap();
    rejects(foreign.token, "issued by another tenant").await;
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn jwt_header_parser_never_panics(s in "[A-Za-z0-9_.=-]{0,200}") {
        let _ = jsonwebtoken::decode_header(&s);
    }
}
