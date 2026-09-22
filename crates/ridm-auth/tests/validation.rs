//! What a validator accepts, what it refuses, and how it treats the key set.

mod common;

use std::time::Duration;

use common::{Issuer, K2_PEM, ROGUE_PEM, access_token, k1_jwk, k2_jwk, sign, unix_now};
use ridm_auth::{AuthError, Kind, Validator};
use serde_json::json;

#[tokio::test]
async fn a_token_from_the_issuer_is_accepted_and_its_claims_read() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap();
    assert_eq!(validator.jwks_uri(), issuer.jwks_uri());

    let claims = validator
        .validate(&access_token(&issuer.claims()))
        .await
        .unwrap();

    assert_eq!(claims.sub, "5d3a1f12-4b0e-4a5f-9b6f-1c2d3e4f5a6b");
    assert_eq!(claims.aud, ["urn:orders"]);
    assert_eq!(claims.client_id.as_deref(), Some("orders-web"));
    assert!(claims.has_scope("orders:read"));
    assert!(claims.has_role("staff"));
    assert!(claims.has_group("warehouse"));
    claims.require_permission("orders:read").unwrap();
    assert!(!claims.is_client_only());
}

#[tokio::test]
async fn discovery_must_name_the_issuer_the_document_was_fetched_from() {
    let issuer = Issuer::start().await;
    issuer.claim_issuer("https://elsewhere.example");

    let e = issuer.validator().discover().await.unwrap_err();
    assert_eq!(e.kind(), Kind::Unavailable);
    assert!(e.to_string().contains("elsewhere.example"), "{e}");
}

#[tokio::test]
async fn the_key_set_is_fetched_once_and_then_answered_from_the_cache() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap();
    let token = access_token(&issuer.claims());

    for _ in 0..5 {
        validator.validate(&token).await.unwrap();
    }
    assert_eq!(issuer.jwks_requests(), 1);
}

#[tokio::test]
async fn a_token_naming_a_key_the_cache_has_not_seen_refreshes_the_set() {
    let issuer = Issuer::start().await;
    // No cooldown, so the unknown `kid` is looked up straight away.
    let validator = issuer
        .validator()
        .min_refresh_interval(Duration::ZERO)
        .discover()
        .await
        .unwrap();
    validator
        .validate(&access_token(&issuer.claims()))
        .await
        .unwrap();
    assert_eq!(issuer.jwks_requests(), 1);

    // The tenant rotates: a new key signs, and both stay published.
    issuer.publish(vec![k1_jwk(), k2_jwk()]);
    let rotated = sign(K2_PEM, "k2", "at+jwt", &issuer.claims());

    let claims = validator.validate(&rotated).await.unwrap();
    assert_eq!(claims.aud, ["urn:orders"]);
    assert_eq!(issuer.jwks_requests(), 2, "one refresh, not one per key");

    // And the refreshed set still answers for the old key without fetching.
    validator
        .validate(&access_token(&issuer.claims()))
        .await
        .unwrap();
    assert_eq!(issuer.jwks_requests(), 2);
}

#[tokio::test]
async fn an_unknown_key_cannot_drive_a_fetch_per_request() {
    let issuer = Issuer::start().await;
    let validator = issuer
        .validator()
        .min_refresh_interval(Duration::from_secs(60))
        .discover()
        .await
        .unwrap();
    validator
        .validate(&access_token(&issuer.claims()))
        .await
        .unwrap();
    assert_eq!(issuer.jwks_requests(), 1);

    let forged = sign(ROGUE_PEM, "does-not-exist", "at+jwt", &issuer.claims());
    for _ in 0..10 {
        let e = validator.validate(&forged).await.unwrap_err();
        assert!(
            matches!(e, AuthError::UnknownKey(ref kid) if kid == "does-not-exist"),
            "{e}"
        );
    }
    assert_eq!(
        issuer.jwks_requests(),
        1,
        "a set fetched moments ago is an answer, not a reason to ask again"
    );
}

#[tokio::test]
async fn once_the_cooldown_lapses_an_unknown_key_is_looked_up_again() {
    let issuer = Issuer::start().await;
    let validator = issuer
        .validator()
        .min_refresh_interval(Duration::from_millis(50))
        .discover()
        .await
        .unwrap();
    validator
        .validate(&access_token(&issuer.claims()))
        .await
        .unwrap();

    // The tenant rotates while this process is not looking.
    issuer.publish(vec![k1_jwk(), k2_jwk()]);
    let rotated = sign(K2_PEM, "k2", "at+jwt", &issuer.claims());
    let e = validator.validate(&rotated).await.unwrap_err();
    assert!(matches!(e, AuthError::UnknownKey(_)), "{e}");
    assert_eq!(
        issuer.jwks_requests(),
        1,
        "the cooldown holds the first miss"
    );

    tokio::time::sleep(Duration::from_millis(60)).await;
    validator.validate(&rotated).await.unwrap();
    assert_eq!(issuer.jwks_requests(), 2);
}

#[tokio::test]
async fn concurrent_misses_make_one_request_between_them() {
    let issuer = Issuer::start().await;
    let validator = std::sync::Arc::new(
        issuer
            .validator()
            .min_refresh_interval(Duration::ZERO)
            .discover()
            .await
            .unwrap(),
    );
    assert_eq!(issuer.jwks_requests(), 0, "discovery does not fetch keys");

    let token = access_token(&issuer.claims());
    let mut waiting = Vec::new();
    for _ in 0..16 {
        let (validator, token) = (validator.clone(), token.clone());
        waiting.push(tokio::spawn(
            async move { validator.validate(&token).await },
        ));
    }
    for task in waiting {
        task.await.unwrap().unwrap();
    }
    assert_eq!(issuer.jwks_requests(), 1);
}

#[tokio::test]
async fn a_stale_set_keeps_answering_while_the_issuer_is_unreachable() {
    let issuer = Issuer::start().await;
    let validator = issuer
        .validator()
        // Every request wants a fresh set, so only the fallback can answer.
        .jwks_max_age(Duration::ZERO)
        .min_refresh_interval(Duration::ZERO)
        .discover()
        .await
        .unwrap();
    validator.warm().await.unwrap();

    issuer.take_jwks_down(true);
    validator
        .validate(&access_token(&issuer.claims()))
        .await
        .unwrap();

    // A key the stale set never held is still a refusal, not an outage.
    let e = validator
        .validate(&sign(ROGUE_PEM, "k9", "at+jwt", &issuer.claims()))
        .await
        .unwrap_err();
    assert_eq!(e.kind(), Kind::Unavailable);
    assert!(e.is_transient(), "{e}");
}

#[tokio::test]
async fn a_token_signed_by_a_key_the_issuer_does_not_publish_is_refused() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap();

    // The forger names a published `kid` but signs with their own key.
    let forged = sign(ROGUE_PEM, "k1", "at+jwt", &issuer.claims());
    let e = validator.validate(&forged).await.unwrap_err();
    assert!(matches!(e, AuthError::BadSignature), "{e}");
    assert_eq!(e.status(), 401);
}

#[tokio::test]
async fn a_key_published_for_one_algorithm_does_not_verify_another() {
    let issuer = Issuer::start().await;
    let mut mislabelled = k1_jwk();
    mislabelled["alg"] = json!("RS256");
    issuer.publish(vec![mislabelled]);
    let validator = issuer.validator().discover().await.unwrap();

    let e = validator
        .validate(&access_token(&issuer.claims()))
        .await
        .unwrap_err();
    assert!(matches!(e, AuthError::UnacceptableAlgorithm(_)), "{e}");
}

#[tokio::test]
async fn a_token_without_a_kid_or_with_a_symmetric_algorithm_is_refused() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap();

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some("at+jwt".into());
    let key = jsonwebtoken::EncodingKey::from_ec_pem(common::K1_PEM.as_bytes()).unwrap();
    let anonymous = jsonwebtoken::encode(&header, &issuer.claims(), &key).unwrap();
    assert!(matches!(
        validator.validate(&anonymous).await,
        Err(AuthError::NoKeyId)
    ));

    // HS256 over a key an attacker picked: the algorithm is not in the set.
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.typ = Some("at+jwt".into());
    header.kid = Some("k1".into());
    let hmac = jsonwebtoken::encode(
        &header,
        &issuer.claims(),
        &jsonwebtoken::EncodingKey::from_secret(b"guess"),
    )
    .unwrap();
    let e = validator.validate(&hmac).await.unwrap_err();
    assert!(matches!(e, AuthError::UnacceptableAlgorithm(_)), "{e}");
}

#[tokio::test]
async fn an_id_token_cannot_be_spent_as_an_access_token() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap();

    let id_token = sign(common::K1_PEM, "k1", "JWT", &issuer.claims());
    let e = validator.validate(&id_token).await.unwrap_err();
    assert!(matches!(e, AuthError::WrongType { .. }), "{e}");

    // A validator told to accept any type takes it.
    let lenient = issuer
        .validator()
        .token_type(None::<String>)
        .discover()
        .await
        .unwrap();
    lenient.validate(&id_token).await.unwrap();

    // `application/at+jwt` is the same type spelled long (RFC 9068 §4).
    let long = sign(common::K1_PEM, "k1", "application/AT+JWT", &issuer.claims());
    validator.validate(&long).await.unwrap();
}

#[tokio::test]
async fn a_token_for_another_audience_or_another_issuer_is_refused() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap();

    let mut billing = issuer.claims();
    billing["aud"] = json!("urn:billing");
    let e = validator
        .validate(&access_token(&billing))
        .await
        .unwrap_err();
    assert!(matches!(e, AuthError::WrongAudience(_)), "{e}");
    assert!(e.to_string().contains("urn:orders"), "{e}");

    // A token for several audiences including this one is fine.
    let mut both = issuer.claims();
    both["aud"] = json!(["urn:billing", "urn:orders"]);
    validator.validate(&access_token(&both)).await.unwrap();

    let mut elsewhere = issuer.claims();
    elsewhere["iss"] = json!("https://elsewhere.example/t/acme");
    let e = validator
        .validate(&access_token(&elsewhere))
        .await
        .unwrap_err();
    assert!(matches!(e, AuthError::WrongIssuer { .. }), "{e}");
}

#[tokio::test]
async fn expiry_is_enforced_but_clock_skew_within_the_leeway_is_forgiven() {
    let issuer = Issuer::start().await;
    let validator = issuer
        .validator()
        .leeway(Duration::from_secs(60))
        .discover()
        .await
        .unwrap();

    let mut just_expired = issuer.claims();
    just_expired["exp"] = json!(unix_now() - 30);
    validator
        .validate(&access_token(&just_expired))
        .await
        .unwrap();

    let mut long_expired = issuer.claims();
    long_expired["exp"] = json!(unix_now() - 3600);
    let e = validator
        .validate(&access_token(&long_expired))
        .await
        .unwrap_err();
    assert!(matches!(e, AuthError::Expired), "{e}");

    // A clock that runs fast at the issuer: `nbf` a little ahead is forgiven.
    let mut early = issuer.claims();
    early["nbf"] = json!(unix_now() + 30);
    validator.validate(&access_token(&early)).await.unwrap();

    let mut much_too_early = issuer.claims();
    much_too_early["nbf"] = json!(unix_now() + 3600);
    much_too_early["exp"] = json!(unix_now() + 7200);
    let e = validator
        .validate(&access_token(&much_too_early))
        .await
        .unwrap_err();
    assert!(matches!(e, AuthError::NotYetValid), "{e}");

    // And a validator with no leeway holds the issuer to its own clock.
    let strict = issuer
        .validator()
        .leeway(Duration::ZERO)
        .discover()
        .await
        .unwrap();
    let e = strict
        .validate(&access_token(&just_expired))
        .await
        .unwrap_err();
    assert!(matches!(e, AuthError::Expired), "{e}");
}

#[tokio::test]
async fn a_certificate_bound_token_needs_its_certificate() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap();
    let cert = b"not really DER, but the thumbprint is all that is compared";
    let other = b"another certificate";

    let mut bound = issuer.claims();
    bound["cnf"] = json!({ "x5t#S256": ridm_auth::certificate_thumbprint(cert) });
    let token = access_token(&bound);

    let e = validator.validate(&token).await.unwrap_err();
    assert!(matches!(e, AuthError::SenderConstrained), "{e}");
    let e = validator
        .validate_with_certificate(&token, Some(other))
        .await
        .unwrap_err();
    assert!(matches!(e, AuthError::CertificateMismatch), "{e}");
    let claims = validator
        .validate_with_certificate(&token, Some(cert))
        .await
        .unwrap();
    assert_eq!(
        claims.x5t_s256(),
        Some(ridm_auth::certificate_thumbprint(cert).as_str())
    );

    // Bound to a DPoP key as well: the certificate settles only half of it.
    bound["cnf"]["jkt"] = json!("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
    let e = validator
        .validate_with_certificate(&access_token(&bound), Some(cert))
        .await
        .unwrap_err();
    assert!(matches!(e, AuthError::SenderConstrained), "{e}");
}

#[tokio::test]
async fn a_sender_constrained_token_is_refused_unless_the_caller_opts_in() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap();

    let mut bound = issuer.claims();
    bound["cnf"] = json!({ "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" });
    let e = validator.validate(&access_token(&bound)).await.unwrap_err();
    assert!(matches!(e, AuthError::SenderConstrained), "{e}");

    let permissive = issuer
        .validator()
        .allow_sender_constrained(true)
        .discover()
        .await
        .unwrap();
    let claims = permissive.validate(&access_token(&bound)).await.unwrap();
    assert_eq!(
        claims.jkt(),
        Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I")
    );
}

#[tokio::test]
async fn what_the_builder_requires_is_checked_on_every_token() {
    let issuer = Issuer::start().await;
    let validator = issuer
        .validator()
        .require_scope("orders:read")
        .require_permission("orders:write")
        .discover()
        .await
        .unwrap();

    let e = validator
        .validate(&access_token(&issuer.claims()))
        .await
        .unwrap_err();
    assert!(
        matches!(e, AuthError::MissingPermission(ref p) if p == "orders:write"),
        "{e}"
    );
    assert_eq!(e.status(), 403);

    let mut allowed = issuer.claims();
    allowed["permissions"] = json!(["orders:read", "orders:write"]);
    validator.validate(&access_token(&allowed)).await.unwrap();
}

#[tokio::test]
async fn a_machine_token_carries_its_client_as_the_subject() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap();

    let mut machine = issuer.claims();
    machine["sub"] = json!("reporting-job");
    machine["client_id"] = json!("reporting-job");
    machine.as_object_mut().unwrap().remove("roles");
    machine.as_object_mut().unwrap().remove("groups");

    let claims = validator.validate(&access_token(&machine)).await.unwrap();
    assert!(claims.is_client_only());
    assert!(claims.roles.is_empty());
}

#[tokio::test]
async fn the_authorization_header_is_read_and_nothing_else_is() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap();
    let token = access_token(&issuer.claims());

    validator
        .validate_authorization(Some(&format!("Bearer {token}")))
        .await
        .unwrap();
    for header in [None, Some(""), Some("Basic abc"), Some("Bearer ")] {
        let e = validator.validate_authorization(header).await.unwrap_err();
        assert!(matches!(e, AuthError::Missing), "{header:?}: {e}");
    }
    // A DPoP-bound token presented as a bearer token loses its binding.
    let e = validator
        .validate_authorization(Some(&format!("DPoP {token}")))
        .await
        .unwrap_err();
    assert!(matches!(e, AuthError::Missing), "{e}");
}

#[tokio::test]
async fn nonsense_in_place_of_a_token_is_a_refusal_not_a_panic() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap();

    for token in [
        "",
        ".",
        "a.b",
        "a.b.c",
        "not a jwt",
        "eyJhbGciOiJub25lIn0..",
        &"x".repeat(9000),
    ] {
        let e = validator.validate(token).await.unwrap_err();
        assert_eq!(e.status(), 401, "{token}: {e}");
    }
}

#[tokio::test]
async fn an_issuer_that_publishes_nothing_usable_is_an_outage_not_a_refusal() {
    let issuer = Issuer::start().await;
    issuer.publish(vec![]);
    let validator = issuer.validator().discover().await.unwrap();

    let e = validator
        .validate(&access_token(&issuer.claims()))
        .await
        .unwrap_err();
    assert!(matches!(e, AuthError::Jwks { .. }), "{e}");
    assert_eq!(e.status(), 503);
}

#[tokio::test]
async fn a_validator_can_be_built_without_ever_contacting_the_issuer() {
    let issuer = Issuer::start().await;
    let validator = Validator::builder(&issuer.base)
        .audience("urn:orders")
        .allow_http(true)
        .jwks_uri(issuer.jwks_uri())
        .build()
        .unwrap()
        .shared();

    validator
        .validate(&access_token(&issuer.claims()))
        .await
        .unwrap();
}
