mod common;

use common::TestApp;
use ridm_api::error::AppError;
use ridm_api::models::{
    ClientStatus, ClientType, NewClient, NewScope, NewUser, STANDARD_SCOPES,
    TokenEndpointAuthMethod, grants,
};
use ridm_api::services::{clients, consents, scopes, users};
use ridm_core::events::Actor;

#[tokio::test]
async fn every_tenant_gets_the_standard_scopes() {
    let app = TestApp::spawn().await;
    let list = scopes::list(&app.state, app.tenant.id).await.unwrap();
    let names: Vec<&str> = list.iter().map(|s| s.name.as_str()).collect();
    for s in STANDARD_SCOPES {
        assert!(names.contains(&s), "missing {s}");
    }
    assert!(list.iter().find(|s| s.name == "openid").unwrap().is_default);
    assert!(
        list.iter()
            .find(|s| s.name == "email")
            .unwrap()
            .claims
            .contains(&"email".to_string())
    );

    // Custom scope, cache invalidation, standard scopes are protected.
    let custom = scopes::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewScope {
            name: "read:users".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        scopes::list(&app.state, app.tenant.id)
            .await
            .unwrap()
            .iter()
            .any(|s| s.id == custom.id)
    );
    assert!(matches!(
        scopes::create(
            &app.state,
            app.tenant.id,
            Actor::System,
            NewScope {
                name: "read:users".into(),
                ..Default::default()
            }
        )
        .await,
        Err(AppError::Conflict(_))
    ));
    assert!(matches!(
        scopes::create(
            &app.state,
            app.tenant.id,
            Actor::System,
            NewScope {
                name: "bad scope".into(),
                ..Default::default()
            }
        )
        .await,
        Err(AppError::BadRequest(_))
    ));
    let openid = list.iter().find(|s| s.name == "openid").unwrap();
    assert!(matches!(
        scopes::delete(&app.state, app.tenant.id, Actor::System, openid.id).await,
        Err(AppError::BadRequest(_))
    ));
    scopes::delete(&app.state, app.tenant.id, Actor::System, custom.id)
        .await
        .unwrap();
    let (known, unknown) = scopes::resolve(
        &app.state,
        app.tenant.id,
        &["openid".into(), "read:users".into()],
    )
    .await
    .unwrap();
    assert_eq!(known.len(), 1);
    assert_eq!(unknown, vec!["read:users"]);
}

#[tokio::test]
async fn client_types_get_sensible_defaults() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let mk = |t: ClientType, redirect: bool| NewClient {
        name: format!("{t:?} app"),
        client_type: Some(t),
        redirect_uris: if redirect {
            vec!["https://app.example/cb".into()]
        } else {
            vec![]
        },
        ..Default::default()
    };

    let spa = clients::create(&app.state, tid, Actor::System, mk(ClientType::Spa, true))
        .await
        .unwrap();
    assert!(spa.client_secret.is_none());
    assert_eq!(
        spa.client.token_endpoint_auth_method,
        TokenEndpointAuthMethod::None
    );
    assert!(spa.client.require_pkce);
    assert_eq!(
        spa.client.allowed_grants,
        vec![grants::AUTHORIZATION_CODE, grants::REFRESH_TOKEN]
    );
    assert_eq!(spa.client.allowed_scopes.len(), STANDARD_SCOPES.len());
    assert!(clients::is_valid_client_id(&spa.client.client_id));

    let web = clients::create(&app.state, tid, Actor::System, mk(ClientType::Web, true))
        .await
        .unwrap();
    let secret = web
        .client_secret
        .clone()
        .expect("confidential client gets a secret");
    assert!(secret.starts_with("cs_"));
    assert_eq!(
        web.client.token_endpoint_auth_method,
        TokenEndpointAuthMethod::ClientSecretBasic
    );
    assert!(clients::verify_secret(&web.client, &secret));
    assert!(!clients::verify_secret(&web.client, "cs_wrong"));
    let json = serde_json::to_value(&web.client).unwrap();
    assert!(
        json.get("secret_hashes").is_none(),
        "hashes never serialize"
    );

    let machine = clients::create(
        &app.state,
        tid,
        Actor::System,
        mk(ClientType::Machine, false),
    )
    .await
    .unwrap();
    assert_eq!(
        machine.client.allowed_grants,
        vec![grants::CLIENT_CREDENTIALS]
    );
    assert!(!machine.client.require_pkce);
    assert!(machine.client.allowed_scopes.is_empty());

    let device = clients::create(
        &app.state,
        tid,
        Actor::System,
        mk(ClientType::Device, false),
    )
    .await
    .unwrap();
    assert_eq!(
        device.client.allowed_grants,
        vec![grants::DEVICE_CODE, grants::REFRESH_TOKEN]
    );

    // Validation.
    let bad = |input: NewClient| {
        let st = app.state.clone();
        async move {
            let r = clients::create(&st, tid, Actor::System, input).await;
            assert!(matches!(r, Err(AppError::BadRequest(_))), "{r:?}");
        }
    };
    bad(mk(ClientType::Web, false)).await; // no redirect uri
    bad(NewClient {
        redirect_uris: vec!["http://app.example/cb".into()],
        ..mk(ClientType::Web, false)
    })
    .await;
    bad(NewClient {
        client_id: Some("bad id!".into()),
        ..mk(ClientType::Web, true)
    })
    .await;
    bad(NewClient {
        token_endpoint_auth_method: Some(TokenEndpointAuthMethod::None),
        allowed_grants: Some(vec![grants::CLIENT_CREDENTIALS.into()]),
        ..mk(ClientType::Machine, false)
    })
    .await;
    bad(NewClient {
        token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
        ..mk(ClientType::Web, true)
    })
    .await;
    bad(NewClient {
        allowed_grants: Some(vec!["password".into()]),
        ..mk(ClientType::Web, true)
    })
    .await;
    bad(NewClient {
        cors_origins: vec!["https://app.example/path".into()],
        ..mk(ClientType::Spa, true)
    })
    .await;

    let dup = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some(spa.client.client_id.clone()),
            ..mk(ClientType::Web, true)
        },
    )
    .await;
    assert!(matches!(dup, Err(AppError::Conflict(_))));
}

#[tokio::test]
async fn secret_rotation_grace_and_cached_lookup() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let created = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            name: "api".into(),
            client_type: Some(ClientType::Machine),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let first = created.client_secret.unwrap();
    let id = created.client.id;

    let found = clients::find_by_client_id(&app.state, tid, &created.client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.id, id);
    assert!(
        clients::find_by_client_id(&app.state, tid, "does-not-exist")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        clients::find_by_client_id(&app.state, tid, "bad id")
            .await
            .unwrap()
            .is_none()
    );

    let (rotated, second) = clients::rotate_secret(&app.state, tid, Actor::System, id)
        .await
        .unwrap();
    assert_eq!(rotated.secret_hashes.len(), 2);
    assert!(clients::verify_secret(&rotated, &second));
    assert!(
        clients::verify_secret(&rotated, &first),
        "old secret works during grace"
    );
    let old = rotated
        .secret_hashes
        .iter()
        .find(|h| h.expires_at.is_some())
        .unwrap();
    assert!(old.expires_at.unwrap() > chrono::Utc::now());
    // Cache reflects the rotation.
    let cached = clients::find_by_client_id(&app.state, tid, &rotated.client_id)
        .await
        .unwrap()
        .unwrap();
    assert!(clients::verify_secret(&cached, &second));

    // A third rotation drops the oldest secret; only two ever exist.
    let (again, third) = clients::rotate_secret(&app.state, tid, Actor::System, id)
        .await
        .unwrap();
    assert_eq!(again.secret_hashes.len(), 2);
    assert!(!clients::verify_secret(&again, &first));
    assert!(clients::verify_secret(&again, &second));
    assert!(clients::verify_secret(&again, &third));

    let only = clients::revoke_old_secrets(&app.state, tid, Actor::System, id)
        .await
        .unwrap();
    assert_eq!(only.secret_hashes.len(), 1);
    assert!(!clients::verify_secret(&only, &second));
    assert!(clients::verify_secret(&only, &third));

    // Public clients have no secret to rotate.
    let spa = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            name: "spa".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://a.example/cb".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        clients::rotate_secret(&app.state, tid, Actor::System, spa.client.id).await,
        Err(AppError::BadRequest(_))
    ));

    let disabled = clients::set_status(&app.state, tid, Actor::System, id, ClientStatus::Disabled)
        .await
        .unwrap();
    assert!(!disabled.is_active());
    assert!(
        !clients::find_by_client_id(&app.state, tid, &disabled.client_id)
            .await
            .unwrap()
            .unwrap()
            .is_active()
    );

    let page = clients::list(&app.state, tid, Some("API"), None, None)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    clients::delete(&app.state, tid, Actor::System, id)
        .await
        .unwrap();
    assert!(
        clients::find_by_client_id(&app.state, tid, &disabled.client_id)
            .await
            .unwrap()
            .is_none()
    );

    // Isolation.
    let other = common::create_tenant(&app.state.db).await;
    assert!(
        clients::find_by_client_id(&app.state, other.id, &spa.client.client_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        clients::get(&app.state, other.id, spa.client.id).await,
        Err(AppError::NotFound(_))
    ));
}

#[tokio::test]
async fn consents_merge_and_revoke() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
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
    let client = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            name: "app".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://a.example/cb".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .client;
    let req: Vec<String> = ["openid", "profile", "email"].map(String::from).to_vec();

    assert_eq!(
        consents::missing_scopes(&app.state, tid, user.id, client.id, &req)
            .await
            .unwrap(),
        req
    );
    consents::grant(&app.state, tid, user.id, client.id, &req[..2])
        .await
        .unwrap();
    assert_eq!(
        consents::missing_scopes(&app.state, tid, user.id, client.id, &req)
            .await
            .unwrap(),
        vec!["email"]
    );
    let merged = consents::grant(&app.state, tid, user.id, client.id, &["email".into()])
        .await
        .unwrap();
    let mut s = merged.scopes.clone();
    s.sort();
    assert_eq!(s, vec!["email", "openid", "profile"]);
    assert!(
        consents::missing_scopes(&app.state, tid, user.id, client.id, &req)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        consents::list_for_user(&app.state, tid, user.id)
            .await
            .unwrap()
            .len(),
        1
    );

    assert!(
        consents::revoke(&app.state, tid, Actor::System, user.id, client.id)
            .await
            .unwrap()
    );
    assert!(
        !consents::revoke(&app.state, tid, Actor::System, user.id, client.id)
            .await
            .unwrap()
    );
    assert_eq!(
        consents::missing_scopes(&app.state, tid, user.id, client.id, &req)
            .await
            .unwrap(),
        req
    );
    assert!(
        consents::list_for_user(&app.state, tid, user.id)
            .await
            .unwrap()
            .is_empty()
    );
    // Re-granting un-revokes.
    consents::grant(&app.state, tid, user.id, client.id, &req)
        .await
        .unwrap();
    assert!(
        consents::missing_scopes(&app.state, tid, user.id, client.id, &req)
            .await
            .unwrap()
            .is_empty()
    );
}
