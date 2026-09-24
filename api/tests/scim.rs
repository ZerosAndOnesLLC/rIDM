//! SCIM 2.0: discovery documents, bearer tokens per tenant, user and group
//! lifecycle with filters, PUT and PATCH semantics, pagination, and refusals.

mod common;

use common::TestApp;
use common::admin::{admin_token, call};
use reqwest::{Method, Response, StatusCode};
use ridm_api::models::{NewGroup, NewScimToken, NewUser};
use ridm_api::services::admin_access::{ADMIN_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE};
use ridm_api::services::{groups, scim_tokens, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

struct Fx {
    app: TestApp,
    token: String,
}

async fn fixture() -> Fx {
    let app = TestApp::spawn().await;
    let created = scim_tokens::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewScimToken {
            name: "entra".into(),
            expires_in_days: None,
        },
    )
    .await
    .unwrap();
    Fx {
        app,
        token: created.token,
    }
}

impl Fx {
    fn base(&self) -> String {
        self.app.url(&format!("/scim/v2/{}", self.app.tenant.slug))
    }

    async fn req(&self, method: Method, path: &str, body: Option<Value>) -> Response {
        let mut r = self
            .app
            .http
            .request(method, format!("{}{path}", self.base()))
            .bearer_auth(&self.token);
        if let Some(b) = body {
            r = r
                .header("content-type", "application/scim+json")
                .body(serde_json::to_vec(&b).unwrap());
        }
        r.send().await.unwrap()
    }

    async fn json(&self, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let res = self.req(method, path, body).await;
        let status = res.status();
        assert_eq!(
            res.headers()["content-type"].to_str().unwrap(),
            "application/scim+json",
            "{path}"
        );
        (status, res.json().await.unwrap())
    }
}

fn user_doc(name: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": name,
        "externalId": format!("ext-{name}"),
        "name": { "givenName": "Ann", "familyName": "Lee" },
        "displayName": "Ann Lee",
        "emails": [{ "value": format!("{name}@example.com"), "type": "work", "primary": true }],
        "phoneNumbers": [{ "value": "+14155550100", "type": "work" }],
        "active": true,
        "locale": "en"
    })
}

#[tokio::test]
async fn discovery_documents_and_token_rules() {
    let fx = fixture().await;
    let (status, spc) = fx.json(Method::GET, "/ServiceProviderConfig", None).await;
    assert_eq!(status, 200);
    assert_eq!(spc["patch"]["supported"], true);
    assert_eq!(spc["bulk"]["supported"], false);
    assert_eq!(spc["filter"]["maxResults"], 200);
    let (_, types) = fx.json(Method::GET, "/ResourceTypes", None).await;
    let names: Vec<&str> = types
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["User", "Group"]);
    let (_, schemas) = fx.json(Method::GET, "/Schemas", None).await;
    assert_eq!(schemas.as_array().unwrap().len(), 2);

    // No token, a bad token, a revoked token, another tenant's token.
    let res = fx
        .app
        .http
        .get(format!("{}/Users", fx.base()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    assert!(
        res.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("scim")
    );
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:Error"
    );
    assert_eq!(body["status"], "401");
    let res = fx
        .app
        .http
        .get(format!("{}/Users", fx.base()))
        .bearer_auth("rscim_nope")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let other = common::create_tenant(&fx.app.state.db).await;
    let res = fx
        .app
        .http
        .get(fx.app.url(&format!("/scim/v2/{}/Users", other.slug)))
        .bearer_auth(&fx.token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let tokens = scim_tokens::list(
        &fx.app.state,
        &ridm_api::services::tenants::get(&fx.app.state, fx.app.tenant.id)
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(tokens.base_url, fx.base());
    scim_tokens::revoke(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        tokens.tokens[0].id,
    )
    .await
    .unwrap();
    let res = fx.req(Method::GET, "/Users", None).await;
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn user_lifecycle_with_filters_put_and_patch() {
    let fx = fixture().await;
    let (status, created) = fx.json(Method::POST, "/Users", Some(user_doc("ann"))).await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["userName"], "ann");
    assert_eq!(created["externalId"], "ext-ann");
    assert_eq!(created["emails"][0]["value"], "ann@example.com");
    assert_eq!(created["phoneNumbers"][0]["value"], "+14155550100");
    assert_eq!(created["active"], true);
    assert_eq!(created["meta"]["resourceType"], "User");
    assert_eq!(
        created["meta"]["location"],
        format!("{}/Users/{id}", fx.base())
    );
    // Name attributes are dropped unless the profile schema declares them (the
    // default schema does not), so the document carries none back.
    assert!(created.get("name").is_none() || created["name"]["givenName"].is_null());

    // Duplicate userName.
    let (status, dup) = fx.json(Method::POST, "/Users", Some(user_doc("ann"))).await;
    assert_eq!(status, 409, "{dup}");
    assert_eq!(dup["scimType"], "uniqueness");
    // Missing userName.
    let (status, bad) = fx
        .json(Method::POST, "/Users", Some(json!({ "active": true })))
        .await;
    assert_eq!(status, 400);
    assert_eq!(bad["scimType"], "invalidValue");

    // Filters: indexed and scanned.
    for f in [
        "userName eq \"ann\"",
        "userName eq \"ANN\"",
        "externalId eq \"ext-ann\"",
        "emails.value eq \"ann@example.com\"",
        "emails eq \"ann@example.com\"",
        &format!("id eq \"{id}\""),
        "userName sw \"an\" and active eq true",
        "emails[type eq \"work\"].value co \"example\"",
    ] {
        let (status, list) = fx
            .json(
                Method::GET,
                &format!("/Users?filter={}", urlencoding(f)),
                None,
            )
            .await;
        assert_eq!(status, 200, "{f}: {list}");
        assert_eq!(list["totalResults"], 1, "{f}: {list}");
        assert_eq!(list["Resources"][0]["id"], id, "{f}");
    }
    let (_, none) = fx
        .json(
            Method::GET,
            "/Users?filter=userName%20eq%20%22nobody%22",
            None,
        )
        .await;
    assert_eq!(none["totalResults"], 0);
    let (status, bad) = fx
        .json(Method::GET, "/Users?filter=userName%20zz%20%22x%22", None)
        .await;
    assert_eq!(status, 400);
    assert_eq!(bad["scimType"], "invalidFilter");

    // GET by id, unknown id.
    let (status, got) = fx.json(Method::GET, &format!("/Users/{id}"), None).await;
    assert_eq!(status, 200);
    assert_eq!(got["userName"], "ann");
    let (status, _) = fx
        .json(Method::GET, &format!("/Users/{}", Uuid::new_v4()), None)
        .await;
    assert_eq!(status, 404);

    // PATCH: deactivate with a string boolean under a schema-prefixed path,
    // change the email through a filtered path, add a phone number.
    let (status, patched) = fx
        .json(
            Method::PATCH,
            &format!("/Users/{id}"),
            Some(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    { "op": "Replace", "path": "urn:ietf:params:scim:schemas:core:2.0:User:active", "value": "False" },
                    { "op": "replace", "path": "emails[type eq \"work\"].value", "value": "ann.lee@example.com" },
                    { "op": "add", "value": { "locale": "de" } }
                ]
            })),
        )
        .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["active"], false);
    assert_eq!(patched["emails"][0]["value"], "ann.lee@example.com");
    assert_eq!(patched["locale"], "de");
    let u = users::get(&fx.app.state, fx.app.tenant.id, id.parse().unwrap())
        .await
        .unwrap();
    assert_eq!(u.status, ridm_api::models::UserStatus::Disabled);
    assert_eq!(u.email.as_deref(), Some("ann.lee@example.com"));

    // PATCH refusals.
    let (status, bad) = fx
        .json(
            Method::PATCH,
            &format!("/Users/{id}"),
            Some(json!({ "Operations": [] })),
        )
        .await;
    assert_eq!(status, 400);
    assert_eq!(bad["scimType"], "invalidSyntax");
    let (status, bad) = fx
        .json(
            Method::PATCH,
            &format!("/Users/{id}"),
            Some(json!({ "Operations": [{ "op": "replace", "path": "emails[type eq \"home\"].value", "value": "x" }] })),
        )
        .await;
    assert_eq!(status, 400);
    assert_eq!(bad["scimType"], "noTarget");

    // PUT replaces: no phone, active again, new external id.
    let (status, put) = fx
        .json(
            Method::PUT,
            &format!("/Users/{id}"),
            Some(json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "ann", "externalId": "ext-2", "active": true,
                "emails": [{ "value": "ann@example.com" }]
            })),
        )
        .await;
    assert_eq!(status, 200, "{put}");
    assert_eq!(put["active"], true);
    assert_eq!(put["externalId"], "ext-2");
    assert!(put.get("phoneNumbers").is_none());
    assert!(put.get("locale").is_none());

    // DELETE soft-deletes; the user is gone from SCIM.
    let res = fx.req(Method::DELETE, &format!("/Users/{id}"), None).await;
    assert_eq!(res.status(), 204);
    let (status, _) = fx.json(Method::GET, &format!("/Users/{id}"), None).await;
    assert_eq!(status, 404);
    let (_, list) = fx
        .json(Method::GET, "/Users?filter=userName%20eq%20%22ann%22", None)
        .await;
    assert_eq!(list["totalResults"], 0);
}

#[tokio::test]
async fn the_filter_grammar_and_patch_removals_work_over_http() {
    let fx = fixture().await;
    for name in ["ann", "bob"] {
        let (status, created) = fx.json(Method::POST, "/Users", Some(user_doc(name))).await;
        assert_eq!(status, 201, "{created}");
    }
    // Deactivate bob so the combinators have something to separate.
    let (_, list) = fx
        .json(Method::GET, "/Users?filter=userName%20eq%20%22bob%22", None)
        .await;
    let bob = list["Resources"][0]["id"].as_str().unwrap().to_string();
    let (status, _) = fx
        .json(
            Method::PATCH,
            &format!("/Users/{bob}"),
            Some(json!({ "Operations": [{ "op": "replace", "path": "active", "value": false }] })),
        )
        .await;
    assert_eq!(status, 200);

    // Every combinator the parser accepts, evaluated by the scan path.
    let names = |list: &Value| -> Vec<String> {
        let mut n: Vec<String> = list["Resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["userName"].as_str().unwrap().to_string())
            .collect();
        n.sort();
        n
    };
    for (filter, expected) in [
        (
            "userName eq \"ann\" or userName eq \"bob\"",
            vec!["ann", "bob"],
        ),
        ("not (userName eq \"bob\")", vec!["ann"]),
        ("userName pr and active eq true", vec!["ann"]),
        ("userName ne \"ann\"", vec!["bob"]),
        (
            "(userName sw \"a\" or userName sw \"b\") and active eq false",
            vec!["bob"],
        ),
        (
            "emails[type eq \"work\"].value ew \"@example.com\"",
            vec!["ann", "bob"],
        ),
        ("locale eq \"en\" and not (active eq false)", vec!["ann"]),
        ("userName gt \"ann\"", vec!["bob"]),
        (
            "externalId co \"ext-\" and userName le \"ann\"",
            vec!["ann"],
        ),
    ] {
        let (status, list) = fx
            .json(
                Method::GET,
                &format!("/Users?filter={}", urlencoding(filter)),
                None,
            )
            .await;
        assert_eq!(status, 200, "{filter}: {list}");
        assert_eq!(names(&list), expected, "{filter}: {list}");
        assert_eq!(list["totalResults"], expected.len() as i64, "{filter}");
    }
    // Grammar refusals, each as an `invalidFilter`.
    for bad in [
        "userName eq",
        "(userName eq \"a\"",
        "userName eq \"a\" and",
        "not userName eq \"a\"",
        "emails[type eq \"work\".value eq \"x\"",
    ] {
        let (status, body) = fx
            .json(
                Method::GET,
                &format!("/Users?filter={}", urlencoding(bad)),
                None,
            )
            .await;
        assert_eq!(status, 400, "{bad}: {body}");
        assert_eq!(body["scimType"], "invalidFilter", "{bad}");
    }

    // PATCH `remove` (RFC 7644 §3.5.2): a whole attribute, and one element of
    // a multi-valued attribute selected by a filter.
    let (_, list) = fx
        .json(Method::GET, "/Users?filter=userName%20eq%20%22ann%22", None)
        .await;
    let ann = list["Resources"][0]["id"].as_str().unwrap().to_string();
    let (status, patched) = fx
        .json(
            Method::PATCH,
            &format!("/Users/{ann}"),
            Some(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    { "op": "add", "path": "emails", "value": [{ "value": "ann@home.example", "type": "home" }] },
                    { "op": "remove", "path": "phoneNumbers" }
                ]
            })),
        )
        .await;
    assert_eq!(status, 200, "{patched}");
    assert!(patched.get("phoneNumbers").is_none(), "{patched}");
    let (status, patched) = fx
        .json(
            Method::PATCH,
            &format!("/Users/{ann}"),
            Some(json!({
                "Operations": [
                    { "op": "remove", "path": "emails[type eq \"home\"]" }
                ]
            })),
        )
        .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["emails"].as_array().unwrap().len(), 1, "{patched}");
    assert_eq!(patched["emails"][0]["value"], "ann@example.com");
    // A `remove` needs something to remove, and an unknown op is a syntax error.
    let (status, bad) = fx
        .json(
            Method::PATCH,
            &format!("/Users/{ann}"),
            Some(json!({ "Operations": [{ "op": "remove" }] })),
        )
        .await;
    assert_eq!(status, 400, "{bad}");
    assert_eq!(bad["scimType"], "noTarget");
    let (status, bad) = fx
        .json(
            Method::PATCH,
            &format!("/Users/{ann}"),
            Some(json!({ "Operations": [{ "op": "merge", "path": "locale", "value": "de" }] })),
        )
        .await;
    assert_eq!(status, 400, "{bad}");
    assert_eq!(bad["scimType"], "invalidSyntax");
}

#[tokio::test]
async fn listing_pages_through_users() {
    let fx = fixture().await;
    for i in 0..7 {
        users::create(
            &fx.app.state,
            fx.app.tenant.id,
            Actor::System,
            NewUser {
                username: format!("u{i}"),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    let (status, page) = fx
        .json(Method::GET, "/Users?startIndex=1&count=3", None)
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        page["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    );
    assert_eq!(page["totalResults"], 7);
    assert_eq!(page["startIndex"], 1);
    assert_eq!(page["itemsPerPage"], 3);
    let first: Vec<String> = page["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["userName"].as_str().unwrap().to_string())
        .collect();
    let (_, page2) = fx
        .json(Method::GET, "/Users?startIndex=4&count=3", None)
        .await;
    let second: Vec<String> = page2["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["userName"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(second.len(), 3);
    assert!(
        first.iter().all(|u| !second.contains(u)),
        "pages do not overlap"
    );
    let (_, page3) = fx
        .json(Method::GET, "/Users?startIndex=7&count=3", None)
        .await;
    assert_eq!(page3["itemsPerPage"], 1);
    assert_eq!(page3["totalResults"], 7);
    // Each user on a page carries its groups (read for the page at once).
    let last = page3["Resources"][0]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let g = groups::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewGroup {
            name: "paged".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    groups::add_member(&fx.app.state, fx.app.tenant.id, Actor::System, g.id, last)
        .await
        .unwrap();
    let (_, page3) = fx
        .json(Method::GET, "/Users?startIndex=7&count=3", None)
        .await;
    assert_eq!(page3["Resources"][0]["groups"][0]["display"], "paged");
    let (_, all) = fx.json(Method::GET, "/Users?count=1000", None).await;
    assert_eq!(
        all["itemsPerPage"], 7,
        "count is clamped to 200 and everything fits"
    );
    let (status, far) = fx.json(Method::GET, "/Users?startIndex=999999", None).await;
    assert_eq!(status, 400);
    assert_eq!(far["scimType"], "tooMany");
}

#[tokio::test]
async fn group_lifecycle_with_members() {
    let fx = fixture().await;
    let (_, a) = fx.json(Method::POST, "/Users", Some(user_doc("a"))).await;
    let (_, b) = fx.json(Method::POST, "/Users", Some(user_doc("b"))).await;
    let (a, b) = (
        a["id"].as_str().unwrap().to_string(),
        b["id"].as_str().unwrap().to_string(),
    );

    let (status, g) = fx
        .json(
            Method::POST,
            "/Groups",
            Some(json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": "Engineering", "externalId": "grp-1",
                "members": [{ "value": a }]
            })),
        )
        .await;
    assert_eq!(status, 201, "{g}");
    let gid = g["id"].as_str().unwrap().to_string();
    assert_eq!(g["displayName"], "Engineering");
    assert_eq!(g["externalId"], "grp-1");
    assert_eq!(g["members"].as_array().unwrap().len(), 1);
    assert_eq!(g["members"][0]["value"], a);
    assert_eq!(g["members"][0]["$ref"], format!("{}/Users/{a}", fx.base()));

    // The user's document lists the group.
    let (_, ua) = fx.json(Method::GET, &format!("/Users/{a}"), None).await;
    assert_eq!(ua["groups"][0]["value"], gid);
    assert_eq!(ua["groups"][0]["display"], "Engineering");

    // Filter by displayName and externalId.
    let (_, list) = fx
        .json(
            Method::GET,
            "/Groups?filter=displayName%20eq%20%22engineering%22",
            None,
        )
        .await;
    assert_eq!(list["totalResults"], 1);
    let (_, list) = fx
        .json(
            Method::GET,
            "/Groups?filter=externalId%20eq%20%22grp-1%22",
            None,
        )
        .await;
    assert_eq!(list["totalResults"], 1);
    let (_, list) = fx
        .json(
            Method::GET,
            "/Groups?filter=displayName%20eq%20%22nope%22",
            None,
        )
        .await;
    assert_eq!(list["totalResults"], 0);

    // excludedAttributes=members leaves the members out of a get and a list,
    // and a PATCH still sees them (a is kept until removed below).
    let (_, lean) = fx
        .json(
            Method::GET,
            &format!("/Groups/{gid}?excludedAttributes=members"),
            None,
        )
        .await;
    assert_eq!(lean["displayName"], "Engineering");
    assert!(lean.get("members").is_none(), "{lean}");
    let (_, list) = fx
        .json(Method::GET, "/Groups?excludedAttributes=members", None)
        .await;
    assert_eq!(list["totalResults"], 1);
    assert!(list["Resources"][0].get("members").is_none(), "{list}");
    let (_, list) = fx.json(Method::GET, "/Groups", None).await;
    assert_eq!(list["Resources"][0]["members"][0]["value"], a);
    // A filter on members reads them, excluded from the answer or not.
    let (_, list) = fx
        .json(
            Method::GET,
            &format!(
                "/Groups?excludedAttributes=members&filter={}",
                urlencoding(&format!("members.value eq \"{a}\""))
            ),
            None,
        )
        .await;
    assert_eq!(list["totalResults"], 1, "{list}");
    assert!(list["Resources"][0].get("members").is_none(), "{list}");

    // PATCH members: add b, remove a; rename.
    let (status, patched) = fx
        .json(
            Method::PATCH,
            &format!("/Groups/{gid}"),
            Some(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    { "op": "add", "path": "members", "value": [{ "value": b }] },
                    { "op": "remove", "path": format!("members[value eq \"{a}\"]") },
                    { "op": "replace", "value": { "displayName": "Platform" } }
                ]
            })),
        )
        .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["displayName"], "Platform");
    let members: Vec<&str> = patched["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["value"].as_str().unwrap())
        .collect();
    assert_eq!(members, [b.as_str()]);

    // An unknown member is refused.
    let (status, bad) = fx
        .json(
            Method::PATCH,
            &format!("/Groups/{gid}"),
            Some(json!({ "Operations": [{ "op": "add", "path": "members", "value": [{ "value": Uuid::new_v4() }] }] })),
        )
        .await;
    assert_eq!(status, 400, "{bad}");

    // PUT with an empty member list empties the group.
    let (status, put) = fx
        .json(
            Method::PUT,
            &format!("/Groups/{gid}"),
            Some(json!({ "displayName": "Platform", "members": [] })),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(put["members"].as_array().unwrap().len(), 0);

    let res = fx
        .req(Method::DELETE, &format!("/Groups/{gid}"), None)
        .await;
    assert_eq!(res.status(), 204);
    let (status, _) = fx.json(Method::GET, &format!("/Groups/{gid}"), None).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn admin_manages_tokens_under_the_scim_permissions() {
    let app = TestApp::spawn().await;
    let base = format!("/admin/tenants/{}/scim/tokens", app.tenant.slug);
    let manager = admin_token(&app, app.tenant.id, USER_MANAGER_ROLE).await;
    let (status, created, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&manager),
        Some(&json!({ "name": "okta", "expires_in_days": 30 })),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let token = created["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("rscim_"));
    assert!(created["expires_at"].is_string());
    let id = created["id"].as_str().unwrap().to_string();

    // The token works against SCIM.
    let res = app
        .http
        .get(app.url(&format!(
            "/scim/v2/{}/ServiceProviderConfig",
            app.tenant.slug
        )))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Listing never returns the token again; viewers may list, not mint.
    let viewer = admin_token(&app, app.tenant.id, VIEWER_ROLE).await;
    let (status, list, _) = call(&app, Method::GET, &base, Some(&viewer), None).await;
    assert_eq!(status, 200, "{list}");
    assert_eq!(list["tokens"][0]["name"], "okta");
    assert!(list["tokens"][0].get("token").is_none());
    assert!(
        list["base_url"]
            .as_str()
            .unwrap()
            .ends_with(&format!("/scim/v2/{}", app.tenant.slug))
    );
    let (status, _, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&viewer),
        Some(&json!({ "name": "x" })),
    )
    .await;
    assert_eq!(status, 403);

    // Validation.
    let (status, _, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&manager),
        Some(&json!({ "name": "" })),
    )
    .await;
    assert_eq!(status, 400);
    let (status, _, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&manager),
        Some(&json!({ "name": "x", "expires_in_days": 0 })),
    )
    .await;
    assert_eq!(status, 400);

    // Revoke: the token stops working at once; revoking twice is 404.
    let admin = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let res = app
        .http
        .get(app.url(&format!(
            "/scim/v2/{}/ServiceProviderConfig",
            app.tenant.slug
        )))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 404);

    // Another tenant's administrator cannot see them.
    let other = common::create_tenant(&app.state.db).await;
    let stranger = admin_token(&app, other.id, ADMIN_ROLE).await;
    let (status, _, _) = call(&app, Method::GET, &base, Some(&stranger), None).await;
    assert_eq!(status, 403);
}

fn urlencoding(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
