//! A shared Keycloak for the SAML interoperability tests.
//!
//! testcontainers starts `quay.io/keycloak/keycloak` in dev mode once per
//! test binary as a named, reusable container (`ridm-test-keycloak`; remove
//! it with `docker rm -f ridm-test-keycloak`). Every test works in its own
//! realm (`r-…`) and never sees another's users, clients or providers; the
//! next run's first test deletes them.
//!
//! Keycloak is reached as `localhost` while the test server listens on
//! `127.0.0.1`: cookies ignore ports, so two different host names keep the
//! browser's two cookie jars apart. In dev mode Keycloak builds its URLs
//! from the request, so its metadata names `localhost` too.

use std::time::{Duration, Instant};

use reqwest::Method;
use serde_json::{Value, json};
use testcontainers::core::{ContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt, ReuseDirective};
use tokio::sync::OnceCell;
use uuid::Uuid;

pub const IMAGE: &str = "quay.io/keycloak/keycloak";
pub const TAG: &str = "26.7.4";
const ADMIN: &str = "admin";
const ADMIN_PASSWORD: &str = "admin-Passw0rd";
/// The password of every user [`Realm::user`] makes.
pub const USER_PASSWORD: &str = "correct-horse-battery";

pub struct Keycloak {
    pub base_url: String,
    http: reqwest::Client,
    /// The admin token and when it was issued: master-realm tokens live a
    /// minute, and every test asking for its own trips Keycloak up.
    token: tokio::sync::Mutex<Option<(String, Instant)>>,
    _container: ContainerAsync<GenericImage>,
}

static KEYCLOAK: OnceCell<Keycloak> = OnceCell::const_new();

pub async fn keycloak() -> &'static Keycloak {
    KEYCLOAK
        .get_or_init(|| async { super::RT.spawn(start()).await.expect("keycloak init") })
        .await
}

async fn start() -> Keycloak {
    let container = GenericImage::new(IMAGE, TAG)
        .with_exposed_port(ContainerPort::Tcp(8080))
        .with_wait_for(WaitFor::message_on_stdout("Listening on:"))
        .with_env_var("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN)
        .with_env_var("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
        .with_cmd(["start-dev"])
        .with_container_name("ridm-test-keycloak")
        .with_label("dev.ridm.test", "true")
        .with_reuse(ReuseDirective::Always)
        .with_startup_timeout(Duration::from_secs(180))
        .start()
        .await
        .expect("start keycloak container");
    let port = container
        .get_host_port_ipv4(8080)
        .await
        .expect("keycloak port");
    let kc = Keycloak {
        base_url: format!("http://localhost:{port}"),
        // No idle connections: one opened on a finished test's runtime dies
        // with it, and the next test to pick it up fails.
        http: reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .build()
            .unwrap(),
        token: tokio::sync::Mutex::new(None),
        _container: container,
    };
    let mut ready = false;
    for _ in 0..120 {
        if kc.new_token().await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(ready, "Keycloak never issued an admin token");
    // A reused container still holds the realms of earlier runs.
    let (_, _, realms) = kc.call(Method::GET, "", None).await;
    for realm in realms.as_array().into_iter().flatten() {
        if let Some(name) = realm["realm"].as_str().filter(|n| n.starts_with("r-")) {
            kc.call(Method::DELETE, &format!("/{name}"), None).await;
        }
    }
    kc
}

impl Keycloak {
    /// A current admin token (renewed after 30 s, retried on failure).
    async fn token(&self) -> String {
        let mut held = self.token.lock().await;
        if let Some((token, at)) = held.as_ref()
            && at.elapsed() < Duration::from_secs(30)
        {
            return token.clone();
        }
        let mut last = String::new();
        for _ in 0..10 {
            match self.new_token().await {
                Ok(token) => {
                    *held = Some((token.clone(), Instant::now()));
                    return token;
                }
                Err(e) => last = e,
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        panic!("no Keycloak admin token: {last}");
    }

    async fn new_token(&self) -> Result<String, String> {
        let res = self
            .http
            .post(format!(
                "{}/realms/master/protocol/openid-connect/token",
                self.base_url
            ))
            .form(&[
                ("grant_type", "password"),
                ("client_id", "admin-cli"),
                ("username", ADMIN),
                ("password", ADMIN_PASSWORD),
            ])
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let text = res.text().await.map_err(|e| e.to_string())?;
        serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|b| b["access_token"].as_str().map(str::to_string))
            .ok_or(text)
    }

    /// An admin REST call (`/admin/realms…`): the status, the `Location`
    /// header, and the JSON body (`Null` when empty or not JSON).
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> (u16, Option<String>, Value) {
        let token = self.token().await;
        let mut req = self
            .http
            .request(method, format!("{}/admin/realms{path}", self.base_url))
            .bearer_auth(token);
        if let Some(b) = body {
            req = req.json(b);
        }
        let res = req.send().await.expect("keycloak admin call");
        let status = res.status().as_u16();
        let location = res
            .headers()
            .get("location")
            .map(|l| l.to_str().unwrap().to_string());
        let text = res.text().await.unwrap();
        (
            status,
            location,
            serde_json::from_str(&text).unwrap_or(Value::Null),
        )
    }

    /// A fresh realm over plain HTTP.
    pub async fn realm(&self) -> Realm<'_> {
        let name = format!("r-{}", &Uuid::new_v4().simple().to_string()[..12]);
        let (s, _, body) = self
            .call(
                Method::POST,
                "",
                Some(&json!({"realm": name, "enabled": true, "sslRequired": "none"})),
            )
            .await;
        assert_eq!(s, 201, "create realm: {body}");
        Realm { kc: self, name }
    }
}

pub struct Realm<'a> {
    pub kc: &'a Keycloak,
    pub name: String,
}

impl Realm<'_> {
    /// `{base}/realms/{realm}{path}`: the realm's public URLs.
    pub fn url(&self, path: &str) -> String {
        format!("{}/realms/{}{path}", self.kc.base_url, self.name)
    }

    /// An admin call under `/admin/realms/{realm}`.
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> (u16, Option<String>, Value) {
        self.kc
            .call(method, &format!("/{}{path}", self.name), body)
            .await
    }

    /// An admin call that must succeed; its body.
    pub async fn ok(&self, method: Method, path: &str, body: Option<&Value>) -> Value {
        let (s, _, out) = self.call(method.clone(), path, body).await;
        assert!((200..300).contains(&s), "{method} {path}: {s} {out}");
        out
    }

    /// Keycloak's reading of an SP's metadata: the client it would create.
    pub async fn client_from_metadata(&self, xml: &str) -> Value {
        let token = self.kc.token().await;
        let res = self
            .kc
            .http
            .post(format!(
                "{}/admin/realms/{}/client-description-converter",
                self.kc.base_url, self.name
            ))
            .bearer_auth(token)
            .header("content-type", "text/plain")
            .body(xml.to_string())
            .send()
            .await
            .expect("convert client metadata");
        assert_eq!(res.status(), 200);
        res.json().await.unwrap()
    }

    /// A user with a password; returns its id.
    pub async fn user(&self, username: &str, email: &str, first: &str, last: &str) -> String {
        let (s, location, body) = self
            .call(
                Method::POST,
                "/users",
                Some(&json!({
                    "username": username,
                    "email": email,
                    "emailVerified": true,
                    "firstName": first,
                    "lastName": last,
                    "enabled": true,
                    "credentials": [{"type": "password", "value": USER_PASSWORD, "temporary": false}],
                })),
            )
            .await;
        assert_eq!(s, 201, "create user: {body}");
        location.unwrap().rsplit('/').next().unwrap().to_string()
    }

    /// The one user with this email, as Keycloak stores it.
    pub async fn user_by_email(&self, email: &str) -> Option<Value> {
        let found = self
            .ok(
                Method::GET,
                &format!("/users?email={}&exact=true", urlencoding(email)),
                None,
            )
            .await;
        found.as_array().unwrap().first().cloned()
    }

    /// How many sessions the user has open in the realm.
    pub async fn session_count(&self, user_id: &str) -> usize {
        self.ok(Method::GET, &format!("/users/{user_id}/sessions"), None)
            .await
            .as_array()
            .unwrap()
            .len()
    }
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
