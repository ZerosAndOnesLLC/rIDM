//! Phase 13.4: Kerberos interoperability with MIT Kerberos. A container
//! runs a real MIT KDC (realm `EXAMPLE.TEST`) and `python3-gssapi` as the
//! initiator: after `kinit`, MIT's own SPNEGO mechanism builds the
//! Negotiate token a browser on Linux would send (Chrome and Firefox call
//! the same library), the live API accepts it against the keytab the KDC
//! exported, and MIT then checks rIDM's mutual-authentication answer.
//!
//! Needs Docker. It skips without it unless `RIDM_REQUIRE_KDC=1` (CI sets
//! it), which turns a missing Docker into a failure. The image
//! (`ridm-test-kdc:1`, Debian with krb5-kdc and python3-gssapi) is built on
//! first use and kept.
#![cfg(feature = "kerberos")]

mod common;

use std::process::Stdio;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use common::TestApp;
use common::admin::{admin_token, call};
use reqwest::Method;
use ridm_api::models::{ClientType, NewClient, NewUser};
use ridm_api::services::admin_access::OWNER_ROLE;
use ridm_api::services::{clients, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::Command;

const IMAGE: &str = "ridm-test-kdc:1";
const DOCKERFILE: &str = "FROM debian:bookworm-slim\n\
RUN apt-get update \\\n\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \\\n\
    krb5-kdc krb5-admin-server krb5-user python3-gssapi \\\n\
 && rm -rf /var/lib/apt/lists/*\n";

const SPN: &str = "HTTP/sso.example.test@EXAMPLE.TEST";
const ALICE_PW: &str = "Alice-Krb-Pw1";

/// The realm, the service principal (AES-SHA1 keys only: RFC 8009's
/// SHA-2 types, MIT's newer default, are not supported) and its keytab.
const SETUP: &str = r#"set -e
cat > /etc/krb5.conf <<'EOF'
[libdefaults]
  default_realm = EXAMPLE.TEST
  dns_lookup_kdc = false
  dns_lookup_realm = false
  dns_canonicalize_hostname = false
  rdns = false
[realms]
  EXAMPLE.TEST = {
    kdc = 127.0.0.1
    admin_server = 127.0.0.1
  }
[domain_realm]
  .example.test = EXAMPLE.TEST
  sso.example.test = EXAMPLE.TEST
EOF
kdb5_util create -s -r EXAMPLE.TEST -P master-pw >/dev/null
kadmin.local -q "addprinc -pw Alice-Krb-Pw1 alice" >/dev/null
kadmin.local -q "addprinc -randkey -e aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal HTTP/sso.example.test" >/dev/null
kadmin.local -q "ktadd -norandkey -k /tmp/http.keytab HTTP/sso.example.test" >/dev/null
krb5kdc
touch /tmp/ready
exec sleep infinity
"#;

/// MIT's SPNEGO initiator: print the first token, read the acceptor's
/// answer, say whether the context (mutual authentication) completed.
const INITIATOR: &str = r#"
import base64, sys, gssapi
spnego = gssapi.raw.OID.from_int_seq("1.3.6.1.5.5.2")
name = gssapi.Name("HTTP@sso.example.test", gssapi.NameType.hostbased_service)
flags = gssapi.RequirementFlag.mutual_authentication | gssapi.RequirementFlag.out_of_sequence_detection
ctx = gssapi.SecurityContext(name=name, mech=spnego, usage="initiate", flags=flags)
print(base64.b64encode(ctx.step()).decode(), flush=True)
answer = sys.stdin.readline().strip()
try:
    ctx.step(base64.b64decode(answer))
    print("complete" if ctx.complete else "incomplete", flush=True)
except Exception as e:
    print("error: %s" % e, flush=True)
"#;

async fn docker(args: &[&str]) -> Option<String> {
    let out = Command::new("docker").args(args).output().await.ok()?;
    if !out.status.success() {
        eprintln!(
            "docker {}: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Removes the container when the test ends, however it ends.
struct Kdc(String);

impl Drop for Kdc {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &self.0])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

async fn start_kdc() -> Option<Kdc> {
    let required = std::env::var("RIDM_REQUIRE_KDC").as_deref() == Ok("1");
    let skip = |why: &str| {
        assert!(!required, "RIDM_REQUIRE_KDC=1 but {why}");
        eprintln!("skipping the MIT Kerberos test: {why}");
        None
    };
    if docker(&["version", "--format", "{{.Server.Version}}"])
        .await
        .is_none()
    {
        return skip("Docker is not available");
    }
    if docker(&["image", "inspect", IMAGE]).await.is_none() {
        let mut build = Command::new("docker")
            .args(["build", "-t", IMAGE, "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("docker build");
        build
            .stdin
            .take()
            .unwrap()
            .write_all(DOCKERFILE.as_bytes())
            .await
            .unwrap();
        if !build.wait().await.unwrap().success() {
            return skip("the KDC image did not build");
        }
    }
    let id = docker(&["run", "-d", IMAGE, "sh", "-c", SETUP])
        .await
        .expect("docker run");
    let kdc = Kdc(id);
    for _ in 0..120 {
        if docker(&["exec", &kdc.0, "test", "-f", "/tmp/ready"])
            .await
            .is_some()
        {
            return Some(kdc);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let logs = docker(&["logs", &kdc.0]).await.unwrap_or_default();
    panic!("the KDC did not come up: {logs}");
}

#[tokio::test]
async fn mit_kerberos_signs_in_through_spnego_and_verifies_the_answer() {
    let Some(kdc) = start_kdc().await else {
        return;
    };
    let keytab = docker(&["exec", &kdc.0, "base64", "-w0", "/tmp/http.keytab"])
        .await
        .expect("keytab");

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
    users::create(
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
    let token = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let (s, created, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/identity-providers", app.tenant.slug),
        Some(&token),
        Some(&json!({
            "alias": "mit",
            "kind": "kerberos",
            "kerberos": {"keytab": keytab},
        })),
    )
    .await;
    assert_eq!(s, 201, "{created}");
    assert_eq!(created["kerberos"]["service_principal"], SPN);

    // A login flow, as the browser starts it.
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
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let flow = loc
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .unwrap()
        .1
        .into_owned();
    let state: Value = http
        .get(app.tenant_url(&format!("/flows/{flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Alice signs in to the realm, and MIT's SPNEGO builds her token.
    let script =
        format!("echo '{ALICE_PW}' | kinit alice >/dev/null && exec python3 -c '{INITIATOR}'");
    let mut initiator = Command::new("docker")
        .args(["exec", "-i", &kdc.0, "sh", "-c", &script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("docker exec");
    let mut stdin = initiator.stdin.take().unwrap();
    let mut lines = BufReader::new(initiator.stdout.take().unwrap()).lines();
    let negotiate = lines.next_line().await.unwrap().expect("a token from MIT");

    let res = http
        .post(app.tenant_url(&format!("/flows/{flow}/kerberos")))
        .header("Authorization", format!("Negotiate {negotiate}"))
        .json(&json!({"csrf": state["csrf"]}))
        .send()
        .await
        .unwrap();
    let status = res.status();
    let answer = res
        .headers()
        .get("www-authenticate")
        .map(|v| v.to_str().unwrap().to_string());
    let body: Value = res.json().await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["stage"], "done", "{body}");
    assert_eq!(body["user"]["username"], "alice");

    // MIT checks the AP-REP inside rIDM's answer: mutual authentication.
    let answer = answer.expect("a Negotiate answer");
    let answer = answer.strip_prefix("Negotiate ").expect("Negotiate scheme");
    assert!(B64.decode(answer).is_ok());
    stdin
        .write_all(format!("{answer}\n").as_bytes())
        .await
        .unwrap();
    let verdict = lines.next_line().await.unwrap().unwrap_or_default();
    assert_eq!(verdict, "complete", "MIT refused rIDM's answer");
    let _ = initiator.wait().await;
}
