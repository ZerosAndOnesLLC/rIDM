//! A shared OpenLDAP directory for the LDAP tests.
//!
//! testcontainers starts `osixia/openldap` once per test binary as a named,
//! reusable container (`ridm-test-openldap`; remove it with
//! `docker rm -f ridm-test-openldap`), with a server certificate for
//! `localhost` issued by a throwaway CA so LDAPS and StartTLS are tested
//! against a pinned CA. The CA is read back from the container, so a reused
//! container and a new test run agree on it. Every test works under its own
//! `ou=t-…` and never sees another's entries.

use std::collections::HashSet;
use std::time::Duration;

use ldap3::{LdapConnAsync, Mod, Scope, SearchEntry};
use testcontainers::core::{ContainerPort, ExecCommand, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt, ReuseDirective};
use tokio::sync::OnceCell;
use uuid::Uuid;

pub const ADMIN_DN: &str = "cn=admin,dc=example,dc=org";
pub const ADMIN_PASSWORD: &str = "admin-Passw0rd";
pub const ROOT: &str = "dc=example,dc=org";
const CERTS: &str = "/container/service/slapd/assets/certs";

pub struct Directory {
    port: u16,
    tls_port: u16,
    /// The CA the server certificate chains to (PEM).
    pub ca_pem: String,
    _container: ContainerAsync<GenericImage>,
}

impl Directory {
    /// Plain LDAP on loopback (accepted without TLS).
    pub fn url(&self) -> String {
        format!("ldap://127.0.0.1:{}", self.port)
    }

    /// LDAP by the name the certificate carries (for StartTLS).
    pub fn starttls_url(&self) -> String {
        format!("ldap://localhost:{}", self.port)
    }

    /// LDAPS by the name the certificate carries.
    pub fn ldaps_url(&self) -> String {
        format!("ldaps://localhost:{}", self.tls_port)
    }
}

static DIRECTORY: OnceCell<Directory> = OnceCell::const_new();

pub async fn directory() -> &'static Directory {
    DIRECTORY
        .get_or_init(|| async { super::RT.spawn(start()).await.expect("openldap init") })
        .await
}

fn certificates() -> (String, String, String) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "rIDM test CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let key = KeyPair::generate().unwrap();
    let mut params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    let cert = params.signed_by(&key, &issuer).unwrap();
    (ca_cert.pem(), cert.pem(), key.serialize_pem())
}

async fn start() -> Directory {
    let (ca, cert, key) = certificates();
    let container = GenericImage::new("osixia/openldap", "1.5.0")
        .with_exposed_port(ContainerPort::Tcp(389))
        .with_exposed_port(ContainerPort::Tcp(636))
        .with_wait_for(WaitFor::message_on_stderr("slapd starting"))
        .with_env_var("LDAP_ORGANISATION", "Example")
        .with_env_var("LDAP_DOMAIN", "example.org")
        .with_env_var("LDAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
        .with_env_var("LDAP_TLS_VERIFY_CLIENT", "never")
        .with_env_var("LDAP_TLS_CRT_FILENAME", "ldap.crt")
        .with_env_var("LDAP_TLS_KEY_FILENAME", "ldap.key")
        .with_env_var("LDAP_TLS_CA_CRT_FILENAME", "ca.crt")
        .with_copy_to(format!("{CERTS}/ca.crt"), ca.into_bytes())
        .with_copy_to(format!("{CERTS}/ldap.crt"), cert.into_bytes())
        .with_copy_to(format!("{CERTS}/ldap.key"), key.into_bytes())
        .with_container_name("ridm-test-openldap")
        .with_label("dev.ridm.test", "true")
        .with_reuse(ReuseDirective::Always)
        .start()
        .await
        .expect("start openldap container");
    let port = container.get_host_port_ipv4(389).await.expect("ldap port");
    let tls_port = container.get_host_port_ipv4(636).await.expect("ldaps port");
    let mut out = container
        .exec(ExecCommand::new(["cat", &format!("{CERTS}/ca.crt")]))
        .await
        .expect("read the CA");
    let ca_pem = String::from_utf8(out.stdout_to_vec().await.expect("CA bytes")).unwrap();
    let dir = Directory {
        port,
        tls_port,
        ca_pem,
        _container: container,
    };
    // The image starts slapd once to configure itself and again for real:
    // wait until the admin can bind.
    for _ in 0..60 {
        if bind_ok(&dir.url(), ADMIN_DN, ADMIN_PASSWORD).await {
            return dir;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("the OpenLDAP container never accepted the admin bind");
}

async fn connect(url: &str) -> ldap3::Ldap {
    let (conn, ldap) = LdapConnAsync::new(url).await.expect("connect to openldap");
    tokio::spawn(async move {
        let _ = conn.drive().await;
    });
    ldap
}

/// Does a simple bind with these credentials succeed?
pub async fn bind_ok(url: &str, dn: &str, password: &str) -> bool {
    let Ok((conn, mut ldap)) = LdapConnAsync::new(url).await else {
        return false;
    };
    tokio::spawn(async move {
        let _ = conn.drive().await;
    });
    let ok = ldap
        .simple_bind(dn, password)
        .await
        .is_ok_and(|r| r.rc == 0);
    let _ = ldap.unbind().await;
    ok
}

async fn admin() -> ldap3::Ldap {
    let dir = directory().await;
    let mut ldap = connect(&dir.url()).await;
    ldap.simple_bind(ADMIN_DN, ADMIN_PASSWORD)
        .await
        .unwrap()
        .success()
        .unwrap();
    ldap
}

fn set(values: &[&str]) -> HashSet<String> {
    values.iter().map(|v| v.to_string()).collect()
}

/// A test's own subtree: `ou=t-…` with `ou=people` and `ou=groups`.
pub struct Namespace {
    pub base: String,
    pub people: String,
    pub groups: String,
}

pub async fn namespace() -> Namespace {
    let ou = format!("t-{}", &Uuid::new_v4().simple().to_string()[..12]);
    let base = format!("ou={ou},{ROOT}");
    let people = format!("ou=people,{base}");
    let groups = format!("ou=groups,{base}");
    let mut ldap = admin().await;
    for (dn, name) in [
        (&base, ou.as_str()),
        (&people, "people"),
        (&groups, "groups"),
    ] {
        ldap.add(
            dn,
            vec![
                ("objectClass".to_string(), set(&["organizationalUnit"])),
                ("ou".to_string(), set(&[name])),
            ],
        )
        .await
        .unwrap()
        .success()
        .unwrap();
    }
    let _ = ldap.unbind().await;
    Namespace {
        base,
        people,
        groups,
    }
}

/// An `inetOrgPerson` under `ou=people`; returns its DN.
pub async fn add_user(
    ns: &Namespace,
    uid: &str,
    password: &str,
    mail: Option<&str>,
    given_name: Option<&str>,
) -> String {
    let dn = format!("uid={uid},{}", ns.people);
    let mut attrs = vec![
        ("objectClass".to_string(), set(&["inetOrgPerson"])),
        ("uid".to_string(), set(&[uid])),
        ("cn".to_string(), set(&[uid])),
        ("sn".to_string(), set(&["Tester"])),
        ("userPassword".to_string(), set(&[password])),
    ];
    if let Some(m) = mail {
        attrs.push(("mail".to_string(), set(&[m])));
    }
    if let Some(g) = given_name {
        attrs.push(("givenName".to_string(), set(&[g])));
    }
    let mut ldap = admin().await;
    ldap.add(&dn, attrs).await.unwrap().success().unwrap();
    let _ = ldap.unbind().await;
    dn
}

/// A `groupOfNames` under `ou=groups` (it must have a member: an empty one
/// gets the admin as a placeholder, which is nobody rIDM knows).
pub async fn add_group(ns: &Namespace, cn: &str, members: &[&str]) -> String {
    let dn = format!("cn={cn},{}", ns.groups);
    let members = if members.is_empty() {
        set(&[ADMIN_DN])
    } else {
        set(members)
    };
    let mut ldap = admin().await;
    ldap.add(
        &dn,
        vec![
            ("objectClass".to_string(), set(&["groupOfNames"])),
            ("cn".to_string(), set(&[cn])),
            ("member".to_string(), members),
        ],
    )
    .await
    .unwrap()
    .success()
    .unwrap();
    let _ = ldap.unbind().await;
    dn
}

/// Replace an attribute's values (none deletes it).
pub async fn replace(dn: &str, attribute: &str, values: &[&str]) {
    let mut ldap = admin().await;
    ldap.modify(dn, vec![Mod::Replace(attribute.to_string(), set(values))])
        .await
        .unwrap()
        .success()
        .unwrap();
    let _ = ldap.unbind().await;
}

pub async fn delete(dn: &str) {
    let mut ldap = admin().await;
    ldap.delete(dn).await.unwrap().success().unwrap();
    let _ = ldap.unbind().await;
}

/// An attribute's values, read as the admin.
pub async fn read(dn: &str, attribute: &str) -> Vec<String> {
    let mut ldap = admin().await;
    let (entries, _) = ldap
        .search(dn, Scope::Base, "(objectClass=*)", vec![attribute])
        .await
        .unwrap()
        .success()
        .unwrap();
    let _ = ldap.unbind().await;
    entries
        .into_iter()
        .next()
        .map(|e| {
            SearchEntry::construct(e)
                .attrs
                .into_iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(attribute))
                .map(|(_, v)| v)
                .unwrap_or_default()
        })
        .unwrap_or_default()
}
