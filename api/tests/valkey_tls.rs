//! Valkey over TLS with a private CA and client-certificate authentication
//! (`REDIS_TLS_CA_FILE`, `REDIS_TLS_CERT_FILE`, `REDIS_TLS_KEY_FILE`): a
//! Valkey that accepts only certificates from the test CA and maps their CN
//! onto an ACL user with no password (`tls-auth-clients-user CN`), as the
//! FIPS build's deployments run it. Runs in both builds.

mod common;

use std::path::PathBuf;

use redis::aio::ConnectionLike as _;
use ridm_api::cache;
use ridm_api::config::{Config, RedisTlsConfig};
use testcontainers::core::{ContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

const VALKEY: (&str, &str) = ("valkey/valkey", "9.1.2-alpine3.24");

struct Pem {
    ca: String,
    server_cert: String,
    server_key: String,
    /// `CN=ridm`, the ACL user the server knows.
    client_cert: String,
    client_key: String,
    /// `CN=nobody`, from the same CA, no ACL user.
    other_cert: String,
    other_key: String,
}

fn certificates() -> Pem {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "rIDM test CA");
    let ca = ca_params.self_signed(&ca_key).unwrap().pem();
    let issuer = Issuer::new(ca_params, ca_key);
    let server_key = KeyPair::generate().unwrap();
    let mut server =
        CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()]).unwrap();
    server.distinguished_name.push(DnType::CommonName, "valkey");
    let server_cert = server.signed_by(&server_key, &issuer).unwrap().pem();
    let client = |cn: &str| {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        (
            params.signed_by(&key, &issuer).unwrap().pem(),
            key.serialize_pem(),
        )
    };
    let (client_cert, client_key) = client("ridm");
    let (other_cert, other_key) = client("nobody");
    Pem {
        ca,
        server_cert,
        server_key: server_key.serialize_pem(),
        client_cert,
        client_key,
        other_cert,
        other_key,
    }
}

/// A Valkey that speaks only TLS, accepts only client certificates from the
/// CA, and authenticates each connection as the ACL user its CN names.
async fn valkey(pem: &Pem) -> (ContainerAsync<GenericImage>, u16) {
    let conf = "\
port 0
tls-port 6379
tls-cert-file /certs/server.crt
tls-key-file /certs/server.key
tls-ca-cert-file /certs/ca.crt
tls-auth-clients yes
tls-auth-clients-user CN
user default off
user ridm on nopass ~* &* +@all
";
    let container = GenericImage::new(VALKEY.0, VALKEY.1)
        .with_exposed_port(ContainerPort::Tcp(6379))
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .with_copy_to("/certs/ca.crt", pem.ca.clone().into_bytes())
        .with_copy_to("/certs/server.crt", pem.server_cert.clone().into_bytes())
        .with_copy_to("/certs/server.key", pem.server_key.clone().into_bytes())
        .with_copy_to("/etc/valkey/valkey.conf", conf.as_bytes().to_vec())
        .with_cmd(["valkey-server", "/etc/valkey/valkey.conf"])
        .start()
        .await
        .expect("start valkey (tls)");
    let port = container
        .get_host_port_ipv4(6379)
        .await
        .expect("valkey port");
    (container, port)
}

/// The files as a deployment mounts them, in a directory of their own.
struct Files {
    dir: PathBuf,
}

impl Files {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("ridm-valkey-tls-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn write(&self, name: &str, pem: &str) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, pem).unwrap();
        // Past any filesystem's timestamp resolution, so a rewrite is seen.
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        std::fs::File::open(&path)
            .unwrap()
            .set_modified(later)
            .unwrap();
        path
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn config(port: u16, tls: Option<RedisTlsConfig>) -> Config {
    let _ = ridm_api::crypto_provider::install();
    let mut config = common::test_config(
        "postgres://unused:unused@127.0.0.1:1/unused",
        &format!("rediss://127.0.0.1:{port}"),
        "http://127.0.0.1:0",
    );
    config.redis_tls = tls;
    config
}

async fn whoami(cache: &cache::Cache) -> Result<String, ridm_api::error::AppError> {
    let mut conn = cache.get().await?;
    Ok(redis::cmd("ACL")
        .arg("WHOAMI")
        .query_async(&mut conn)
        .await?)
}

#[tokio::test]
async fn connects_with_the_private_ca_and_the_client_certificate() {
    let pem = certificates();
    let (_valkey, port) = valkey(&pem).await;
    let files = Files::new("ok");
    let tls = RedisTlsConfig {
        ca_file: Some(files.write("ca.crt", &pem.ca)),
        client_cert: Some((
            files.write("tls.crt", &pem.client_cert),
            files.write("tls.key", &pem.client_key),
        )),
    };
    let cache = cache::connect(&config(port, Some(tls))).expect("connect");
    cache::ping(&cache).await.expect("ping over TLS");
    // Authenticated by the certificate's CN, with no password anywhere.
    assert_eq!(whoami(&cache).await.unwrap(), "ridm");
    // The pub/sub subscriber, a client of its own, carries the same certificates.
    let client = cache.pubsub_client().await.expect("pubsub client");
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("pubsub connection");
    let pong: String = redis::cmd("PING").query_async(&mut conn).await.unwrap();
    assert_eq!(pong, "PONG");
    assert_eq!(conn.get_db(), 0);
}

#[tokio::test]
async fn refuses_without_the_client_certificate() {
    let pem = certificates();
    let (_valkey, port) = valkey(&pem).await;
    let files = Files::new("no-client-cert");
    let tls = RedisTlsConfig {
        ca_file: Some(files.write("ca.crt", &pem.ca)),
        client_cert: None,
    };
    let cache = cache::connect(&config(port, Some(tls))).expect("the pool is built lazily");
    cache::ping(&cache)
        .await
        .expect_err("the server requires a client certificate");
}

#[tokio::test]
async fn refuses_without_the_private_ca() {
    let pem = certificates();
    let (_valkey, port) = valkey(&pem).await;
    let files = Files::new("no-ca");
    let tls = RedisTlsConfig {
        ca_file: None,
        client_cert: Some((
            files.write("tls.crt", &pem.client_cert),
            files.write("tls.key", &pem.client_key),
        )),
    };
    let cache = cache::connect(&config(port, Some(tls))).expect("the pool is built lazily");
    cache::ping(&cache)
        .await
        .expect_err("the test CA is not among the system roots");
}

#[tokio::test]
async fn a_renewed_certificate_is_used_without_a_restart() {
    let pem = certificates();
    let (_valkey, port) = valkey(&pem).await;
    let files = Files::new("renewal");
    // First a certificate the server does not map onto a user: the TLS
    // handshake passes (same CA), the connection is not authenticated.
    let tls = RedisTlsConfig {
        ca_file: Some(files.write("ca.crt", &pem.ca)),
        client_cert: Some((
            files.write("tls.crt", &pem.other_cert),
            files.write("tls.key", &pem.other_key),
        )),
    };
    let cache = cache::connect(&config(port, Some(tls))).expect("connect");
    assert!(
        whoami(&cache).await.is_err(),
        "a certificate without an ACL user must not be authenticated"
    );
    // The files are rewritten in place, as cert-manager does: the next
    // connection carries the new certificate, with no restart.
    std::thread::sleep(std::time::Duration::from_millis(20));
    files.write("tls.crt", &pem.client_cert);
    files.write("tls.key", &pem.client_key);
    assert_eq!(
        whoami(&cache)
            .await
            .expect("the renewed certificate authenticates"),
        "ridm"
    );
}
