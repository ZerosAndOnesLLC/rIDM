//! Valkey over TLS with a private CA and a client certificate
//! ([`RedisTlsConfig`]): the files are read when a connection is made and
//! read again whenever one of them changes on disk, so a certificate
//! renewed in place (cert-manager, a secret mount) is picked up without a
//! restart. Single-server `rediss://` only.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use deadpool::managed::{Manager, Metrics, RecycleError, RecycleResult};
use redis::aio::MultiplexedConnection;
use redis::{Client, ClientTlsConfig, RedisError, TlsCertificates};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::RedisTlsConfig;
use crate::error::AppError;

/// A client for `url`: with `tls`, one that trusts the CA and presents the
/// client certificate the files hold now.
pub fn client(url: &str, tls: Option<&RedisTlsConfig>) -> Result<Client, AppError> {
    match tls {
        None => Ok(Client::open(url)?),
        Some(tls) => {
            let certificates = read(tls)?;
            require_fips(&certificates)?;
            Ok(Client::build_with_tls(url, certificates)?)
        }
    }
}

/// The files' contents, as the redis client takes them.
fn read(tls: &RedisTlsConfig) -> Result<TlsCertificates, AppError> {
    let file = |path: &std::path::Path| {
        std::fs::read(path)
            .map_err(|e| AppError::Cache(format!("cannot read {}: {e}", path.display())))
    };
    Ok(TlsCertificates {
        root_cert: tls.ca_file.as_deref().map(file).transpose()?,
        client_tls: match &tls.client_cert {
            Some((cert, key)) => Some(ClientTlsConfig {
                client_cert: file(cert)?,
                client_key: file(key)?,
            }),
            None => None,
        },
    })
}

/// The redis client builds its rustls configuration from the process
/// default provider, which [`crate::crypto_provider::install`] made ours;
/// the same configuration built here, from the same material, must pass
/// the FIPS check in the FIPS build, as every other TLS configuration does.
fn require_fips(certificates: &TlsCertificates) -> Result<(), AppError> {
    let mut roots = RootCertStore::empty();
    if let Some(pem) = &certificates.root_cert {
        for cert in CertificateDer::pem_slice_iter(pem) {
            let cert = cert.map_err(|e| AppError::Cache(format!("REDIS_TLS_CA_FILE: {e}")))?;
            roots
                .add(cert)
                .map_err(|e| AppError::Cache(format!("REDIS_TLS_CA_FILE: {e}")))?;
        }
    }
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let config = match &certificates.client_tls {
        Some(client) => {
            let chain = CertificateDer::pem_slice_iter(&client.client_cert)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| AppError::Cache(format!("REDIS_TLS_CERT_FILE: {e}")))?;
            let key = PrivateKeyDer::from_pem_slice(&client.client_key)
                .map_err(|e| AppError::Cache(format!("REDIS_TLS_KEY_FILE: {e}")))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| AppError::Cache(format!("REDIS_TLS_CERT_FILE: {e}")))?
        }
        None => builder.with_no_client_auth(),
    };
    crate::crypto_provider::require_fips("the Valkey connection", config.fips())
        .map_err(AppError::Cache)
}

/// The files' modification times; a change means a renewal.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp(Vec<Option<SystemTime>>);

impl Stamp {
    fn of(tls: &RedisTlsConfig) -> Self {
        Self(
            tls.files()
                .iter()
                .map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
                .collect(),
        )
    }
}

/// A pool manager for one `rediss://` server that rebuilds its client from
/// the certificate files whenever they change.
pub struct TlsManager {
    url: String,
    tls: RedisTlsConfig,
    current: Mutex<(Stamp, Client)>,
    ping_number: AtomicUsize,
}

impl std::fmt::Debug for TlsManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsManager")
            .field("url", &self.url)
            .finish()
    }
}

impl TlsManager {
    /// Reads the files once; a file that cannot be read is an error here,
    /// where it stops the server, rather than at the first connection.
    pub fn new(url: &str, tls: RedisTlsConfig) -> Result<Self, AppError> {
        let stamp = Stamp::of(&tls);
        let client = client(url, Some(&tls))?;
        Ok(Self {
            url: url.to_string(),
            tls,
            current: Mutex::new((stamp, client)),
            ping_number: AtomicUsize::new(0),
        })
    }

    /// The client for the files as they are now. A renewal that cannot be
    /// read yet (half-written, a key not yet rotated) keeps the previous
    /// client and is tried again at the next connection.
    fn client(&self) -> Client {
        let stamp = Stamp::of(&self.tls);
        let mut current = self.current.lock().unwrap_or_else(|e| e.into_inner());
        if current.0 != stamp {
            match client(&self.url, Some(&self.tls)) {
                Ok(client) => {
                    tracing::info!("Valkey TLS certificate files changed; reloaded");
                    *current = (stamp, client);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Valkey TLS certificate files changed but cannot be loaded; keeping the previous ones");
                }
            }
        }
        current.1.clone()
    }
}

impl Manager for TlsManager {
    type Type = MultiplexedConnection;
    type Error = RedisError;

    async fn create(&self) -> Result<MultiplexedConnection, RedisError> {
        self.client().get_multiplexed_async_connection().await
    }

    async fn recycle(
        &self,
        conn: &mut MultiplexedConnection,
        _: &Metrics,
    ) -> RecycleResult<RedisError> {
        // As deadpool-redis does: a pipelined UNWATCH and a PING the reply must echo.
        let ping_number = self.ping_number.fetch_add(1, Ordering::Relaxed).to_string();
        let (n,) = redis::Pipeline::with_capacity(2)
            .cmd("UNWATCH")
            .ignore()
            .cmd("PING")
            .arg(&ping_number)
            .query_async::<(String,)>(conn)
            .await?;
        if n == ping_number {
            Ok(())
        } else {
            Err(RecycleError::message("Invalid PING response"))
        }
    }
}

/// The pool and its connections, for the single-server TLS form.
pub type TlsPool = deadpool::managed::Pool<TlsManager>;
pub type TlsConnection = deadpool::managed::Object<TlsManager>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stamp_changes_when_a_file_does() {
        let dir = std::env::temp_dir().join(format!("ridm-tls-stamp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = dir.join("ca.crt");
        std::fs::write(&ca, "one").unwrap();
        let tls = RedisTlsConfig {
            ca_file: Some(ca.clone()),
            client_cert: None,
        };
        let before = Stamp::of(&tls);
        assert_eq!(before, Stamp::of(&tls));
        // A later modification time, whatever the filesystem's resolution.
        let later = SystemTime::now() + std::time::Duration::from_secs(5);
        std::fs::write(&ca, "two").unwrap();
        std::fs::File::open(&ca)
            .unwrap()
            .set_modified(later)
            .unwrap();
        assert_ne!(before, Stamp::of(&tls));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_file_is_a_stamp_too() {
        let tls = RedisTlsConfig {
            ca_file: Some("/nonexistent/ca.crt".into()),
            client_cert: None,
        };
        assert_eq!(Stamp::of(&tls), Stamp(vec![None]));
    }
}
