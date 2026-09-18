//! `ridm-api --healthcheck`: the container's liveness probe. Distroless
//! images have no curl, so the binary asks its own `/healthz`.
//!
//! It dials the address the server binds (`BIND_ADDR`; a wildcard becomes
//! the loopback address of the same family) and speaks TLS when the server
//! does (`TLS_CERT` set). Over TLS the probe trusts exactly the certificate in
//! `TLS_CERT`: the server must present that certificate and prove it holds
//! its key. The certificate's names are not checked (the probe dials an IP
//! address the certificate was never issued for), nor its chain or validity
//! dates (a local probe asks whether the process answers, not whether the
//! certificate is still fit for clients).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// What to probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub addr: SocketAddr,
    /// The server's certificate (`TLS_CERT`) when it serves HTTPS.
    pub tls_cert: Option<PathBuf>,
}

impl Target {
    /// From the environment the server itself reads (`BIND_ADDR`, `TLS_CERT`).
    pub fn from_env() -> Result<Self, String> {
        let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
        let bind: SocketAddr = bind
            .parse()
            .map_err(|e| format!("BIND_ADDR `{bind}`: {e}"))?;
        let tls_cert = std::env::var("TLS_CERT")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from);
        Ok(Self {
            addr: dial_addr(bind),
            tls_cert,
        })
    }
}

/// The address to dial for a bind address: a wildcard means "every local
/// address", so its family's loopback; anything else as it is.
pub fn dial_addr(bind: SocketAddr) -> SocketAddr {
    let ip = match bind.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    };
    SocketAddr::new(ip, bind.port())
}

/// `0` when `/healthz` answers with a success status, `1` otherwise.
pub async fn run() -> i32 {
    match Target::from_env() {
        Ok(target) => match probe(&target).await {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("healthcheck: {err}");
                1
            }
        },
        Err(err) => {
            eprintln!("healthcheck: {err}");
            1
        }
    }
}

/// Ask `target`'s `/healthz`.
pub async fn probe(target: &Target) -> Result<(), String> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());
    let scheme = match &target.tls_cert {
        Some(path) => {
            builder = builder.tls_backend_preconfigured(pinned_tls(path)?);
            "https"
        }
        None => "http",
    };
    let client = builder.build().map_err(|e| e.to_string())?;
    let url = format!("{scheme}://{}/healthz", target.addr);
    let res = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("{url}: {}", crate::util::outbound::describe(&e)))?;
    if res.status().is_success() {
        Ok(())
    } else {
        Err(format!("{url}: {}", res.status()))
    }
}

/// A TLS client configuration that accepts exactly the first certificate
/// of the PEM file at `path`.
fn pinned_tls(path: &Path) -> Result<rustls::ClientConfig, String> {
    let cert = CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("TLS_CERT {}: {e}", path.display()))?
        .next()
        .ok_or_else(|| format!("TLS_CERT {}: no certificate", path.display()))?
        .map_err(|e| format!("TLS_CERT {}: {e}", path.display()))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    Ok(
        rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCert { cert, provider }))
            .with_no_client_auth(),
    )
}

/// Trusts one certificate, byte for byte; the handshake signature is still
/// verified, so the peer must hold that certificate's key.
#[derive(Debug)]
pub struct PinnedCert {
    cert: CertificateDer<'static>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.cert.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "the server's certificate is not the one in TLS_CERT".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_dial_the_loopback_of_their_family() {
        let dial = |s: &str| dial_addr(s.parse().unwrap()).to_string();
        assert_eq!(dial("0.0.0.0:8080"), "127.0.0.1:8080");
        assert_eq!(dial("[::]:8443"), "[::1]:8443");
        assert_eq!(dial("10.1.2.3:9000"), "10.1.2.3:9000");
        assert_eq!(dial("[fd00::5]:8080"), "[fd00::5]:8080");
        assert_eq!(dial("127.0.0.1:18080"), "127.0.0.1:18080");
    }

    #[test]
    fn only_the_pinned_certificate_is_accepted() {
        let pinned = PinnedCert {
            cert: CertificateDer::from(vec![1, 2, 3]),
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        };
        let name = ServerName::try_from("127.0.0.1").unwrap();
        let now = UnixTime::now();
        assert!(
            pinned
                .verify_server_cert(&CertificateDer::from(vec![1, 2, 3]), &[], &name, &[], now)
                .is_ok()
        );
        assert!(
            pinned
                .verify_server_cert(&CertificateDer::from(vec![1, 2, 4]), &[], &name, &[], now)
                .is_err()
        );
    }
}
