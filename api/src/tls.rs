//! rIDM's own mutual-TLS listener (`MTLS_BIND`, RFC 8705).
//!
//! It serves the same routes as the main listener, but asks every
//! connection for a client certificate. It does not require one and does not
//! judge the chain: which CA a client's certificate must come from, or which
//! certificate it must be, is per client and per tenant, and only known once
//! the request names its client (see [`crate::oidc::mtls`]). What the
//! handshake does settle is that the client holds the certificate's key — it
//! signs the handshake with it — so a certificate reaching a handler this way
//! is proven, not merely claimed.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::http::Request;
use axum_server::accept::{Accept, DefaultAcceptor};
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use rustls::DigitallySignedStruct;
use rustls::DistinguishedName;
use rustls::SignatureScheme;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;

use crate::config::TlsConfig;
use crate::oidc::mtls::PeerCertificates;

/// Accepts any client certificate whose handshake signature verifies, and
/// connections without one.
#[derive(Debug)]
struct AnyClientCertificate {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for AnyClientCertificate {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Judged per request, against the client it authenticates.
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// The server configuration of the mTLS listener: the given certificate and
/// key, a request for a client certificate, HTTP/2 and HTTP/1.1.
pub fn server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> io::Result<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(AnyClientCertificate {
        algorithms: provider.signature_verification_algorithms,
    });
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .map_err(io::Error::other)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// [`server_config`] from the PEM files of `MTLS_CERT`/`MTLS_KEY` (or the
/// main listener's).
pub fn load(tls: &TlsConfig) -> io::Result<RustlsConfig> {
    let chain = CertificateDer::pem_file_iter(&tls.cert_path)
        .map_err(io::Error::other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    let key = PrivateKeyDer::from_pem_file(&tls.key_path).map_err(io::Error::other)?;
    Ok(RustlsConfig::from_config(Arc::new(server_config(
        chain, key,
    )?)))
}

/// The TLS acceptor, plus the client's certificate chain on every request of
/// the connection as [`PeerCertificates`].
#[derive(Clone)]
pub struct PeerCertAcceptor {
    inner: RustlsAcceptor<DefaultAcceptor>,
}

impl PeerCertAcceptor {
    pub fn new(config: RustlsConfig) -> Self {
        Self {
            inner: RustlsAcceptor::new(config),
        }
    }
}

type AcceptFuture<S, V> = Pin<Box<dyn Future<Output = io::Result<(S, V)>> + Send>>;

impl<I, S> Accept<I, S> for PeerCertAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = WithPeerCertificates<S>;
    type Future = AcceptFuture<Self::Stream, Self::Service>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let handshake = self.inner.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = handshake.await?;
            let certs = stream
                .get_ref()
                .1
                .peer_certificates()
                .filter(|c| !c.is_empty())
                .map(|c| PeerCertificates(c.iter().map(|c| c.clone().into_owned()).collect()));
            Ok((
                stream,
                WithPeerCertificates {
                    inner: service,
                    certs,
                },
            ))
        })
    }
}

/// A connection's service that stamps its requests with the client's chain.
#[derive(Clone)]
pub struct WithPeerCertificates<S> {
    inner: S,
    certs: Option<PeerCertificates>,
}

impl<S, B> tower::Service<Request<B>> for WithPeerCertificates<S>
where
    S: tower::Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        match &self.certs {
            Some(certs) => {
                req.extensions_mut().insert(certs.clone());
            }
            // A client could not otherwise put one there, but make sure.
            None => {
                req.extensions_mut().remove::<PeerCertificates>();
            }
        }
        self.inner.call(req)
    }
}
