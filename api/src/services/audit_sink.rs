//! Audit export sink: every audit row is also shipped to an external system
//! (`AUDIT_SINK_URL`).
//!
//! * `https://` / `http://`: batches of up to [`BATCH`] rows of one chain, in
//!   chain order, POSTed as a JSON array. `Authorization: Bearer
//!   <AUDIT_SINK_TOKEN>` when a token is set, and `X-RIDM-Signature:
//!   t=<unix>,v1=<hex HMAC-SHA256>` over `"<t>.<body>"` when
//!   `AUDIT_SINK_SECRET` is (the same scheme as webhooks).
//! * `syslog://host:port` (UDP), `syslog+tcp://host:port` (one RFC 5424
//!   message per line) and `syslog+tls://host:port` (RFC 5425: TLS, each
//!   message prefixed with its length). The row is the message, as JSON.
//!
//! This module only delivers. What to deliver comes from the database, driven
//! by [`crate::jobs::audit_sink`]: a row is shipped once it is recorded,
//! whatever happens to the node, and delivery is at least once — a receiver
//! deduplicates on the row's `id` (or its chain and `seq`).

use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject as _};
use tokio::io::AsyncWriteExt as _;
use url::Url;

use crate::models::AuditEvent;

/// Rows per delivery.
pub const BATCH: usize = 100;
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
enum Target {
    Http { url: Url },
    SyslogUdp { addr: String },
    SyslogTcp { addr: String },
    SyslogTls { addr: String, host: String },
}

/// A configured destination.
#[derive(Clone)]
pub struct AuditSink {
    target: Target,
    /// Stable name of the destination (no credentials), to notice when the
    /// deployment points the sink somewhere else.
    id: String,
    token: Option<String>,
    secret: Option<String>,
    http: reqwest::Client,
    tls: Option<Arc<rustls::ClientConfig>>,
}

impl std::fmt::Debug for AuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditSink").field("id", &self.id).finish()
    }
}

impl AuditSink {
    /// Build the sink for `url`. `ca_file` names PEM certificates to trust
    /// instead of the system's roots (an internal collector).
    pub fn new(
        url: &Url,
        token: Option<String>,
        secret: Option<String>,
        ca_file: Option<&Path>,
    ) -> Result<Self, String> {
        let roots = ca_file.map(load_roots).transpose()?;
        let (target, tls) = match url.scheme() {
            "http" | "https" => (Target::Http { url: url.clone() }, None),
            "syslog" | "syslog+udp" => (
                Target::SyslogUdp {
                    addr: host_port(url)?,
                },
                None,
            ),
            "syslog+tcp" => (
                Target::SyslogTcp {
                    addr: host_port(url)?,
                },
                None,
            ),
            "syslog+tls" => (
                Target::SyslogTls {
                    addr: host_port(url)?,
                    host: url.host_str().unwrap_or_default().to_string(),
                },
                Some(Arc::new(tls_config(roots.as_deref())?)),
            ),
            other => return Err(format!("unsupported audit sink scheme `{other}`")),
        };
        let mut http = reqwest::Client::builder().timeout(TIMEOUT);
        if let (Target::Http { .. }, Some(roots)) = (&target, &roots) {
            let certs = roots
                .iter()
                .map(|der| reqwest::Certificate::from_der(der.as_ref()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("AUDIT_SINK_CA_FILE: {e}"))?;
            http = http.tls_certs_only(certs);
        }
        let http = http.build().map_err(|e| e.to_string())?;
        let mut id = url.clone();
        let _ = id.set_username("");
        let _ = id.set_password(None);
        id.set_query(None);
        id.set_fragment(None);
        Ok(Self {
            target,
            id: id.to_string(),
            token,
            secret,
            http,
            tls,
        })
    }

    /// The destination, without credentials.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Deliver `rows` (one chain, in order). Nothing is retried here: a
    /// failed delivery leaves the cursor where it was, and the worker tries
    /// the same rows again after a backoff.
    pub async fn deliver(&self, rows: &[AuditEvent]) -> Result<(), String> {
        match &self.target {
            Target::Http { url } => self.send_http(url, rows).await,
            Target::SyslogUdp { addr } => send_udp(addr, rows).await,
            Target::SyslogTcp { addr } => {
                let stream = tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect(addr))
                    .await
                    .map_err(|_| "connect timed out".to_string())?
                    .map_err(|e| e.to_string())?;
                write_all(stream, rows, Framing::Newline).await
            }
            Target::SyslogTls { addr, host } => {
                let tcp = tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect(addr))
                    .await
                    .map_err(|_| "connect timed out".to_string())?
                    .map_err(|e| e.to_string())?;
                let name = ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
                let config = self.tls.clone().ok_or("no TLS configuration")?;
                let stream = tokio::time::timeout(
                    TIMEOUT,
                    tokio_rustls::TlsConnector::from(config).connect(name, tcp),
                )
                .await
                .map_err(|_| "TLS handshake timed out".to_string())?
                .map_err(|e| e.to_string())?;
                write_all(stream, rows, Framing::OctetCounting).await
            }
        }
    }

    async fn send_http(&self, url: &Url, rows: &[AuditEvent]) -> Result<(), String> {
        let body = serde_json::to_vec(rows).map_err(|e| e.to_string())?;
        let mut req = self
            .http
            .post(url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        if let Some(secret) = &self.secret {
            let signature =
                crate::services::webhooks::sign(secret, chrono::Utc::now().timestamp(), &body);
            req = req.header("X-RIDM-Signature", signature);
        }
        let res = req.body(body).send().await.map_err(|e| e.to_string())?;
        if res.status().is_success() {
            Ok(())
        } else {
            Err(format!("the sink answered {}", res.status()))
        }
    }
}

fn host_port(url: &Url) -> Result<String, String> {
    let host = url.host_str().ok_or("audit sink URL needs a host")?;
    let default = if url.scheme() == "syslog+tls" {
        6514
    } else {
        514
    };
    Ok(format!("{host}:{}", url.port().unwrap_or(default)))
}

fn load_roots(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("AUDIT_SINK_CA_FILE: {e}"))?;
    let certs: Vec<_> = CertificateDer::pem_reader_iter(&mut BufReader::new(file))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("AUDIT_SINK_CA_FILE: {e}"))?;
    if certs.is_empty() {
        return Err("AUDIT_SINK_CA_FILE holds no certificate".into());
    }
    Ok(certs)
}

/// TLS for a syslog collector: the given roots, or the platform's verifier.
fn tls_config(roots: Option<&[CertificateDer<'static>]>) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    let config = match roots {
        Some(certs) => {
            let mut store = rustls::RootCertStore::empty();
            for c in certs {
                store.add(c.clone()).map_err(|e| e.to_string())?;
            }
            builder.with_root_certificates(store).with_no_client_auth()
        }
        None => {
            let verifier =
                rustls_platform_verifier::Verifier::new(provider).map_err(|e| e.to_string())?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        }
    };
    Ok(config)
}

/// RFC 5424 line: facility local0 (16) × 8 + severity informational (6).
pub fn syslog_line(row: &AuditEvent) -> String {
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "-".into());
    let body = serde_json::to_string(row).unwrap_or_default();
    format!(
        "<134>1 {} {host} ridm - {} - {body}",
        row.recorded_at
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        row.name
    )
}

enum Framing {
    /// One message per line (the common `syslog+tcp` convention).
    Newline,
    /// `<length> <message>` (RFC 5425 §4.3, RFC 6587 §3.4.1).
    OctetCounting,
}

fn frame(row: &AuditEvent, framing: &Framing) -> String {
    let line = syslog_line(row);
    match framing {
        Framing::Newline => format!("{line}\n"),
        Framing::OctetCounting => format!("{} {line}", line.len()),
    }
}

async fn write_all<S: tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    rows: &[AuditEvent],
    framing: Framing,
) -> Result<(), String> {
    let mut buf = Vec::new();
    for row in rows {
        buf.extend_from_slice(frame(row, &framing).as_bytes());
    }
    tokio::time::timeout(TIMEOUT, async {
        stream.write_all(&buf).await?;
        stream.flush().await?;
        stream.shutdown().await
    })
    .await
    .map_err(|_| "write timed out".to_string())?
    .map_err(|e| e.to_string())
}

async fn send_udp(addr: &str, rows: &[AuditEvent]) -> Result<(), String> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| e.to_string())?;
    for row in rows {
        socket
            .send_to(syslog_line(row).as_bytes(), addr)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_destination_is_named_without_its_credentials() {
        let url = Url::parse("https://user:pw@logs.example/in?key=1").unwrap();
        let sink = AuditSink::new(&url, None, None, None).unwrap();
        assert_eq!(sink.id(), "https://logs.example/in");
        assert!(AuditSink::new(&Url::parse("ftp://x").unwrap(), None, None, None).is_err());
    }

    #[test]
    fn tls_syslog_frames_count_octets() {
        let row = AuditEvent {
            id: uuid::Uuid::nil(),
            tenant_id: None,
            seq: 1,
            occurred_at: chrono::Utc::now(),
            recorded_at: chrono::Utc::now(),
            name: "user.created".into(),
            actor_type: "system".into(),
            actor_id: None,
            subject_id: None,
            impersonator_id: None,
            ip: None,
            user_agent: None,
            payload: serde_json::json!({}),
            prev_hash: None,
            hash: vec![1],
        };
        let framed = frame(&row, &Framing::OctetCounting);
        let (len, rest) = framed.split_once(' ').unwrap();
        assert_eq!(len.parse::<usize>().unwrap(), rest.len());
        assert!(frame(&row, &Framing::Newline).ends_with('\n'));
    }
}
