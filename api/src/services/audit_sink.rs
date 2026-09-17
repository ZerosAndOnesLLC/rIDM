//! Audit export sink: every recorded audit row is also shipped to an
//! external system (`AUDIT_SINK_URL`).
//!
//! * `https://` / `http://`: batches of up to [`BATCH`] rows (or whatever
//!   accumulated within a second) are POSTed as a JSON array, with
//!   `Authorization: Bearer <AUDIT_SINK_TOKEN>` when set; a failed batch is
//!   retried three times with backoff, then dropped with a warning.
//! * `syslog://host:port` (UDP) and `syslog+tcp://host:port`: one RFC 5424
//!   message per row, the row as JSON structured data-free message body.
//!
//! The sink is fed from a bounded channel: when the exporter falls behind,
//! rows are dropped (counted in `ridm_audit_sink_dropped_total`) rather than
//! slowing the audit writer.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use url::Url;

use crate::models::AuditEvent;

const QUEUE: usize = 10_000;
const BATCH: usize = 100;
const FLUSH_EVERY: Duration = Duration::from_secs(1);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct AuditSink {
    tx: mpsc::Sender<AuditEvent>,
}

#[derive(Debug, Clone)]
enum Target {
    Http { url: Url, token: Option<String> },
    SyslogUdp(String),
    SyslogTcp(String),
}

impl AuditSink {
    /// Start the exporter for `url`; `None` when the URL is not a supported sink.
    pub fn spawn(url: &Url, token: Option<String>) -> Result<Self, String> {
        let target = match url.scheme() {
            "http" | "https" => Target::Http {
                url: url.clone(),
                token,
            },
            "syslog" | "syslog+udp" => Target::SyslogUdp(host_port(url, 514)?),
            "syslog+tcp" => Target::SyslogTcp(host_port(url, 514)?),
            other => return Err(format!("unsupported audit sink scheme `{other}`")),
        };
        let (tx, rx) = mpsc::channel(QUEUE);
        tokio::spawn(run(target, rx));
        Ok(Self { tx })
    }

    /// Queue a row; never blocks the caller.
    pub fn offer(&self, row: AuditEvent) {
        if self.tx.try_send(row).is_err() {
            metrics::counter!("ridm_audit_sink_dropped_total").increment(1);
            tracing::warn!("audit sink queue full; row dropped");
        }
    }
}

fn host_port(url: &Url, default_port: u16) -> Result<String, String> {
    let host = url.host_str().ok_or("audit sink URL needs a host")?;
    Ok(format!("{host}:{}", url.port().unwrap_or(default_port)))
}

async fn run(target: Target, mut rx: mpsc::Receiver<AuditEvent>) {
    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .expect("reqwest client"),
    );
    let mut batch: Vec<AuditEvent> = Vec::with_capacity(BATCH);
    loop {
        let first = match rx.recv().await {
            Some(row) => row,
            None => break,
        };
        batch.push(first);
        // Gather what arrives within the flush window, up to a batch.
        let deadline = tokio::time::Instant::now() + FLUSH_EVERY;
        while batch.len() < BATCH {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(row)) => batch.push(row),
                Ok(None) | Err(_) => break,
            }
        }
        let rows = std::mem::take(&mut batch);
        let ok = match &target {
            Target::Http { url, token } => send_http(&client, url, token.as_deref(), &rows).await,
            Target::SyslogUdp(addr) => send_syslog_udp(addr, &rows).await,
            Target::SyslogTcp(addr) => send_syslog_tcp(addr, &rows).await,
        };
        if ok {
            metrics::counter!("ridm_audit_sink_rows_total").increment(rows.len() as u64);
        } else {
            metrics::counter!("ridm_audit_sink_failures_total").increment(1);
            tracing::warn!(
                rows = rows.len(),
                "audit sink delivery failed; rows dropped"
            );
        }
    }
}

async fn send_http(
    client: &reqwest::Client,
    url: &Url,
    token: Option<&str>,
    rows: &[AuditEvent],
) -> bool {
    for attempt in 0..3u32 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(500 * (1u64 << attempt))).await;
        }
        let mut req = client.post(url.clone()).json(rows);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        match req.send().await {
            Ok(res) if res.status().is_success() => return true,
            Ok(res) => {
                tracing::debug!(status = %res.status(), attempt, "audit sink refused the batch")
            }
            Err(err) => tracing::debug!(error = %err, attempt, "audit sink request failed"),
        }
    }
    false
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

async fn send_syslog_udp(addr: &str, rows: &[AuditEvent]) -> bool {
    let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
        return false;
    };
    for row in rows {
        if socket
            .send_to(syslog_line(row).as_bytes(), addr)
            .await
            .is_err()
        {
            return false;
        }
    }
    true
}

async fn send_syslog_tcp(addr: &str, rows: &[AuditEvent]) -> bool {
    use tokio::io::AsyncWriteExt as _;
    let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await else {
        return false;
    };
    for row in rows {
        let line = format!("{}\n", syslog_line(row));
        if stream.write_all(line.as_bytes()).await.is_err() {
            return false;
        }
    }
    stream.flush().await.is_ok()
}
