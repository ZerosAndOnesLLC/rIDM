//! Email and SMS senders and the per-tenant factory.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use lettre::AsyncTransport as _;
use lettre::message::{Mailbox, MultiPart, SinglePart, header};
use lettre::transport::smtp::PoolConfig;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use ridm_core::providers::{EmailMessage, EmailSender, ProviderError, SmsMessage, SmsSender};
use uuid::Uuid;

use crate::error::AppResult;
use crate::models::{EmailProviderConfig, ProviderKind, SmsProviderConfig, SmtpConfig};
use crate::services::provider_settings;
use crate::state::AppState;

/// Connections one SMTP sender keeps open to its server.
const SMTP_POOL_SIZE: u32 = 8;
/// Every HTTP email or SMS request carries this timeout.
const HTTP_SEND_TIMEOUT: Duration = Duration::from_secs(15);

/// Chooses senders for a tenant (its own settings, then deployment defaults).
#[async_trait]
pub trait SenderFactory: Send + Sync {
    async fn email(
        &self,
        state: &AppState,
        tenant_id: Uuid,
    ) -> AppResult<Option<Arc<dyn EmailSender>>>;
    async fn sms(&self, state: &AppState, tenant_id: Uuid)
    -> AppResult<Option<Arc<dyn SmsSender>>>;
}

/// Builds senders from each tenant's settings (else the deployment's SMTP
/// defaults) and keeps them, so an SMTP sender's connection pool outlives
/// one message. A sender is keyed by a fingerprint of the configuration it
/// was built from: a changed configuration gets a new sender, and the old
/// one ages out unused.
pub struct DefaultSenderFactory {
    email: moka::sync::Cache<(Uuid, u64), Arc<dyn EmailSender>>,
    sms: moka::sync::Cache<(Uuid, u64), Arc<dyn SmsSender>>,
}

/// How long an unused sender (and its pooled connections) is kept.
const SENDER_IDLE: Duration = Duration::from_secs(600);
/// Senders kept per kind; one per tenant with its own configuration.
const SENDERS_KEPT: u64 = 10_000;

impl Default for DefaultSenderFactory {
    fn default() -> Self {
        Self {
            email: moka::sync::Cache::builder()
                .max_capacity(SENDERS_KEPT)
                .time_to_idle(SENDER_IDLE)
                .build(),
            sms: moka::sync::Cache::builder()
                .max_capacity(SENDERS_KEPT)
                .time_to_idle(SENDER_IDLE)
                .build(),
        }
    }
}

/// A stable fingerprint of a configuration (it never leaves the process).
fn fingerprint(cfg: &impl serde::Serialize) -> u64 {
    use std::hash::{Hash as _, Hasher as _};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    serde_json::to_vec(cfg).unwrap_or_default().hash(&mut h);
    h.finish()
}

#[async_trait]
impl SenderFactory for DefaultSenderFactory {
    async fn email(
        &self,
        state: &AppState,
        tenant_id: Uuid,
    ) -> AppResult<Option<Arc<dyn EmailSender>>> {
        if let Some(cfg) =
            provider_settings::get::<EmailProviderConfig>(state, tenant_id, ProviderKind::Smtp)
                .await?
        {
            let key = (tenant_id, fingerprint(&*cfg));
            if let Some(sender) = self.email.get(&key) {
                return Ok(Some(sender));
            }
            let sender: Arc<dyn EmailSender> = match &*cfg {
                EmailProviderConfig::Smtp(smtp) => Arc::new(SmtpEmailSender::for_tenant(smtp)?),
                EmailProviderConfig::Http {
                    url,
                    auth_header,
                    from,
                } => Arc::new(HttpEmailSender::new(url, auth_header.clone(), from)),
            };
            self.email.insert(key, sender.clone());
            return Ok(Some(sender));
        }
        let Some(defaults) = state.config.smtp.as_ref() else {
            return Ok(None);
        };
        // The deployment's own server: one sender (one pool) for every tenant.
        let key = (Uuid::nil(), 0);
        if let Some(sender) = self.email.get(&key) {
            return Ok(Some(sender));
        }
        let sender: Arc<dyn EmailSender> = Arc::new(
            SmtpEmailSender::new(&SmtpConfig {
                host: defaults.host.clone(),
                port: defaults.port,
                username: defaults.username.clone(),
                password: defaults.password.as_ref().map(|p| p.expose().to_string()),
                from: defaults.from.clone(),
                security: defaults.security.clone(),
            })
            .map_err(|e| crate::error::AppError::Internal(format!("smtp defaults: {e}")))?,
        );
        self.email.insert(key, sender.clone());
        Ok(Some(sender))
    }

    async fn sms(
        &self,
        state: &AppState,
        tenant_id: Uuid,
    ) -> AppResult<Option<Arc<dyn SmsSender>>> {
        let Some(cfg) =
            provider_settings::get::<SmsProviderConfig>(state, tenant_id, ProviderKind::Sms)
                .await?
        else {
            return Ok(None);
        };
        let key = (tenant_id, fingerprint(&*cfg));
        if let Some(sender) = self.sms.get(&key) {
            return Ok(Some(sender));
        }
        let sender: Arc<dyn SmsSender> = Arc::new(WebhookSmsSender::new(&cfg));
        self.sms.insert(key, sender.clone());
        Ok(Some(sender))
    }
}

// ---------------------------------------------------------------------------
// SMTP
// ---------------------------------------------------------------------------

pub struct SmtpEmailSender {
    cfg: SmtpConfig,
    from: Mailbox,
    /// The host was chosen by a tenant administrator, not the operator: it is
    /// resolved under the outbound policy before every connection
    /// ([`crate::util::outbound::resolve_public`]).
    public_only: bool,
    /// The transport (and its connection pool) last used, with the address
    /// it connects to. A tenant's host is resolved again for every message;
    /// while it resolves to the same address, the pooled connections are
    /// reused, and a new address gets a new transport.
    pooled: std::sync::Mutex<Option<(String, AsyncSmtpTransport<Tokio1Executor>)>>,
}

impl SmtpEmailSender {
    /// The deployment's own SMTP server (`SMTP_*`): the operator chose it, so
    /// any address is fine (a private relay is the usual case).
    pub fn new(cfg: &SmtpConfig) -> AppResult<Self> {
        Self::build(cfg, false)
    }

    /// A tenant's SMTP server: public addresses only (SSRF), with the same
    /// loopback allowance as the other outbound targets (`localhost` and
    /// loopback literals, for development).
    pub fn for_tenant(cfg: &SmtpConfig) -> AppResult<Self> {
        crate::util::outbound::check_host(&cfg.host)
            .map_err(|e| crate::error::AppError::BadRequest(format!("smtp host: {e}")))?;
        Self::build(cfg, true)
    }

    fn build(cfg: &SmtpConfig, public_only: bool) -> AppResult<Self> {
        let from: Mailbox = cfg
            .from
            .parse()
            .map_err(|e| crate::error::AppError::BadRequest(format!("smtp from: {e}")))?;
        let sender = Self {
            cfg: cfg.clone(),
            from,
            public_only,
            pooled: std::sync::Mutex::new(None),
        };
        // Validates the TLS parameters up front.
        sender
            .transport(&cfg.host)
            .map_err(|e| crate::error::AppError::BadRequest(format!("smtp: {e}")))?;
        Ok(sender)
    }

    /// The pooled transport to `address`, built on first use.
    fn transport_to(
        &self,
        address: &str,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>, lettre::transport::smtp::Error> {
        let mut slot = self.pooled.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((pooled_address, transport)) = slot.as_ref()
            && pooled_address == address
        {
            return Ok(transport.clone());
        }
        let transport = self.transport(address)?;
        *slot = Some((address.to_string(), transport.clone()));
        Ok(transport)
    }

    /// A transport that connects to `address` (the configured host, or the
    /// address vetted for it) while TLS verifies the certificate against the
    /// configured host name.
    fn transport(
        &self,
        address: &str,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>, lettre::transport::smtp::Error> {
        let cfg = &self.cfg;
        let tls = match cfg.security.as_str() {
            "tls" => Tls::Wrapper(TlsParameters::new(cfg.host.clone())?),
            "none" => Tls::None,
            _ => Tls::Required(TlsParameters::new(cfg.host.clone())?),
        };
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(address)
            .port(cfg.port)
            .tls(tls)
            .timeout(Some(Duration::from_secs(15)))
            .pool_config(
                PoolConfig::new()
                    .max_size(SMTP_POOL_SIZE)
                    .idle_timeout(Duration::from_secs(60)),
            );
        if let (Some(u), Some(p)) = (&cfg.username, &cfg.password) {
            builder = builder.credentials(Credentials::new(u.clone(), p.clone()));
        }
        Ok(builder.build())
    }
}

#[async_trait]
impl EmailSender for SmtpEmailSender {
    fn name(&self) -> &'static str {
        "smtp"
    }

    async fn send(&self, message: &EmailMessage) -> Result<(), ProviderError> {
        let mut builder = lettre::Message::builder().from(
            message
                .from
                .as_ref()
                .and_then(|a| a.email.parse::<Mailbox>().ok())
                .unwrap_or_else(|| self.from.clone()),
        );
        for to in &message.to {
            let mb: Mailbox = match &to.name {
                Some(n) => format!("{n} <{}>", to.email).parse(),
                None => to.email.parse(),
            }
            .map_err(|e| ProviderError::Rejected(format!("recipient: {e}")))?;
            builder = builder.to(mb);
        }
        if let Some(r) = &message.reply_to
            && let Ok(mb) = r.email.parse::<Mailbox>()
        {
            builder = builder.reply_to(mb);
        }
        builder = builder.subject(&message.subject);
        let email = match &message.html {
            Some(html) => builder.multipart(MultiPart::alternative_plain_html(
                message.text.clone(),
                html.clone(),
            )),
            None => builder.singlepart(
                SinglePart::builder()
                    .header(header::ContentType::TEXT_PLAIN)
                    .body(message.text.clone()),
            ),
        }
        .map_err(|e| ProviderError::Rejected(format!("build: {e}")))?;
        // A tenant's host is resolved here, right before the connection, and
        // the connection goes to the address that passed, not to the name.
        let address = if self.public_only {
            crate::util::outbound::resolve_public(&self.cfg.host, self.cfg.port)
                .await
                .map_err(ProviderError::Rejected)?
                .ip()
                .to_string()
        } else {
            self.cfg.host.clone()
        };
        let transport = self
            .transport_to(&address)
            .map_err(|e| ProviderError::Rejected(format!("smtp: {e}")))?;
        transport.send(email).await.map(|_| ()).map_err(|e| {
            if e.is_permanent() {
                ProviderError::Rejected(e.to_string())
            } else {
                ProviderError::Unavailable(e.to_string())
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Generic HTTP (JSON webhook)
// ---------------------------------------------------------------------------

pub struct HttpEmailSender {
    url: String,
    auth_header: Option<String>,
    from: String,
}

impl HttpEmailSender {
    pub fn new(url: &str, auth_header: Option<String>, from: &str) -> Self {
        Self {
            url: url.to_string(),
            auth_header,
            from: from.to_string(),
        }
    }
}

#[async_trait]
impl EmailSender for HttpEmailSender {
    fn name(&self) -> &'static str {
        "http"
    }

    async fn send(&self, message: &EmailMessage) -> Result<(), ProviderError> {
        let body = serde_json::json!({
            "from": message.from.as_ref().map(|a| a.email.clone()).unwrap_or_else(|| self.from.clone()),
            "to": message.to.iter().map(|a| a.email.clone()).collect::<Vec<_>>(),
            "subject": message.subject,
            "text": message.text,
            "html": message.html,
            "reply_to": message.reply_to.as_ref().map(|a| a.email.clone()),
            "headers": message.headers,
        });
        crate::util::outbound::check_url(&self.url).map_err(ProviderError::Rejected)?;
        // A tenant chose this URL: the shared outbound client reaches public
        // addresses only (SSRF).
        let mut req = crate::util::outbound::shared()
            .post(&self.url)
            .timeout(HTTP_SEND_TIMEOUT)
            .json(&body);
        if let Some(h) = &self.auth_header {
            req = req.header("authorization", h);
        }
        let res = req.send().await.map_err(ProviderError::unavailable)?;
        match res.status() {
            s if s.is_success() => Ok(()),
            s if s.is_client_error() => {
                Err(ProviderError::Rejected(format!("webhook returned {s}")))
            }
            s => Err(ProviderError::Unavailable(format!("webhook returned {s}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// SMS webhook
// ---------------------------------------------------------------------------

pub struct WebhookSmsSender {
    url: String,
    auth_header: Option<String>,
    from: Option<String>,
}

impl WebhookSmsSender {
    pub fn new(cfg: &SmsProviderConfig) -> Self {
        Self {
            url: cfg.url.clone(),
            auth_header: cfg.auth_header.clone(),
            from: cfg.from.clone(),
        }
    }
}

#[async_trait]
impl SmsSender for WebhookSmsSender {
    fn name(&self) -> &'static str {
        "http"
    }

    async fn send(&self, message: &SmsMessage) -> Result<(), ProviderError> {
        let body = serde_json::json!({"to": message.to, "body": message.body, "from": self.from});
        crate::util::outbound::check_url(&self.url).map_err(ProviderError::Rejected)?;
        // A tenant chose this URL: the shared outbound client reaches public
        // addresses only (SSRF).
        let mut req = crate::util::outbound::shared()
            .post(&self.url)
            .timeout(HTTP_SEND_TIMEOUT)
            .json(&body);
        if let Some(h) = &self.auth_header {
            req = req.header("authorization", h);
        }
        let res = req.send().await.map_err(ProviderError::unavailable)?;
        match res.status() {
            s if s.is_success() => Ok(()),
            s if s.is_client_error() => {
                Err(ProviderError::Rejected(format!("webhook returned {s}")))
            }
            s => Err(ProviderError::Unavailable(format!("webhook returned {s}"))),
        }
    }
}
