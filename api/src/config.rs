//! Typed configuration loaded from environment variables (12-factor).
//!
//! Every deployment (bare metal, docker-compose, Kubernetes, any cloud) uses the
//! same image and configures it through the variables documented in `.env.example`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use ipnet::IpNet;
use url::Url;

use crate::util::secret::{SecretBytes, SecretString};
use crate::util::security_txt::SecurityTxt;

/// Length in bytes of the master key used to encrypt secrets at rest.
pub const MASTER_KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("invalid value for {name}: {reason}")]
    Invalid { name: &'static str, reason: String },
    #[error("failed to read {name} from {path}: {source}")]
    Io {
        name: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

impl FromStr for LogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "pretty" | "text" => Ok(Self::Pretty),
            other => Err(format!("expected `json` or `pretty`, got `{other}`")),
        }
    }
}

/// Native TLS termination. When absent, TLS is expected to be terminated by the
/// operator's reverse proxy or load balancer.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Mutual-TLS client authentication (RFC 8705). A client certificate reaches
/// rIDM in one of two ways: over rIDM's own mTLS listener, or in a header set
/// by a reverse proxy that terminated the TLS connection. Either one turns
/// the feature on.
#[derive(Debug, Clone, Default)]
pub struct MtlsConfig {
    /// A second listener that asks every connection for a client certificate
    /// (without requiring one) and serves the same routes (`MTLS_BIND`).
    pub bind_addr: Option<SocketAddr>,
    /// Its server certificate: `MTLS_CERT`/`MTLS_KEY`, else `TLS_CERT`/`TLS_KEY`.
    pub tls: Option<TlsConfig>,
    /// Where clients reach the mTLS endpoints (`MTLS_PUBLIC_URL`); discovery
    /// publishes them as `mtls_endpoint_aliases` (RFC 8705 §5).
    pub public_url: Option<Url>,
    /// Header a trusted proxy puts the client certificate in
    /// (`CLIENT_CERT_HEADER`, lower-case). Only read from a
    /// [`Config::trusted_proxies`] peer.
    pub cert_header: Option<String>,
}

impl MtlsConfig {
    /// Whether client certificates can reach rIDM at all.
    pub fn enabled(&self) -> bool {
        self.bind_addr.is_some() || self.cert_header.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Postgres connection string.
    pub database_url: String,
    /// A read replica for listings and statistics (`DATABASE_READ_URL`);
    /// `None` sends them to the primary.
    pub database_read_url: Option<String>,
    /// Redis / Valkey connection string.
    pub redis_url: String,
    /// Externally visible base URL, e.g. `https://id.example.com`. Issuer URLs
    /// are derived from it: `{PUBLIC_URL}/t/{tenant_slug}`.
    pub public_url: Url,
    /// Base URL of the static UI (login, consent, ... pages). Defaults to
    /// `PUBLIC_URL`: the UI on the API's origin, which a build with the
    /// `embedded-ui` feature serves itself; set when the UI is hosted
    /// elsewhere.
    pub ui_url: Url,
    /// Serve the UI compiled into the binary (`EMBEDDED_UI`, default on).
    /// Only has an effect in a build with the `embedded-ui` feature, and only
    /// when `UI_URL` is the API's own origin.
    pub embedded_ui: bool,
    /// 32-byte key that encrypts secrets at rest (current generation).
    /// Optional with a key custody backend (`KEY_WRAPPER`), which then
    /// supplies the current generation; kept while rows are rotated off it.
    pub master_key: Option<SecretBytes>,
    /// Generation number of `master_key`; stored with every ciphertext.
    pub master_key_version: u32,
    /// Older generations still needed to decrypt rows not yet re-encrypted
    /// (`MASTER_KEY_PREVIOUS="1=<hex>,2=<hex>"`).
    pub master_key_previous: Vec<(u32, SecretBytes)>,
    /// An HSM or KMS holding the master-key generations (`KEY_WRAPPER`).
    pub key_custody: crate::key_custody::KeyCustodyConfig,
    /// Socket address the HTTP(S) listener binds to.
    pub bind_addr: SocketAddr,
    pub log_format: LogFormat,
    /// Serve Swagger UI at `/docs`. Disable in production.
    pub docs_enabled: bool,
    /// Set the `Secure` attribute on cookies. Only disable for plain-HTTP local dev.
    pub cookie_secure: bool,
    /// Peers whose `X-Forwarded-For` / `Forwarded` headers are trusted.
    pub trusted_proxies: Vec<IpNet>,
    /// Private networks that outbound requests to tenant-chosen URLs may
    /// reach anyway (an internal application's back-channel logout endpoint,
    /// an internal webhook receiver). Empty: public addresses only.
    pub outbound_allow_networks: Vec<IpNet>,
    /// Deployment-wide request ceilings (per-tenant policy is in tenant settings).
    pub rate_limits: RateLimitConfig,
    /// What `/.well-known/security.txt` serves; `None` answers 404. Set by
    /// `SECURITY_TXT`/`SECURITY_TXT_FILE`, or `SECURITY_CONTACT` and
    /// `SECURITY_POLICY_URL`.
    pub security_txt: Option<SecurityTxt>,
    /// `Strict-Transport-Security` max-age in seconds, sent when `PUBLIC_URL`
    /// is https; 0 disables the header.
    pub hsts_max_age: u64,
    /// Days the hourly cleanup keeps spent rows (expired tokens and sessions,
    /// login attempts, sent messages, finished webhook deliveries, ...).
    pub retention_days: u32,
    /// OTLP/HTTP collector base URL for trace export (`OTEL_EXPORTER_OTLP_ENDPOINT`).
    pub otlp_endpoint: Option<Url>,
    /// `service.name` on exported traces (`OTEL_SERVICE_NAME`, default `ridm`).
    pub otel_service_name: String,
    /// Bearer token `/metrics` demands; open when unset.
    pub metrics_token: Option<SecretString>,
    /// Where audit rows are also shipped (`https://`, `syslog://`,
    /// `syslog+tcp://`, `syslog+tls://`).
    pub audit_sink_url: Option<Url>,
    pub audit_sink_token: Option<SecretString>,
    /// Key an HTTP(S) sink's batches are signed with (`X-RIDM-Signature`).
    pub audit_sink_secret: Option<SecretString>,
    /// PEM certificates to trust for the sink instead of the system's roots.
    pub audit_sink_ca_file: Option<PathBuf>,
    pub tls: Option<TlsConfig>,
    pub mtls: MtlsConfig,
    pub db_pool_min: u32,
    pub db_pool_max: u32,
    /// Valkey connections per node (`REDIS_POOL_MAX`, default 32).
    pub redis_pool_max: u32,
    /// Apply pending migrations at startup.
    pub migrate_on_start: bool,
    pub argon2: Argon2Params,
    /// Range endpoint of a Have I Been Pwned compatible breached-password
    /// API; `None` disables the check deployment-wide (air-gapped installs).
    pub breach_check_url: Option<Url>,
    /// Deployment-wide SMTP defaults used by tenants without their own settings.
    pub smtp: Option<SmtpDefaults>,
    /// First-run bootstrap from the environment (dev convenience). Runs after
    /// migrations when both email and password are set; a no-op once a global
    /// admin exists.
    pub bootstrap: Option<BootstrapConfig>,
    /// Where the risk policy's location signals get a country from.
    pub geoip: GeoIpConfig,
}

/// Geo-IP sources for risk-based adaptive authentication, in the order they
/// are consulted. Neither is required: a deployment with no source simply
/// raises no location signals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoIpConfig {
    /// Headers a trusted proxy or CDN sets, first one present wins. Only read
    /// when the request came through a [`Config::trusted_proxies`] peer, so
    /// nothing a client sends itself is believed.
    pub country_headers: Vec<String>,
    pub latitude_headers: Vec<String>,
    pub longitude_headers: Vec<String>,
    /// A MaxMind DB (`GEOIP_DB`), read into memory at startup. A City
    /// database also yields coordinates, which is what impossible travel
    /// needs; a Country database yields the country alone.
    pub db_path: Option<PathBuf>,
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            country_headers: ["cloudfront-viewer-country", "cf-ipcountry", "x-geo-country"]
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            latitude_headers: ["cloudfront-viewer-latitude", "x-geo-latitude"]
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            longitude_headers: ["cloudfront-viewer-longitude", "x-geo-longitude"]
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            db_path: None,
        }
    }
}

/// Rate limiting switches that belong to the deployment rather than a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Master switch; off only for tests and local experiments.
    pub enabled: bool,
    /// Requests per minute one client address may make to every limited
    /// endpoint of every tenant together (0 = off).
    pub ip_per_minute: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ip_per_minute: 6000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmtpDefaults {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<SecretString>,
    /// `From` header, e.g. `rIDM <no-reply@example.com>`.
    pub from: String,
    /// `starttls` (default), `tls`, or `none`.
    pub security: String,
}

#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    pub admin_email: String,
    pub admin_username: String,
    pub admin_password: SecretString,
    /// Also make sure `master` has the sample public client `sample-spa`
    /// (redirect `http://localhost:3000/callback`), see
    /// [`crate::services::bootstrap::ensure_sample_client`].
    pub sample_client: bool,
}

/// argon2id cost parameters. Defaults follow the OWASP minimum recommendation
/// (19 MiB, 2 iterations, 1 lane); raise them on capable hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory in KiB.
    pub m_cost: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

/// A secret setting: `NAME` itself, else the contents of the file `NAME_FILE`
/// names (a Docker or Kubernetes secret mount). The variable wins when both
/// are set, as with `MASTER_KEY`.
macro_rules! secret {
    ($name:literal) => {
        secret($name, concat!($name, "_FILE"))
    };
}

/// [`secret!`] for a setting the server cannot start without.
macro_rules! required_secret {
    ($name:literal) => {
        secret!($name)?.ok_or(ConfigError::Missing(concat!($name, " or ", $name, "_FILE")))
    };
}

impl Config {
    /// Load configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::load(true)
    }

    /// The configuration without the master key or key custody settings,
    /// for `ridm-api migrate`: migrations never touch an encrypted value, and
    /// the job that runs them should hold no key and need no KMS credentials.
    pub fn from_env_without_keys() -> Result<Self, ConfigError> {
        Self::load(false)
    }

    fn load(keys: bool) -> Result<Self, ConfigError> {
        let database_url = required_secret!("DATABASE_URL")?;
        let database_read_url = secret!("DATABASE_READ_URL")?;
        let redis_url = required_secret!("REDIS_URL")?;
        let public_url = parse("PUBLIC_URL", required("PUBLIC_URL")?, |v| {
            Url::parse(&v).map_err(|e| e.to_string()).and_then(|u| {
                if !matches!(u.scheme(), "http" | "https") {
                    return Err("scheme must be http or https".into());
                }
                Ok(u)
            })
        })?;
        let ui_url = match optional("UI_URL") {
            Some(v) => parse("UI_URL", v, |v| Url::parse(&v).map_err(|e| e.to_string()))?,
            None => public_url.clone(),
        };
        let key_custody = if keys {
            crate::key_custody::KeyCustodyConfig::from_env()?
        } else {
            Default::default()
        };
        let master_key = match keys.then(load_master_key) {
            None => None,
            Some(Ok(k)) => Some(k),
            Some(Err(ConfigError::Missing(_))) if key_custody.wrapper.is_some() => None,
            Some(Err(e)) => return Err(e),
        };
        if keys && master_key.is_none() && optional("MASTER_KEY_PREVIOUS").is_some() {
            return Err(ConfigError::Invalid {
                name: "MASTER_KEY_PREVIOUS",
                reason: "needs MASTER_KEY (keep it set until `rotate-master-key --status` shows \
                         no rows left on the environment's generations)"
                    .into(),
            });
        }
        let master_key_version = parse_u32("MASTER_KEY_VERSION", 1)?;
        if master_key_version == 0 {
            return Err(ConfigError::Invalid {
                name: "MASTER_KEY_VERSION",
                reason: "must be >= 1".into(),
            });
        }
        let master_key_previous = parse(
            "MASTER_KEY_PREVIOUS",
            optional("MASTER_KEY_PREVIOUS")
                .filter(|_| keys)
                .unwrap_or_default(),
            |v| -> Result<Vec<(u32, SecretBytes)>, String> {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|pair| {
                        let (ver, key) = pair
                            .split_once('=')
                            .ok_or_else(|| "expected `version=key` pairs".to_string())?;
                        let ver: u32 = ver.trim().parse().map_err(|_| "bad version".to_string())?;
                        if ver == 0 || ver >= master_key_version {
                            return Err(
                                "previous versions must be lower than MASTER_KEY_VERSION".into()
                            );
                        }
                        let key = decode_master_key("MASTER_KEY_PREVIOUS", key.trim().as_bytes())
                            .map_err(|e| e.to_string())?;
                        Ok((ver, key))
                    })
                    .collect()
            },
        )?;
        let bind_addr = parse(
            "BIND_ADDR",
            optional("BIND_ADDR").unwrap_or_else(|| "0.0.0.0:8080".to_string()),
            |v| v.parse::<SocketAddr>().map_err(|e| e.to_string()),
        )?;
        let log_format = parse(
            "LOG_FORMAT",
            optional("LOG_FORMAT").unwrap_or_else(|| "json".to_string()),
            |v| v.parse::<LogFormat>(),
        )?;
        let docs_enabled = parse_bool("DOCS_ENABLED", false)?;
        let embedded_ui = parse_bool("EMBEDDED_UI", true)?;
        let cookie_secure = parse_bool("COOKIE_SECURE", true)?;
        let trusted_proxies = parse(
            "TRUSTED_PROXIES",
            optional("TRUSTED_PROXIES").unwrap_or_default(),
            parse_networks,
        )?;
        let outbound_allow_networks = parse(
            "OUTBOUND_ALLOW_NETWORKS",
            optional("OUTBOUND_ALLOW_NETWORKS").unwrap_or_default(),
            parse_networks,
        )?;
        let rate_limits = RateLimitConfig {
            enabled: parse_bool("RATE_LIMITS", RateLimitConfig::default().enabled)?,
            ip_per_minute: parse_u32(
                "RATE_LIMIT_IP_PER_MINUTE",
                RateLimitConfig::default().ip_per_minute,
            )?,
        };
        let security_txt = SecurityTxt::from_settings(
            secret!("SECURITY_TXT")?,
            optional("SECURITY_CONTACT"),
            optional("SECURITY_POLICY_URL"),
        )
        .map_err(|(name, reason)| ConfigError::Invalid { name, reason })?;
        let hsts_max_age = u64::from(parse_u32("HSTS_MAX_AGE", 63_072_000)?);
        let retention_days = parse_u32("RETENTION_DAYS", 30)?;
        let otlp_endpoint = optional("OTEL_EXPORTER_OTLP_ENDPOINT")
            .map(|v| {
                parse("OTEL_EXPORTER_OTLP_ENDPOINT", v, |v| {
                    Url::parse(&v).map_err(|e| e.to_string())
                })
            })
            .transpose()?;
        let otel_service_name = optional("OTEL_SERVICE_NAME").unwrap_or_else(|| "ridm".to_string());
        let metrics_token = secret!("METRICS_TOKEN")?.map(SecretString::new);
        let audit_sink_url = optional("AUDIT_SINK_URL")
            .map(|v| {
                parse("AUDIT_SINK_URL", v, |v| {
                    Url::parse(&v).map_err(|e| e.to_string()).and_then(|u| {
                        if !matches!(
                            u.scheme(),
                            "http" | "https" | "syslog" | "syslog+udp" | "syslog+tcp" | "syslog+tls"
                        ) {
                            return Err(
                                "scheme must be http(s), syslog, syslog+udp, syslog+tcp or syslog+tls"
                                    .into(),
                            );
                        }
                        if u.scheme().starts_with("syslog") && u.host_str().is_none() {
                            return Err("a syslog sink needs a host".into());
                        }
                        Ok(u)
                    })
                })
            })
            .transpose()?;
        let audit_sink_token = secret!("AUDIT_SINK_TOKEN")?.map(SecretString::new);
        let audit_sink_secret = secret!("AUDIT_SINK_SECRET")?.map(SecretString::new);
        let audit_sink_ca_file = optional("AUDIT_SINK_CA_FILE").map(PathBuf::from);
        if retention_days == 0 {
            return Err(ConfigError::Invalid {
                name: "RETENTION_DAYS",
                reason: "must be at least 1".into(),
            });
        }
        let tls = match (optional("TLS_CERT"), optional("TLS_KEY")) {
            (Some(cert), Some(key)) => Some(TlsConfig {
                cert_path: PathBuf::from(cert),
                key_path: PathBuf::from(key),
            }),
            (None, None) => None,
            _ => {
                return Err(ConfigError::Invalid {
                    name: "TLS_CERT",
                    reason: "TLS_CERT and TLS_KEY must be set together".into(),
                });
            }
        };
        let mtls = mtls_config(tls.as_ref())?;
        let db_pool_min = parse_u32("DB_POOL_MIN", 2)?;
        let redis_pool_max = parse_u32("REDIS_POOL_MAX", 32)?.max(1);
        let db_pool_max = parse_u32("DB_POOL_MAX", 20)?;
        if db_pool_min > db_pool_max {
            return Err(ConfigError::Invalid {
                name: "DB_POOL_MIN",
                reason: "must not exceed DB_POOL_MAX".into(),
            });
        }
        let migrate_on_start = parse_bool("MIGRATE_ON_START", false)?;
        let defaults = Argon2Params::default();
        let argon2 = Argon2Params {
            m_cost: parse_u32("ARGON2_M_COST_KIB", defaults.m_cost)?,
            t_cost: parse_u32("ARGON2_T_COST", defaults.t_cost)?,
            p_cost: parse_u32("ARGON2_P_COST", defaults.p_cost)?,
        };
        if argon2.m_cost < 8 * 1024 || argon2.t_cost == 0 || argon2.p_cost == 0 {
            return Err(ConfigError::Invalid {
                name: "ARGON2_M_COST_KIB",
                reason: "argon2 parameters below the minimum (8 MiB, 1 iteration, 1 lane)".into(),
            });
        }

        let breach_check_url = match optional("BREACH_CHECK_URL").as_deref() {
            None => Some(
                Url::parse(crate::services::breach::HIBP_RANGE_URL).expect("valid default url"),
            ),
            Some("") | Some("off") | Some("none") | Some("false") => None,
            Some(raw) => {
                let mut url = Url::parse(raw).map_err(|e| ConfigError::Invalid {
                    name: "BREACH_CHECK_URL",
                    reason: e.to_string(),
                })?;
                if !url.path().ends_with('/') {
                    url.set_path(&format!("{}/", url.path()));
                }
                Some(url)
            }
        };
        let smtp = match optional("SMTP_HOST") {
            Some(host) => Some(SmtpDefaults {
                host,
                port: parse_u32("SMTP_PORT", 587)? as u16,
                username: optional("SMTP_USERNAME"),
                password: secret!("SMTP_PASSWORD")?.map(SecretString::new),
                from: optional("SMTP_FROM").ok_or(ConfigError::Missing("SMTP_FROM"))?,
                security: optional("SMTP_SECURITY").unwrap_or_else(|| "starttls".into()),
            }),
            None => None,
        };
        let bootstrap = match (
            optional("BOOTSTRAP_ADMIN_EMAIL"),
            secret!("BOOTSTRAP_ADMIN_PASSWORD")?,
        ) {
            (Some(admin_email), Some(password)) => Some(BootstrapConfig {
                admin_email,
                admin_username: optional("BOOTSTRAP_ADMIN_USERNAME")
                    .unwrap_or_else(|| "admin".to_string()),
                admin_password: SecretString::new(password),
                sample_client: parse_bool("BOOTSTRAP_SAMPLE_CLIENT", false)?,
            }),
            (None, None) => None,
            _ => {
                return Err(ConfigError::Invalid {
                    name: "BOOTSTRAP_ADMIN_EMAIL",
                    reason:
                        "BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD must be set together"
                            .into(),
                });
            }
        };

        let header_list = |name: &'static str, fallback: Vec<String>| match optional(name) {
            Some(raw) => raw
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            None => fallback,
        };
        let geo_defaults = GeoIpConfig::default();
        let geoip = GeoIpConfig {
            country_headers: header_list("GEOIP_COUNTRY_HEADERS", geo_defaults.country_headers),
            latitude_headers: header_list("GEOIP_LATITUDE_HEADERS", geo_defaults.latitude_headers),
            longitude_headers: header_list(
                "GEOIP_LONGITUDE_HEADERS",
                geo_defaults.longitude_headers,
            ),
            db_path: optional("GEOIP_DB").map(PathBuf::from),
        };

        Ok(Self {
            database_url,
            database_read_url,
            redis_url,
            public_url,
            ui_url,
            embedded_ui,
            master_key,
            master_key_version,
            master_key_previous,
            key_custody,
            bind_addr,
            log_format,
            docs_enabled,
            cookie_secure,
            trusted_proxies,
            outbound_allow_networks,
            rate_limits,
            security_txt,
            hsts_max_age,
            retention_days,
            otlp_endpoint,
            otel_service_name,
            metrics_token,
            audit_sink_url,
            audit_sink_token,
            audit_sink_secret,
            audit_sink_ca_file,
            tls,
            mtls,
            db_pool_min,
            db_pool_max,
            redis_pool_max,
            migrate_on_start,
            argon2,
            breach_check_url,
            smtp,
            bootstrap,
            geoip,
        })
    }

    /// URL of a UI page (`/login/`, `/consent/`, ...) under `UI_URL`, with
    /// query parameters. Pages for a tenant's users go through
    /// [`AppState::ui_page`](crate::state::AppState::ui_page), which knows
    /// about custom domains.
    pub fn ui_page(&self, page: &str, params: &[(&str, &str)]) -> String {
        page_url(&self.ui_url, page, params)
    }

    /// Origins (scheme, host, port) of the UI and of the API itself: browsers on
    /// these may call every endpoint (the consoles and the sign-in pages).
    pub fn own_origins(&self) -> Vec<String> {
        let mut v = vec![self.public_url.origin().ascii_serialization()];
        let ui = self.ui_url.origin().ascii_serialization();
        if !v.contains(&ui) {
            v.push(ui);
        }
        v
    }

    /// Hosts (`host[:port]`, lower-case) the API and the UI are reached on;
    /// a tenant's custom domain may not be one of them.
    pub fn primary_hosts(&self) -> Vec<String> {
        let mut v: Vec<String> = [
            Some(&self.public_url),
            Some(&self.ui_url),
            self.mtls.public_url.as_ref(),
        ]
        .into_iter()
        .flatten()
        .filter_map(|u| {
            let host = u.host_str()?.to_ascii_lowercase();
            Some(match u.port() {
                Some(p) => format!("{host}:{p}"),
                None => host,
            })
        })
        .collect();
        v.dedup();
        v
    }

    /// Issuer URL for a tenant: `{PUBLIC_URL}/t/{slug}` (no trailing slash).
    pub fn issuer_for(&self, tenant_slug: &str) -> String {
        format!(
            "{}/t/{tenant_slug}",
            self.public_url.as_str().trim_end_matches('/')
        )
    }
}

/// `MTLS_BIND`, `MTLS_CERT`/`MTLS_KEY`, `MTLS_PUBLIC_URL`, `CLIENT_CERT_HEADER`.
fn mtls_config(tls: Option<&TlsConfig>) -> Result<MtlsConfig, ConfigError> {
    let bind_addr = optional("MTLS_BIND")
        .map(|v| {
            parse("MTLS_BIND", v, |v| {
                v.parse::<SocketAddr>().map_err(|e| e.to_string())
            })
        })
        .transpose()?;
    let own_tls = match (optional("MTLS_CERT"), optional("MTLS_KEY")) {
        (Some(cert), Some(key)) => Some(TlsConfig {
            cert_path: PathBuf::from(cert),
            key_path: PathBuf::from(key),
        }),
        (None, None) => None,
        _ => {
            return Err(ConfigError::Invalid {
                name: "MTLS_CERT",
                reason: "MTLS_CERT and MTLS_KEY must be set together".into(),
            });
        }
    };
    let tls = own_tls.or_else(|| tls.cloned());
    if bind_addr.is_some() && tls.is_none() {
        return Err(ConfigError::Invalid {
            name: "MTLS_BIND",
            reason: "the mTLS listener needs a server certificate: set MTLS_CERT/MTLS_KEY or TLS_CERT/TLS_KEY".into(),
        });
    }
    let public_url = optional("MTLS_PUBLIC_URL")
        .map(|v| {
            parse("MTLS_PUBLIC_URL", v, |v| {
                let u = Url::parse(&v).map_err(|e| e.to_string())?;
                if u.scheme() != "https" && u.scheme() != "http" {
                    return Err("must be an http(s) URL".to_string());
                }
                if u.query().is_some() || u.fragment().is_some() {
                    return Err("must not have a query or fragment".to_string());
                }
                Ok(u)
            })
        })
        .transpose()?;
    let cert_header = optional("CLIENT_CERT_HEADER")
        .map(|v| {
            parse("CLIENT_CERT_HEADER", v, |v| {
                let v = v.trim().to_ascii_lowercase();
                axum::http::HeaderName::from_bytes(v.as_bytes())
                    .map(|_| v)
                    .map_err(|_| "not a header name".to_string())
            })
        })
        .transpose()?;
    let mtls = MtlsConfig {
        bind_addr,
        tls: bind_addr.and(tls),
        public_url,
        cert_header,
    };
    if mtls.public_url.is_some() && !mtls.enabled() {
        return Err(ConfigError::Invalid {
            name: "MTLS_PUBLIC_URL",
            reason: "set MTLS_BIND or CLIENT_CERT_HEADER as well: nothing would carry a client certificate".into(),
        });
    }
    Ok(mtls)
}

pub(crate) fn optional(name: &'static str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

pub(crate) fn required(name: &'static str) -> Result<String, ConfigError> {
    optional(name).ok_or(ConfigError::Missing(name))
}

pub(crate) fn secret(
    name: &'static str,
    file_var: &'static str,
) -> Result<Option<String>, ConfigError> {
    if let Some(v) = optional(name) {
        return Ok(Some(v));
    }
    match optional(file_var) {
        Some(path) => read_secret_file(file_var, PathBuf::from(path)),
        None => Ok(None),
    }
}

/// The file's contents without the line ending an editor or `echo` leaves;
/// anything else, surrounding spaces included, is part of the secret. An empty
/// file is an unset setting, as an empty variable is, so a deployment can
/// mount a secret for every setting and leave the unused ones empty.
fn read_secret_file(file_var: &'static str, path: PathBuf) -> Result<Option<String>, ConfigError> {
    let raw = std::fs::read_to_string(&path).map_err(|source| ConfigError::Io {
        name: file_var,
        path,
        source,
    })?;
    let value = raw.strip_suffix('\n').unwrap_or(&raw);
    let value = value.strip_suffix('\r').unwrap_or(value);
    Ok((!value.trim().is_empty()).then(|| value.to_string()))
}

pub(crate) fn parse<T, E: ToString>(
    name: &'static str,
    raw: String,
    f: impl FnOnce(String) -> Result<T, E>,
) -> Result<T, ConfigError> {
    f(raw).map_err(|e| ConfigError::Invalid {
        name,
        reason: e.to_string(),
    })
}

/// A comma-separated list of networks (`10.0.0.0/8`) or single addresses.
fn parse_networks(v: String) -> Result<Vec<IpNet>, String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpNet>().or_else(|_| {
                s.parse::<std::net::IpAddr>()
                    .map(IpNet::from)
                    .map_err(|e| format!("`{s}`: {e}"))
            })
        })
        .collect()
}

/// `{base}/{page}/?{params}`: a page of the UI under `base`.
pub fn page_url(base: &Url, page: &str, params: &[(&str, &str)]) -> String {
    let mut u = base.clone();
    let prefix = u.path().trim_end_matches('/').to_string();
    u.set_path(&format!("{prefix}/{}/", page.trim_matches('/')));
    u.set_query(None);
    if !params.is_empty() {
        let mut q = u.query_pairs_mut();
        for (k, v) in params {
            q.append_pair(k, v);
        }
    }
    u.to_string()
}

pub(crate) fn parse_bool(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match optional(name) {
        None => Ok(default),
        Some(v) => match v.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(ConfigError::Invalid {
                name,
                reason: format!("expected a boolean, got `{other}`"),
            }),
        },
    }
}

fn parse_u32(name: &'static str, default: u32) -> Result<u32, ConfigError> {
    match optional(name) {
        None => Ok(default),
        Some(v) => v.parse::<u32>().map_err(|e| ConfigError::Invalid {
            name,
            reason: e.to_string(),
        }),
    }
}

/// `MASTER_KEY` (hex or base64 of 32 bytes) or `MASTER_KEY_FILE` (raw 32 bytes,
/// or the same textual encodings). The env var takes precedence.
fn load_master_key() -> Result<SecretBytes, ConfigError> {
    if let Some(v) = optional("MASTER_KEY") {
        return decode_master_key("MASTER_KEY", v.trim().as_bytes());
    }
    if let Some(path) = optional("MASTER_KEY_FILE") {
        let path = PathBuf::from(path);
        let bytes = std::fs::read(&path).map_err(|source| ConfigError::Io {
            name: "MASTER_KEY_FILE",
            path: path.clone(),
            source,
        })?;
        if bytes.len() == MASTER_KEY_LEN {
            return Ok(SecretBytes::new(bytes));
        }
        let trimmed = bytes.trim_ascii();
        return decode_master_key("MASTER_KEY_FILE", trimmed);
    }
    Err(ConfigError::Missing(
        "MASTER_KEY or MASTER_KEY_FILE (or KEY_WRAPPER)",
    ))
}

fn decode_master_key(name: &'static str, raw: &[u8]) -> Result<SecretBytes, ConfigError> {
    use base64::Engine as _;

    let decoded = hex::decode(raw)
        .ok()
        .or_else(|| base64::engine::general_purpose::STANDARD.decode(raw).ok())
        .or_else(|| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(raw)
                .ok()
        })
        .ok_or_else(|| ConfigError::Invalid {
            name,
            reason: "expected hex or base64".into(),
        })?;
    if decoded.len() != MASTER_KEY_LEN {
        return Err(ConfigError::Invalid {
            name,
            reason: format!(
                "must decode to {MASTER_KEY_LEN} bytes, got {}",
                decoded.len()
            ),
        });
    }
    Ok(SecretBytes::new(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_accepts_hex_and_base64() {
        let hex_key = "00".repeat(MASTER_KEY_LEN);
        assert!(decode_master_key("MASTER_KEY", hex_key.as_bytes()).is_ok());
        let b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(decode_master_key("MASTER_KEY", b64.as_bytes()).is_ok());
        assert!(decode_master_key("MASTER_KEY", b"tooshort").is_err());
    }

    #[test]
    fn secret_files_lose_only_the_line_ending_and_empty_is_unset() {
        let dir = std::env::temp_dir().join(format!("ridm-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let read = |name: &str, contents: &str| {
            let path = dir.join(name);
            std::fs::write(&path, contents).unwrap();
            read_secret_file("X_FILE", path)
        };
        let value = |name: &str, contents: &str| read(name, contents).unwrap();
        assert_eq!(
            value("lf", "postgres://a:b@db/x\n").as_deref(),
            Some("postgres://a:b@db/x")
        );
        assert_eq!(value("crlf", "s3cret\r\n").as_deref(), Some("s3cret"));
        assert_eq!(value("bare", " pass word ").as_deref(), Some(" pass word "));
        assert_eq!(value("two", "a\n\n").as_deref(), Some("a\n"));
        assert_eq!(value("empty", ""), None);
        assert_eq!(value("blank", " \n"), None);
        assert!(matches!(
            read_secret_file("X_FILE", dir.join("missing")),
            Err(ConfigError::Io { name: "X_FILE", .. })
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn log_format_parses() {
        assert_eq!("JSON".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert_eq!("pretty".parse::<LogFormat>().unwrap(), LogFormat::Pretty);
        assert!("xml".parse::<LogFormat>().is_err());
    }
}
