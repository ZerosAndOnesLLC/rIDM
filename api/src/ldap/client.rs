//! A connection to a directory. The host is resolved through
//! [`crate::util::outbound::resolve_public`] and the socket opened to the
//! address it vetted (a tenant administrator chooses the URL, so reaching
//! this server's own network needs the operator's `OUTBOUND_ALLOW_NETWORKS`);
//! TLS then verifies the certificate against the configured host name.
//! Plain `ldap://` without StartTLS is for loopback only.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use ldap3::adapters::{EntriesOnly, PagedResults};
use ldap3::exop::PasswordModify;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Mod, Scope, SearchOptions, StdStream};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use zeroize::Zeroizing;

use super::entry::Entry;

/// LDAP result codes rIDM tells apart (RFC 4511 appendix A).
const RC_SUCCESS: u32 = 0;
const RC_SIZE_LIMIT_EXCEEDED: u32 = 4;
const RC_NO_SUCH_OBJECT: u32 = 32;
const RC_INVALID_CREDENTIALS: u32 = 49;

/// How to reach a directory.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub url: String,
    pub starttls: bool,
    /// PEM certificates the server's chain must end in; none uses the
    /// platform verifier.
    pub ca_certificate: Option<String>,
    pub timeout: Duration,
}

/// Why a directory operation failed.
#[derive(Debug, thiserror::Error)]
pub enum LdapFailure {
    #[error("{0}")]
    Config(String),
    #[error("cannot reach the directory: {0}")]
    Connect(String),
    #[error("the directory refused the operation (result {rc}: {text})")]
    Refused { rc: u32, text: String },
    #[error("the directory did not answer in time")]
    Timeout,
    #[error("the directory sent a malformed entry")]
    Malformed,
}

impl From<ldap3::LdapError> for LdapFailure {
    fn from(e: ldap3::LdapError) -> Self {
        match e {
            ldap3::LdapError::Timeout { .. } => Self::Timeout,
            ldap3::LdapError::LdapResult { result } => Self::Refused {
                rc: result.rc,
                text: result.text,
            },
            other => Self::Connect(other.to_string()),
        }
    }
}

/// Parse and check a directory URL: `ldap` or `ldaps`, a host, no path,
/// query or credentials. Returns the host, the port and whether the
/// transport is TLS from the first byte.
pub fn check_url(raw: &str) -> Result<(String, u16, bool), String> {
    let u = url::Url::parse(raw.trim()).map_err(|_| "must be an ldap:// or ldaps:// URL")?;
    let tls = match u.scheme() {
        "ldaps" => true,
        "ldap" => false,
        _ => return Err("must be an ldap:// or ldaps:// URL".into()),
    };
    let host = u
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or("must name a host")?
        .to_string();
    if !u.username().is_empty() || u.password().is_some() {
        return Err("must not carry credentials (use the bind DN and password)".into());
    }
    if !matches!(u.path(), "" | "/") || u.query().is_some() || u.fragment().is_some() {
        return Err("must be only a scheme, host and port".into());
    }
    let port = u.port().unwrap_or(if tls { 636 } else { 389 });
    Ok((host, port, tls))
}

/// Is `host` loopback by name or address (where plain LDAP is allowed)?
pub fn is_loopback(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Parse PEM certificates (a CA bundle); at least one is required.
pub fn parse_ca(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs: Vec<_> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("is not PEM: {e}"))?;
    if certs.is_empty() || certs.len() > 20 {
        return Err("must hold one to twenty PEM certificates".into());
    }
    for c in &certs {
        x509_parser::parse_x509_certificate(c.as_ref())
            .map_err(|_| "holds something that is not an X.509 certificate".to_string())?;
    }
    Ok(certs)
}

fn tls_config(ca: Option<&str>) -> Result<Arc<rustls::ClientConfig>, LdapFailure> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| LdapFailure::Config(e.to_string()))?;
    let config = match ca {
        Some(pem) => {
            let mut store = rustls::RootCertStore::empty();
            for c in parse_ca(pem).map_err(LdapFailure::Config)? {
                store
                    .add(c)
                    .map_err(|e| LdapFailure::Config(format!("CA certificate: {e}")))?;
            }
            builder.with_root_certificates(store).with_no_client_auth()
        }
        None => {
            let verifier = rustls_platform_verifier::Verifier::new(provider)
                .map_err(|e| LdapFailure::Config(e.to_string()))?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        }
    };
    Ok(Arc::new(config))
}

/// An open connection. Dropping it closes the socket; [`Conn::close`]
/// unbinds politely first.
pub struct Conn {
    ldap: Ldap,
    timeout: Duration,
}

impl Conn {
    /// Connect (TCP to a vetted address, then TLS or StartTLS).
    pub async fn open(opts: &ConnectOptions) -> Result<Conn, LdapFailure> {
        let (host, port, tls) = check_url(&opts.url).map_err(LdapFailure::Config)?;
        if !tls && !opts.starttls && !is_loopback(&host) {
            return Err(LdapFailure::Config(
                "plain ldap:// needs StartTLS unless the host is loopback".into(),
            ));
        }
        let addr = crate::util::outbound::resolve_public(&host, port)
            .await
            .map_err(LdapFailure::Connect)?;
        let tcp = tokio::time::timeout(opts.timeout, tokio::net::TcpStream::connect(addr))
            .await
            .map_err(|_| LdapFailure::Timeout)?
            .map_err(|e| LdapFailure::Connect(e.to_string()))?;
        let std_stream = tcp
            .into_std()
            .map_err(|e| LdapFailure::Connect(e.to_string()))?;
        let mut settings = LdapConnSettings::new()
            .set_conn_timeout(opts.timeout)
            .set_std_stream(StdStream::Tcp(std_stream))
            .set_starttls(opts.starttls && !tls);
        if tls || opts.starttls {
            settings = settings.set_config(tls_config(opts.ca_certificate.as_deref())?);
        }
        // The URL is rebuilt from what was checked: the connection goes to
        // the vetted socket, TLS verifies `host`.
        let scheme = if tls { "ldaps" } else { "ldap" };
        let url = if host.contains(':') {
            format!("{scheme}://[{host}]:{port}")
        } else {
            format!("{scheme}://{host}:{port}")
        };
        let (conn, ldap) =
            tokio::time::timeout(opts.timeout, LdapConnAsync::with_settings(settings, &url))
                .await
                .map_err(|_| LdapFailure::Timeout)??;
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                tracing::debug!(error = %e, "LDAP connection ended");
            }
        });
        Ok(Conn {
            ldap,
            timeout: opts.timeout,
        })
    }

    /// A simple bind. `Ok(false)` for wrong credentials. An empty password
    /// is never sent: LDAP treats it as an unauthenticated bind, which
    /// succeeds without proving anything (RFC 4513 5.1.2).
    pub async fn bind(&mut self, dn: &str, password: &str) -> Result<bool, LdapFailure> {
        if dn.is_empty() || password.is_empty() {
            return Ok(false);
        }
        let res = self
            .ldap
            .with_timeout(self.timeout)
            .simple_bind(dn, password)
            .await?;
        match res.rc {
            RC_SUCCESS => Ok(true),
            RC_INVALID_CREDENTIALS => {
                if !res.text.is_empty() {
                    // Active Directory says why (expired, must change,
                    // disabled) in the diagnostic text.
                    tracing::debug!(diagnostic = %res.text, "LDAP bind refused");
                }
                Ok(false)
            }
            rc => Err(LdapFailure::Refused { rc, text: res.text }),
        }
    }

    /// Search, keeping at most `limit` entries: the directory is asked
    /// for `limit` (so a caller can ask for 2 to learn an identifier is
    /// ambiguous) and a size-limit answer is not an error.
    pub async fn search(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[String],
        limit: i32,
    ) -> Result<Vec<Entry>, LdapFailure> {
        let mut stream = self
            .ldap
            .with_timeout(self.timeout)
            .with_search_options(SearchOptions::new().sizelimit(limit))
            .streaming_search_with(EntriesOnly::new(), base, scope, filter, attrs.to_vec())
            .await?;
        let mut out = vec![];
        while let Some(re) = stream.next().await? {
            out.push(Entry::parse(re).ok_or(LdapFailure::Malformed)?);
            if out.len() >= limit as usize {
                break;
            }
        }
        let res = stream.finish().await;
        match res.rc {
            RC_SUCCESS | RC_SIZE_LIMIT_EXCEEDED | RC_NO_SUCH_OBJECT => Ok(out),
            // Abandoned after `limit` entries: what was read stands.
            _ if out.len() >= limit as usize => Ok(out),
            rc => Err(LdapFailure::Refused { rc, text: res.text }),
        }
    }

    /// Start a paged search (Simple Paged Results, RFC 2696), for sync.
    pub async fn search_paged(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<String>,
        page_size: i32,
    ) -> Result<PagedSearch, LdapFailure> {
        let adapters: Vec<Box<dyn ldap3::adapters::Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(page_size)),
        ];
        let stream = self
            .ldap
            .with_timeout(self.timeout)
            .streaming_search_with(adapters, base, scope, filter, attrs)
            .await?;
        Ok(PagedSearch { stream })
    }

    /// Modify an entry.
    pub async fn modify(&mut self, dn: &str, mods: Vec<Mod<Vec<u8>>>) -> Result<(), LdapFailure> {
        let res = self
            .ldap
            .with_timeout(self.timeout)
            .modify(dn, mods)
            .await?;
        match res.rc {
            RC_SUCCESS => Ok(()),
            rc => Err(LdapFailure::Refused { rc, text: res.text }),
        }
    }

    /// Set an entry's password with the Password Modify extended operation
    /// (RFC 3062; OpenLDAP and most directories other than AD).
    pub async fn password_modify(&mut self, dn: &str, new: &str) -> Result<(), LdapFailure> {
        let (res, _) = self
            .ldap
            .with_timeout(self.timeout)
            .extended(PasswordModify {
                user_id: Some(dn),
                old_pass: None,
                new_pass: Some(new),
            })
            .await?
            .success()?;
        let _ = res;
        Ok(())
    }

    /// Set an Active Directory password: `unicodePwd` replaced with the
    /// quoted password in UTF-16LE (AD accepts it only over TLS).
    pub async fn set_ad_password(&mut self, dn: &str, new: &str) -> Result<(), LdapFailure> {
        let quoted: Zeroizing<Vec<u8>> = Zeroizing::new(
            format!("\"{new}\"")
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        );
        self.modify(
            dn,
            vec![Mod::Replace(
                b"unicodePwd".to_vec(),
                HashSet::from([quoted.to_vec()]),
            )],
        )
        .await
    }

    /// Unbind and close.
    pub async fn close(mut self) {
        let _ = self.ldap.unbind().await;
    }
}

/// A paged search in progress.
pub struct PagedSearch {
    stream: ldap3::SearchStream<'static, String, Vec<String>>,
}

impl PagedSearch {
    /// The next entry; `None` when the search is done.
    pub async fn next(&mut self) -> Result<Option<Entry>, LdapFailure> {
        match self.stream.next().await? {
            Some(re) => Ok(Some(Entry::parse(re).ok_or(LdapFailure::Malformed)?)),
            None => {
                let res = self.stream.finish().await;
                match res.rc {
                    RC_SUCCESS | RC_NO_SUCH_OBJECT => Ok(None),
                    rc => Err(LdapFailure::Refused { rc, text: res.text }),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_scheme_host_and_port_only() {
        assert_eq!(
            check_url("ldaps://dc1.corp.example").unwrap(),
            ("dc1.corp.example".into(), 636, true)
        );
        assert_eq!(
            check_url("ldap://127.0.0.1:1389").unwrap(),
            ("127.0.0.1".into(), 1389, false)
        );
        assert!(check_url("https://dc1").is_err());
        assert!(check_url("ldap://").is_err());
        assert!(check_url("ldap://user:pw@dc1").is_err());
        assert!(check_url("ldap://dc1/dc=example,dc=org").is_err());
        assert!(check_url("ldap://dc1?x").is_err());
    }

    #[test]
    fn loopback_by_name_or_address() {
        assert!(is_loopback("localhost"));
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("[::1]"));
        assert!(!is_loopback("dc1.corp.example"));
        assert!(!is_loopback("10.0.0.5"));
    }

    #[tokio::test]
    async fn plain_ldap_off_loopback_is_refused_before_connecting() {
        let err = Conn::open(&ConnectOptions {
            url: "ldap://dc1.corp.example".into(),
            starttls: false,
            ca_certificate: None,
            timeout: Duration::from_secs(1),
        })
        .await
        .err()
        .unwrap();
        assert!(matches!(err, LdapFailure::Config(_)), "{err}");
    }

    #[test]
    fn a_ca_bundle_must_be_certificates() {
        assert!(parse_ca("not pem").is_err());
        assert!(parse_ca("").is_err());
    }
}
