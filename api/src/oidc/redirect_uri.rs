//! Redirect URI matching (OAuth 2.0 Security BCP §4.1.3): exact string
//! comparison, except that native clients may register a loopback redirect
//! and use any port at request time (RFC 8252 §7.3).

use url::Url;

use crate::models::ClientType;

pub fn matches(registered: &[String], requested: &str, client_type: ClientType) -> bool {
    if registered.iter().any(|r| r == requested) {
        return true;
    }
    if client_type != ClientType::Native {
        return false;
    }
    let Ok(req) = Url::parse(requested) else {
        return false;
    };
    if req.scheme() != "http" || !is_loopback_host(req.host_str()) {
        return false;
    }
    registered.iter().any(|r| {
        Url::parse(r).is_ok_and(|reg| {
            reg.scheme() == "http"
                && is_loopback_host(reg.host_str())
                && reg.host_str() == req.host_str()
                && reg.path() == req.path()
                && reg.query() == req.query()
        })
    })
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(
        host,
        Some("127.0.0.1") | Some("[::1]") | Some("::1") | Some("localhost")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_only_for_non_native() {
        let reg = vec!["https://app.example/cb".to_string()];
        assert!(matches(&reg, "https://app.example/cb", ClientType::Web));
        assert!(!matches(&reg, "https://app.example/cb/", ClientType::Web));
        assert!(!matches(
            &reg,
            "https://app.example/cb?x=1",
            ClientType::Web
        ));
        assert!(!matches(
            &reg,
            "https://app.example.evil/cb",
            ClientType::Web
        ));
        assert!(!matches(
            &reg,
            "https://evil.example/https://app.example/cb",
            ClientType::Web
        ));
        assert!(!matches(&reg, "HTTPS://app.example/cb", ClientType::Web));
        let loop_reg = vec!["http://127.0.0.1/cb".to_string()];
        assert!(
            !matches(&loop_reg, "http://127.0.0.1:8080/cb", ClientType::Spa),
            "port flexibility is native-only"
        );
    }

    #[test]
    fn native_loopback_ports_are_flexible() {
        let reg = vec![
            "http://127.0.0.1/cb".to_string(),
            "com.example.app:/oauth".to_string(),
        ];
        assert!(matches(
            &reg,
            "http://127.0.0.1:49152/cb",
            ClientType::Native
        ));
        assert!(matches(&reg, "http://127.0.0.1/cb", ClientType::Native));
        assert!(matches(&reg, "com.example.app:/oauth", ClientType::Native));
        assert!(!matches(
            &reg,
            "http://127.0.0.1:49152/other",
            ClientType::Native
        ));
        assert!(
            !matches(&reg, "http://localhost:49152/cb", ClientType::Native),
            "host must match the registration"
        );
        assert!(!matches(
            &reg,
            "https://127.0.0.1:49152/cb",
            ClientType::Native
        ));
        assert!(!matches(
            &reg,
            "http://127.0.0.1.evil:49152/cb",
            ClientType::Native
        ));
        let v6 = vec!["http://[::1]/cb".to_string()];
        assert!(matches(&v6, "http://[::1]:5000/cb", ClientType::Native));
    }
}
