//! Locale negotiation for the browser flows and the messages they trigger.
//!
//! Order of preference: the OIDC `ui_locales` request parameter, then the
//! user's stored locale, then the tenant default. A candidate is accepted
//! when the tenant supports it exactly (`de-CH`) or by language (`de-CH`
//! matches a supported `de`, and `de` matches a supported `de-CH`).

use crate::error::{AppError, AppResult};
use crate::models::LocaleSettings;

/// Languages written right to left (BCP 47 primary subtags).
const RTL_LANGUAGES: &[&str] = &[
    "ar", "arc", "ckb", "dv", "fa", "he", "iw", "ks", "ku", "pa", "ps", "sd", "ug", "ur", "yi",
];

/// Canonical form: `pt_BR` / ` PT-br ` → `pt-BR`; language lowercase, region uppercase.
pub fn normalize(tag: &str) -> Option<String> {
    let tag = tag.trim().replace('_', "-");
    if tag.is_empty() || tag.len() > 35 {
        return None;
    }
    let mut out = Vec::new();
    for (i, part) in tag.split('-').enumerate() {
        if part.is_empty() || part.len() > 8 || !part.chars().all(|c| c.is_ascii_alphanumeric()) {
            return None;
        }
        out.push(match (i, part.len()) {
            (0, _) => part.to_ascii_lowercase(),
            (_, 2) => part.to_ascii_uppercase(),
            (_, 4) => {
                let mut s = part[..1].to_ascii_uppercase();
                s.push_str(&part[1..].to_ascii_lowercase());
                s
            }
            _ => part.to_ascii_lowercase(),
        });
    }
    Some(out.join("-"))
}

fn language(tag: &str) -> &str {
    tag.split('-').next().unwrap_or(tag)
}

/// Best supported locale for one candidate: exact match, else same language.
fn resolve(candidate: &str, supported: &[String]) -> Option<String> {
    let c = normalize(candidate)?;
    if let Some(s) = supported.iter().find(|s| s.eq_ignore_ascii_case(&c)) {
        return Some(s.clone());
    }
    let lang = language(&c);
    supported
        .iter()
        .find(|s| language(s).eq_ignore_ascii_case(lang))
        .cloned()
}

/// Pick the locale for a request. `requested` is `ui_locales` in preference
/// order; `user` the account's stored locale. Falls back to the tenant
/// default, which is always returned normalized.
pub fn negotiate(requested: &[String], user: Option<&str>, settings: &LocaleSettings) -> String {
    let supported = supported_of(settings);
    requested
        .iter()
        .map(String::as_str)
        .chain(user)
        .find_map(|c| resolve(c, &supported))
        .unwrap_or_else(|| default_of(settings))
}

/// Supported locales, normalized, with the default guaranteed present.
pub fn supported_of(settings: &LocaleSettings) -> Vec<String> {
    let mut out: Vec<String> = settings
        .supported
        .iter()
        .filter_map(|s| normalize(s))
        .collect();
    let d = default_of(settings);
    if !out.contains(&d) {
        out.insert(0, d);
    }
    out.dedup();
    out
}

fn default_of(settings: &LocaleSettings) -> String {
    normalize(&settings.default).unwrap_or_else(|| "en".into())
}

pub fn is_rtl(locale: &str) -> bool {
    let lang = language(locale).to_ascii_lowercase();
    RTL_LANGUAGES.contains(&lang.as_str())
}

/// `ltr` or `rtl`, for the `dir` attribute.
pub fn direction(locale: &str) -> &'static str {
    if is_rtl(locale) { "rtl" } else { "ltr" }
}

/// Canonicalize tenant locale settings and reject a default outside the
/// supported list or malformed tags.
pub fn validate_settings(settings: &mut LocaleSettings) -> AppResult<()> {
    let default = normalize(&settings.default)
        .ok_or_else(|| AppError::BadRequest("locale.default is not a valid language tag".into()))?;
    let mut supported = Vec::with_capacity(settings.supported.len() + 1);
    for tag in &settings.supported {
        let n = normalize(tag).ok_or_else(|| {
            AppError::BadRequest(format!("locale.supported contains an invalid tag `{tag}`"))
        })?;
        if !supported.contains(&n) {
            supported.push(n);
        }
    }
    if supported.is_empty() {
        supported.push(default.clone());
    }
    if !supported.contains(&default) {
        return Err(AppError::BadRequest(
            "locale.default must be one of locale.supported".into(),
        ));
    }
    settings.default = default;
    settings.supported = supported;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(default: &str, supported: &[&str]) -> LocaleSettings {
        LocaleSettings {
            default: default.into(),
            supported: supported.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn normalizes_tags() {
        assert_eq!(normalize("pt_BR").as_deref(), Some("pt-BR"));
        assert_eq!(normalize(" EN-us ").as_deref(), Some("en-US"));
        assert_eq!(normalize("zh-hant-TW").as_deref(), Some("zh-Hant-TW"));
        assert_eq!(normalize(""), None);
        assert_eq!(normalize("en-"), None);
        assert_eq!(normalize("en_US!"), None);
    }

    #[test]
    fn negotiation_order_and_matching() {
        let s = settings("en", &["en", "de", "fr-CA"]);
        // ui_locales first, in order, skipping unsupported ones.
        assert_eq!(
            negotiate(&["es".into(), "de-CH".into()], Some("fr"), &s),
            "de"
        );
        // Language match in both directions.
        assert_eq!(negotiate(&["fr".into()], None, &s), "fr-CA");
        assert_eq!(negotiate(&["fr-FR".into()], None, &s), "fr-CA");
        // Then the user's locale.
        assert_eq!(negotiate(&["es".into()], Some("de"), &s), "de");
        // Then the tenant default.
        assert_eq!(negotiate(&["es".into()], Some("it"), &s), "en");
        assert_eq!(negotiate(&[], None, &s), "en");
        // Garbage never panics.
        assert_eq!(negotiate(&["!!".into()], Some(""), &s), "en");
    }

    #[test]
    fn default_is_always_supported() {
        let s = settings("de", &["en"]);
        assert_eq!(supported_of(&s), vec!["de", "en"]);
        assert_eq!(negotiate(&["de".into()], None, &s), "de");
    }

    #[test]
    fn rtl_detection() {
        assert!(is_rtl("ar"));
        assert!(is_rtl("he-IL"));
        assert!(is_rtl("fa"));
        assert!(!is_rtl("en"));
        assert_eq!(direction("ur"), "rtl");
        assert_eq!(direction("de-CH"), "ltr");
    }

    #[test]
    fn settings_validation() {
        let mut s = settings("pt_br", &["en", "PT-BR", "pt-br"]);
        validate_settings(&mut s).unwrap();
        assert_eq!(s.default, "pt-BR");
        assert_eq!(s.supported, vec!["en", "pt-BR"]);
        let mut s = settings("de", &["en"]);
        assert!(validate_settings(&mut s).is_err());
        let mut s = settings("de", &[]);
        validate_settings(&mut s).unwrap();
        assert_eq!(s.supported, vec!["de"]);
        let mut s = settings("x y", &[]);
        assert!(validate_settings(&mut s).is_err());
    }
}
