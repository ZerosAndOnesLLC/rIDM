//! Feature flags (`settings.features`): switches a tenant's applications
//! consult, each on or off tenant-wide and, optionally, per organization.
//!
//! An application learns which are on for a user by asking for the
//! `features` scope (a `features` claim in the access and ID tokens) or by
//! calling `GET /t/{slug}/features` with a token of the tenant. Only flags
//! that are on are listed, so a flag no one has created reads as off.

use std::collections::BTreeMap;

use uuid::Uuid;

use crate::error::{AppError, AppResult, FieldError};
use crate::middleware::is_valid_slug;
use crate::models::{FeatureFlag, Tenant};
use crate::services::organizations;
use crate::state::AppState;

/// The scope that releases the `features` claim.
pub const SCOPE: &str = "features";
pub const MAX_FLAGS: usize = 200;
pub const MAX_DESCRIPTION: usize = 500;
pub const MAX_OVERRIDES: usize = 1000;

/// `a-z`, `0-9`, then also `.`, `_` and `-`; at most 64 characters.
pub fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && key.len() <= 64
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

pub fn validate(flags: &BTreeMap<String, FeatureFlag>) -> AppResult<()> {
    if flags.len() > MAX_FLAGS {
        return Err(AppError::BadRequest(format!(
            "at most {MAX_FLAGS} feature flags"
        )));
    }
    let mut errors = vec![];
    for (key, flag) in flags {
        let field = format!("features.{key}");
        if !is_valid_key(key) {
            errors.push(FieldError {
                field: field.clone(),
                message: "must be 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter or digit".into(),
            });
        }
        if flag
            .description
            .as_ref()
            .is_some_and(|d| d.chars().count() > MAX_DESCRIPTION)
        {
            errors.push(FieldError {
                field: format!("{field}.description"),
                message: format!("must be at most {MAX_DESCRIPTION} characters"),
            });
        }
        if flag.organizations.len() > MAX_OVERRIDES {
            errors.push(FieldError {
                field: format!("{field}.organizations"),
                message: format!("at most {MAX_OVERRIDES} organizations"),
            });
        }
        if let Some(bad) = flag.organizations.keys().find(|s| !is_valid_slug(s)) {
            errors.push(FieldError {
                field: format!("{field}.organizations"),
                message: format!("`{bad}` is not an organization slug"),
            });
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation(errors))
    }
}

/// The flags on for a user acting in the organization `org_slug` (or in
/// none), sorted.
pub fn enabled(flags: &BTreeMap<String, FeatureFlag>, org_slug: Option<&str>) -> Vec<String> {
    flags
        .iter()
        .filter(|(_, f)| {
            org_slug
                .and_then(|slug| f.organizations.get(slug).copied())
                .unwrap_or(f.enabled)
        })
        .map(|(k, _)| k.clone())
        .collect()
}

/// [`enabled`] for a sign-in acting in `org_id`. An organization that no
/// longer exists counts as none.
pub async fn enabled_for(
    state: &AppState,
    tenant: &Tenant,
    org_id: Option<Uuid>,
) -> AppResult<Vec<String>> {
    let flags = &tenant.settings.features;
    if flags.is_empty() {
        return Ok(vec![]);
    }
    let slug = match org_id {
        Some(id) if flags.values().any(|f| !f.organizations.is_empty()) => {
            match organizations::get(state, tenant.id, id).await {
                Ok(org) => Some(org.slug),
                Err(AppError::NotFound(_)) => None,
                Err(e) => return Err(e),
            }
        }
        _ => None,
    };
    Ok(enabled(flags, slug.as_deref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flag(enabled: bool, orgs: &[(&str, bool)]) -> FeatureFlag {
        FeatureFlag {
            enabled,
            description: None,
            organizations: orgs.iter().map(|(s, v)| (s.to_string(), *v)).collect(),
        }
    }

    #[test]
    fn an_organization_value_wins_over_the_tenant_wide_one() {
        let flags: BTreeMap<String, FeatureFlag> = [
            ("beta".to_string(), flag(false, &[("acme", true)])),
            ("new-ui".to_string(), flag(true, &[("globex", false)])),
            ("off".to_string(), flag(false, &[])),
        ]
        .into();
        assert_eq!(enabled(&flags, None), ["new-ui"]);
        assert_eq!(enabled(&flags, Some("acme")), ["beta", "new-ui"]);
        assert!(enabled(&flags, Some("globex")).is_empty());
    }

    #[test]
    fn bare_booleans_from_older_documents_still_load() {
        let flags: BTreeMap<String, FeatureFlag> =
            serde_json::from_str(r#"{"a": true, "b": {"enabled": false, "description": "B"}}"#)
                .unwrap();
        assert!(flags["a"].enabled);
        assert_eq!(flags["b"].description.as_deref(), Some("B"));
        let out = serde_json::to_value(&flags).unwrap();
        assert_eq!(out["a"], serde_json::json!({"enabled": true}));
    }

    #[test]
    fn keys_descriptions_and_slugs_are_checked() {
        assert!(is_valid_key("checkout.v2_beta-1"));
        for bad in ["", "Upper", "-lead", "sp ace", &"x".repeat(65)] {
            assert!(!is_valid_key(bad), "{bad}");
        }
        let mut flags: BTreeMap<String, FeatureFlag> = [("ok".to_string(), flag(true, &[]))].into();
        assert!(validate(&flags).is_ok());
        flags.insert("ok".into(), flag(true, &[("Not A Slug", true)]));
        assert!(validate(&flags).is_err());
        flags.insert(
            "ok".into(),
            FeatureFlag {
                description: Some("d".repeat(MAX_DESCRIPTION + 1)),
                ..flag(true, &[])
            },
        );
        assert!(validate(&flags).is_err());
    }
}
