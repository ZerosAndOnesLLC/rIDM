//! Profile schema: definition management and attribute validation.
//!
//! `validate_attributes` is the single choke point through which every write
//! to `users.attributes` passes (admin API, account console, registration,
//! imports, identity-provider mappers).

use std::sync::Arc;
use std::time::Duration;

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult, FieldError};
use crate::models::{AttributeDef, AttributeType, EditableBy, ProfileSchema};
use crate::repos;
use crate::state::AppState;

const SCHEMA_CACHE_TTL: Duration = Duration::from_secs(600);
const MAX_ATTRIBUTES: usize = 200;
const MAX_VALUE_BYTES: usize = 64 * 1024;

/// Who is writing attributes; decides which `editable_by` levels are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Editor {
    User,
    Admin,
    /// Imports (bulk user import, SCIM provisioning; see
    /// [`crate::services::users::create_as`]) and mappers: may write
    /// `editable_by: none` attributes too.
    System,
}

impl From<&Actor> for Editor {
    fn from(actor: &Actor) -> Self {
        match actor {
            Actor::User { .. } => Editor::User,
            Actor::Admin { .. } | Actor::Client { .. } => Editor::Admin,
            Actor::System => Editor::System,
        }
    }
}

pub async fn get(state: &AppState, tenant_id: Uuid) -> AppResult<Arc<ProfileSchema>> {
    let db = state.db.clone();
    let schema = state
        .cache
        .get_or_load(
            &keys::profile_schema(tenant_id),
            SCHEMA_CACHE_TTL,
            || async move {
                let mut tx = db::tenant_tx(&db, tenant_id).await?;
                let s = repos::profile_schema::get(&mut *tx, tenant_id).await?;
                tx.commit().await?;
                Ok(Some(s.unwrap_or_default()))
            },
        )
        .await?;
    Ok(schema.unwrap_or_default())
}

pub async fn set(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    schema: ProfileSchema,
) -> AppResult<ProfileSchema> {
    validate_schema(&schema)?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    repos::profile_schema::upsert(&mut *tx, tenant_id, &schema)
        .await
        .map_err(AppError::from_db)?;
    tx.commit().await?;
    state
        .cache
        .invalidate(&[keys::profile_schema(tenant_id)])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ProfileSchemaUpdated { tenant_id },
    ));
    Ok(schema)
}

/// Structural validation of the schema itself.
pub fn validate_schema(schema: &ProfileSchema) -> AppResult<()> {
    let mut errors = vec![];
    if schema.attributes.len() > MAX_ATTRIBUTES {
        errors.push(FieldError {
            field: "attributes".into(),
            message: format!("at most {MAX_ATTRIBUTES} attributes"),
        });
    }
    let mut seen = std::collections::HashSet::new();
    for (i, def) in schema.attributes.iter().enumerate() {
        let field = format!("attributes[{i}]");
        if !is_valid_attribute_name(&def.name) {
            errors.push(FieldError {
                field: format!("{field}.name"),
                message: "must match ^[a-zA-Z][a-zA-Z0-9_]{0,63}$".into(),
            });
        }
        if !seen.insert(def.name.as_str()) {
            errors.push(FieldError {
                field: format!("{field}.name"),
                message: format!("duplicate attribute `{}`", def.name),
            });
        }
        if def.kind == AttributeType::Enum && def.validation.values.is_empty() {
            errors.push(FieldError {
                field: format!("{field}.validation.values"),
                message: "enum attributes need at least one value".into(),
            });
        }
        if let Some(p) = &def.validation.pattern
            && compile_pattern(p).is_none()
        {
            errors.push(FieldError {
                field: format!("{field}.validation.pattern"),
                message: "invalid regular expression".into(),
            });
        }
        if let (Some(min), Some(max)) = (def.validation.min_length, def.validation.max_length)
            && min > max
        {
            errors.push(FieldError {
                field: format!("{field}.validation"),
                message: "min_length exceeds max_length".into(),
            });
        }
        if let (Some(min), Some(max)) = (def.validation.min, def.validation.max)
            && min > max
        {
            errors.push(FieldError {
                field: format!("{field}.validation"),
                message: "min exceeds max".into(),
            });
        }
        if def.required && def.editable_by == EditableBy::None {
            errors.push(FieldError {
                field: format!("{field}.required"),
                message: "a required attribute cannot be editable by nobody".into(),
            });
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation(errors))
    }
}

pub fn is_valid_attribute_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_alphabetic()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

fn compile_pattern(p: &str) -> Option<regex::Regex> {
    if p.len() > 512 {
        return None;
    }
    regex::RegexBuilder::new(&format!("^(?:{p})$"))
        .size_limit(1 << 20)
        .build()
        .ok()
}

/// Validate and normalize a full attribute document for a create, or a
/// replacement document for an update.
///
/// * Unknown attributes are rejected unless `allow_undeclared` (then admins
///   and system may write them, users may not).
/// * `editable_by` is enforced against `editor`; on updates a non-editable
///   attribute may be *kept* unchanged but not changed.
/// * Required attributes must be present (and non-empty) in the result.
/// * Values are type-checked and coerced to canonical JSON (numbers, booleans,
///   trimmed strings, arrays for multivalued).
pub fn validate_attributes(
    schema: &ProfileSchema,
    incoming: &Value,
    editor: Editor,
    existing: Option<&Value>,
) -> AppResult<Value> {
    validate_attributes_with(schema, incoming, editor, existing, true)
}

/// [`validate_attributes`], with `require_all = false` letting required
/// attributes be missing for now: an account created from an upstream
/// identity completes its profile at the next step of the sign-in.
pub fn validate_attributes_with(
    schema: &ProfileSchema,
    incoming: &Value,
    editor: Editor,
    existing: Option<&Value>,
    require_all: bool,
) -> AppResult<Value> {
    let Some(incoming) = incoming.as_object() else {
        return Err(AppError::BadRequest(
            "attributes must be a JSON object".into(),
        ));
    };
    let existing = existing.and_then(Value::as_object);
    let mut errors = vec![];
    let mut out = Map::new();

    for (name, value) in incoming {
        let field = format!("attributes.{name}");
        let unchanged = existing.is_some_and(|e| e.get(name) == Some(value));
        match schema.get(name) {
            None => {
                if !schema.allow_undeclared {
                    errors.push(FieldError {
                        field,
                        message: "unknown attribute".into(),
                    });
                } else if editor == Editor::User && !unchanged {
                    errors.push(FieldError {
                        field,
                        message: "not editable".into(),
                    });
                } else if value.to_string().len() > MAX_VALUE_BYTES {
                    errors.push(FieldError {
                        field,
                        message: "value too large".into(),
                    });
                } else {
                    out.insert(name.clone(), value.clone());
                }
            }
            Some(def) => {
                let allowed = match (def.editable_by, editor) {
                    (_, Editor::System) => true,
                    (EditableBy::User, _) => true,
                    (EditableBy::Admin, Editor::Admin) => true,
                    (EditableBy::Admin, Editor::User) => false,
                    (EditableBy::None, _) => false,
                };
                if !allowed && !unchanged {
                    errors.push(FieldError {
                        field,
                        message: "not editable".into(),
                    });
                    continue;
                }
                if value.is_null() {
                    // Explicit null clears the attribute.
                    continue;
                }
                match validate_value(def, value) {
                    Ok(v) => {
                        out.insert(name.clone(), v);
                    }
                    Err(message) => errors.push(FieldError { field, message }),
                }
            }
        }
    }

    // Preserve attributes the editor is not allowed to touch (and did not send).
    if let Some(existing) = existing {
        for (name, value) in existing {
            if out.contains_key(name) || incoming.contains_key(name) {
                continue;
            }
            let keep = match schema.get(name) {
                Some(def) => match (def.editable_by, editor) {
                    (_, Editor::System) => false,
                    (EditableBy::User, _) => false,
                    (EditableBy::Admin, Editor::Admin) => false,
                    (EditableBy::Admin, Editor::User) => true,
                    (EditableBy::None, _) => true,
                },
                None => editor == Editor::User,
            };
            if keep {
                out.insert(name.clone(), value.clone());
            }
        }
    }

    for def in &schema.attributes {
        if require_all && def.required && !out.get(&def.name).is_some_and(is_non_empty) {
            errors.push(FieldError {
                field: format!("attributes.{}", def.name),
                message: "required".into(),
            });
        }
    }

    if errors.is_empty() {
        Ok(Value::Object(out))
    } else {
        Err(AppError::Validation(errors))
    }
}

fn is_non_empty(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::String(s) => !s.trim().is_empty(),
        Value::Array(a) => !a.is_empty(),
        _ => true,
    }
}

fn validate_value(def: &AttributeDef, value: &Value) -> Result<Value, String> {
    if def.multivalued {
        let Some(items) = value.as_array() else {
            return Err("expected an array".into());
        };
        if items.len() > 100 {
            return Err("at most 100 values".into());
        }
        let mut out = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            out.push(validate_scalar(def, item).map_err(|e| format!("[{i}]: {e}"))?);
        }
        return Ok(Value::Array(out));
    }
    validate_scalar(def, value)
}

fn validate_scalar(def: &AttributeDef, value: &Value) -> Result<Value, String> {
    let v = &def.validation;
    let check_len = |s: &str| -> Result<(), String> {
        let n = s.chars().count() as u32;
        if v.min_length.is_some_and(|m| n < m) {
            return Err(format!(
                "must be at least {} characters",
                v.min_length.unwrap_or(0)
            ));
        }
        if v.max_length.is_some_and(|m| n > m) {
            return Err(format!(
                "must be at most {} characters",
                v.max_length.unwrap_or(0)
            ));
        }
        if let Some(p) = &v.pattern
            && !compile_pattern(p).is_some_and(|re| re.is_match(s))
        {
            return Err("does not match the required pattern".into());
        }
        Ok(())
    };
    match def.kind {
        AttributeType::String => {
            let Some(s) = value.as_str() else {
                return Err("expected a string".into());
            };
            let s = s.trim();
            if s.len() > MAX_VALUE_BYTES {
                return Err("value too large".into());
            }
            check_len(s)?;
            Ok(Value::String(s.to_string()))
        }
        AttributeType::Email => {
            let Some(s) = value.as_str() else {
                return Err("expected a string".into());
            };
            let s = s.trim().to_lowercase();
            if !validator::ValidateEmail::validate_email(&s) {
                return Err("invalid email address".into());
            }
            check_len(&s)?;
            Ok(Value::String(s))
        }
        AttributeType::Url => {
            let Some(s) = value.as_str() else {
                return Err("expected a string".into());
            };
            let s = s.trim();
            let parsed = url::Url::parse(s).map_err(|_| "invalid URL".to_string())?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err("URL must use http or https".into());
            }
            check_len(s)?;
            Ok(Value::String(s.to_string()))
        }
        AttributeType::Phone => {
            let Some(s) = value.as_str() else {
                return Err("expected a string".into());
            };
            let p = crate::services::users::normalize_phone(s).map_err(|e| e.to_string())?;
            Ok(Value::String(p))
        }
        AttributeType::Date => {
            let Some(s) = value.as_str() else {
                return Err("expected a string".into());
            };
            let d = chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d")
                .map_err(|_| "expected a date in YYYY-MM-DD form".to_string())?;
            Ok(Value::String(d.to_string()))
        }
        AttributeType::Enum => {
            let Some(s) = value.as_str() else {
                return Err("expected a string".into());
            };
            if !v.values.iter().any(|allowed| allowed == s) {
                return Err(format!("must be one of: {}", v.values.join(", ")));
            }
            Ok(Value::String(s.to_string()))
        }
        AttributeType::Number => {
            let Some(n) = value.as_f64() else {
                return Err("expected a number".into());
            };
            if v.min.is_some_and(|m| n < m) {
                return Err(format!("must be at least {}", v.min.unwrap_or(0.0)));
            }
            if v.max.is_some_and(|m| n > m) {
                return Err(format!("must be at most {}", v.max.unwrap_or(0.0)));
            }
            Ok(value.clone())
        }
        AttributeType::Boolean => match value {
            Value::Bool(_) => Ok(value.clone()),
            Value::String(s) if s == "true" || s == "false" => Ok(Value::Bool(s == "true")),
            _ => Err("expected a boolean".into()),
        },
        AttributeType::Json => {
            if !(value.is_object() || value.is_array()) {
                return Err("expected an object or array".into());
            }
            if value.to_string().len() > MAX_VALUE_BYTES {
                return Err("value too large".into());
            }
            Ok(value.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AttributeValidation, Exposure};
    use serde_json::json;

    fn schema() -> ProfileSchema {
        ProfileSchema {
            attributes: vec![
                AttributeDef {
                    name: "department".into(),
                    kind: AttributeType::Enum,
                    required: true,
                    validation: AttributeValidation {
                        values: vec!["eng".into(), "sales".into()],
                        ..Default::default()
                    },
                    ..Default::default()
                },
                AttributeDef {
                    name: "employee_id".into(),
                    kind: AttributeType::String,
                    editable_by: EditableBy::Admin,
                    validation: AttributeValidation {
                        pattern: Some("E[0-9]{4}".into()),
                        ..Default::default()
                    },
                    visible_in: vec![Exposure::IdToken],
                    ..Default::default()
                },
                AttributeDef {
                    name: "tags".into(),
                    multivalued: true,
                    validation: AttributeValidation {
                        max_length: Some(10),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                AttributeDef {
                    name: "score".into(),
                    kind: AttributeType::Number,
                    validation: AttributeValidation {
                        min: Some(0.0),
                        max: Some(100.0),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                AttributeDef {
                    name: "source".into(),
                    editable_by: EditableBy::None,
                    ..Default::default()
                },
            ],
            allow_undeclared: false,
        }
    }

    fn errs(r: AppResult<Value>) -> Vec<String> {
        match r {
            Err(AppError::Validation(e)) => e
                .into_iter()
                .map(|f| format!("{}: {}", f.field, f.message))
                .collect(),
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn schema_validation_catches_structural_problems() {
        let mut s = schema();
        s.attributes.push(AttributeDef {
            name: "department".into(),
            ..Default::default()
        });
        s.attributes.push(AttributeDef {
            name: "9bad".into(),
            ..Default::default()
        });
        s.attributes.push(AttributeDef {
            name: "re".into(),
            validation: AttributeValidation {
                pattern: Some("(".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        s.attributes.push(AttributeDef {
            name: "e".into(),
            kind: AttributeType::Enum,
            ..Default::default()
        });
        let e = match validate_schema(&s) {
            Err(AppError::Validation(e)) => e,
            other => panic!("{other:?}"),
        };
        assert_eq!(e.len(), 4, "{e:?}");
        assert!(validate_schema(&schema()).is_ok());
    }

    #[test]
    fn create_by_user_respects_types_required_and_editable_by() {
        let s = schema();
        let ok = validate_attributes(
            &s,
            &json!({"department": "eng", "tags": [" a ", "b"], "score": 42}),
            Editor::User,
            None,
        )
        .unwrap();
        assert_eq!(
            ok,
            json!({"department": "eng", "tags": ["a", "b"], "score": 42})
        );

        let e = errs(validate_attributes(
            &s,
            &json!({"department": "hr", "employee_id": "E0001", "tags": "x", "score": 200, "nope": 1}),
            Editor::User,
            None,
        ));
        assert!(
            e.iter()
                .any(|m| m.starts_with("attributes.department: must be one of")),
            "{e:?}"
        );
        assert!(
            e.iter()
                .any(|m| m == "attributes.employee_id: not editable"),
            "{e:?}"
        );
        assert!(
            e.iter().any(|m| m == "attributes.tags: expected an array"),
            "{e:?}"
        );
        assert!(
            e.iter()
                .any(|m| m.starts_with("attributes.score: must be at most")),
            "{e:?}"
        );
        assert!(
            e.iter().any(|m| m == "attributes.nope: unknown attribute"),
            "{e:?}"
        );

        let e = errs(validate_attributes(&s, &json!({}), Editor::User, None));
        assert_eq!(e, vec!["attributes.department: required"]);
    }

    #[test]
    fn admin_can_set_admin_fields_but_not_none_fields() {
        let s = schema();
        let ok = validate_attributes(
            &s,
            &json!({"department": "eng", "employee_id": "E1234"}),
            Editor::Admin,
            None,
        )
        .unwrap();
        assert_eq!(ok["employee_id"], "E1234");
        let e = errs(validate_attributes(
            &s,
            &json!({"department": "eng", "employee_id": "X1", "source": "ldap"}),
            Editor::Admin,
            None,
        ));
        assert!(
            e.iter()
                .any(|m| m == "attributes.employee_id: does not match the required pattern"),
            "{e:?}"
        );
        assert!(
            e.iter().any(|m| m == "attributes.source: not editable"),
            "{e:?}"
        );
        // System may write anything declared.
        assert!(
            validate_attributes(
                &s,
                &json!({"department": "eng", "source": "ldap"}),
                Editor::System,
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn update_preserves_protected_attributes_and_allows_unchanged_values() {
        let s = schema();
        let existing = json!({"department": "eng", "employee_id": "E1234", "source": "ldap"});
        // User sends a full replacement without the admin fields: they are preserved.
        let out = validate_attributes(
            &s,
            &json!({"department": "sales"}),
            Editor::User,
            Some(&existing),
        )
        .unwrap();
        assert_eq!(
            out,
            json!({"department": "sales", "employee_id": "E1234", "source": "ldap"})
        );
        // Sending the protected field unchanged is fine; changing it is not.
        assert!(
            validate_attributes(
                &s,
                &json!({"department": "sales", "employee_id": "E1234"}),
                Editor::User,
                Some(&existing)
            )
            .is_ok()
        );
        let e = errs(validate_attributes(
            &s,
            &json!({"department": "sales", "employee_id": "E9999"}),
            Editor::User,
            Some(&existing),
        ));
        assert_eq!(e, vec!["attributes.employee_id: not editable"]);
        // Admin replacing the document drops admin-editable fields it omits, keeps `none` fields.
        let out = validate_attributes(
            &s,
            &json!({"department": "eng"}),
            Editor::Admin,
            Some(&existing),
        )
        .unwrap();
        assert_eq!(out, json!({"department": "eng", "source": "ldap"}));
        // Explicit null clears.
        let out = validate_attributes(
            &s,
            &json!({"department": "eng", "employee_id": null}),
            Editor::Admin,
            Some(&existing),
        )
        .unwrap();
        assert!(out.get("employee_id").is_none());
    }

    #[test]
    fn undeclared_attributes_when_allowed() {
        let mut s = schema();
        s.allow_undeclared = true;
        assert!(
            validate_attributes(
                &s,
                &json!({"department": "eng", "extra": {"a": 1}}),
                Editor::Admin,
                None
            )
            .is_ok()
        );
        let e = errs(validate_attributes(
            &s,
            &json!({"department": "eng", "extra": 1}),
            Editor::User,
            None,
        ));
        assert_eq!(e, vec!["attributes.extra: not editable"]);
    }

    #[test]
    fn scalar_coercions() {
        let def = |kind| AttributeDef {
            name: "x".into(),
            kind,
            ..Default::default()
        };
        assert_eq!(
            validate_scalar(&def(AttributeType::Boolean), &json!("true")).unwrap(),
            json!(true)
        );
        assert_eq!(
            validate_scalar(&def(AttributeType::Email), &json!(" A@B.co ")).unwrap(),
            json!("a@b.co")
        );
        assert!(validate_scalar(&def(AttributeType::Url), &json!("ftp://x")).is_err());
        assert!(validate_scalar(&def(AttributeType::Date), &json!("2026-02-30")).is_err());
        assert_eq!(
            validate_scalar(&def(AttributeType::Date), &json!("2026-09-14")).unwrap(),
            json!("2026-09-14")
        );
        assert_eq!(
            validate_scalar(&def(AttributeType::Phone), &json!("+1 555 0100")).unwrap(),
            json!("+15550100")
        );
    }
}
