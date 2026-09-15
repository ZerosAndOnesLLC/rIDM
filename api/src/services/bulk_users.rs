//! Bulk user import (JSON or CSV, with legacy password hashes) and export.
//! Import works row by row: a bad row is reported and skipped, good rows
//! land. Export streams pages so a tenant of any size can be dumped.

use std::collections::HashMap;

use futures::stream::{self, Stream};
use ridm_core::events::Actor;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::models::{NewUser, Principal, Tenant, User, UserFilter, UserStatus};
use crate::services::password::{self, SetPasswordOptions};
use crate::services::{groups, roles, users};
use crate::state::AppState;
use crate::util::cursor::MAX_PAGE_SIZE;

/// Rows accepted per request.
pub const MAX_ROWS: usize = 10_000;

/// One user to import. `roles` and `groups` are names; `password_hash` is a
/// hash produced elsewhere (argon2, bcrypt, pbkdf2, sha, md5 formats) that
/// is upgraded transparently at first login; `password` is checked against
/// the tenant policy.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImportRow {
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub locale: Option<String>,
    pub status: Option<UserStatus>,
    pub attributes: Option<Value>,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub password: Option<String>,
    pub password_hash: Option<String>,
    pub must_change_password: bool,
}

#[derive(Debug, Serialize)]
pub struct ImportError {
    /// 1-based position in the submitted data.
    pub row: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub error: String,
}

#[derive(Debug, Default, Serialize)]
pub struct ImportReport {
    pub dry_run: bool,
    pub total: usize,
    pub created: usize,
    pub failed: usize,
    pub errors: Vec<ImportError>,
}

pub fn parse_json(bytes: &[u8]) -> AppResult<Vec<ImportRow>> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|e| AppError::BadRequest(format!("malformed JSON: {e}")))?;
    let items = match value {
        Value::Array(items) => items,
        Value::Object(mut o) => match o.remove("users") {
            Some(Value::Array(items)) => items,
            _ => {
                return Err(AppError::BadRequest(
                    "expected a JSON array of users or {\"users\": [...]}".into(),
                ));
            }
        },
        _ => {
            return Err(AppError::BadRequest(
                "expected a JSON array of users".into(),
            ));
        }
    };
    if items.len() > MAX_ROWS {
        return Err(AppError::BadRequest(format!(
            "at most {MAX_ROWS} users per request"
        )));
    }
    items
        .into_iter()
        .enumerate()
        .map(|(i, v)| {
            serde_json::from_value::<ImportRow>(v)
                .map_err(|e| AppError::BadRequest(format!("row {}: {e}", i + 1)))
        })
        .collect()
}

fn csv_bool(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "y"
    )
}

fn csv_list(s: &str) -> Vec<String> {
    s.split([';', '|'])
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

/// CSV with a header row. Known columns: `username`, `email`,
/// `email_verified`, `phone`, `phone_verified`, `locale`, `status`,
/// `roles` and `groups` (`;`-separated), `password`, `password_hash`,
/// `must_change_password`; `attr.<name>` columns become profile attributes
/// (JSON-parsed when they look like JSON, strings otherwise).
pub fn parse_csv(bytes: &[u8]) -> AppResult<Vec<ImportRow>> {
    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .flexible(false)
        .from_reader(bytes);
    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| AppError::BadRequest(format!("malformed CSV header: {e}")))?
        .iter()
        .map(|h| h.trim().to_string())
        .collect();
    const KNOWN: [&str; 12] = [
        "username",
        "email",
        "email_verified",
        "phone",
        "phone_verified",
        "locale",
        "status",
        "roles",
        "groups",
        "password",
        "password_hash",
        "must_change_password",
    ];
    if !headers.iter().any(|h| h == "username") {
        return Err(AppError::BadRequest("CSV needs a `username` column".into()));
    }
    if let Some(bad) = headers
        .iter()
        .find(|h| !KNOWN.contains(&h.as_str()) && !h.starts_with("attr."))
    {
        return Err(AppError::BadRequest(format!("unknown CSV column `{bad}`")));
    }
    let mut rows = Vec::new();
    for (i, record) in reader.records().enumerate() {
        let record = record
            .map_err(|e| AppError::BadRequest(format!("row {}: malformed CSV: {e}", i + 1)))?;
        if rows.len() >= MAX_ROWS {
            return Err(AppError::BadRequest(format!(
                "at most {MAX_ROWS} users per request"
            )));
        }
        let mut row = ImportRow::default();
        let mut attrs = Map::new();
        for (h, v) in headers.iter().zip(record.iter()) {
            let opt = || (!v.is_empty()).then(|| v.to_string());
            match h.as_str() {
                "username" => row.username = v.to_string(),
                "email" => row.email = opt(),
                "email_verified" => row.email_verified = csv_bool(v),
                "phone" => row.phone = opt(),
                "phone_verified" => row.phone_verified = csv_bool(v),
                "locale" => row.locale = opt(),
                "status" => {
                    row.status = match v.trim().to_ascii_lowercase().as_str() {
                        "" => None,
                        "active" => Some(UserStatus::Active),
                        "disabled" => Some(UserStatus::Disabled),
                        "pending" => Some(UserStatus::Pending),
                        other => {
                            return Err(AppError::BadRequest(format!(
                                "row {}: unknown status `{other}`",
                                i + 1
                            )));
                        }
                    }
                }
                "roles" => row.roles = csv_list(v),
                "groups" => row.groups = csv_list(v),
                "password" => row.password = opt(),
                "password_hash" => row.password_hash = opt(),
                "must_change_password" => row.must_change_password = csv_bool(v),
                other => {
                    if let Some(name) = other.strip_prefix("attr.")
                        && !v.is_empty()
                    {
                        let parsed = serde_json::from_str::<Value>(v)
                            .ok()
                            .filter(|p| !p.is_string() || v.starts_with('"'))
                            .unwrap_or_else(|| Value::String(v.to_string()));
                        attrs.insert(name.to_string(), parsed);
                    }
                }
            }
        }
        if !attrs.is_empty() {
            row.attributes = Some(Value::Object(attrs));
        }
        rows.push(row);
    }
    Ok(rows)
}

struct Lookups {
    roles: HashMap<String, Uuid>,
    groups: HashMap<String, Uuid>,
}

async fn lookups(state: &AppState, tenant_id: Uuid) -> AppResult<Lookups> {
    let roles = roles::list(state, tenant_id, Some(None))
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let groups = groups::list(state, tenant_id)
        .await?
        .into_iter()
        .map(|g| (g.name, g.id))
        .collect();
    Ok(Lookups { roles, groups })
}

/// Checks that need no database write: shape, credentials, references.
fn validate(row: &ImportRow, tenant: &Tenant, lookups: &Lookups) -> AppResult<()> {
    users::normalize_username(&row.username)?;
    if let Some(e) = &row.email {
        users::normalize_email(e)?;
    }
    if let Some(p) = &row.phone {
        users::normalize_phone(p)?;
    }
    if row.password.is_some() && row.password_hash.is_some() {
        return Err(AppError::BadRequest(
            "send either password or password_hash".into(),
        ));
    }
    if let Some(p) = &row.password {
        let problems = password::check_policy(&tenant.settings.password, p, None);
        if !problems.is_empty() {
            return Err(AppError::BadRequest(format!(
                "password: {}",
                problems.join("; ")
            )));
        }
    }
    if let Some(h) = &row.password_hash
        && password::legacy::algorithm_of(h) == "unknown"
    {
        return Err(AppError::BadRequest(
            "password_hash: unsupported hash format".into(),
        ));
    }
    if matches!(row.status, Some(UserStatus::Locked | UserStatus::Deleted)) {
        return Err(AppError::BadRequest(
            "status must be active, disabled or pending".into(),
        ));
    }
    for r in &row.roles {
        if !lookups.roles.contains_key(r) {
            return Err(AppError::BadRequest(format!("unknown role `{r}`")));
        }
    }
    for g in &row.groups {
        if !lookups.groups.contains_key(g) {
            return Err(AppError::BadRequest(format!("unknown group `{g}`")));
        }
    }
    Ok(())
}

async fn import_one(
    state: &AppState,
    tenant: &Tenant,
    actor: &Actor,
    lookups: &Lookups,
    row: ImportRow,
) -> AppResult<User> {
    let user = users::create(
        state,
        tenant.id,
        actor.clone(),
        NewUser {
            username: row.username,
            email: row.email,
            email_verified: row.email_verified,
            phone: row.phone,
            phone_verified: row.phone_verified,
            status: row.status,
            attributes: row.attributes,
            locale: row.locale,
            org_id: None,
        },
    )
    .await?;
    if let Some(h) = row.password_hash {
        password::import_hash(state, tenant.id, user.id, &h).await?;
        if row.must_change_password {
            users::update(
                state,
                tenant.id,
                actor.clone(),
                user.id,
                crate::models::UserUpdate {
                    must_change_password: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        }
    } else if let Some(p) = row.password {
        password::set_password(
            state,
            tenant.id,
            &tenant.settings.password,
            actor.clone(),
            user.id,
            Zeroizing::new(p),
            SetPasswordOptions {
                must_change: row.must_change_password,
                skip_policy: true, // validated already
                by_user: false,
                notify: false,
            },
        )
        .await?;
    }
    for r in &row.roles {
        roles::assign(
            state,
            tenant.id,
            actor.clone(),
            lookups.roles[r],
            Principal::User { id: user.id },
        )
        .await?;
    }
    for g in &row.groups {
        groups::add_member(state, tenant.id, actor.clone(), lookups.groups[g], user.id).await?;
    }
    Ok(user)
}

/// Import rows one at a time; failures are reported per row and never stop
/// the rest. With `dry_run` nothing is written and only validation runs
/// (uniqueness is then checked against existing users, not within the batch).
pub async fn import(
    state: &AppState,
    tenant: &Tenant,
    actor: Actor,
    rows: Vec<ImportRow>,
    dry_run: bool,
) -> AppResult<ImportReport> {
    let lookups = lookups(state, tenant.id).await?;
    let mut report = ImportReport {
        dry_run,
        total: rows.len(),
        ..Default::default()
    };
    for (i, row) in rows.into_iter().enumerate() {
        let username = Some(row.username.clone()).filter(|u| !u.is_empty());
        let outcome = match validate(&row, tenant, &lookups) {
            Err(e) => Err(e),
            Ok(()) if dry_run => {
                let taken = users::find_by_identifier(state, tenant.id, &row.username)
                    .await?
                    .is_some()
                    || match &row.email {
                        Some(e) => users::find_by_identifier(state, tenant.id, e)
                            .await?
                            .is_some(),
                        None => false,
                    };
                if taken {
                    Err(AppError::Conflict(
                        "username or email already in use".into(),
                    ))
                } else {
                    Ok(())
                }
            }
            Ok(()) => import_one(state, tenant, &actor, &lookups, row)
                .await
                .map(|_| ()),
        };
        match outcome {
            Ok(()) => report.created += 1,
            Err(e) => {
                report.failed += 1;
                report.errors.push(ImportError {
                    row: i + 1,
                    username,
                    error: match e {
                        AppError::BadRequest(d) | AppError::Conflict(d) => d,
                        AppError::Validation(fields) => fields
                            .iter()
                            .map(|f| format!("{}: {}", f.field, f.message))
                            .collect::<Vec<_>>()
                            .join("; "),
                        other => other.to_string(),
                    },
                });
            }
        }
    }
    Ok(report)
}

/// What an export row carries: the user record without credentials.
#[derive(Serialize)]
pub struct ExportRow {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub status: UserStatus,
    pub locale: Option<String>,
    pub attributes: Value,
    pub must_change_password: bool,
    pub last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<User> for ExportRow {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            email: u.email,
            email_verified: u.email_verified,
            phone: u.phone,
            phone_verified: u.phone_verified,
            status: u.status,
            locale: u.locale,
            attributes: u.attributes,
            must_change_password: u.must_change_password,
            last_login_at: u.last_login_at,
            created_at: u.created_at,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Json,
    Csv,
}

const CSV_HEADER: [&str; 12] = [
    "id",
    "username",
    "email",
    "email_verified",
    "phone",
    "phone_verified",
    "status",
    "locale",
    "attributes",
    "must_change_password",
    "last_login_at",
    "created_at",
];

fn csv_page(rows: &[ExportRow], with_header: bool) -> AppResult<Vec<u8>> {
    let mut w = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(Vec::new());
    let io = |e: csv::Error| AppError::Internal(format!("csv: {e}"));
    if with_header {
        w.write_record(CSV_HEADER).map_err(io)?;
    }
    for r in rows {
        w.write_record([
            r.id.to_string(),
            r.username.clone(),
            r.email.clone().unwrap_or_default(),
            r.email_verified.to_string(),
            r.phone.clone().unwrap_or_default(),
            r.phone_verified.to_string(),
            serde_json::to_value(r.status)?
                .as_str()
                .unwrap_or_default()
                .to_string(),
            r.locale.clone().unwrap_or_default(),
            r.attributes.to_string(),
            r.must_change_password.to_string(),
            r.last_login_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
            r.created_at.to_rfc3339(),
        ])
        .map_err(io)?;
    }
    w.into_inner()
        .map_err(|e| AppError::Internal(format!("csv: {e}")))
}

/// Stream every live user of the tenant, one page per chunk.
pub fn export(
    state: AppState,
    tenant_id: Uuid,
    format: ExportFormat,
) -> impl Stream<Item = AppResult<Vec<u8>>> {
    enum Step {
        Page(Option<String>, bool),
        Done,
    }
    stream::try_unfold(Step::Page(None, true), move |step| {
        let state = state.clone();
        async move {
            let (cursor, first) = match step {
                Step::Page(c, first) => (c, first),
                Step::Done => return Ok(None),
            };
            let page = users::list(
                &state,
                tenant_id,
                &UserFilter::default(),
                cursor.as_deref(),
                Some(MAX_PAGE_SIZE),
            )
            .await?;
            let rows: Vec<ExportRow> = page.items.into_iter().map(ExportRow::from).collect();
            let last = page.next_cursor.is_none();
            let mut chunk = match format {
                ExportFormat::Json => {
                    let mut out = Vec::new();
                    if first {
                        out.push(b'[');
                    }
                    for (i, r) in rows.iter().enumerate() {
                        if !first || i > 0 {
                            out.push(b',');
                        }
                        serde_json::to_writer(&mut out, r)?;
                    }
                    out
                }
                ExportFormat::Csv => csv_page(&rows, first)?,
            };
            if last && format == ExportFormat::Json {
                chunk.push(b']');
                chunk.push(b'\n');
            }
            let next = if last {
                Step::Done
            } else {
                Step::Page(page.next_cursor, false)
            };
            Ok(Some((chunk, next)))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_rows_map_onto_import_rows() {
        let data =
            b"username,email,email_verified,roles,attr.department,attr.level,password_hash\n\
                     alice,alice@example.com,true,editor;viewer,Sales,3,$2b$12$abc\n\
                     bob,,,,,,\n";
        let rows = parse_csv(data).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].username, "alice");
        assert!(rows[0].email_verified);
        assert_eq!(rows[0].roles, vec!["editor", "viewer"]);
        assert_eq!(rows[0].attributes.as_ref().unwrap()["department"], "Sales");
        assert_eq!(rows[0].attributes.as_ref().unwrap()["level"], 3);
        assert_eq!(rows[0].password_hash.as_deref(), Some("$2b$12$abc"));
        assert_eq!(rows[1].username, "bob");
        assert!(rows[1].email.is_none() && rows[1].attributes.is_none());
        assert!(parse_csv(b"email\nx@y.z\n").is_err(), "username required");
        assert!(
            parse_csv(b"username,colour\na,red\n").is_err(),
            "unknown column"
        );
    }

    #[test]
    fn json_accepts_array_or_wrapper() {
        assert_eq!(parse_json(br#"[{"username": "a"}]"#).unwrap().len(), 1);
        assert_eq!(
            parse_json(br#"{"users": [{"username": "a"}, {"username": "b"}]}"#)
                .unwrap()
                .len(),
            2
        );
        assert!(parse_json(br#"{"username": "a"}"#).is_err());
        assert!(parse_json(br#"[{"username": "a", "colour": "red"}]"#).is_err());
    }
}
