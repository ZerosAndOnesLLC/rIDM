//! SCIM 2.0 (RFC 7643/7644) over rIDM users and groups.
//!
//! A SCIM `User` maps onto a user row: `userName` ↔ `username`, `externalId`
//! ↔ `external_id`, the primary `emails` entry ↔ `email`, the first
//! `phoneNumbers` entry ↔ `phone`, `active` ↔ status (active / disabled),
//! `locale` ↔ `locale`, and `name.givenName`, `name.familyName`,
//! `displayName` ↔ the profile attributes `given_name`, `family_name`,
//! `display_name` when the tenant's profile schema declares them (an
//! undeclared one is dropped unless the schema allows undeclared attributes).
//! `groups` is read-only. A SCIM `Group` maps onto a group: `displayName` ↔
//! `name`, `externalId` ↔ `attributes.externalId`, `members` ↔ memberships
//! (users only). A SCIM token carries no administrator whose permissions could
//! bound what it hands out, so it may not add members to a group whose roles
//! (with its ancestors' and composites) grant any admin-catalogue permission:
//! that is refused with 403 before anything changes.
//!
//! Filters follow RFC 7644 §3.4.2.2 (`eq ne co sw ew pr gt ge lt le`,
//! `and`/`or`/`not`, parentheses, dotted paths). A filter that is one
//! equality on `userName`, `externalId`, `emails.value`/`emails` or `id`
//! becomes an index lookup; any other user filter is evaluated over the
//! tenant's users up to [`SCAN_LIMIT`] rows and refused beyond that
//! (`tooMany`). PATCH applies RFC 7644 §3.5.2 operations to the resource's
//! SCIM document — simple, dotted and `attr[filter].sub` paths, schema-URN
//! prefixes, case-insensitive names, `"True"`/`"False"` strings for
//! booleans — and stores the result as a full replace, so PUT and PATCH
//! share one path.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use ridm_core::events::Actor;
use serde::Serialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::error::AppError;
use crate::models::{
    Group, NewGroup, NewUser, ProfileSchema, Tenant, User, UserFilter, UserStatus, UserUpdate,
};
use crate::services::admin_access::{self, Grant};
use crate::services::{groups, profile_schema, users};
use crate::state::AppState;

pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub const CONTENT_TYPE: &str = "application/scim+json";
/// `count` above this is clamped; `startIndex` beyond `SCAN_LIMIT` is refused.
pub const MAX_PAGE: i64 = 200;
/// Users a non-indexed filter may look at.
pub const SCAN_LIMIT: i64 = 2000;

const ATTR_GIVEN: &str = "given_name";
const ATTR_FAMILY: &str = "family_name";
const ATTR_DISPLAY: &str = "display_name";

// --- errors ------------------------------------------------------------------

/// RFC 7644 §3.12 error document.
#[derive(Debug, Clone, Serialize)]
pub struct ScimError {
    pub schemas: [&'static str; 1],
    pub status: String,
    #[serde(rename = "scimType", skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<&'static str>,
    pub detail: String,
}

impl ScimError {
    pub fn new(
        status: StatusCode,
        scim_type: Option<&'static str>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            schemas: [ERROR_SCHEMA],
            status: status.as_u16().to_string(),
            scim_type,
            detail: detail.into(),
        }
    }

    pub fn bad(scim_type: &'static str, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, Some(scim_type), detail)
    }

    pub fn not_found(what: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, None, format!("{what} not found"))
    }

    pub fn status_code(&self) -> StatusCode {
        self.status
            .parse::<u16>()
            .ok()
            .and_then(|s| StatusCode::from_u16(s).ok())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

impl From<AppError> for ScimError {
    fn from(e: AppError) -> Self {
        match e {
            AppError::NotFound(what) => Self::not_found(what),
            AppError::Conflict(d) => Self::new(StatusCode::CONFLICT, Some("uniqueness"), d),
            AppError::BadRequest(d) => Self::bad("invalidValue", d),
            AppError::Validation(fields) => Self::bad(
                "invalidValue",
                fields
                    .iter()
                    .map(|f| format!("{}: {}", f.field, f.message))
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
            AppError::Forbidden(d) => Self::new(StatusCode::FORBIDDEN, None, d),
            AppError::Unauthorized => {
                Self::new(StatusCode::UNAUTHORIZED, None, "authentication required")
            }
            AppError::RateLimited { .. } => {
                Self::new(StatusCode::TOO_MANY_REQUESTS, None, "rate limit exceeded")
            }
            other => {
                tracing::error!(error = ?other, "scim request failed");
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, None, "internal error")
            }
        }
    }
}

impl From<sqlx::Error> for ScimError {
    fn from(e: sqlx::Error) -> Self {
        Self::from(AppError::from_db(e))
    }
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        scim_json(self.status_code(), &self)
    }
}

pub type ScimResult<T> = Result<T, ScimError>;

/// A JSON body with the SCIM media type.
pub fn scim_json<T: Serialize>(status: StatusCode, body: &T) -> Response {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    (
        status,
        [(axum::http::header::CONTENT_TYPE, CONTENT_TYPE)],
        bytes,
    )
        .into_response()
}

// --- mapping -----------------------------------------------------------------

fn meta(
    kind: &str,
    base: &str,
    id: Uuid,
    created: DateTime<Utc>,
    modified: DateTime<Utc>,
) -> Value {
    json!({
        "resourceType": kind,
        "created": created.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "lastModified": modified.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "location": format!("{base}/{}s/{id}", kind),
    })
}

/// The SCIM document of a user. `groups` lists direct memberships.
pub fn user_to_scim(base: &str, u: &User, member_of: &[Group]) -> Value {
    let attrs = u.attributes.as_object();
    let attr = |k: &str| {
        attrs
            .and_then(|a| a.get(k))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let mut doc = json!({
        "schemas": [USER_SCHEMA],
        "id": u.id,
        "userName": u.username,
        "active": u.status == UserStatus::Active,
        "meta": meta("User", base, u.id, u.created_at, u.updated_at),
    });
    if let Some(x) = &u.external_id {
        doc["externalId"] = json!(x);
    }
    let given = attr(ATTR_GIVEN);
    let family = attr(ATTR_FAMILY);
    if given.is_some() || family.is_some() {
        let mut name = Map::new();
        if let Some(g) = &given {
            name.insert("givenName".into(), json!(g));
        }
        if let Some(f) = &family {
            name.insert("familyName".into(), json!(f));
        }
        let formatted = [given.as_deref(), family.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        name.insert("formatted".into(), json!(formatted));
        doc["name"] = Value::Object(name);
    }
    if let Some(d) = attr(ATTR_DISPLAY) {
        doc["displayName"] = json!(d);
    }
    if let Some(e) = &u.email {
        doc["emails"] = json!([{ "value": e, "type": "work", "primary": true }]);
    }
    if let Some(p) = &u.phone {
        doc["phoneNumbers"] = json!([{ "value": p, "type": "work" }]);
    }
    if let Some(l) = &u.locale {
        doc["locale"] = json!(l);
    }
    if !member_of.is_empty() {
        doc["groups"] = Value::Array(
            member_of
                .iter()
                .map(|g| json!({ "value": g.id, "display": g.name, "$ref": format!("{base}/Groups/{}", g.id) }))
                .collect(),
        );
    }
    doc
}

pub fn group_to_scim(base: &str, g: &Group, members: &[User]) -> Value {
    let mut doc = json!({
        "schemas": [GROUP_SCHEMA],
        "id": g.id,
        "displayName": g.name,
        "members": members.iter().map(|u| json!({ "value": u.id, "display": u.username, "$ref": format!("{base}/Users/{}", u.id) })).collect::<Vec<_>>(),
        "meta": meta("Group", base, g.id, g.created_at, g.updated_at),
    });
    if let Some(x) = g.attributes.get("externalId").and_then(Value::as_str) {
        doc["externalId"] = json!(x);
    }
    doc
}

/// Case-insensitive member lookup, with schema-URN prefixes tolerated.
fn get_ci<'a>(obj: &'a Value, key: &str) -> Option<&'a Value> {
    let o = obj.as_object()?;
    let key = strip_schema(key);
    o.iter()
        .find(|(k, _)| strip_schema(k).eq_ignore_ascii_case(key))
        .map(|(_, v)| v)
}

fn strip_schema(path: &str) -> &str {
    for s in [USER_SCHEMA, GROUP_SCHEMA] {
        if let Some(rest) = path.strip_prefix(s) {
            return rest.trim_start_matches(':');
        }
    }
    path
}

/// A boolean, accepting the `"True"` / `"False"` strings some clients send.
fn as_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn non_empty(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The primary (or first) `value` of a multi-valued attribute.
fn primary_value(list: Option<&Value>) -> Option<String> {
    let arr = list?.as_array()?;
    let pick = arr
        .iter()
        .find(|e| get_ci(e, "primary").and_then(as_bool) == Some(true))
        .or_else(|| arr.first())?;
    match pick {
        Value::String(s) => Some(s.clone()),
        other => non_empty(get_ci(other, "value")),
    }
}

/// What a SCIM user document says, as the fields rIDM stores.
pub struct UserFields {
    pub username: String,
    pub external_id: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub active: bool,
    pub locale: Option<String>,
    /// Name attributes that the profile schema accepts.
    pub attributes: Map<String, Value>,
}

/// Read a SCIM user document. `schema` decides which name attributes are kept.
pub fn user_from_scim(doc: &Value, schema: &ProfileSchema) -> ScimResult<UserFields> {
    let username = non_empty(get_ci(doc, "userName"))
        .ok_or_else(|| ScimError::bad("invalidValue", "userName is required"))?;
    let name = get_ci(doc, "name");
    let mut attributes = Map::new();
    let keep = |key: &str| schema.get(key).is_some() || schema.allow_undeclared;
    let mut put = |key: &str, v: Option<String>| {
        if keep(key) {
            attributes.insert(key.into(), v.map(Value::String).unwrap_or(Value::Null));
        }
    };
    put(
        ATTR_GIVEN,
        name.and_then(|n| non_empty(get_ci(n, "givenName"))),
    );
    put(
        ATTR_FAMILY,
        name.and_then(|n| non_empty(get_ci(n, "familyName"))),
    );
    put(ATTR_DISPLAY, non_empty(get_ci(doc, "displayName")));
    let active = match get_ci(doc, "active") {
        None => true,
        Some(v) => {
            as_bool(v).ok_or_else(|| ScimError::bad("invalidValue", "active must be a boolean"))?
        }
    };
    Ok(UserFields {
        username,
        external_id: non_empty(get_ci(doc, "externalId")),
        email: primary_value(get_ci(doc, "emails")),
        phone: primary_value(get_ci(doc, "phoneNumbers")),
        active,
        locale: non_empty(get_ci(doc, "locale")),
        attributes,
    })
}

// --- filters -----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    Cmp {
        attr: String,
        op: String,
        value: Value,
    },
    Present(String),
    And(Box<Filter>, Box<Filter>),
    Or(Box<Filter>, Box<Filter>),
    Not(Box<Filter>),
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    LParen,
    RParen,
    LBracket,
    RBracket,
    Word(String),
    Str(String),
    Num(f64),
}

fn tokenize(s: &str) -> ScimResult<Vec<Tok>> {
    let mut out = vec![];
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\n' | '\r' => i += 1,
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '[' => {
                out.push(Tok::LBracket);
                i += 1;
            }
            ']' => {
                out.push(Tok::RBracket);
                i += 1;
            }
            '"' => {
                let mut buf = String::new();
                i += 1;
                loop {
                    let Some(&ch) = chars.get(i) else {
                        return Err(ScimError::bad("invalidFilter", "unterminated string"));
                    };
                    i += 1;
                    match ch {
                        '"' => break,
                        '\\' => {
                            let Some(&esc) = chars.get(i) else {
                                return Err(ScimError::bad("invalidFilter", "bad escape"));
                            };
                            i += 1;
                            buf.push(match esc {
                                'n' => '\n',
                                't' => '\t',
                                other => other,
                            });
                        }
                        other => buf.push(other),
                    }
                }
                out.push(Tok::Str(buf));
            }
            _ => {
                let start = i;
                while i < chars.len()
                    && !matches!(chars[i], ' ' | '\t' | '\n' | '\r' | '(' | ')' | '[' | ']')
                {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                if let Ok(n) = word.parse::<f64>()
                    && word
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_digit() || c == '-')
                {
                    out.push(Tok::Num(n));
                } else {
                    out.push(Tok::Word(word));
                }
            }
        }
    }
    Ok(out)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn peek_word(&self, w: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word(x)) if x.eq_ignore_ascii_case(w))
    }

    fn expr(&mut self) -> ScimResult<Filter> {
        let mut left = self.term()?;
        loop {
            if self.peek_word("and") {
                self.pos += 1;
                let right = self.term()?;
                left = Filter::And(Box::new(left), Box::new(right));
            } else if self.peek_word("or") {
                self.pos += 1;
                let right = self.term()?;
                left = Filter::Or(Box::new(left), Box::new(right));
            } else {
                return Ok(left);
            }
        }
    }

    fn term(&mut self) -> ScimResult<Filter> {
        if self.peek_word("not") {
            self.pos += 1;
            if self.next() != Some(Tok::LParen) {
                return Err(ScimError::bad("invalidFilter", "not must be followed by ("));
            }
            let inner = self.expr()?;
            if self.next() != Some(Tok::RParen) {
                return Err(ScimError::bad("invalidFilter", "missing )"));
            }
            return Ok(Filter::Not(Box::new(inner)));
        }
        if self.peek() == Some(&Tok::LParen) {
            self.pos += 1;
            let inner = self.expr()?;
            if self.next() != Some(Tok::RParen) {
                return Err(ScimError::bad("invalidFilter", "missing )"));
            }
            return Ok(inner);
        }
        let Some(Tok::Word(attr)) = self.next() else {
            return Err(ScimError::bad("invalidFilter", "expected an attribute"));
        };
        let mut attr = strip_schema(&attr).to_string();
        // `attr[sub eq "x"].sub2` inside a filter: flatten to `attr.sub2` with the
        // bracket condition anded in (`emails[type eq "work"].value eq "a"`).
        let mut bracket: Option<Filter> = None;
        if self.peek() == Some(&Tok::LBracket) {
            self.pos += 1;
            let inner = self.expr()?;
            if self.next() != Some(Tok::RBracket) {
                return Err(ScimError::bad("invalidFilter", "missing ]"));
            }
            bracket = Some(prefix_filter(&attr, inner));
            if let Some(Tok::Word(rest)) = self.peek().cloned()
                && let Some(sub) = rest.strip_prefix('.')
            {
                self.pos += 1;
                attr = format!("{attr}.{sub}");
            }
        }
        let Some(Tok::Word(op)) = self.next() else {
            return Err(ScimError::bad("invalidFilter", "expected an operator"));
        };
        let op = op.to_ascii_lowercase();
        let f = if op == "pr" {
            Filter::Present(attr)
        } else {
            if !matches!(
                op.as_str(),
                "eq" | "ne" | "co" | "sw" | "ew" | "gt" | "ge" | "lt" | "le"
            ) {
                return Err(ScimError::bad(
                    "invalidFilter",
                    format!("unknown operator `{op}`"),
                ));
            }
            let value = match self.next() {
                Some(Tok::Str(s)) => Value::String(s),
                Some(Tok::Num(n)) => json!(n),
                Some(Tok::Word(w)) if w.eq_ignore_ascii_case("true") => Value::Bool(true),
                Some(Tok::Word(w)) if w.eq_ignore_ascii_case("false") => Value::Bool(false),
                Some(Tok::Word(w)) if w.eq_ignore_ascii_case("null") => Value::Null,
                _ => return Err(ScimError::bad("invalidFilter", "expected a value")),
            };
            Filter::Cmp { attr, op, value }
        };
        Ok(match bracket {
            Some(b) => Filter::And(Box::new(b), Box::new(f)),
            None => f,
        })
    }
}

/// `type eq "work"` inside `emails[...]` becomes `emails.type eq "work"`.
fn prefix_filter(prefix: &str, f: Filter) -> Filter {
    match f {
        Filter::Cmp { attr, op, value } => Filter::Cmp {
            attr: format!("{prefix}.{attr}"),
            op,
            value,
        },
        Filter::Present(a) => Filter::Present(format!("{prefix}.{a}")),
        Filter::And(a, b) => Filter::And(
            Box::new(prefix_filter(prefix, *a)),
            Box::new(prefix_filter(prefix, *b)),
        ),
        Filter::Or(a, b) => Filter::Or(
            Box::new(prefix_filter(prefix, *a)),
            Box::new(prefix_filter(prefix, *b)),
        ),
        Filter::Not(a) => Filter::Not(Box::new(prefix_filter(prefix, *a))),
    }
}

pub fn parse_filter(s: &str) -> ScimResult<Filter> {
    if s.len() > 2048 {
        return Err(ScimError::bad("invalidFilter", "filter too long"));
    }
    let toks = tokenize(s)?;
    if toks.is_empty() {
        return Err(ScimError::bad("invalidFilter", "empty filter"));
    }
    let mut p = Parser { toks, pos: 0 };
    let f = p.expr()?;
    if p.pos != p.toks.len() {
        return Err(ScimError::bad("invalidFilter", "unexpected trailing input"));
    }
    Ok(f)
}

/// Values a dotted path selects in a document (arrays fan out).
fn select<'a>(doc: &'a Value, path: &str) -> Vec<&'a Value> {
    let mut current = vec![doc];
    for part in path.split('.') {
        let mut next = vec![];
        for v in current {
            match v {
                Value::Array(items) => {
                    for item in items {
                        if let Some(x) = get_ci(item, part) {
                            next.push(x);
                        }
                    }
                }
                other => {
                    if let Some(x) = get_ci(other, part) {
                        next.push(x);
                    }
                }
            }
        }
        current = next;
    }
    // A multi-valued attribute compared as a whole matches on its values.
    current
        .into_iter()
        .flat_map(|v| match v {
            Value::Array(items) => items
                .iter()
                .map(|i| get_ci(i, "value").unwrap_or(i))
                .collect::<Vec<_>>(),
            other => vec![other],
        })
        .collect()
}

fn compare(op: &str, actual: &Value, wanted: &Value) -> bool {
    match (actual, wanted) {
        (Value::String(a), Value::String(w)) => {
            let (a, w) = (a.to_lowercase(), w.to_lowercase());
            match op {
                "eq" => a == w,
                "ne" => a != w,
                "co" => a.contains(&w),
                "sw" => a.starts_with(&w),
                "ew" => a.ends_with(&w),
                "gt" => a > w,
                "ge" => a >= w,
                "lt" => a < w,
                "le" => a <= w,
                _ => false,
            }
        }
        (Value::Bool(a), w) => match (op, as_bool(w)) {
            ("eq", Some(b)) => *a == b,
            ("ne", Some(b)) => *a != b,
            _ => false,
        },
        (Value::Number(a), Value::Number(w)) => {
            let (a, w) = (a.as_f64().unwrap_or(0.0), w.as_f64().unwrap_or(0.0));
            match op {
                "eq" => a == w,
                "ne" => a != w,
                "gt" => a > w,
                "ge" => a >= w,
                "lt" => a < w,
                "le" => a <= w,
                _ => false,
            }
        }
        (a, Value::String(w)) if !a.is_object() && !a.is_array() => {
            compare(op, &Value::String(a.to_string()), &Value::String(w.clone()))
        }
        _ => false,
    }
}

/// Does `doc` satisfy `f`?
pub fn matches(f: &Filter, doc: &Value) -> bool {
    match f {
        Filter::Cmp { attr, op, value } => {
            let found = select(doc, attr);
            if op == "ne" {
                return found.is_empty() || found.iter().all(|a| compare("ne", a, value));
            }
            found.iter().any(|a| compare(op, a, value))
        }
        Filter::Present(attr) => select(doc, attr).iter().any(|v| !v.is_null()),
        Filter::And(a, b) => matches(a, doc) && matches(b, doc),
        Filter::Or(a, b) => matches(a, doc) || matches(b, doc),
        Filter::Not(a) => !matches(a, doc),
    }
}

/// An equality a user filter can be answered with by index.
enum Lookup {
    Username(String),
    ExternalId(String),
    Email(String),
    Id(Uuid),
}

fn lookup_of(f: &Filter) -> Option<Lookup> {
    let Filter::Cmp { attr, op, value } = f else {
        return None;
    };
    if op != "eq" {
        return None;
    }
    let v = value.as_str()?.to_string();
    match attr.to_ascii_lowercase().as_str() {
        "username" => Some(Lookup::Username(v)),
        "externalid" => Some(Lookup::ExternalId(v)),
        "emails" | "emails.value" => Some(Lookup::Email(v)),
        "id" => Uuid::parse_str(&v).ok().map(Lookup::Id),
        _ => None,
    }
}

/// The index lookup inside `f`, when `f` is that lookup possibly anded with
/// more conditions that are then checked on the result.
fn indexed(f: &Filter) -> Option<Lookup> {
    match f {
        Filter::And(a, b) => indexed(a).or_else(|| indexed(b)),
        other => lookup_of(other),
    }
}

// --- listing -----------------------------------------------------------------

/// RFC 7644 §3.4.2 list response.
#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub schemas: [&'static str; 1],
    #[serde(rename = "totalResults")]
    pub total_results: i64,
    #[serde(rename = "startIndex")]
    pub start_index: i64,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: i64,
    #[serde(rename = "Resources")]
    pub resources: Vec<Value>,
}

pub struct PageQuery {
    pub filter: Option<String>,
    pub start_index: i64,
    pub count: i64,
}

impl PageQuery {
    pub fn new(
        filter: Option<String>,
        start_index: Option<i64>,
        count: Option<i64>,
    ) -> ScimResult<Self> {
        let start_index = start_index.unwrap_or(1).max(1);
        let count = count.unwrap_or(MAX_PAGE).clamp(0, MAX_PAGE);
        if start_index > SCAN_LIMIT {
            return Err(ScimError::bad(
                "tooMany",
                format!("startIndex beyond {SCAN_LIMIT} is not supported"),
            ));
        }
        Ok(Self {
            filter,
            start_index,
            count,
        })
    }
}

fn page_of(all: Vec<Value>, total: i64, q: &PageQuery) -> ListResponse {
    let skip = usize::try_from(q.start_index - 1).unwrap_or(0);
    let resources: Vec<Value> = all.into_iter().skip(skip).take(q.count as usize).collect();
    ListResponse {
        schemas: [LIST_SCHEMA],
        total_results: total,
        start_index: q.start_index,
        items_per_page: resources.len() as i64,
        resources,
    }
}

/// Users of the tenant up to `limit`, in creation order.
async fn scan_users(
    state: &AppState,
    tenant_id: Uuid,
    limit: i64,
) -> ScimResult<(Vec<User>, bool)> {
    let mut out = vec![];
    let mut cursor: Option<String> = None;
    let filter = UserFilter::default();
    loop {
        let page = users::list(state, tenant_id, &filter, cursor.as_deref(), Some(200)).await?;
        out.extend(page.items);
        if out.len() as i64 >= limit {
            out.truncate(limit as usize);
            return Ok((out, page.next_cursor.is_some()));
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => return Ok((out, false)),
        }
    }
}

async fn with_groups(state: &AppState, base: &str, tenant_id: Uuid, u: &User) -> ScimResult<Value> {
    let member_of = groups::groups_of_user(state, tenant_id, u.id, false).await?;
    Ok(user_to_scim(base, u, &member_of))
}

pub async fn list_users(
    state: &AppState,
    tenant: &Tenant,
    base: &str,
    q: PageQuery,
) -> ScimResult<ListResponse> {
    let filter = q.filter.as_deref().map(parse_filter).transpose()?;
    // Index lookups first.
    if let Some(f) = &filter
        && let Some(lookup) = indexed(f)
    {
        let found: Option<User> = match lookup {
            Lookup::Username(v) | Lookup::Email(v) => {
                users::find_by_identifier(state, tenant.id, &v).await?
            }
            Lookup::ExternalId(v) => {
                let mut tx = crate::db::tenant_tx(&state.db, tenant.id).await?;
                let u = crate::repos::users::find_by_external_id(&mut *tx, tenant.id, &v).await?;
                tx.commit().await?;
                u
            }
            Lookup::Id(id) => match users::get(state, tenant.id, id).await {
                Ok(u) => Some(u),
                Err(AppError::NotFound(_)) => None,
                Err(e) => return Err(e.into()),
            },
        };
        let mut docs = vec![];
        if let Some(u) = found.filter(|u| u.deleted_at.is_none()) {
            let doc = with_groups(state, base, tenant.id, &u).await?;
            if matches(f, &doc) {
                docs.push(doc);
            }
        }
        let total = docs.len() as i64;
        return Ok(page_of(docs, total, &q));
    }
    let wanted = q.start_index - 1 + q.count;
    let limit = if filter.is_some() {
        SCAN_LIMIT
    } else {
        wanted.max(1)
    };
    let (rows, more) = scan_users(state, tenant.id, limit).await?;
    if filter.is_some() && more {
        return Err(ScimError::bad(
            "tooMany",
            format!(
                "this filter cannot be answered by index and the tenant has more than {SCAN_LIMIT} users; filter on userName, externalId, emails or id"
            ),
        ));
    }
    let total = if filter.is_some() {
        0 // set below
    } else {
        let mut tx = crate::db::tenant_tx(&state.db, tenant.id).await?;
        let n = crate::repos::users::count(&mut *tx, tenant.id).await?;
        tx.commit().await?;
        n
    };
    let mut docs = Vec::with_capacity(rows.len());
    for u in &rows {
        let doc = with_groups(state, base, tenant.id, u).await?;
        if filter.as_ref().is_none_or(|f| matches(f, &doc)) {
            docs.push(doc);
        }
    }
    let total = if filter.is_some() {
        docs.len() as i64
    } else {
        total
    };
    Ok(page_of(docs, total, &q))
}

pub async fn get_user(
    state: &AppState,
    tenant: &Tenant,
    base: &str,
    id: Uuid,
) -> ScimResult<Value> {
    let u = users::get(state, tenant.id, id).await?;
    if u.deleted_at.is_some() {
        return Err(ScimError::not_found("user"));
    }
    with_groups(state, base, tenant.id, &u).await
}

pub async fn create_user(
    state: &AppState,
    tenant: &Tenant,
    base: &str,
    actor: Actor,
    doc: &Value,
) -> ScimResult<Value> {
    let schema = profile_schema::get(state, tenant.id).await?;
    let f = user_from_scim(doc, &schema)?;
    let attributes = Value::Object(
        f.attributes
            .into_iter()
            .filter(|(_, v)| !v.is_null())
            .collect(),
    );
    // Provisioning is an import: it may set `editable_by: none` attributes.
    let user = users::create_as(
        state,
        tenant.id,
        actor,
        profile_schema::Editor::System,
        NewUser {
            username: f.username,
            email: f.email,
            email_verified: true,
            phone: f.phone,
            phone_verified: false,
            status: Some(if f.active {
                UserStatus::Active
            } else {
                UserStatus::Disabled
            }),
            attributes: Some(attributes),
            locale: f.locale,
            org_id: None,
            external_id: f.external_id,
            defer_required: true,
        },
    )
    .await?;
    with_groups(state, base, tenant.id, &user).await
}

/// Store a full SCIM document over an existing user (PUT, and PATCH's result).
pub async fn replace_user(
    state: &AppState,
    tenant: &Tenant,
    base: &str,
    actor: Actor,
    id: Uuid,
    doc: &Value,
) -> ScimResult<Value> {
    let before = users::get(state, tenant.id, id).await?;
    if before.deleted_at.is_some() {
        return Err(ScimError::not_found("user"));
    }
    let schema = profile_schema::get(state, tenant.id).await?;
    let f = user_from_scim(doc, &schema)?;
    // Name attributes ride on top of the stored ones; everything else is untouched.
    let mut attributes = before.attributes.as_object().cloned().unwrap_or_default();
    for (k, v) in f.attributes {
        if v.is_null() {
            attributes.remove(&k);
        } else {
            attributes.insert(k, v);
        }
    }
    let status = match (f.active, before.status) {
        (true, UserStatus::Disabled) => Some(UserStatus::Active),
        (false, UserStatus::Active) | (false, UserStatus::Pending) => Some(UserStatus::Disabled),
        _ => None,
    };
    let user = users::update_as(
        state,
        tenant.id,
        actor,
        profile_schema::Editor::System,
        id,
        UserUpdate {
            username: Some(f.username),
            email: Some(f.email),
            email_verified: None,
            phone: Some(f.phone),
            phone_verified: None,
            status,
            attributes: Some(Value::Object(attributes)),
            locale: Some(f.locale),
            org_id: None,
            must_change_password: None,
            external_id: Some(f.external_id),
        },
    )
    .await?;
    with_groups(state, base, tenant.id, &user).await
}

pub async fn delete_user(
    state: &AppState,
    tenant: &Tenant,
    actor: Actor,
    id: Uuid,
) -> ScimResult<()> {
    let u = users::get(state, tenant.id, id).await?;
    if u.deleted_at.is_some() {
        return Err(ScimError::not_found("user"));
    }
    users::delete(state, tenant.id, actor, id).await?;
    Ok(())
}

// --- groups ------------------------------------------------------------------

async fn group_doc(state: &AppState, base: &str, tenant_id: Uuid, g: &Group) -> ScimResult<Value> {
    let members = groups::members(state, tenant_id, g.id).await?;
    Ok(group_to_scim(base, g, &members))
}

pub async fn list_groups(
    state: &AppState,
    tenant: &Tenant,
    base: &str,
    q: PageQuery,
) -> ScimResult<ListResponse> {
    let filter = q.filter.as_deref().map(parse_filter).transpose()?;
    let all = groups::list(state, tenant.id).await?;
    let mut docs = vec![];
    for g in &all {
        // Cheap pre-check on the name before loading members.
        if let Some(f) = &filter
            && let Filter::Cmp { attr, op, value } = f
            && attr.eq_ignore_ascii_case("displayName")
            && op == "eq"
            && !compare("eq", &Value::String(g.name.clone()), value)
        {
            continue;
        }
        let doc = group_doc(state, base, tenant.id, g).await?;
        if filter.as_ref().is_none_or(|f| matches(f, &doc)) {
            docs.push(doc);
        }
    }
    let total = docs.len() as i64;
    Ok(page_of(docs, total, &q))
}

pub async fn get_group(
    state: &AppState,
    tenant: &Tenant,
    base: &str,
    id: Uuid,
) -> ScimResult<Value> {
    let g = groups::get(state, tenant.id, id).await?;
    group_doc(state, base, tenant.id, &g).await
}

/// `displayName`, `externalId` and the member ids of a group document.
fn group_from_scim(doc: &Value) -> ScimResult<(String, Option<String>, Vec<Uuid>)> {
    let name = non_empty(get_ci(doc, "displayName"))
        .ok_or_else(|| ScimError::bad("invalidValue", "displayName is required"))?;
    let external_id = non_empty(get_ci(doc, "externalId"));
    let mut members = vec![];
    if let Some(list) = get_ci(doc, "members") {
        let items = list
            .as_array()
            .ok_or_else(|| ScimError::bad("invalidValue", "members must be a list"))?;
        for m in items {
            let raw = match m {
                Value::String(s) => s.clone(),
                other => non_empty(get_ci(other, "value"))
                    .ok_or_else(|| ScimError::bad("invalidValue", "members need a value"))?,
            };
            let id = Uuid::parse_str(&raw).map_err(|_| {
                ScimError::bad("invalidValue", format!("member `{raw}` is not a user id"))
            })?;
            if !members.contains(&id) {
                members.push(id);
            }
        }
    }
    Ok((name, external_id, members))
}

async fn member_ids(state: &AppState, tenant_id: Uuid, group_id: Uuid) -> ScimResult<Vec<Uuid>> {
    Ok(groups::members(state, tenant_id, group_id)
        .await?
        .iter()
        .map(|u| u.id)
        .collect())
}

/// Refuse to add anyone to a group that confers admin permissions. RFC 7644
/// §3.12 answers an operation the credentials do not permit with 403 (and
/// defines no `scimType` for it); the grant is refused whatever the admin who
/// minted the token holds, because nothing on the request says who that was.
async fn refuse_admin_membership(
    state: &AppState,
    tenant_id: Uuid,
    group_id: Uuid,
    current: &[Uuid],
    wanted: &[Uuid],
) -> ScimResult<()> {
    if wanted.iter().all(|id| current.contains(id)) {
        return Ok(());
    }
    let granted =
        admin_access::permissions_of_grant(state, tenant_id, Grant::Group(group_id)).await?;
    if granted.is_empty() {
        Ok(())
    } else {
        Err(ScimError::new(
            StatusCode::FORBIDDEN,
            None,
            "this group grants admin permissions; its members cannot be added over SCIM",
        ))
    }
}

async fn set_members(
    state: &AppState,
    tenant_id: Uuid,
    actor: &Actor,
    group: &Group,
    wanted: &[Uuid],
) -> ScimResult<()> {
    let current = member_ids(state, tenant_id, group.id).await?;
    refuse_admin_membership(state, tenant_id, group.id, &current, wanted).await?;
    for id in wanted.iter().filter(|id| !current.contains(id)) {
        groups::add_member(state, tenant_id, actor.clone(), group.id, *id)
            .await
            .map_err(|e| match e {
                AppError::NotFound(_) => {
                    ScimError::bad("invalidValue", format!("member {id} does not exist"))
                }
                other => other.into(),
            })?;
    }
    for id in current.iter().filter(|id| !wanted.contains(id)) {
        groups::remove_member(state, tenant_id, actor.clone(), group.id, *id).await?;
    }
    Ok(())
}

pub async fn create_group(
    state: &AppState,
    tenant: &Tenant,
    base: &str,
    actor: Actor,
    doc: &Value,
) -> ScimResult<Value> {
    let (name, external_id, members) = group_from_scim(doc)?;
    let attributes = external_id.map(|x| json!({ "externalId": x }));
    let g = groups::create(
        state,
        tenant.id,
        actor.clone(),
        NewGroup {
            name,
            parent_id: None,
            description: None,
            attributes,
        },
    )
    .await?;
    if let Err(e) = set_members(state, tenant.id, &actor, &g, &members).await {
        // Leave no half-made group behind.
        if let Err(cleanup) = groups::delete(state, tenant.id, actor, g.id).await {
            tracing::error!(
                group_id = %g.id,
                error = %cleanup,
                "SCIM: could not remove a half-made group"
            );
        }
        return Err(e);
    }
    group_doc(state, base, tenant.id, &g).await
}

pub async fn replace_group(
    state: &AppState,
    tenant: &Tenant,
    base: &str,
    actor: Actor,
    id: Uuid,
    doc: &Value,
) -> ScimResult<Value> {
    let before = groups::get(state, tenant.id, id).await?;
    let (name, external_id, members) = group_from_scim(doc)?;
    // Checked before the rename too, so a refused request changes nothing.
    let current = member_ids(state, tenant.id, id).await?;
    refuse_admin_membership(state, tenant.id, id, &current, &members).await?;
    let mut attributes = before.attributes.as_object().cloned().unwrap_or_default();
    match external_id {
        Some(x) => {
            attributes.insert("externalId".into(), json!(x));
        }
        None => {
            attributes.remove("externalId");
        }
    }
    let g = groups::update(
        state,
        tenant.id,
        actor.clone(),
        id,
        crate::models::GroupUpdate {
            name: Some(name),
            parent_id: None,
            description: None,
            attributes: Some(Value::Object(attributes)),
        },
    )
    .await?;
    set_members(state, tenant.id, &actor, &g, &members).await?;
    group_doc(state, base, tenant.id, &g).await
}

pub async fn delete_group(
    state: &AppState,
    tenant: &Tenant,
    actor: Actor,
    id: Uuid,
) -> ScimResult<()> {
    groups::delete(state, tenant.id, actor, id).await?;
    Ok(())
}

// --- PATCH -------------------------------------------------------------------

/// One `Operations` entry of an RFC 7644 §3.5.2 PatchOp.
pub struct PatchOp {
    pub op: String,
    pub path: Option<String>,
    pub value: Option<Value>,
}

pub fn parse_patch(body: &Value) -> ScimResult<Vec<PatchOp>> {
    let ops = get_ci(body, "Operations")
        .and_then(Value::as_array)
        .ok_or_else(|| ScimError::bad("invalidSyntax", "Operations is required"))?;
    if ops.is_empty() {
        return Err(ScimError::bad("invalidSyntax", "Operations is empty"));
    }
    ops.iter()
        .map(|o| {
            let op = get_ci(o, "op")
                .and_then(Value::as_str)
                .map(|s| s.to_ascii_lowercase())
                .ok_or_else(|| ScimError::bad("invalidSyntax", "each operation needs op"))?;
            if !matches!(op.as_str(), "add" | "replace" | "remove") {
                return Err(ScimError::bad(
                    "invalidSyntax",
                    format!("unknown op `{op}`"),
                ));
            }
            let path = get_ci(o, "path")
                .and_then(Value::as_str)
                .map(|p| p.trim().to_string());
            let value = get_ci(o, "value").cloned();
            if op != "remove" && value.is_none() {
                return Err(ScimError::bad(
                    "invalidValue",
                    format!("{op} needs a value"),
                ));
            }
            if op == "remove" && path.is_none() {
                return Err(ScimError::bad("noTarget", "remove needs a path"));
            }
            Ok(PatchOp { op, path, value })
        })
        .collect()
}

/// A parsed path: `attr`, `attr.sub`, or `attr[filter].sub`.
struct Target {
    attr: String,
    filter: Option<Filter>,
    sub: Option<String>,
}

fn parse_path(path: &str) -> ScimResult<Target> {
    let path = strip_schema(path);
    if let Some(open) = path.find('[') {
        let close = path
            .rfind(']')
            .ok_or_else(|| ScimError::bad("invalidPath", "missing ]"))?;
        let attr = path[..open].to_string();
        let filter = parse_filter(&path[open + 1..close])?;
        let rest = path[close + 1..].trim_start_matches('.');
        let sub = (!rest.is_empty()).then(|| rest.to_string());
        return Ok(Target {
            attr,
            filter: Some(filter),
            sub,
        });
    }
    match path.split_once('.') {
        Some((a, s)) => Ok(Target {
            attr: a.to_string(),
            filter: None,
            sub: Some(s.to_string()),
        }),
        None => Ok(Target {
            attr: path.to_string(),
            filter: None,
            sub: None,
        }),
    }
}

/// The stored key for a case-insensitive attribute name (existing spelling wins).
fn key_for(obj: &Map<String, Value>, name: &str) -> String {
    obj.keys()
        .find(|k| k.eq_ignore_ascii_case(name))
        .cloned()
        .unwrap_or_else(|| name.to_string())
}

fn set_path(obj: &mut Map<String, Value>, attr: &str, sub: Option<&str>, value: Value) {
    let key = key_for(obj, attr);
    match sub {
        None => {
            obj.insert(key, value);
        }
        Some(sub) => {
            let entry = obj.entry(key).or_insert_with(|| Value::Object(Map::new()));
            if !entry.is_object() {
                *entry = Value::Object(Map::new());
            }
            if let Value::Object(inner) = entry {
                let sub_key = key_for(inner, sub);
                inner.insert(sub_key, value);
            }
        }
    }
}

/// Apply one operation to a resource document.
fn apply_op(doc: &mut Value, op: &PatchOp) -> ScimResult<()> {
    let obj = doc
        .as_object_mut()
        .ok_or_else(|| ScimError::bad("invalidValue", "resource is not an object"))?;
    match op.path.as_deref() {
        None => {
            // No path: the value is an object of attributes to add / replace.
            let value = op
                .value
                .as_ref()
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    ScimError::bad("invalidValue", "a value without a path must be an object")
                })?;
            for (k, v) in value {
                let target = parse_path(k)?;
                apply_op(
                    doc,
                    &PatchOp {
                        op: op.op.clone(),
                        path: Some(if let Some(sub) = &target.sub {
                            format!("{}.{sub}", target.attr)
                        } else {
                            target.attr.clone()
                        }),
                        value: Some(v.clone()),
                    },
                )?;
            }
            Ok(())
        }
        Some(path) => {
            let t = parse_path(path)?;
            let key = key_for(obj, &t.attr);
            match (&t.filter, op.op.as_str()) {
                (None, "remove") => {
                    match &t.sub {
                        None => {
                            obj.remove(&key);
                        }
                        Some(sub) => {
                            if let Some(inner) = obj.get_mut(&key).and_then(Value::as_object_mut) {
                                let sk = key_for(inner, sub);
                                inner.remove(&sk);
                            }
                        }
                    }
                    Ok(())
                }
                (None, "add") => {
                    let value = op.value.clone().unwrap_or(Value::Null);
                    let existing = obj.get(&key);
                    match (existing, &value, &t.sub) {
                        // Adding to a multi-valued attribute appends.
                        (Some(Value::Array(cur)), Value::Array(more), None) => {
                            let mut merged = cur.clone();
                            merged.extend(more.iter().cloned());
                            obj.insert(key, Value::Array(merged));
                        }
                        (Some(Value::Array(cur)), single, None) if !single.is_array() => {
                            let mut merged = cur.clone();
                            merged.push(single.clone());
                            obj.insert(key, Value::Array(merged));
                        }
                        _ => set_path(obj, &t.attr, t.sub.as_deref(), value),
                    }
                    Ok(())
                }
                (None, _replace) => {
                    set_path(
                        obj,
                        &t.attr,
                        t.sub.as_deref(),
                        op.value.clone().unwrap_or(Value::Null),
                    );
                    Ok(())
                }
                (Some(filter), action) => {
                    let list = obj.entry(key).or_insert_with(|| Value::Array(vec![]));
                    let items = list.as_array_mut().ok_or_else(|| {
                        ScimError::bad("invalidPath", "filtered path on a single-valued attribute")
                    })?;
                    let hits: Vec<usize> = items
                        .iter()
                        .enumerate()
                        .filter(|(_, item)| matches(filter, item))
                        .map(|(i, _)| i)
                        .collect();
                    match action {
                        "remove" => match &t.sub {
                            None => {
                                for i in hits.into_iter().rev() {
                                    items.remove(i);
                                }
                            }
                            Some(sub) => {
                                for i in hits {
                                    if let Some(o) = items[i].as_object_mut() {
                                        let sk = key_for(o, sub);
                                        o.remove(&sk);
                                    }
                                }
                            }
                        },
                        _ => {
                            let value = op.value.clone().unwrap_or(Value::Null);
                            if hits.is_empty() {
                                if action == "replace" {
                                    return Err(ScimError::bad(
                                        "noTarget",
                                        "no element matches the path filter",
                                    ));
                                }
                                // add: a new element carrying the filter's equalities.
                                let mut element = Map::new();
                                seed_from_filter(filter, &mut element);
                                match &t.sub {
                                    Some(sub) => {
                                        element.insert(sub.clone(), value);
                                    }
                                    None => {
                                        if let Some(o) = value.as_object() {
                                            element.extend(o.clone());
                                        }
                                    }
                                }
                                items.push(Value::Object(element));
                            } else {
                                for i in hits {
                                    match &t.sub {
                                        Some(sub) => {
                                            if let Some(o) = items[i].as_object_mut() {
                                                let sk = key_for(o, sub);
                                                o.insert(sk, value.clone());
                                            }
                                        }
                                        None => items[i] = value.clone(),
                                    }
                                }
                            }
                        }
                    }
                    Ok(())
                }
            }
        }
    }
}

/// `type eq "work"` seeds `{"type": "work"}` for an element added by path.
fn seed_from_filter(f: &Filter, into: &mut Map<String, Value>) {
    match f {
        Filter::Cmp { attr, op, value } if op == "eq" => {
            into.insert(attr.clone(), value.clone());
        }
        Filter::And(a, b) => {
            seed_from_filter(a, into);
            seed_from_filter(b, into);
        }
        _ => {}
    }
}

/// Apply every operation to a copy of `doc`.
pub fn apply_patch(doc: &Value, ops: &[PatchOp]) -> ScimResult<Value> {
    let mut out = doc.clone();
    for op in ops {
        apply_op(&mut out, op)?;
    }
    Ok(out)
}

// --- discovery documents -----------------------------------------------------

pub fn service_provider_config(base: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://github.com/ZerosAndOnesLLC/rIDM#scim-provisioning",
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": MAX_PAGE },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "Bearer token",
            "description": "A provisioning token minted in the rIDM console (Provisioning), sent as Authorization: Bearer.",
            "primary": true
        }],
        "meta": { "resourceType": "ServiceProviderConfig", "location": format!("{base}/ServiceProviderConfig") }
    })
}

pub fn resource_types(base: &str) -> Value {
    json!([
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User", "name": "User", "endpoint": "/Users", "schema": USER_SCHEMA,
            "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/User") }
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": GROUP_SCHEMA,
            "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/Group") }
        }
    ])
}

fn attr(
    name: &str,
    kind: &str,
    multi: bool,
    mutability: &str,
    required: bool,
    sub: Value,
) -> Value {
    let mut a = json!({
        "name": name, "type": kind, "multiValued": multi, "required": required,
        "caseExact": false, "mutability": mutability, "returned": "default", "uniqueness": "none"
    });
    if !sub.is_null() {
        a["subAttributes"] = sub;
    }
    a
}

pub fn schemas(base: &str) -> Value {
    let value_type = |t: &str| {
        json!([
            attr("value", "string", false, "readWrite", false, Value::Null),
            attr("type", "string", false, "readWrite", false, Value::Null),
            attr("primary", "boolean", false, "readWrite", false, Value::Null),
            attr("display", "string", false, "readOnly", false, Value::Null),
            attr("$ref", "reference", false, "readOnly", false, Value::Null)
        ])
        .as_array()
        .cloned()
        .map(|mut v| {
            if t == "ref" {
                v.retain(|a| a["name"] != "type" && a["name"] != "primary");
            }
            Value::Array(v)
        })
        .unwrap_or(Value::Null)
    };
    json!([
        {
            "id": USER_SCHEMA, "name": "User", "description": "User Account",
            "attributes": [
                { "name": "userName", "type": "string", "multiValued": false, "required": true, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "server" },
                { "name": "externalId", "type": "string", "multiValued": false, "required": false, "caseExact": true, "mutability": "readWrite", "returned": "default", "uniqueness": "server" },
                attr("name", "complex", false, "readWrite", false, json!([
                    attr("givenName", "string", false, "readWrite", false, Value::Null),
                    attr("familyName", "string", false, "readWrite", false, Value::Null),
                    attr("formatted", "string", false, "readOnly", false, Value::Null)
                ])),
                attr("displayName", "string", false, "readWrite", false, Value::Null),
                attr("active", "boolean", false, "readWrite", false, Value::Null),
                attr("locale", "string", false, "readWrite", false, Value::Null),
                attr("emails", "complex", true, "readWrite", false, value_type("full")),
                attr("phoneNumbers", "complex", true, "readWrite", false, value_type("full")),
                attr("groups", "complex", true, "readOnly", false, value_type("ref"))
            ],
            "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{USER_SCHEMA}") }
        },
        {
            "id": GROUP_SCHEMA, "name": "Group", "description": "Group",
            "attributes": [
                { "name": "displayName", "type": "string", "multiValued": false, "required": true, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "server" },
                { "name": "externalId", "type": "string", "multiValued": false, "required": false, "caseExact": true, "mutability": "readWrite", "returned": "default", "uniqueness": "none" },
                attr("members", "complex", true, "readWrite", false, value_type("ref"))
            ],
            "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{GROUP_SCHEMA}") }
        }
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(attr: &str, op: &str, v: Value) -> Filter {
        Filter::Cmp {
            attr: attr.into(),
            op: op.into(),
            value: v,
        }
    }

    #[test]
    fn filters_parse() {
        assert_eq!(
            parse_filter("userName eq \"bjensen\"").unwrap(),
            cmp("userName", "eq", json!("bjensen"))
        );
        assert_eq!(
            parse_filter("urn:ietf:params:scim:schemas:core:2.0:User:userName sw \"J\"").unwrap(),
            cmp("userName", "sw", json!("J"))
        );
        let f = parse_filter("emails[type eq \"work\"].value co \"example\" and active eq true")
            .unwrap();
        assert!(matches!(f, Filter::And(..)));
        assert!(matches!(
            parse_filter("title pr").unwrap(),
            Filter::Present(_)
        ));
        assert!(matches!(
            parse_filter("not (active eq false)").unwrap(),
            Filter::Not(_)
        ));
        assert!(parse_filter("userName eq").is_err());
        assert!(parse_filter("userName zz \"x\"").is_err());
        assert!(parse_filter("(userName eq \"a\"").is_err());
    }

    #[test]
    fn filters_match_documents() {
        let doc = json!({
            "userName": "BJensen", "active": true,
            "name": { "givenName": "Barbara" },
            "emails": [{ "value": "bj@example.com", "type": "work", "primary": true }]
        });
        let ok = |s: &str| matches(&parse_filter(s).unwrap(), &doc);
        assert!(ok("userName eq \"bjensen\""));
        assert!(ok("username co \"jens\""));
        assert!(ok("name.givenName sw \"Bar\""));
        assert!(ok("emails.value eq \"bj@example.com\""));
        assert!(ok("emails eq \"bj@example.com\""));
        assert!(ok("emails[type eq \"work\"].value ew \"example.com\""));
        assert!(ok("active eq true"));
        assert!(ok("active eq \"True\""));
        assert!(!ok("active eq false"));
        assert!(!ok("title pr"));
        assert!(ok("name pr"));
        assert!(ok("userName eq \"x\" or active eq true"));
        assert!(!ok("not (userName eq \"bjensen\")"));
        assert!(ok("userName ne \"other\""));
    }

    #[test]
    fn index_lookups_are_recognised() {
        assert!(matches!(
            indexed(&parse_filter("userName eq \"a\"").unwrap()),
            Some(Lookup::Username(_))
        ));
        assert!(matches!(
            indexed(&parse_filter("externalId eq \"e\" and active eq true").unwrap()),
            Some(Lookup::ExternalId(_))
        ));
        assert!(matches!(
            indexed(&parse_filter("emails.value eq \"a@b\"").unwrap()),
            Some(Lookup::Email(_))
        ));
        assert!(indexed(&parse_filter("userName sw \"a\"").unwrap()).is_none());
        assert!(indexed(&parse_filter("userName eq \"a\" or active eq true").unwrap()).is_none());
    }

    #[test]
    fn patch_operations_apply() {
        let doc = json!({
            "userName": "a", "active": true,
            "emails": [{ "value": "old@example.com", "type": "work", "primary": true }],
            "members": [{ "value": "1" }, { "value": "2" }]
        });
        let ops =
            |v: Value| parse_patch(&json!({ "schemas": [PATCH_SCHEMA], "Operations": v })).unwrap();
        // replace with path, string boolean, schema prefix, case-insensitive name
        let out = apply_patch(&doc, &ops(json!([
            { "op": "Replace", "path": "urn:ietf:params:scim:schemas:core:2.0:User:Active", "value": "False" },
            { "op": "add", "path": "name.givenName", "value": "Ann" },
            { "op": "replace", "path": "emails[type eq \"work\"].value", "value": "new@example.com" },
            { "op": "remove", "path": "members[value eq \"1\"]" },
            { "op": "add", "path": "members", "value": [{ "value": "3" }] }
        ]))).unwrap();
        assert_eq!(out["active"], "False");
        assert_eq!(out["name"]["givenName"], "Ann");
        assert_eq!(out["emails"][0]["value"], "new@example.com");
        assert_eq!(out["members"].as_array().unwrap().len(), 2);
        assert_eq!(out["members"][1]["value"], "3");
        // value object without path
        let out = apply_patch(
            &doc,
            &ops(json!([{ "op": "add", "value": { "displayName": "A", "name.familyName": "B" } }])),
        )
        .unwrap();
        assert_eq!(out["displayName"], "A");
        assert_eq!(out["name"]["familyName"], "B");
        // add by filter path with no match appends a seeded element
        let out = apply_patch(&doc, &ops(json!([{ "op": "add", "path": "emails[type eq \"home\"].value", "value": "h@example.com" }]))).unwrap();
        assert_eq!(out["emails"][1]["type"], "home");
        assert_eq!(out["emails"][1]["value"], "h@example.com");
        // remove whole attribute
        let out = apply_patch(&doc, &ops(json!([{ "op": "remove", "path": "emails" }]))).unwrap();
        assert!(out.get("emails").is_none());
        // refusals
        assert!(parse_patch(&json!({ "Operations": [] })).is_err());
        assert!(parse_patch(&json!({ "Operations": [{ "op": "remove" }] })).is_err());
        assert!(apply_patch(&doc, &ops(json!([{ "op": "replace", "path": "emails[type eq \"x\"].value", "value": "v" }]))).is_err());
    }

    #[test]
    fn user_document_round_trip() {
        let schema = ProfileSchema {
            allow_undeclared: true,
            ..Default::default()
        };
        let f = user_from_scim(
            &json!({
                "userName": " Ann ", "externalId": "ext-1", "active": "True", "locale": "de",
                "name": { "givenName": "Ann", "familyName": "Lee" }, "displayName": "Ann Lee",
                "emails": [{ "value": "a@example.com", "type": "home" }, { "value": "w@example.com", "primary": true }],
                "phoneNumbers": [{ "value": "+491701234567" }]
            }),
            &schema,
        )
        .unwrap();
        assert_eq!(f.username, "Ann");
        assert_eq!(f.external_id.as_deref(), Some("ext-1"));
        assert_eq!(f.email.as_deref(), Some("w@example.com"), "primary wins");
        assert_eq!(f.phone.as_deref(), Some("+491701234567"));
        assert!(f.active);
        assert_eq!(f.attributes["given_name"], "Ann");
        assert_eq!(f.attributes["display_name"], "Ann Lee");
        // Undeclared name attributes are dropped under a strict schema.
        let strict = ProfileSchema::default();
        let f = user_from_scim(
            &json!({ "userName": "x", "name": { "givenName": "A" } }),
            &strict,
        )
        .unwrap();
        assert!(f.attributes.is_empty());
        assert!(user_from_scim(&json!({ "active": true }), &strict).is_err());
    }
}
