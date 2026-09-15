//! Per-tenant user profile schema: which custom attributes exist, how they are
//! validated, who may edit them, and where they are exposed.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttributeType {
    String,
    Number,
    Boolean,
    Email,
    Url,
    Phone,
    /// ISO-8601 calendar date (`YYYY-MM-DD`).
    Date,
    /// One of `validation.values`.
    Enum,
    /// Arbitrary JSON (object or array).
    Json,
}

/// Who may set the attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EditableBy {
    /// The user (account console, registration) and admins.
    #[default]
    User,
    /// Admins and the admin API only.
    Admin,
    /// Nobody through the API; set by imports or mappers.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    IdToken,
    Userinfo,
    AccessToken,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default)]
pub struct AttributeValidation {
    pub min_length: Option<u32>,
    pub max_length: Option<u32>,
    /// Anchored regular expression the string form must match.
    pub pattern: Option<String>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    /// Allowed values for `enum`.
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default)]
pub struct AttributeDef {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: AttributeType,
    pub label: Option<String>,
    pub description: Option<String>,
    pub required: bool,
    pub multivalued: bool,
    pub editable_by: EditableBy,
    pub visible_in: Vec<Exposure>,
    pub validation: AttributeValidation,
    /// Position in forms.
    pub order: u32,
}

impl Default for AttributeDef {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: AttributeType::String,
            label: None,
            description: None,
            required: false,
            multivalued: false,
            editable_by: EditableBy::User,
            visible_in: vec![],
            validation: AttributeValidation::default(),
            order: 0,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default)]
pub struct ProfileSchema {
    pub attributes: Vec<AttributeDef>,
    /// Accept attributes not declared in the schema (stored verbatim, admin-editable only).
    pub allow_undeclared: bool,
}

impl ProfileSchema {
    pub fn get(&self, name: &str) -> Option<&AttributeDef> {
        self.attributes.iter().find(|a| a.name == name)
    }
}
