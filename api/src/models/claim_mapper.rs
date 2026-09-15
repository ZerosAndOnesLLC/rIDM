//! Claim mappers add claims to tokens and the userinfo response. The table
//! arrives with the client migration (Phase 3.1); the types and pipeline live
//! here so the token service can be built and tested first.

use serde::{Deserialize, Serialize};

/// Where a claim goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    Access,
    Id,
    Userinfo,
}

/// How a claim value is produced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MapperKind {
    /// Copy a user field (`username`, `email`, ...) or a profile attribute
    /// (`attributes.department`).
    UserAttribute {
        attribute: String,
        claim: String,
        #[serde(default)]
        json_type: JsonType,
    },
    /// Names of the user's effective groups.
    Groups {
        claim: String,
        /// Emit `parent/child` paths instead of bare names.
        #[serde(default)]
        full_path: bool,
    },
    /// Names of the user's effective roles (realm roles, or one client's).
    Roles {
        claim: String,
        #[serde(default)]
        client_id: Option<String>,
    },
    /// A fixed value.
    Hardcoded {
        claim: String,
        value: serde_json::Value,
    },
    /// Handlebars template over `user`, `tenant`, `client`, `roles`, `groups`.
    Template { claim: String, template: String },
    /// Audience to add to access tokens.
    Audience { audience: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonType {
    #[default]
    String,
    Number,
    Boolean,
    Json,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimMapper {
    pub name: String,
    #[serde(flatten)]
    pub kind: MapperKind,
    /// Which artefacts receive the claim.
    pub include_in: Vec<TokenKind>,
}

impl ClaimMapper {
    pub fn applies_to(&self, kind: TokenKind) -> bool {
        self.include_in.contains(&kind)
    }

    pub fn claim_name(&self) -> Option<&str> {
        match &self.kind {
            MapperKind::UserAttribute { claim, .. }
            | MapperKind::Groups { claim, .. }
            | MapperKind::Roles { claim, .. }
            | MapperKind::Hardcoded { claim, .. }
            | MapperKind::Template { claim, .. } => Some(claim),
            MapperKind::Audience { .. } => None,
        }
    }
}

/// Claims that mappers may never set; the token service owns them.
pub const PROTECTED_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "azp",
    "at_hash",
    "c_hash",
    "nonce",
    "auth_time",
    "amr",
    "acr",
    "sid",
    "tid",
    "client_id",
    "scope",
    "typ",
];
