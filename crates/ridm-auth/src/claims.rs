//! The claims an rIDM access token carries, and the questions worth asking of
//! them.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::error::AuthError;

/// A verified access token.
///
/// Every field below `exp` is optional because a token is shaped by the client
/// and the resource server that asked for it: a machine token has no `roles`,
/// a token minted without a session has no `sid`. Claims added by a tenant's
/// own mappers land in [`Claims::extra`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Claims {
    /// The issuer: `https://{host}/t/{tenant}`, or the tenant's custom domain.
    pub iss: String,
    /// The user id, the pairwise subject, or — for a client-credentials token
    /// — the client id.
    pub sub: String,
    /// Always a list here, whether the token spelled it as one or as a string.
    #[serde(deserialize_with = "one_or_many")]
    pub aud: Vec<String>,
    /// When the token stops being valid, in seconds since the epoch.
    pub exp: i64,
    /// When it was issued.
    #[serde(default)]
    pub iat: Option<i64>,
    /// When it starts being valid.
    #[serde(default)]
    pub nbf: Option<i64>,
    /// The token identifier, unique per token.
    #[serde(default)]
    pub jti: Option<String>,

    /// The rIDM tenant that issued the token.
    #[serde(default)]
    pub tid: Option<String>,
    /// The client the token was issued to.
    #[serde(default)]
    pub client_id: Option<String>,
    /// The authorised party — the same client, spelled as OIDC spells it.
    #[serde(default)]
    pub azp: Option<String>,
    /// The SSO session the token was issued in.
    #[serde(default)]
    pub sid: Option<String>,

    /// The raw `scope` claim, space-delimited. Read it with [`Claims::scopes`].
    #[serde(default)]
    pub scope: Option<String>,
    /// The subject's roles in the issuing tenant. Absent for machine tokens.
    #[serde(default, deserialize_with = "string_or_seq")]
    pub roles: Vec<String>,
    /// The subject's groups in the issuing tenant.
    #[serde(default, deserialize_with = "string_or_seq")]
    pub groups: Vec<String>,
    /// The permissions the resource server granted this subject. Present only
    /// when the token was requested for a resource server that defines them.
    #[serde(default, deserialize_with = "string_or_seq")]
    pub permissions: Vec<String>,

    /// When the subject last authenticated interactively.
    #[serde(default)]
    pub auth_time: Option<i64>,
    /// How they authenticated (`pwd`, `otp`, `hwk`, …).
    #[serde(default, deserialize_with = "string_or_seq")]
    pub amr: Vec<String>,
    /// The authentication context class the session reached.
    #[serde(default)]
    pub acr: Option<String>,
    /// RFC 9449 confirmation: present when the token is sender-constrained.
    #[serde(default)]
    pub cnf: Option<Confirmation>,
    /// RFC 8693 `act`: who is acting for the subject, in a delegated token.
    #[serde(default)]
    pub act: Option<Value>,

    /// Everything else the token carried, including a tenant's mapped claims.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The `cnf` claim. `jkt` is the thumbprint of the DPoP key the token is bound
/// to (RFC 9449 §6).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Confirmation {
    /// The RFC 7638 thumbprint of the key the token is bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    /// Any other confirmation method the token carried.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Claims {
    /// The granted scopes, in the order the token lists them.
    pub fn scopes(&self) -> impl Iterator<Item = &str> {
        self.scope.as_deref().unwrap_or_default().split_whitespace()
    }

    /// Does the token carry `scope`?
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes().any(|s| s == scope)
    }

    /// Does the token carry `permission`?
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }

    /// Does the subject hold `role`?
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Is the subject a member of `group`?
    pub fn has_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g == group)
    }

    /// Fail with [`AuthError::MissingScope`] unless the token carries `scope`.
    pub fn require_scope(&self, scope: &str) -> Result<(), AuthError> {
        self.has_scope(scope)
            .then_some(())
            .ok_or_else(|| AuthError::MissingScope(scope.to_string()))
    }

    /// Fail with [`AuthError::MissingPermission`] unless the token carries it.
    pub fn require_permission(&self, permission: &str) -> Result<(), AuthError> {
        self.has_permission(permission)
            .then_some(())
            .ok_or_else(|| AuthError::MissingPermission(permission.to_string()))
    }

    /// Fail with [`AuthError::MissingRole`] unless the subject holds `role`.
    pub fn require_role(&self, role: &str) -> Result<(), AuthError> {
        self.has_role(role)
            .then_some(())
            .ok_or_else(|| AuthError::MissingRole(role.to_string()))
    }

    /// Every one of `permissions` must be present.
    pub fn require_all_permissions<'a>(
        &self,
        permissions: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), AuthError> {
        for permission in permissions {
            self.require_permission(permission)?;
        }
        Ok(())
    }

    /// At least one of `permissions` must be present. An empty list asks for
    /// nothing and passes.
    pub fn require_any_permission<'a>(
        &self,
        permissions: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), AuthError> {
        let mut wanted = Vec::new();
        for permission in permissions {
            if self.has_permission(permission) {
                return Ok(());
            }
            wanted.push(permission);
        }
        if wanted.is_empty() {
            return Ok(());
        }
        Err(AuthError::MissingPermission(wanted.join(" or ")))
    }

    /// A claim this struct does not name, mapped by the tenant or added by a
    /// later version of rIDM.
    pub fn claim(&self, name: &str) -> Option<&Value> {
        self.extra.get(name)
    }

    /// Is the client itself the subject — a token with no user behind it at
    /// all?
    ///
    /// True for `client_credentials` where the client has no service account.
    /// A machine client that *has* one carries that user as `sub` and reads
    /// here like any other user, which is the point of a service account: it
    /// holds roles, groups and permissions.
    pub fn is_client_only(&self) -> bool {
        self.client_id.as_deref() == Some(self.sub.as_str())
    }

    /// The DPoP key thumbprint this token is bound to, if any.
    pub fn jkt(&self) -> Option<&str> {
        self.cnf.as_ref()?.jkt.as_deref()
    }
}

/// `aud` is a string when there is one audience and a list when there are more
/// (RFC 7519 §4.1.3).
fn one_or_many<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    match Value::deserialize(d)? {
        Value::String(s) => Ok(vec![s]),
        Value::Array(items) => Ok(items
            .into_iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s),
                _ => None,
            })
            .collect()),
        Value::Null => Ok(Vec::new()),
        _ => Err(serde::de::Error::custom("expected a string or a list")),
    }
}

/// A list claim that some issuers spell as a space-delimited string. Anything
/// that is neither reads as absent rather than failing the whole token: a
/// tenant is free to map `roles` to something of its own, and that is not a
/// reason to refuse an otherwise valid token.
fn string_or_seq<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(match Option::<Value>::deserialize(d)? {
        Some(Value::String(s)) => s.split_whitespace().map(str::to_string).collect(),
        Some(Value::Array(items)) => items
            .into_iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: Value) -> Claims {
        serde_json::from_value(json).expect("claims")
    }

    fn base() -> Value {
        serde_json::json!({
            "iss": "https://idp.example/t/acme",
            "sub": "a1b2",
            "aud": "urn:orders",
            "exp": 4102444800i64,
        })
    }

    #[test]
    fn a_single_audience_reads_the_same_as_a_list() {
        assert_eq!(parse(base()).aud, ["urn:orders"]);
        let mut many = base();
        many["aud"] = serde_json::json!(["urn:orders", "urn:billing"]);
        assert_eq!(parse(many).aud, ["urn:orders", "urn:billing"]);
    }

    #[test]
    fn list_claims_read_from_a_list_or_a_delimited_string() {
        let mut list = base();
        list["roles"] = serde_json::json!(["admin", "auditor"]);
        list["permissions"] = serde_json::json!("orders:read orders:write");
        let claims = parse(list);
        assert_eq!(claims.roles, ["admin", "auditor"]);
        assert!(claims.has_permission("orders:write"));
    }

    #[test]
    fn a_claim_of_an_unexpected_shape_reads_as_absent_not_as_a_refusal() {
        let mut odd = base();
        odd["roles"] = serde_json::json!({ "acme": ["admin"] });
        let claims = parse(odd);
        assert!(claims.roles.is_empty());
        assert!(
            claims.claim("roles").is_none(),
            "named fields never re-land in extra"
        );
    }

    #[test]
    fn unknown_claims_survive_in_extra() {
        let mut mapped = base();
        mapped["department"] = serde_json::json!("field ops");
        let claims = parse(mapped);
        assert_eq!(
            claims.claim("department").and_then(Value::as_str),
            Some("field ops")
        );
    }

    #[test]
    fn scopes_split_on_whitespace() {
        let mut scoped = base();
        scoped["scope"] = serde_json::json!("openid  profile orders:read");
        let claims = parse(scoped);
        assert_eq!(
            claims.scopes().collect::<Vec<_>>(),
            ["openid", "profile", "orders:read"]
        );
        assert!(claims.has_scope("orders:read"));
        assert!(!claims.has_scope("orders"));
        assert!(parse(base()).scopes().next().is_none());
    }

    #[test]
    fn requirements_name_what_was_missing() {
        let mut token = base();
        token["permissions"] = serde_json::json!(["orders:read"]);
        let claims = parse(token);
        claims.require_permission("orders:read").unwrap();
        let denied = claims.require_permission("orders:write").unwrap_err();
        assert!(denied.to_string().contains("orders:write"), "{denied}");
        assert_eq!(denied.status(), 403);

        claims
            .require_any_permission(["orders:write", "orders:read"])
            .unwrap();
        claims.require_any_permission([]).unwrap();
        let none = claims.require_any_permission(["a", "b"]).unwrap_err();
        assert!(none.to_string().contains("a or b"), "{none}");
        claims.require_all_permissions(["orders:read"]).unwrap();
        assert!(
            claims
                .require_all_permissions(["orders:read", "orders:write"])
                .is_err()
        );
    }

    #[test]
    fn a_token_with_no_user_is_the_one_whose_subject_is_its_client() {
        let mut machine = base();
        machine["sub"] = serde_json::json!("reporting-job");
        machine["client_id"] = serde_json::json!("reporting-job");
        assert!(parse(machine).is_client_only());

        // A machine client with a service account has a user subject, and is
        // not "client only" even though nobody is at a keyboard.
        let mut service_account = base();
        service_account["client_id"] = serde_json::json!("reporting-job");
        assert!(!parse(service_account).is_client_only());

        let mut user = base();
        user["client_id"] = serde_json::json!("web-app");
        assert!(!parse(user).is_client_only());
    }

    #[test]
    fn a_bound_token_exposes_its_key_thumbprint() {
        let mut bound = base();
        bound["cnf"] = serde_json::json!({ "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" });
        assert_eq!(
            parse(bound).jkt(),
            Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I")
        );
        assert!(parse(base()).jkt().is_none());
    }
}
