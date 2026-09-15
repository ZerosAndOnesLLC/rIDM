//! Claim assembly: standard OIDC profile claims by scope, then the tenant's
//! and client's claim mappers, with protected claims kept out of reach.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::error::AppResult;
use crate::models::{
    ClaimMapper, Group, JsonType, MapperKind, PROTECTED_CLAIMS, Role, Tenant, TokenKind, User,
};

/// Everything a mapper may draw on.
pub struct ClaimContext<'a> {
    pub tenant: &'a Tenant,
    pub user: Option<&'a User>,
    pub client_id: &'a str,
    pub scopes: &'a [String],
    pub roles: &'a [Role],
    /// Effective groups with their ancestors, for `full_path`.
    pub groups: &'a [Group],
}

/// Standard claims (OIDC Core §5.4) selected by the granted scopes.
pub fn standard_claims(user: &User, scopes: &[String]) -> Map<String, Value> {
    let has = |s: &str| scopes.iter().any(|x| x == s);
    let mut out = Map::new();
    if has("profile") {
        out.insert("preferred_username".into(), json!(user.username));
        for (attr, claim) in [
            ("name", "name"),
            ("given_name", "given_name"),
            ("family_name", "family_name"),
            ("middle_name", "middle_name"),
            ("nickname", "nickname"),
            ("picture", "picture"),
            ("website", "website"),
            ("gender", "gender"),
            ("birthdate", "birthdate"),
            ("zoneinfo", "zoneinfo"),
        ] {
            if let Some(v) = user.attributes.get(attr).filter(|v| !v.is_null()) {
                out.insert(claim.into(), v.clone());
            }
        }
        if let Some(l) = &user.locale {
            out.insert("locale".into(), json!(l));
        }
        out.insert("updated_at".into(), json!(user.updated_at.timestamp()));
    }
    if has("email")
        && let Some(e) = &user.email
    {
        out.insert("email".into(), json!(e));
        out.insert("email_verified".into(), json!(user.email_verified));
    }
    if has("phone")
        && let Some(p) = &user.phone
    {
        out.insert("phone_number".into(), json!(p));
        out.insert("phone_number_verified".into(), json!(user.phone_verified));
    }
    if has("address")
        && let Some(a) = user.attributes.get("address").filter(|v| v.is_object())
    {
        out.insert("address".into(), a.clone());
    }
    out
}

/// Apply mappers for `kind` on top of `claims`. Returns extra audiences.
pub fn apply_mappers(
    mappers: &[ClaimMapper],
    ctx: &ClaimContext<'_>,
    kind: TokenKind,
    claims: &mut Map<String, Value>,
) -> AppResult<Vec<String>> {
    let mut audiences = vec![];
    for m in mappers.iter().filter(|m| m.applies_to(kind)) {
        if let Some(name) = m.claim_name()
            && PROTECTED_CLAIMS.contains(&name)
        {
            tracing::warn!(mapper = %m.name, claim = name, "mapper targets a protected claim; ignored");
            continue;
        }
        match &m.kind {
            MapperKind::UserAttribute {
                attribute,
                claim,
                json_type,
            } => {
                if let Some(user) = ctx.user
                    && let Some(v) = user_attribute(user, attribute)
                    && let Some(v) = coerce(v, *json_type)
                {
                    claims.insert(claim.clone(), v);
                }
            }
            MapperKind::Groups { claim, full_path } => {
                if ctx.user.is_some() {
                    let names: BTreeSet<String> = ctx
                        .groups
                        .iter()
                        .map(|g| {
                            if *full_path {
                                group_path(g, ctx.groups)
                            } else {
                                g.name.clone()
                            }
                        })
                        .collect();
                    claims.insert(claim.clone(), json!(names));
                }
            }
            MapperKind::Roles { claim, client_id } => {
                let names: BTreeSet<&str> = ctx
                    .roles
                    .iter()
                    .filter(|r| match client_id {
                        None => r.client_id.is_none(),
                        // Client-scoped roles are matched by the client's id in Phase 3.
                        Some(_) => r.client_id.is_some(),
                    })
                    .map(|r| r.name.as_str())
                    .collect();
                claims.insert(claim.clone(), json!(names));
            }
            MapperKind::Hardcoded { claim, value } => {
                claims.insert(claim.clone(), value.clone());
            }
            MapperKind::Template { claim, template } => {
                let data = json!({
                    "user": ctx.user,
                    "tenant": { "slug": ctx.tenant.slug, "id": ctx.tenant.id, "display_name": ctx.tenant.display_name },
                    "client": { "client_id": ctx.client_id },
                    "roles": ctx.roles.iter().map(|r| r.name.clone()).collect::<Vec<_>>(),
                    "groups": ctx.groups.iter().map(|g| g.name.clone()).collect::<Vec<_>>(),
                    "scopes": ctx.scopes,
                });
                let mut hb = handlebars::Handlebars::new();
                hb.set_strict_mode(false);
                hb.register_escape_fn(handlebars::no_escape);
                match hb.render_template(template, &data) {
                    Ok(rendered) if !rendered.is_empty() => {
                        claims.insert(claim.clone(), json!(rendered));
                    }
                    Ok(_) => {}
                    Err(err) => {
                        tracing::warn!(mapper = %m.name, error = %err, "template mapper failed")
                    }
                }
            }
            MapperKind::Audience { audience } => {
                if kind == TokenKind::Access {
                    audiences.push(audience.clone());
                }
            }
        }
    }
    Ok(audiences)
}

fn user_attribute<'a>(user: &'a User, attribute: &str) -> Option<&'a Value> {
    if let Some(rest) = attribute.strip_prefix("attributes.") {
        return user.attributes.get(rest);
    }
    None
}

/// Top-level user fields are exposed through a JSON view so mappers can use
/// `username`, `email`, ... uniformly with `attributes.*`.
pub fn user_field(user: &User, field: &str) -> Option<Value> {
    match field {
        "id" => Some(json!(user.id)),
        "username" => Some(json!(user.username)),
        "email" => user.email.as_ref().map(|e| json!(e)),
        "email_verified" => Some(json!(user.email_verified)),
        "phone" => user.phone.as_ref().map(|p| json!(p)),
        "phone_verified" => Some(json!(user.phone_verified)),
        "locale" => user.locale.as_ref().map(|l| json!(l)),
        "org_id" => user.org_id.map(|o| json!(o)),
        "created_at" => Some(json!(user.created_at.timestamp())),
        "updated_at" => Some(json!(user.updated_at.timestamp())),
        _ => None,
    }
}

fn coerce(v: &Value, t: JsonType) -> Option<Value> {
    match t {
        JsonType::Json => Some(v.clone()),
        JsonType::String => match v {
            Value::String(s) => Some(json!(s)),
            Value::Null => None,
            other => Some(json!(other.to_string())),
        },
        JsonType::Number => match v {
            Value::Number(_) => Some(v.clone()),
            Value::String(s) => s.parse::<f64>().ok().map(|n| json!(n)),
            _ => None,
        },
        JsonType::Boolean => match v {
            Value::Bool(_) => Some(v.clone()),
            Value::String(s) => match s.as_str() {
                "true" => Some(json!(true)),
                "false" => Some(json!(false)),
                _ => None,
            },
            _ => None,
        },
    }
}

fn group_path(g: &Group, all: &[Group]) -> String {
    let mut parts = vec![g.name.clone()];
    let mut parent = g.parent_id;
    let mut depth = 0;
    while let Some(pid) = parent
        && depth < 64
    {
        match all.iter().find(|x| x.id == pid) {
            Some(p) => {
                parts.push(p.name.clone());
                parent = p.parent_id;
            }
            None => break,
        }
        depth += 1;
    }
    parts.reverse();
    parts.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{TenantStatus, UserStatus};
    use chrono::Utc;
    use uuid::Uuid;

    fn tenant() -> Tenant {
        Tenant {
            id: Uuid::nil(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            status: TenantStatus::Active,
            settings: sqlx::types::Json(Default::default()),
            pairwise_salt: vec![1; 32],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn user() -> User {
        User {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            org_id: None,
            username: "alice".into(),
            email: Some("alice@acme.example".into()),
            email_verified: true,
            phone: None,
            phone_verified: false,
            password_hash: None,
            password_algo: None,
            must_change_password: false,
            password_expires_at: None,
            password_changed_at: None,
            status: UserStatus::Active,
            attributes: json!({"department": "eng", "name": "Alice A", "level": "7"}),
            locale: Some("en".into()),
            last_login_at: None,
            failed_attempts: 0,
            locked_until: None,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn role(name: &str, client: bool) -> Role {
        Role {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            client_id: client.then(Uuid::now_v7),
            name: name.into(),
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn standard_claims_follow_scopes() {
        let u = user();
        let none = standard_claims(&u, &[]);
        assert!(none.is_empty());
        let p = standard_claims(&u, &["profile".into(), "email".into()]);
        assert_eq!(p["preferred_username"], "alice");
        assert_eq!(p["name"], "Alice A");
        assert_eq!(p["email"], "alice@acme.example");
        assert_eq!(p["email_verified"], true);
        assert!(p.get("phone_number").is_none());
    }

    #[test]
    fn mappers_apply_and_protected_claims_are_ignored() {
        let t = tenant();
        let u = user();
        let roles = vec![role("admin", false), role("app-user", true)];
        let parent = Group {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            parent_id: None,
            name: "staff".into(),
            description: None,
            attributes: json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let child = Group {
            id: Uuid::now_v7(),
            parent_id: Some(parent.id),
            name: "eng".into(),
            ..parent.clone()
        };
        let groups = vec![parent.clone(), child.clone()];
        let ctx = ClaimContext {
            tenant: &t,
            user: Some(&u),
            client_id: "app",
            scopes: &["openid".into()],
            roles: &roles,
            groups: &groups,
        };
        let mappers = vec![
            ClaimMapper {
                name: "dept".into(),
                kind: MapperKind::UserAttribute {
                    attribute: "attributes.department".into(),
                    claim: "department".into(),
                    json_type: JsonType::String,
                },
                include_in: vec![TokenKind::Access, TokenKind::Id],
            },
            ClaimMapper {
                name: "level".into(),
                kind: MapperKind::UserAttribute {
                    attribute: "attributes.level".into(),
                    claim: "level".into(),
                    json_type: JsonType::Number,
                },
                include_in: vec![TokenKind::Access],
            },
            ClaimMapper {
                name: "groups".into(),
                kind: MapperKind::Groups {
                    claim: "groups".into(),
                    full_path: true,
                },
                include_in: vec![TokenKind::Access],
            },
            ClaimMapper {
                name: "roles".into(),
                kind: MapperKind::Roles {
                    claim: "roles".into(),
                    client_id: None,
                },
                include_in: vec![TokenKind::Access],
            },
            ClaimMapper {
                name: "fixed".into(),
                kind: MapperKind::Hardcoded {
                    claim: "tier".into(),
                    value: json!("gold"),
                },
                include_in: vec![TokenKind::Access],
            },
            ClaimMapper {
                name: "tpl".into(),
                kind: MapperKind::Template {
                    claim: "handle".into(),
                    template: "{{user.username}}@{{tenant.slug}}".into(),
                },
                include_in: vec![TokenKind::Access],
            },
            ClaimMapper {
                name: "aud".into(),
                kind: MapperKind::Audience {
                    audience: "https://api.acme.example".into(),
                },
                include_in: vec![TokenKind::Access],
            },
            ClaimMapper {
                name: "evil".into(),
                kind: MapperKind::Hardcoded {
                    claim: "sub".into(),
                    value: json!("someone-else"),
                },
                include_in: vec![TokenKind::Access],
            },
        ];
        let mut claims = Map::new();
        let auds = apply_mappers(&mappers, &ctx, TokenKind::Access, &mut claims).unwrap();
        assert_eq!(claims["department"], "eng");
        assert_eq!(claims["level"], 7.0);
        assert_eq!(claims["groups"], json!(["staff", "staff/eng"]));
        assert_eq!(claims["roles"], json!(["admin"]), "realm roles only");
        assert_eq!(claims["tier"], "gold");
        assert_eq!(claims["handle"], "alice@acme");
        assert_eq!(auds, vec!["https://api.acme.example"]);
        assert!(claims.get("sub").is_none(), "protected claim untouched");

        let mut id_claims = Map::new();
        apply_mappers(&mappers, &ctx, TokenKind::Id, &mut id_claims).unwrap();
        assert_eq!(
            id_claims.len(),
            1,
            "only mappers included in id tokens: {id_claims:?}"
        );
    }
}
