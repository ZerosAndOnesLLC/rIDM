//! Claim assembly: standard OIDC profile claims by scope, then the tenant's
//! and client's claim mappers, with protected claims kept out of reach.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::error::AppResult;
use crate::models::{
    ClaimMapper, Exposure, Group, JsonType, MapperKind, PROTECTED_CLAIMS, ProfileSchema, Role,
    Scope, Tenant, TokenKind, User,
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

/// Claims the standard scopes release (OIDC Core §5.4), used when a tenant's
/// scope rows are not at hand. They match what migration 0008 seeds as each
/// standard scope's `claims`, so a tenant that never tuned them sees no
/// difference between the two.
fn standard_scope_claims(scope: &str) -> &'static [&'static str] {
    match scope {
        "profile" => &[
            "name",
            "family_name",
            "given_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "updated_at",
        ],
        "email" => &["email", "email_verified"],
        "phone" => &["phone_number", "phone_number_verified"],
        "address" => &["address"],
        _ => &[],
    }
}

/// Claims the token service sets itself in access tokens. A mapper of the
/// matching kind may reshape `roles` and `groups` (its output replaces the
/// built-in value); nothing else may write them, and nothing may write
/// `permissions`, which is computed from the audience's grants.
pub const BUILDER_CLAIMS: &[&str] = &["roles", "groups", "permissions"];

/// Whether `name` may be released from user data (scope claims, profile
/// attributes): never a claim the token service owns.
fn releasable(name: &str) -> bool {
    !PROTECTED_CLAIMS.contains(&name) && !BUILDER_CLAIMS.contains(&name)
}

/// The value of one released claim for `user`, by claim name: the OIDC
/// standard names map onto the user record (`preferred_username` is the
/// username, `phone_number` the phone, ...), `attributes.<name>` and any
/// other name are a top-level user field (see [`user_field`]) or else the
/// profile attribute of that name.
pub fn release_claim(user: &User, name: &str) -> Option<Value> {
    if !releasable(name) {
        return None;
    }
    match name {
        "preferred_username" => Some(json!(user.username)),
        "email" => user.email.as_ref().map(|e| json!(e)),
        "email_verified" => user.email.as_ref().map(|_| json!(user.email_verified)),
        "phone_number" => user.phone.as_ref().map(|p| json!(p)),
        "phone_number_verified" => user.phone.as_ref().map(|_| json!(user.phone_verified)),
        "locale" => user.locale.as_ref().map(|l| json!(l)),
        "updated_at" => Some(json!(user.updated_at.timestamp())),
        // OIDC Core §5.1.1: a JSON object, or nothing.
        "address" => user
            .attributes
            .get("address")
            .filter(|v| v.is_object())
            .cloned(),
        other => user_attribute(user, other),
    }
}

/// Claims selected by the granted scopes (OIDC Core §5.4): each granted
/// scope releases the claims its `claims` list names (see
/// [`release_claim`]). `defs` are the tenant's scope rows; a standard scope
/// missing from them falls back to its standard claim set.
pub fn scope_claims(user: &User, scopes: &[String], defs: &[Scope]) -> Map<String, Value> {
    let mut out = Map::new();
    for granted in scopes {
        let names: Vec<&str> = match defs.iter().find(|d| &d.name == granted) {
            Some(def) => def.claims.iter().map(String::as_str).collect(),
            None => standard_scope_claims(granted).to_vec(),
        };
        for name in names {
            if out.contains_key(name) {
                continue;
            }
            if let Some(v) = release_claim(user, name) {
                out.insert(name.to_string(), v);
            }
        }
    }
    out
}

/// Standard claims (OIDC Core §5.4) selected by the granted scopes, without
/// the tenant's scope definitions: the seeded standard claim sets.
pub fn standard_claims(user: &User, scopes: &[String]) -> Map<String, Value> {
    scope_claims(user, scopes, &[])
}

/// Profile attributes whose schema entry lists `exposure` in `visible_in`,
/// each as a claim of the attribute's name. A claim already present (a scope
/// released it) is left alone, and names the token service owns are never
/// written. Mappers run afterwards and may override.
pub fn profile_claims(
    user: &User,
    schema: &ProfileSchema,
    exposure: Exposure,
    claims: &mut Map<String, Value>,
) {
    for def in schema
        .attributes
        .iter()
        .filter(|a| a.visible_in.contains(&exposure))
    {
        if !releasable(&def.name) || claims.contains_key(&def.name) {
            continue;
        }
        if let Some(v) = user.attributes.get(&def.name).filter(|v| !v.is_null()) {
            claims.insert(def.name.clone(), v.clone());
        }
    }
}

/// Why a mapper may not write its claim, if it may not: protected claims
/// never, builder-owned claims only by the mapper kind that produces them.
pub fn mapper_claim_refusal(mapper: &ClaimMapper) -> Option<String> {
    let name = mapper.claim_name()?;
    if PROTECTED_CLAIMS.contains(&name) {
        return Some(format!("claim `{name}` is set by the token service"));
    }
    let owned_by_kind = matches!(
        (&mapper.kind, name),
        (MapperKind::Roles { .. }, "roles") | (MapperKind::Groups { .. }, "groups")
    );
    if BUILDER_CLAIMS.contains(&name) && !owned_by_kind {
        return Some(match name {
            "permissions" => "claim `permissions` is computed from the audience's grants".into(),
            _ => format!("claim `{name}` may only be written by a `{name}` mapper"),
        });
    }
    None
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
        // Refused at save time; rows written before that rule are skipped.
        if let Some(reason) = mapper_claim_refusal(m) {
            tracing::warn!(mapper = %m.name, %reason, "mapper targets a reserved claim; ignored");
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
                    && let Some(v) = coerce(&v, *json_type)
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
                        // The mapper names the client by its public id; the
                        // pipeline resolves that to the client's row id when
                        // it loads mappers (`oidc::token::effective_mappers`).
                        Some(c) => r.client_id.is_some_and(|id| id.to_string() == *c),
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

/// A user value by name: `attributes.<name>` is that profile attribute; any
/// other name is a top-level user field ([`user_field`]: `username`,
/// `email`, ...) or, failing that, the profile attribute of that name.
fn user_attribute(user: &User, attribute: &str) -> Option<Value> {
    let attr = |name: &str| user.attributes.get(name).filter(|v| !v.is_null()).cloned();
    match attribute.strip_prefix("attributes.") {
        Some(rest) => attr(rest),
        None => user_field(user, attribute).or_else(|| attr(attribute)),
    }
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
            external_id: None,
            last_login_at: None,
            failed_attempts: 0,
            locked_until: None,
            deleted_at: None,
            terms_accepted_at: None,
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
            built_in: false,
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

    fn scope_def(name: &str, claims: &[&str]) -> Scope {
        Scope {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            name: name.into(),
            description: None,
            claims: claims.iter().map(|c| c.to_string()).collect(),
            resource_server_id: None,
            is_default: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn a_scope_releases_the_claims_it_lists() {
        let u = user();
        let defs = vec![
            scope_def(
                "hr",
                &["department", "username", "attributes.level", "sub", "roles"],
            ),
            // A tuned standard scope releases what it lists now.
            scope_def("email", &["email"]),
        ];
        let c = scope_claims(&u, &["hr".into(), "email".into()], &defs);
        assert_eq!(c["department"], "eng", "a profile attribute by name");
        assert_eq!(c["username"], "alice", "a top-level user field");
        assert_eq!(c["attributes.level"], "7");
        assert_eq!(c["email"], "alice@acme.example");
        assert!(c.get("email_verified").is_none(), "no longer listed");
        assert!(
            c.get("sub").is_none() && c.get("roles").is_none(),
            "owned claims never"
        );
        // A standard scope without its row falls back to the standard set.
        let c = scope_claims(&u, &["profile".into()], &[]);
        assert_eq!(c["preferred_username"], "alice");
        assert_eq!(c["name"], "Alice A");
        assert_eq!(c["locale"], "en");
    }

    #[test]
    fn profile_attributes_reach_the_artefacts_they_are_visible_in() {
        use crate::models::{AttributeDef, Exposure, ProfileSchema};
        let u = user();
        let schema = ProfileSchema {
            attributes: vec![
                AttributeDef {
                    name: "department".into(),
                    visible_in: vec![Exposure::IdToken, Exposure::AccessToken],
                    ..Default::default()
                },
                AttributeDef {
                    name: "level".into(),
                    visible_in: vec![Exposure::Userinfo],
                    ..Default::default()
                },
                AttributeDef {
                    name: "name".into(),
                    visible_in: vec![Exposure::Userinfo],
                    ..Default::default()
                },
                AttributeDef {
                    name: "missing".into(),
                    visible_in: vec![Exposure::Userinfo],
                    ..Default::default()
                },
            ],
            allow_undeclared: false,
        };
        let mut id = Map::new();
        profile_claims(&u, &schema, Exposure::IdToken, &mut id);
        assert_eq!(
            id,
            json!({"department": "eng"}).as_object().unwrap().clone()
        );
        let mut ui = Map::new();
        ui.insert("name".into(), json!("from a scope"));
        profile_claims(&u, &schema, Exposure::Userinfo, &mut ui);
        assert_eq!(ui["level"], "7");
        assert_eq!(
            ui["name"], "from a scope",
            "a released claim is not replaced"
        );
        assert!(ui.get("missing").is_none());
        assert!(ui.get("department").is_none());
    }

    #[test]
    fn user_attribute_mappers_read_top_level_fields_too() {
        let t = tenant();
        let u = user();
        let ctx = ClaimContext {
            tenant: &t,
            user: Some(&u),
            client_id: "app",
            scopes: &[],
            roles: &[],
            groups: &[],
        };
        let m = |attribute: &str, claim: &str| ClaimMapper {
            name: claim.into(),
            kind: MapperKind::UserAttribute {
                attribute: attribute.into(),
                claim: claim.into(),
                json_type: JsonType::Json,
            },
            include_in: vec![TokenKind::Access],
        };
        let mut c = Map::new();
        apply_mappers(
            &[
                m("username", "user"),
                m("email_verified", "ev"),
                m("department", "dept"),
            ],
            &ctx,
            TokenKind::Access,
            &mut c,
        )
        .unwrap();
        assert_eq!(c["user"], "alice");
        assert_eq!(c["ev"], true);
        assert_eq!(
            c["dept"], "eng",
            "a bare name that is no field is an attribute"
        );
    }

    #[test]
    fn a_client_roles_mapper_emits_only_that_clients_roles() {
        let t = tenant();
        let u = user();
        let mine = role("editor", true);
        let theirs = role("auditor", true);
        let realm = role("admin", false);
        let roles = vec![mine.clone(), theirs, realm];
        let ctx = ClaimContext {
            tenant: &t,
            user: Some(&u),
            client_id: "app",
            scopes: &[],
            roles: &roles,
            groups: &[],
        };
        // The pipeline has resolved the mapper's public client id to the row id.
        let mapper = ClaimMapper {
            name: "app-roles".into(),
            kind: MapperKind::Roles {
                claim: "app_roles".into(),
                client_id: Some(mine.client_id.unwrap().to_string()),
            },
            include_in: vec![TokenKind::Access],
        };
        let mut c = Map::new();
        apply_mappers(&[mapper], &ctx, TokenKind::Access, &mut c).unwrap();
        assert_eq!(c["app_roles"], json!(["editor"]));
    }

    #[test]
    fn mappers_may_not_write_claims_the_builder_owns() {
        let hard = |claim: &str| ClaimMapper {
            name: "m".into(),
            kind: MapperKind::Hardcoded {
                claim: claim.into(),
                value: json!(1),
            },
            include_in: vec![TokenKind::Access],
        };
        for claim in ["sub", "cnf", "act", "roles", "groups", "permissions"] {
            assert!(mapper_claim_refusal(&hard(claim)).is_some(), "{claim}");
        }
        assert!(mapper_claim_refusal(&hard("tier")).is_none());
        let roles = ClaimMapper {
            name: "r".into(),
            kind: MapperKind::Roles {
                claim: "roles".into(),
                client_id: None,
            },
            include_in: vec![TokenKind::Access],
        };
        assert!(
            mapper_claim_refusal(&roles).is_none(),
            "its own kind reshapes it"
        );
        let groups_as_roles = ClaimMapper {
            name: "g".into(),
            kind: MapperKind::Groups {
                claim: "roles".into(),
                full_path: false,
            },
            include_in: vec![TokenKind::Access],
        };
        assert!(mapper_claim_refusal(&groups_as_roles).is_some());
    }
}
