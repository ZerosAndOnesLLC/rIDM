//! Phase 5.13: the permission matrix (every built-in role × every admin
//! operation) and tenant isolation v2 (every tenant-scoped operation called
//! across tenants). Both are derived from the route sources: each handler's
//! `#[utoipa::path]` gives method and path, its first `admin.require*` call
//! the permission it needs, so a new endpoint is covered the moment it exists.

mod common;

use std::collections::BTreeMap;

use common::admin::{admin_token, call};
use common::{TestApp, create_tenant};
use reqwest::Method;
use ridm_api::models::MASTER_TENANT_ID;
use ridm_api::services::admin_access::{
    ADMIN_ROLE, BUILT_IN_ROLES, CLIENT_MANAGER_ROLE, OWNER_ROLE, PermissionSet, USER_MANAGER_ROLE,
    VIEWER_ROLE,
};
use serde_json::{Value, json};
use uuid::Uuid;

const SOURCES: &[(&str, &str)] = &[
    ("audit", include_str!("../src/routes/admin/audit.rs")),
    ("auth", include_str!("../src/routes/admin/auth.rs")),
    ("clients", include_str!("../src/routes/admin/clients.rs")),
    ("groups", include_str!("../src/routes/admin/groups.rs")),
    (
        "invitations",
        include_str!("../src/routes/admin/invitations.rs"),
    ),
    ("ip_rules", include_str!("../src/routes/admin/ip_rules.rs")),
    ("keys", include_str!("../src/routes/admin/keys.rs")),
    ("mappers", include_str!("../src/routes/admin/mappers.rs")),
    (
        "messaging",
        include_str!("../src/routes/admin/messaging.rs"),
    ),
    (
        "resource_servers",
        include_str!("../src/routes/admin/resource_servers.rs"),
    ),
    ("roles", include_str!("../src/routes/admin/roles.rs")),
    ("scopes", include_str!("../src/routes/admin/scopes.rs")),
    ("stats", include_str!("../src/routes/admin/stats.rs")),
    (
        "tenant_config",
        include_str!("../src/routes/admin/tenant_config.rs"),
    ),
    ("tenants", include_str!("../src/routes/admin/tenants.rs")),
    ("users", include_str!("../src/routes/admin/users.rs")),
    ("webhooks", include_str!("../src/routes/admin/webhooks.rs")),
];

#[derive(Debug, Clone, PartialEq)]
enum Needs {
    /// Any administrator (identity routes).
    Any,
    /// A tenant-scoped permission.
    Permission(String),
    /// A global-only permission.
    Global(String),
}

#[derive(Debug, Clone)]
struct Operation {
    method: Method,
    path: String,
    handler: String,
    needs: Needs,
}

fn constants(src: &str) -> BTreeMap<String, String> {
    src.lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("const ")?;
            let (name, value) = rest.split_once(": &str = ")?;
            let value = value.trim_end_matches(';').trim_matches('"');
            Some((name.to_string(), value.to_string()))
        })
        .collect()
}

fn resolve(arg: &str, consts: &BTreeMap<String, String>) -> String {
    let a = arg.trim();
    if let Some(lit) = a.strip_prefix('"') {
        return lit.trim_end_matches('"').to_string();
    }
    consts
        .get(a)
        .cloned()
        .unwrap_or_else(|| panic!("unknown permission constant {a}"))
}

/// Every operation of every admin router, from the sources.
fn operations() -> Vec<Operation> {
    let mut ops = vec![];
    for (_, src) in SOURCES {
        let consts = constants(src);
        let mut lines = src.lines().peekable();
        while let Some(line) = lines.next() {
            let Some(ann) = line.trim().strip_prefix("#[utoipa::path(") else {
                continue;
            };
            let method = ann.split(',').next().unwrap().trim();
            let path = ann
                .split("path = \"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .expect("path in annotation")
                .to_string();
            let fn_line = lines.next().expect("handler after annotation");
            let handler = fn_line
                .trim()
                .strip_prefix("async fn ")
                .and_then(|s| s.split('(').next())
                .expect("async fn")
                .to_string();
            // Handler body runs until the first line that is exactly `}`.
            let mut body = String::new();
            for l in lines.by_ref() {
                if l == "}" {
                    break;
                }
                body.push_str(l);
                body.push('\n');
            }
            let needs = if let Some(i) = body.find("admin.require(") {
                let args = &body[i + "admin.require(".len()..];
                let perm = args.split(',').nth(1).unwrap().split(')').next().unwrap();
                Needs::Permission(resolve(perm, &consts))
            } else if let Some(i) = body.find("admin.require_global(") {
                let args = &body[i + "admin.require_global(".len()..];
                let perm = args.split(')').next().unwrap();
                Needs::Global(resolve(perm, &consts))
            } else {
                Needs::Any
            };
            ops.push(Operation {
                method: Method::from_bytes(method.to_uppercase().as_bytes()).unwrap(),
                path,
                handler,
                needs,
            });
        }
    }
    ops
}

/// Minimal bodies that deserialize, so the permission check is what decides.
fn body_for(op: &Operation) -> Option<Value> {
    if !matches!(op.method, Method::POST | Method::PUT | Method::PATCH) {
        return None;
    }
    let p = op.path.as_str();
    let h = op.handler.as_str();
    Some(match (p, h) {
        ("/admin/tenants", "create") => {
            json!({"slug": format!("m-{}", &Uuid::new_v4().simple().to_string()[..10]), "display_name": "Matrix"})
        }
        (_, "import") if p.ends_with("/import") && !p.contains("/users/") => {
            json!({"format": "ridm.tenant/1", "tenant": {"slug": "x", "display_name": "x"}})
        }
        (_, "import") => json!([]),
        (_, "captcha_put") => json!({"provider": "turnstile", "site_key": "s", "secret": "k"}),
        (_, "email_put") => {
            json!({"type": "http", "url": "https://hook.example/mail", "from": "a@example.com"})
        }
        (_, "sms_put") => json!({"url": "https://hook.example/sms"}),
        (_, "email_test") | (_, "sms_test") => json!({"to": "+15550001111"}),
        (_, "template_put") => json!({"body_text": "x"}),
        (_, "preview") => json!({"event": "otp"}),
        (_, "create") if p.ends_with("/clients") => json!({"name": "m", "client_type": "machine"}),
        (_, "create") if p.ends_with("/invitations") => json!({"email": "m@example.com"}),
        (_, "create") if p.ends_with("/webhooks") => {
            json!({"name": "m", "url": "https://hook.example/w", "events": ["*"]})
        }
        (_, "create") if p.ends_with("/resource-servers") => {
            json!({"identifier": format!("urn:m:{}", Uuid::new_v4()), "name": "m"})
        }
        (_, "create") if p.ends_with("/claim-mappers") => {
            json!({"name": "m", "config": {"type": "hardcoded", "claim": "a", "value": 1, "include_in": ["access"]}})
        }
        (_, "create") if p.ends_with("/ip-rules") => json!({"cidr": "10.9.8.0/24"}),
        (_, "create")
            if p.ends_with("/scopes") || p.ends_with("/roles") || p.ends_with("/groups") =>
        {
            json!({"name": format!("m-{}", &Uuid::new_v4().simple().to_string()[..8])})
        }
        (_, "create_permission") => json!({"name": "m:read"}),
        _ => json!({}),
    })
}

fn concrete_path(op: &Operation, slug: &str) -> String {
    let mut out = String::new();
    for seg in op.path.split('/') {
        out.push('/');
        match seg {
            "" => out.pop().map(|_| ()).unwrap_or(()),
            "{slug}" => out.push_str(slug),
            "{client}" => out.push_str("no-such-client"),
            "{channel}" => out.push_str("email"),
            "{event}" => out.push_str("otp"),
            "{locale}" => out.push_str("en"),
            s if s.starts_with('{') => out.push_str(&Uuid::new_v4().to_string()),
            s => out.push_str(s),
        }
    }
    if op.path.ends_with("/import") {
        out.push_str("?dry_run=true");
    }
    out
}

fn role_permissions(role: &str) -> PermissionSet {
    let r = BUILT_IN_ROLES.iter().find(|r| r.name == role).unwrap();
    PermissionSet::new(r.permissions())
}

#[tokio::test]
async fn every_built_in_role_is_checked_against_every_admin_operation() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let ops = operations();
    assert!(ops.len() >= 130, "{} operations parsed", ops.len());
    assert!(
        ops.iter()
            .any(|o| o.needs == Needs::Global("ridm:tenants:create".into()))
    );
    assert!(
        ops.iter()
            .any(|o| o.needs == Needs::Permission("ridm:webhooks:write".into()))
    );

    let mut tokens = BTreeMap::new();
    for role in [
        OWNER_ROLE,
        ADMIN_ROLE,
        USER_MANAGER_ROLE,
        CLIENT_MANAGER_ROLE,
        VIEWER_ROLE,
    ] {
        tokens.insert(role, admin_token(&app, app.tenant.id, role).await);
    }
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;

    let mut checks = 0;
    let mut failures = vec![];
    for op in &ops {
        let path = concrete_path(op, &slug);
        let body = body_for(op);
        // Deleting the tenant under test would end the run; denial is still checked.
        let destructive = op.handler == "delete" && op.path == "/admin/tenants/{slug}";
        for (role, token) in &tokens {
            let allowed = match &op.needs {
                Needs::Any => true,
                Needs::Permission(p) => role_permissions(role).allows(p),
                Needs::Global(_) => false,
            };
            if allowed && destructive {
                continue;
            }
            let (status, resp, _) =
                call(&app, op.method.clone(), &path, Some(token), body.as_ref()).await;
            checks += 1;
            let ok = if allowed {
                status != 401 && status != 403
            } else {
                status == 403
            };
            if !ok {
                failures.push(format!(
                    "{role} {} {} ({}) needs {:?}: expected {}, got {status} {resp}",
                    op.method,
                    path,
                    op.handler,
                    op.needs,
                    if allowed { "allowed" } else { "403" }
                ));
            }
        }
        // The global owner reaches everything, global operations included.
        if !destructive {
            let (status, resp, _) =
                call(&app, op.method.clone(), &path, Some(&global), body.as_ref()).await;
            checks += 1;
            if status == 401 || status == 403 {
                failures.push(format!(
                    "global owner {} {} ({}): got {status} {resp}",
                    op.method, path, op.handler
                ));
            }
        }
        // No token at all is always 401.
        let (status, _, www) = call(&app, op.method.clone(), &path, None, body.as_ref()).await;
        checks += 1;
        if status != 401 || !www.starts_with("Bearer") {
            failures.push(format!(
                "anonymous {} {} ({}): got {status} ({www})",
                op.method, path, op.handler
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {checks} checks failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(checks >= 900, "{checks} checks");
}

#[tokio::test]
async fn every_tenant_scoped_operation_is_confined_to_the_admins_tenant() {
    let app = TestApp::spawn().await;
    let other = create_tenant(&app.state.db).await;
    let owner_of_own = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let mut checks = 0;
    let mut failures = vec![];
    for op in operations().iter().filter(|o| o.path.contains("{slug}")) {
        let path = concrete_path(op, &other.slug);
        let body = body_for(op);
        let (status, resp, _) = call(
            &app,
            op.method.clone(),
            &path,
            Some(&owner_of_own),
            body.as_ref(),
        )
        .await;
        checks += 1;
        if status != 403 {
            failures.push(format!(
                "{} {} ({}) reached another tenant: {status} {resp}",
                op.method, path, op.handler
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {checks} checks failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(checks >= 120, "{checks} checks");
}
