//! OpenAPI document for the admin API, derived from the admin routers so it
//! can never drift from what is actually served. `GET /openapi.json` serves
//! it; Swagger UI at `/docs` is enabled with `DOCS_ENABLED=true`; the
//! `ridm-api openapi` command prints it for client generation.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_axum::router::OpenApiRouter;

use crate::routes::{account, admin};
use crate::state::AppState;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "rIDM Admin API",
        description = "Administration API of rIDM, plus the self-service account API. Admin operations \
                       need a bearer access token carrying the `urn:ridm:admin` audience; permissions \
                       are `ridm:<resource>:<action>`. Account operations (`/t/{slug}/account/...`) \
                       need a token of that tenant carrying the `urn:ridm:account` audience and act on \
                       its subject only. Errors are RFC 9457 problem documents.",
        license(name = "MIT")
    ),
    modifiers(&BearerAuth),
    tags(
        (name = "auth", description = "Caller identity and the permission catalogue"),
        (name = "tenants", description = "Tenants and their settings"),
        (name = "tenant_config", description = "Tenant configuration as code"),
        (name = "clients", description = "OAuth / OIDC clients"),
        (name = "users", description = "Users and everything attached to them"),
        (name = "groups", description = "Groups, membership and group roles"),
        (name = "organizations", description = "Organizations within a tenant: membership, email domains and org-scoped role grants"),
        (name = "roles", description = "Roles, composites and permission grants"),
        (name = "resource_servers", description = "Resource servers (audiences) and permissions"),
        (name = "scopes", description = "OAuth scopes"),
        (name = "mappers", description = "Claim mappers"),
        (name = "keys", description = "Signing keys and master-key rotation"),
        (name = "invitations", description = "Invitations"),
        (name = "messaging", description = "Email and SMS delivery, templates, delivery log"),
        (name = "audit", description = "Audit log"),
        (name = "webhooks", description = "Webhooks and deliveries"),
        (name = "scim", description = "SCIM provisioning tokens"),
        (name = "ip_rules", description = "IP allow and deny rules"),
        (name = "identity_providers", description = "Upstream identity providers (OpenID Connect and OAuth 2.0 brokering)"),
        (name = "account", description = "Self-service account API: the signed-in user's profile, password, contact details, second factors, trusted devices, sessions, consented applications, data export and account deletion")
    )
)]
struct ApiDoc;

struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some(
                        "Access token with the `urn:ridm:admin` audience, issued to a client \
                         allowed that audience",
                    ))
                    .build(),
            ),
        );
    }
}

/// Every admin router, with the OpenAPI document collected alongside.
pub fn admin_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(admin::auth_router())
        .merge(admin::tenants_router())
        .merge(admin::tenant_config_router())
        .merge(admin::clients_router())
        .merge(admin::users_router())
        .merge(admin::groups_router())
        .merge(admin::organizations_router())
        .merge(admin::roles_router())
        .merge(admin::resource_servers_router())
        .merge(admin::scopes_router())
        .merge(admin::stats_router())
        .merge(admin::mappers_router())
        .merge(admin::keys_router())
        .merge(admin::invitations_router())
        .merge(admin::messaging_router())
        .merge(admin::audit_router())
        .merge(admin::webhooks_router())
        .merge(admin::scim_router())
        .merge(admin::dcr_router())
        .merge(admin::ip_rules_router())
        .merge(admin::identity_providers_router())
        .merge(account::me_router())
        .merge(account::mfa_router())
        .merge(account::devices_router())
        .merge(account::profile_router())
        .merge(account::password_router())
        .merge(account::contact_router())
        .merge(account::sessions_router())
        .merge(account::apps_router())
        .merge(account::data_router())
        .merge(account::identities_router())
        .merge(account::tokens_router())
}

/// The admin API document as served and committed.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = admin_router().into_openapi();
    finalize(&mut doc);
    doc
}

/// Version-stamp the document from the crate and make operation ids unique:
/// the handler names prefixed with their tag (`users_list`), as generated
/// clients require. Applied to the served document and the CLI output alike.
pub fn finalize(doc: &mut utoipa::openapi::OpenApi) {
    doc.info.version = env!("CARGO_PKG_VERSION").to_string();
    for item in doc.paths.paths.values_mut() {
        for op in [
            &mut item.get,
            &mut item.put,
            &mut item.post,
            &mut item.delete,
            &mut item.patch,
        ]
        .into_iter()
        .flatten()
        {
            if let (Some(tag), Some(id)) = (
                op.tags.as_ref().and_then(|t| t.first()),
                op.operation_id.as_ref(),
            ) && !id.starts_with(&format!("{tag}_"))
            {
                op.operation_id = Some(format!("{tag}_{id}"));
            }
        }
    }
}
