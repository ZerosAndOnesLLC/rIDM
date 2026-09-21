# Summary

[Introduction](introduction.md)

# Concepts

- [Tenants and issuers](concepts/tenants.md)
- [Clients](concepts/clients.md)
- [Users, groups and roles](concepts/users-groups-roles.md)
- [Organizations](concepts/organizations.md)
- [Resource servers, scopes and permissions](concepts/resource-servers.md)
- [Tokens](concepts/tokens.md)
- [Signing keys and the master key](concepts/keys.md)
- [Sign-in flows and sessions](concepts/flows-and-sessions.md)
- [MFA and passkeys](concepts/mfa.md)
- [Identity brokering](concepts/brokering.md)
- [Configuration as code](concepts/config-as-code.md)
- [Events, audit and webhooks](concepts/events.md)

# Quickstarts

- [Run rIDM locally](quickstarts/local.md)
- [Protect a Rust API with ridm-auth](quickstarts/protect-an-api.md)
- [Sign in from a single-page app](quickstarts/spa.md)
- [Sign in from a server-side web app](quickstarts/web-app.md)
- [Machine-to-machine access](quickstarts/machine-to-machine.md)

# Admin guide

- [The admin and account consoles](admin/consoles.md)
- [The ridm command line](admin/cli.md)
- [Tenants and tenant settings](admin/tenants.md)
- [Users, invitations and bulk import](admin/users.md)
- [Registering clients](admin/clients.md)
- [Administrator access](admin/access.md)
- [Organizations](admin/organizations.md)
- [MFA policy](admin/mfa-policy.md)
- [Adaptive authentication](admin/adaptive-auth.md)
- [Email, SMS and templates](admin/messaging.md)
- [SCIM provisioning](admin/scim.md)
- [Webhooks and the audit log](admin/webhooks-audit.md)
- [Rotating keys](admin/key-rotation.md)
- [Custom domains](admin/custom-domains.md)
- [Rate limits, IP rules and CAPTCHA](admin/security-controls.md)

# Reference

- [HTTP endpoints](reference/endpoints.md)
- [Admin API (OpenAPI)](reference/admin-api.md)
- [Token claims](reference/token-claims.md)
- [Server configuration](reference/configuration.md)
- [Tenant configuration document](reference/tenant-document.md)
- [Errors](reference/errors.md)

# Deployment

- [Deployment overview](deploy/overview.md)
- [docker-compose](deploy/docker-compose.md)
- [Production with docker-compose](deploy/production-compose.md)
- [Container image](deploy/container.md)
- [Kubernetes (Helm)](deploy/kubernetes.md)
- [Releases and verification](deploy/releases.md)
- [TLS and reverse proxies](deploy/tls-and-proxies.md)
- [Postgres and Valkey](deploy/postgres-valkey.md)
- [Scaling and performance](deploy/scaling.md)
- [Observability](deploy/observability.md)
- [Backup and restore](deploy/backup-restore.md)
- [Upgrading](deploy/upgrading.md)
- [Production checklist](deploy/checklist.md)

# Migration

- [Migrating to rIDM](migrate/overview.md)
- [From Keycloak](migrate/keycloak.md)
- [From Auth0](migrate/auth0.md)
