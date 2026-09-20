# Changelog

Every release of rIDM, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); until 1.0.0 a minor
version may break compatibility, and its notes say how, under **Upgrade notes**. That
heading also marks any release whose migrations do not keep the release before it
working, which makes its upgrade stop-the-world (see the docs' *Upgrading*).

A release's section becomes the body of its GitHub release
(`scripts/release/notes.sh`), and the release workflow refuses a tag whose version
has no section here. Changes land under **Unreleased** as they merge; cutting a
release renames that heading to the version and date.

## [Unreleased]

### Added

- Organizations within a tenant: membership (a user may belong to several, one
  of them primary), role grants scoped to an organization, email domains
  verified by DNS TXT record with auto-join, an organization step in the login
  flow, and an `org_id` claim in access and ID tokens taken from the session, so
  one user can act in different organizations in different sessions. New
  `ridm:orgs:read` and `ridm:orgs:write` permissions (user managers hold both),
  a console page, and a read-only list in the account console. A tenant with no
  organizations is unaffected, and no token gains a claim.
- Organization administrators: a role granted *inside* an organization now
  reaches the admin API for that organization alone — its record, members,
  domains, invitations and internal role grants — and never satisfies a
  tenant-wide permission check. A sixth built-in role, `ridm:org-admin`, is
  seeded in every tenant for it. Creating, deleting and listing organizations,
  changing a slug or status, and adding an existing user as a member stay
  tenant-wide; an organization's own administrator adds people through new
  org-scoped invitation routes, and `GET …/{org}/grantable-roles` says which
  roles they may grant there. `GET /admin/me` gained `organization` and
  `organization_permissions`, the console opens such an administrator on their
  own organization, and the MFA-for-administrators policy counts them.

## [0.1.0] - 2026-09-19

The first release.

### Added

- Multi-tenant OpenID Connect provider: authorization code with PKCE, PAR, JAR,
  JARM, DPoP, device authorization, client credentials, token exchange, refresh
  rotation, introspection, revocation, RP-initiated, front- and back-channel logout,
  dynamic client registration.
- Users, groups, roles, resource servers and permissions; passwords, magic links,
  TOTP, WebAuthn passkeys, recovery codes; social and OIDC brokering; SCIM 2.0;
  bulk import from Keycloak and Auth0 exports.
- Admin and account consoles, embedded in the server binary.
- Webhooks, a tamper-evident audit log with export sinks, rate limits, IP rules
  and CAPTCHA.
- The `ridm` admin CLI and the `ridm-auth` crate for Rust resource servers.
- Container image, Helm chart, production docker-compose stack with nginx, Caddy
  and Traefik configurations, and a documentation site.
- Release workflow: signed multi-arch images with SBOMs, static Linux binaries,
  the Helm chart as an OCI artifact, checksums signed with Sigstore.
- Backup and restore, and upgrade, guides; a start-up check that refuses a master key
  that does not decrypt the database's signing keys, and a warning when the database was
  migrated by a newer release.
- `/.well-known/security.txt` is the operator's: `SECURITY_CONTACT`,
  `SECURITY_POLICY_URL` or a whole `SECURITY_TXT_FILE`, and 404 until one is set.

[Unreleased]: https://github.com/ZerosAndOnesLLC/rIDM/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ZerosAndOnesLLC/rIDM/releases/tag/v0.1.0
