# Changelog

Every release of rIDM, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); until 1.0.0 a minor
version may break compatibility, and its notes say how.

A release's section becomes the body of its GitHub release
(`scripts/release/notes.sh`), and the release workflow refuses a tag whose version
has no section here. Changes land under **Unreleased** as they merge; cutting a
release renames that heading to the version and date.

## [Unreleased]

The first release, 0.1.0, is being prepared. It will cover everything built so far:

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

[Unreleased]: https://github.com/ZerosAndOnesLLC/rIDM/commits/main
