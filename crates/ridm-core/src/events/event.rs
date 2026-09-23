//! Typed domain events. Every state-changing domain action emits exactly one
//! event; the audit log and webhooks subscribe. Security notifications are
//! sent by the services themselves, and caches are invalidated through the
//! cache layer's own channel, not through these events.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Who caused the event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Actor {
    User { id: Uuid },
    Client { id: Uuid },
    Admin { id: Uuid },
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    /// `None` for global (cross-tenant) events such as master-key rotation.
    pub tenant_id: Option<Uuid>,
    pub occurred_at: DateTime<Utc>,
    pub actor: Actor,
    /// Client IP as seen through trusted proxies, when the event came from a request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// The administrator behind the event when it happened in a session they
    /// opened as the user (impersonation). Filled from the request's
    /// [`super::acting`] slot when the event is published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonator: Option<Uuid>,
    pub kind: EventKind,
}

impl Event {
    pub fn new(tenant_id: Option<Uuid>, actor: Actor, kind: EventKind) -> Self {
        Self {
            id: Uuid::now_v7(),
            tenant_id,
            occurred_at: Utc::now(),
            actor,
            ip: None,
            user_agent: None,
            impersonator: None,
            kind,
        }
    }

    pub fn with_request(mut self, ip: Option<String>, user_agent: Option<String>) -> Self {
        self.ip = ip;
        self.user_agent = user_agent;
        self
    }

    /// Stable dotted name (`user.created`) used by audit, webhooks and metrics.
    pub fn name(&self) -> &'static str {
        self.kind.name()
    }
}

/// The event catalogue. Variants are added phase by phase; the `name()` string
/// is part of the public webhook contract and must never change once shipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventKind {
    // Tenants
    TenantCreated {
        tenant_id: Uuid,
    },
    TenantUpdated {
        tenant_id: Uuid,
    },
    TenantDeleted {
        tenant_id: Uuid,
    },
    /// `ridm-api move-tenant` moved the tenant's data to another database;
    /// a region of `None` is the home database.
    TenantMoved {
        tenant_id: Uuid,
        from_region: Option<String>,
        to_region: Option<String>,
    },
    ProfileSchemaUpdated {
        tenant_id: Uuid,
    },
    /// First-run bootstrap created the global admin.
    Bootstrapped {
        admin_user_id: Uuid,
    },

    // Users
    UserCreated {
        user_id: Uuid,
    },
    UserUpdated {
        user_id: Uuid,
    },
    UserDeleted {
        user_id: Uuid,
    },
    /// Password set by an admin, reset flow, or the user; `by_user` tells which.
    PasswordChanged {
        user_id: Uuid,
        by_user: bool,
    },
    /// A legacy or weaker hash was replaced after a successful verification.
    PasswordHashUpgraded {
        user_id: Uuid,
        from_algo: String,
    },

    // Clients
    ClientCreated {
        client_id: Uuid,
        public_id: String,
    },
    ClientUpdated {
        client_id: Uuid,
    },
    ClientDeleted {
        client_id: Uuid,
    },
    ClientSecretRotated {
        client_id: Uuid,
    },
    /// An initial access token for dynamic client registration was issued.
    InitialAccessTokenCreated {
        token_id: Uuid,
    },
    InitialAccessTokenRevoked {
        token_id: Uuid,
    },
    ConsentGranted {
        user_id: Uuid,
        client_id: Uuid,
        scopes: Vec<String>,
    },
    ConsentRevoked {
        user_id: Uuid,
        client_id: Uuid,
    },

    // Groups
    GroupCreated {
        group_id: Uuid,
    },
    GroupUpdated {
        group_id: Uuid,
    },
    GroupDeleted {
        group_id: Uuid,
    },
    GroupMemberAdded {
        group_id: Uuid,
        user_id: Uuid,
    },
    GroupMemberRemoved {
        group_id: Uuid,
        user_id: Uuid,
    },

    // Organizations
    OrganizationCreated {
        org_id: Uuid,
    },
    OrganizationUpdated {
        org_id: Uuid,
    },
    OrganizationDeleted {
        org_id: Uuid,
    },
    OrganizationMemberAdded {
        org_id: Uuid,
        user_id: Uuid,
    },
    OrganizationMemberRemoved {
        org_id: Uuid,
        user_id: Uuid,
    },
    OrganizationDomainAdded {
        org_id: Uuid,
        domain_id: Uuid,
    },
    OrganizationDomainVerified {
        org_id: Uuid,
        domain_id: Uuid,
    },
    OrganizationDomainRemoved {
        org_id: Uuid,
        domain_id: Uuid,
    },

    // Roles
    RoleCreated {
        role_id: Uuid,
    },
    RoleUpdated {
        role_id: Uuid,
    },
    RoleDeleted {
        role_id: Uuid,
    },
    RoleAssigned {
        role_id: Uuid,
        user_id: Option<Uuid>,
        group_id: Option<Uuid>,
    },
    RoleUnassigned {
        role_id: Uuid,
        user_id: Option<Uuid>,
        group_id: Option<Uuid>,
    },
    RoleCompositeAdded {
        parent_role_id: Uuid,
        child_role_id: Uuid,
    },
    RoleCompositeRemoved {
        parent_role_id: Uuid,
        child_role_id: Uuid,
    },

    // Registration and invitations
    UserRegistered {
        user_id: Uuid,
        verified: bool,
    },
    EmailVerified {
        user_id: Uuid,
    },
    InvitationCreated {
        invitation_id: Uuid,
        email: String,
    },
    InvitationAccepted {
        invitation_id: Uuid,
        user_id: Uuid,
    },
    InvitationRevoked {
        invitation_id: Uuid,
    },
    /// A fresh link was sent (the old one stops working).
    InvitationResent {
        invitation_id: Uuid,
    },

    // Authentication
    PasswordResetRequested {
        user_id: Uuid,
    },
    PasswordResetCompleted {
        user_id: Uuid,
    },
    PasswordlessSent {
        user_id: Uuid,
        method: String,
    },
    LoginSucceeded {
        user_id: Uuid,
        method: String,
    },
    LoginFailed {
        identifier: String,
        reason: String,
    },
    UserLocked {
        user_id: Uuid,
        until_secs: i64,
    },
    TermsAccepted {
        user_id: Uuid,
    },
    /// A sign-in scored at or above the tenant's step-up threshold: the
    /// second factor was demanded whatever the MFA policy says.
    RiskStepUp {
        user_id: Uuid,
        score: u32,
        /// `new_device`, `new_country`, `impossible_travel`, `velocity`.
        signals: Vec<String>,
        country: Option<String>,
    },
    /// A sign-in scored at or above the tenant's block threshold and was
    /// refused. No session survives it.
    RiskBlocked {
        user_id: Uuid,
        score: u32,
        signals: Vec<String>,
        country: Option<String>,
    },

    // Impersonation
    /// An administrator asked to sign in as a user; the ticket is not yet
    /// redeemed, so no session exists.
    ImpersonationRequested {
        user_id: Uuid,
        reason: String,
    },
    /// The ticket was redeemed: a session as the user, opened by the
    /// administrator the event's actor names.
    ImpersonationStarted {
        user_id: Uuid,
        session_id: Uuid,
        impersonator_id: Uuid,
        impersonator_tenant_id: Uuid,
        reason: String,
    },
    /// The session was ended before its time ran out, by the administrator or
    /// by anyone who revoked it. One that runs out simply expires.
    ImpersonationEnded {
        user_id: Uuid,
        session_id: Uuid,
        impersonator_id: Uuid,
    },

    // Security notices
    /// A sign-in from a browser the user had not used before.
    NewDeviceLogin {
        user_id: Uuid,
        session_id: Uuid,
    },
    EmailChanged {
        user_id: Uuid,
        old_email: Option<String>,
        new_email: Option<String>,
    },
    /// MFA enrolment changed (`change` is a short description, e.g. "TOTP enrolled").
    MfaChanged {
        user_id: Uuid,
        change: String,
    },

    // Sessions and authorization
    TrustedDeviceAdded {
        user_id: Uuid,
        device_id: Uuid,
    },
    TrustedDeviceRevoked {
        user_id: Uuid,
        device_id: Uuid,
    },
    SessionCreated {
        session_id: Uuid,
        user_id: Uuid,
    },
    SessionRevoked {
        session_id: Uuid,
        user_id: Uuid,
    },
    AuthorizationGranted {
        user_id: Uuid,
        client_id: Uuid,
        scopes: Vec<String>,
    },
    /// A client asked, over the back channel (CIBA), for the user to sign
    /// in; `request_id` is the request's row, never its `auth_req_id`.
    BackchannelRequested {
        request_id: Uuid,
        client_id: Uuid,
        user_id: Uuid,
        scopes: Vec<String>,
        binding_message: Option<String>,
    },
    /// The user refused a backchannel request.
    BackchannelDenied {
        request_id: Uuid,
        client_id: Uuid,
        user_id: Uuid,
    },

    // Tokens
    RefreshTokenReuseDetected {
        family_id: Uuid,
        client_id: String,
        user_id: Option<Uuid>,
    },
    TokensRevoked {
        user_id: Option<Uuid>,
        session_id: Option<Uuid>,
        count: u64,
    },

    // Keys
    SigningKeyCreated {
        key_id: Uuid,
        kid: String,
        alg: String,
    },
    SigningKeyStatusChanged {
        key_id: Uuid,
        kid: String,
        status: String,
    },
    MasterKeyRotated {
        new_version: u32,
    },
    /// A key custody backend wrapped a new master-key generation, which is
    /// now the one new secrets are encrypted under.
    MasterKeyGenerationCreated {
        version: u32,
        backend: String,
    },
    /// A SAML signing key was generated (the first on demand, the next by
    /// an operator starting a rollover).
    SamlKeyCreated {
        key_id: Uuid,
    },
    /// A SAML signing key was activated, retired or deleted.
    SamlKeyStatusChanged {
        key_id: Uuid,
        status: String,
    },
    /// The scheduled verification found the chain this event is recorded in
    /// broken at `seq`: a row there was changed, removed or put out of order.
    AuditChainBroken {
        seq: i64,
        reason: String,
    },

    // Scopes, claim mappers, resource servers and permissions
    ScopeCreated {
        scope_id: Uuid,
    },
    ScopeUpdated {
        scope_id: Uuid,
    },
    ScopeDeleted {
        scope_id: Uuid,
    },
    ClaimMapperCreated {
        mapper_id: Uuid,
    },
    ClaimMapperUpdated {
        mapper_id: Uuid,
    },
    ClaimMapperDeleted {
        mapper_id: Uuid,
    },
    ResourceServerCreated {
        resource_server_id: Uuid,
    },
    ResourceServerUpdated {
        resource_server_id: Uuid,
    },
    ResourceServerDeleted {
        resource_server_id: Uuid,
    },
    PermissionCreated {
        resource_server_id: Uuid,
        permission_id: Uuid,
    },
    PermissionDeleted {
        resource_server_id: Uuid,
        permission_id: Uuid,
    },
    PermissionGranted {
        role_id: Uuid,
        permission_id: Uuid,
    },
    PermissionRevoked {
        role_id: Uuid,
        permission_id: Uuid,
    },

    // Webhooks and IP rules
    WebhookCreated {
        webhook_id: Uuid,
    },
    WebhookUpdated {
        webhook_id: Uuid,
    },
    WebhookDeleted {
        webhook_id: Uuid,
    },
    WebhookSecretRotated {
        webhook_id: Uuid,
    },
    /// Synthetic event delivered by an administrator's test ping.
    WebhookTest {
        webhook_id: Uuid,
    },
    ScimTokenCreated {
        token_id: Uuid,
    },
    ScimTokenRevoked {
        token_id: Uuid,
    },
    /// A delivery exhausted its attempts (or was refused outright) and
    /// waits in the dead-letter log for an administrator.
    WebhookDeliveryDead {
        webhook_id: Uuid,
        delivery_id: Uuid,
        event_name: String,
    },
    IpRuleCreated {
        rule_id: Uuid,
    },
    IpRuleUpdated {
        rule_id: Uuid,
    },
    IpRuleDeleted {
        rule_id: Uuid,
    },
    /// A certificate authority for `tls_client_auth` clients was added.
    MtlsTrustAnchorCreated {
        anchor_id: Uuid,
        fingerprint: String,
    },
    MtlsTrustAnchorDeleted {
        anchor_id: Uuid,
    },

    // Identity brokering
    IdentityProviderCreated {
        idp_id: Uuid,
    },
    IdentityProviderUpdated {
        idp_id: Uuid,
    },
    IdentityProviderDeleted {
        idp_id: Uuid,
    },
    /// An upstream identity was attached to a user (first sign-in, or a
    /// link made from the account console or by an administrator).
    IdentityLinked {
        user_id: Uuid,
        idp_id: Uuid,
        external_subject: String,
    },
    IdentityUnlinked {
        user_id: Uuid,
        idp_id: Uuid,
    },
    /// A sign-in through an upstream provider succeeded.
    BrokeredLogin {
        user_id: Uuid,
        idp_id: Uuid,
        /// The provider's alias.
        provider: String,
    },
    /// An upstream SAML identity provider's `LogoutRequest` ended sessions
    /// it had brokered.
    UpstreamLogout {
        idp_id: Uuid,
        /// The provider's alias.
        provider: String,
    },
    /// An LDAP directory sync pass finished (users it disabled or enabled
    /// also emit `user.updated`).
    DirectorySynced {
        idp_id: Uuid,
        /// The provider's alias.
        provider: String,
        /// A full pass (it may disable users); otherwise incremental.
        full: bool,
        created: u64,
        updated: u64,
        disabled: u64,
        enabled: u64,
    },

    // Personal access tokens
    PersonalTokenCreated {
        user_id: Uuid,
        token_id: Uuid,
        scopes: Vec<String>,
    },
    PersonalTokenRevoked {
        user_id: Uuid,
        token_id: Uuid,
    },
}

impl EventKind {
    pub fn name(&self) -> &'static str {
        match self {
            Self::TenantCreated { .. } => "tenant.created",
            Self::TenantUpdated { .. } => "tenant.updated",
            Self::TenantDeleted { .. } => "tenant.deleted",
            Self::TenantMoved { .. } => "tenant.moved",
            Self::ProfileSchemaUpdated { .. } => "tenant.profile_schema_updated",
            Self::Bootstrapped { .. } => "system.bootstrapped",
            Self::UserCreated { .. } => "user.created",
            Self::UserUpdated { .. } => "user.updated",
            Self::UserDeleted { .. } => "user.deleted",
            Self::PasswordChanged { .. } => "user.password_changed",
            Self::PasswordHashUpgraded { .. } => "user.password_hash_upgraded",
            Self::ClientCreated { .. } => "client.created",
            Self::ClientUpdated { .. } => "client.updated",
            Self::ClientDeleted { .. } => "client.deleted",
            Self::ClientSecretRotated { .. } => "client.secret_rotated",
            Self::InitialAccessTokenCreated { .. } => "dcr_token.created",
            Self::InitialAccessTokenRevoked { .. } => "dcr_token.revoked",
            Self::ConsentGranted { .. } => "consent.granted",
            Self::ConsentRevoked { .. } => "consent.revoked",
            Self::GroupCreated { .. } => "group.created",
            Self::GroupUpdated { .. } => "group.updated",
            Self::GroupDeleted { .. } => "group.deleted",
            Self::GroupMemberAdded { .. } => "group.member_added",
            Self::GroupMemberRemoved { .. } => "group.member_removed",
            Self::OrganizationCreated { .. } => "organization.created",
            Self::OrganizationUpdated { .. } => "organization.updated",
            Self::OrganizationDeleted { .. } => "organization.deleted",
            Self::OrganizationMemberAdded { .. } => "organization.member_added",
            Self::OrganizationMemberRemoved { .. } => "organization.member_removed",
            Self::OrganizationDomainAdded { .. } => "organization.domain_added",
            Self::OrganizationDomainVerified { .. } => "organization.domain_verified",
            Self::OrganizationDomainRemoved { .. } => "organization.domain_removed",
            Self::RoleCreated { .. } => "role.created",
            Self::RoleUpdated { .. } => "role.updated",
            Self::RoleDeleted { .. } => "role.deleted",
            Self::RoleAssigned { .. } => "role.assigned",
            Self::RoleUnassigned { .. } => "role.unassigned",
            Self::RoleCompositeAdded { .. } => "role.composite_added",
            Self::RoleCompositeRemoved { .. } => "role.composite_removed",
            Self::UserRegistered { .. } => "user.registered",
            Self::EmailVerified { .. } => "user.email_verified",
            Self::InvitationCreated { .. } => "invitation.created",
            Self::InvitationAccepted { .. } => "invitation.accepted",
            Self::InvitationRevoked { .. } => "invitation.revoked",
            Self::InvitationResent { .. } => "invitation.resent",
            Self::PasswordResetRequested { .. } => "user.password_reset_requested",
            Self::PasswordResetCompleted { .. } => "user.password_reset_completed",
            Self::PasswordlessSent { .. } => "login.passwordless_sent",
            Self::LoginSucceeded { .. } => "login.succeeded",
            Self::LoginFailed { .. } => "login.failed",
            Self::UserLocked { .. } => "user.locked",
            Self::TermsAccepted { .. } => "user.terms_accepted",
            Self::RiskStepUp { .. } => "risk.step_up",
            Self::RiskBlocked { .. } => "risk.blocked",
            Self::ImpersonationRequested { .. } => "impersonation.requested",
            Self::ImpersonationStarted { .. } => "impersonation.started",
            Self::ImpersonationEnded { .. } => "impersonation.ended",
            Self::NewDeviceLogin { .. } => "login.new_device",
            Self::EmailChanged { .. } => "user.email_changed",
            Self::MfaChanged { .. } => "mfa.changed",
            Self::TrustedDeviceAdded { .. } => "device.trusted",
            Self::TrustedDeviceRevoked { .. } => "device.revoked",
            Self::SessionCreated { .. } => "session.created",
            Self::SessionRevoked { .. } => "session.revoked",
            Self::AuthorizationGranted { .. } => "authorization.granted",
            Self::BackchannelRequested { .. } => "backchannel.requested",
            Self::BackchannelDenied { .. } => "backchannel.denied",
            Self::RefreshTokenReuseDetected { .. } => "token.refresh_reuse_detected",
            Self::TokensRevoked { .. } => "token.revoked",
            Self::SigningKeyCreated { .. } => "signing_key.created",
            Self::SigningKeyStatusChanged { .. } => "signing_key.status_changed",
            Self::MasterKeyRotated { .. } => "master_key.rotated",
            Self::MasterKeyGenerationCreated { .. } => "master_key.generation_created",
            Self::SamlKeyCreated { .. } => "saml_key.created",
            Self::SamlKeyStatusChanged { .. } => "saml_key.status_changed",
            Self::AuditChainBroken { .. } => "audit.chain_broken",
            Self::ScopeCreated { .. } => "scope.created",
            Self::ScopeUpdated { .. } => "scope.updated",
            Self::ScopeDeleted { .. } => "scope.deleted",
            Self::ClaimMapperCreated { .. } => "claim_mapper.created",
            Self::ClaimMapperUpdated { .. } => "claim_mapper.updated",
            Self::ClaimMapperDeleted { .. } => "claim_mapper.deleted",
            Self::ResourceServerCreated { .. } => "resource_server.created",
            Self::ResourceServerUpdated { .. } => "resource_server.updated",
            Self::ResourceServerDeleted { .. } => "resource_server.deleted",
            Self::PermissionCreated { .. } => "permission.created",
            Self::PermissionDeleted { .. } => "permission.deleted",
            Self::PermissionGranted { .. } => "permission.granted",
            Self::PermissionRevoked { .. } => "permission.revoked",
            Self::WebhookCreated { .. } => "webhook.created",
            Self::WebhookUpdated { .. } => "webhook.updated",
            Self::WebhookDeleted { .. } => "webhook.deleted",
            Self::WebhookSecretRotated { .. } => "webhook.secret_rotated",
            Self::WebhookTest { .. } => "webhook.test",
            Self::WebhookDeliveryDead { .. } => "webhook.delivery_dead",
            Self::ScimTokenCreated { .. } => "scim_token.created",
            Self::ScimTokenRevoked { .. } => "scim_token.revoked",
            Self::IpRuleCreated { .. } => "ip_rule.created",
            Self::IpRuleUpdated { .. } => "ip_rule.updated",
            Self::IpRuleDeleted { .. } => "ip_rule.deleted",
            Self::MtlsTrustAnchorCreated { .. } => "mtls_trust_anchor.created",
            Self::MtlsTrustAnchorDeleted { .. } => "mtls_trust_anchor.deleted",
            Self::IdentityProviderCreated { .. } => "identity_provider.created",
            Self::IdentityProviderUpdated { .. } => "identity_provider.updated",
            Self::IdentityProviderDeleted { .. } => "identity_provider.deleted",
            Self::IdentityLinked { .. } => "identity.linked",
            Self::IdentityUnlinked { .. } => "identity.unlinked",
            Self::BrokeredLogin { .. } => "login.brokered",
            Self::UpstreamLogout { .. } => "logout.upstream",
            Self::DirectorySynced { .. } => "directory.synced",
            Self::PersonalTokenCreated { .. } => "personal_token.created",
            Self::PersonalTokenRevoked { .. } => "personal_token.revoked",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serializes_with_tagged_kind() {
        let e = Event::new(
            Some(Uuid::nil()),
            Actor::System,
            EventKind::UserCreated {
                user_id: Uuid::nil(),
            },
        );
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["kind"]["type"], "user_created");
        assert_eq!(json["actor"]["type"], "system");
        assert_eq!(e.name(), "user.created");
        let back: Event = serde_json::from_value(json).unwrap();
        assert_eq!(back, e);
    }
}
