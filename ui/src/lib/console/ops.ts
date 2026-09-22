// Shared shapes for keys, audit, webhooks, IP rules and messaging.

import type { Schemas } from "@api/client";
import { tenantBase } from "@/lib/api";
import { sessionStore } from "./session";

export type SigningKey = Schemas["SigningKey"];
export type KeyStatus = Schemas["KeyStatus"];
export type AuditEvent = Schemas["AuditEvent"];
export type Webhook = Schemas["Webhook"];
export type WebhookDelivery = Schemas["WebhookDelivery"];
export type IpRule = Schemas["IpRule"];
export type MtlsTrustAnchor = Schemas["MtlsTrustAnchor"];
export type ScimToken = Schemas["ScimToken"];
export type InitialAccessToken = Schemas["InitialAccessToken"];
export type TemplateView = Schemas["TemplateView"];
export type LogEntry = Schemas["LogEntry"];
export type IdentityProvider = Schemas["IdentityProviderView"];
export type IdentityProviderPatch = Partial<Schemas["IdentityProviderUpdate"]>;
export type IdpPreset = Schemas["Preset"];
export type SamlUpstream = Schemas["SamlUpstream"];
export type SamlUpstreamSettings = Schemas["SamlUpstreamSettings"];
export type LdapUpstream = Schemas["LdapUpstream"];
export type LdapSettings = Schemas["LdapSettings"];
export type LdapSyncStats = Schemas["LdapSyncStats"];
export type LdapTestReport = Schemas["TestReport"];
export type KerberosUpstream = Schemas["KerberosUpstream"];
export type KerberosSettings = Schemas["KerberosSettings"];
export type KeytabReport = Schemas["KeytabReport"];
export type SamlIdp = Schemas["IdpView"];
export type SamlKey = Schemas["SamlKeyView"];
export type SamlSp = Schemas["SamlSpView"];
export type SamlSpInput = Schemas["SamlSpInput"];
export type SamlAttribute = Schemas["SamlAttribute"];

export function href(page: string, tenant: string, params: Record<string, string> = {}): string {
  return `/console/${page}/?${new URLSearchParams({ tenant, ...params })}`;
}

/** Every event name the server emits (mirrors `ridm_core::events::EventKind::name`). */
export const EVENT_NAMES = [
  "audit.chain_broken", "authorization.granted", "backchannel.denied", "backchannel.requested",
  "claim_mapper.created", "claim_mapper.deleted", "claim_mapper.updated",
  "client.created", "client.deleted", "client.secret_rotated", "client.updated",
  "consent.granted", "consent.revoked", "device.revoked", "device.trusted",
  "directory.synced",
  "group.created", "group.deleted", "group.member_added", "group.member_removed", "group.updated",
  "organization.created", "organization.deleted", "organization.domain_added", "organization.domain_removed",
  "organization.domain_verified", "organization.member_added", "organization.member_removed", "organization.updated",
  "identity.linked", "identity.unlinked",
  "identity_provider.created", "identity_provider.deleted", "identity_provider.updated",
  "impersonation.ended", "impersonation.requested", "impersonation.started",
  "invitation.accepted", "invitation.created", "invitation.revoked",
  "login.brokered", "login.failed", "login.new_device", "login.passwordless_sent", "login.succeeded",
  "logout.upstream",
  "master_key.rotated", "mfa.changed", "mtls_trust_anchor.created", "mtls_trust_anchor.deleted",
  "risk.blocked", "risk.step_up",
  "saml_key.created", "saml_key.status_changed",
  "role.assigned", "role.composite_added", "role.composite_removed", "role.created", "role.deleted", "role.unassigned", "role.updated",
  "scope.created", "scope.deleted", "scope.updated",
  "session.created", "session.revoked", "signing_key.created", "signing_key.status_changed",
  "system.bootstrapped", "tenant.created", "tenant.deleted", "tenant.profile_schema_updated", "tenant.updated",
  "token.refresh_reuse_detected", "token.revoked",
  "user.created", "user.deleted", "user.email_changed", "user.email_verified", "user.locked",
  "user.password_changed", "user.password_hash_upgraded", "user.password_reset_completed", "user.password_reset_requested",
  "user.registered", "user.terms_accepted", "user.updated",
];

/** `user.*`, `client.*`, … for webhook patterns. */
export const EVENT_PREFIXES = [...new Set(EVENT_NAMES.map((n) => `${n.split(".")[0]}.*`))];

export function adminBase(): string {
  return tenantBase("x").replace(/\/t\/x$/, "");
}

/** Fetch a file through the console's token and hand it to the browser. */
export async function downloadWithToken(path: string, filename: string): Promise<void> {
  const token = await sessionStore.token();
  const res = await fetch(`${adminBase()}${path}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as { detail?: string; title?: string } | null;
    throw new Error(body?.detail ?? body?.title ?? `Download failed (${res.status}).`);
  }
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/** `datetime-local` value → RFC 3339 with `Z` (the API rejects `+00:00`). */
export function toRfc3339(local: string): string | undefined {
  if (!local) return undefined;
  const d = new Date(local);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}
