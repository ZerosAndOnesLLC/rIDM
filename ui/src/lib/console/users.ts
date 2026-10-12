// Shared shapes and helpers for the users pages.

import type { Schemas } from "@api/client";

export type User = Schemas["User"];
export type UserDetail = Schemas["UserDetail"];
export type UserUpdate = Schemas["UserUpdate"];
export type UserStatus = Schemas["UserStatus"];
export type ProfileSchema = Schemas["ProfileSchema"];
export type AttributeDef = Schemas["AttributeDef"];
export type Role = Schemas["Role"];
export type Group = Schemas["Group"];
export type Invitation = Schemas["Invitation"];

export const STATUS_LABELS: Record<UserStatus, string> = {
  active: "Active",
  disabled: "Disabled",
  locked: "Locked",
  pending: "Pending",
  deleted: "Deleted",
};

export function statusTone(s: UserStatus): "ok" | "danger" | "neutral" | "accent" {
  switch (s) {
    case "active":
      return "ok";
    case "disabled":
    case "deleted":
      return "danger";
    case "locked":
      return "accent";
    default:
      return "neutral";
  }
}

export function userHref(tenant: string, id: string, tab?: string): string {
  const q = new URLSearchParams({ tenant, user: id });
  if (tab) q.set("tab", tab);
  return `/console/users/?${q}`;
}

export const TABS = ["profile", "security", "sessions", "roles", "groups", "consents", "audit"] as const;
export type Tab = (typeof TABS)[number];
export const TAB_LABELS: Record<Tab, string> = {
  profile: "Profile",
  security: "Password & credentials",
  sessions: "Sessions & devices",
  roles: "Roles",
  groups: "Groups",
  consents: "Consents",
  audit: "Audit",
};

/**
 * What a person is called, from the profile attributes a tenant's schema
 * commonly carries (`name`, or given and family names); null when none.
 */
export function displayName(u: Pick<User, "attributes">): string | null {
  const a = (u.attributes ?? {}) as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === "string" && v.trim() ? v.trim() : null);
  const name = str(a.name) ?? str(a.display_name) ?? str(a.full_name);
  if (name) return name;
  const parts = [str(a.given_name) ?? str(a.first_name), str(a.family_name) ?? str(a.last_name)].filter(Boolean);
  return parts.length ? parts.join(" ") : null;
}

/** A role's display name: `client/name` for client-scoped roles. */
export function roleName(r: Role, clientNames: Record<string, string> = {}): string {
  return r.client_id ? `${clientNames[r.client_id] ?? "client"}/${r.name}` : r.name;
}

/** Text form of an attribute value for an input. */
export function attrToText(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v, null, 2);
}
