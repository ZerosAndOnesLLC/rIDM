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

/** A role's display name: `client/name` for client-scoped roles. */
export function roleName(r: Role, clientNames: Record<string, string> = {}): string {
  return r.client_id ? `${clientNames[r.client_id] ?? "client"}/${r.name}` : r.name;
}

/** Human summary of a user agent string. */
export function describeAgent(ua: string | null | undefined): string {
  if (!ua) return "Unknown browser";
  const browser = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : ua.split(" ")[0] ?? "Browser";
  const os = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : null;
  return os ? `${browser} on ${os}` : browser;
}

/** Text form of an attribute value for an input. */
export function attrToText(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v, null, 2);
}
