// Shared shapes and helpers for the tenant settings editor.

import type { Schemas } from "@api/client";
import { mergePatches } from "./autosave";

export type Tenant = Schemas["Tenant"];
export type TenantSettings = Schemas["TenantSettings"];
/** What the console sends to `PATCH /admin/tenants/{slug}`: any subset of the fields. */
export interface TenantPatch {
  display_name?: string;
  status?: "active" | "disabled";
  settings?: SettingsPatch;
}
export type TenantPatchBody = Schemas["TenantPatch"];

/** A merge patch over `settings`, typed loosely: any subset, `null` resets a field to its default. */
export type SettingsPatch = { [K in keyof TenantSettings]?: Partial<TenantSettings[K]> | null | Record<string, unknown> };

/** Apply a settings merge patch to a draft tenant (what the server will store, minus defaults). */
export function applySettings(draft: Tenant, patch: SettingsPatch): Tenant {
  return { ...draft, settings: mergePatches(draft.settings, patch) as TenantSettings };
}

export const GRANTS: { value: string; label: string }[] = [
  { value: "authorization_code", label: "Authorization code" },
  { value: "refresh_token", label: "Refresh token" },
  { value: "client_credentials", label: "Client credentials" },
  { value: "urn:ietf:params:oauth:grant-type:device_code", label: "Device code" },
  { value: "urn:ietf:params:oauth:grant-type:token-exchange", label: "Token exchange" },
];

export const SIGNING_ALGS = ["RS256", "RS384", "RS512", "ES256", "EdDSA"] as const;
export const RSA_BITS = [
  { value: "B2048", label: "2048 bits" },
  { value: "B3072", label: "3072 bits" },
  { value: "B4096", label: "4096 bits" },
] as const;

export function isHttpUrl(v: string): boolean {
  try {
    const u = new URL(v);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

/** Tenant slug rule shared with the API (`is_valid_slug`). */
export function isValidSlug(v: string): boolean {
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(v);
}

/** Sections of the settings page, in order; ids double as anchors. */
export const SECTIONS: { id: string; label: string }[] = [
  { id: "general", label: "General" },
  { id: "signin", label: "Sign-in" },
  { id: "profile", label: "Profile attributes" },
  { id: "passwords", label: "Passwords & lockout" },
  { id: "ratelimits", label: "Rate limits" },
  { id: "sessions", label: "Sessions & tokens" },
  { id: "branding", label: "Branding" },
  { id: "locale", label: "Locale & notices" },
  { id: "advanced", label: "Keys, discovery & audit" },
];
