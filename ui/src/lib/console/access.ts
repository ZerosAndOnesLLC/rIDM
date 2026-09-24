// Shared shapes for groups, roles, resource servers, scopes and mappers.

import type { Schemas } from "@api/client";

export type Group = Schemas["Group"];
export type GroupDetail = Schemas["GroupDetail"];
export type Member = Schemas["Member"];
export type RoleHolder = Schemas["RoleHolder"];
export type Role = Schemas["Role"];
export type RoleDetail = Schemas["RoleDetail"];
export type Permission = Schemas["Permission"];
export type ResourceServer = Schemas["ResourceServer"];
export type ResourceServerDetail = Schemas["ResourceServerDetail"];
export type Scope = Schemas["Scope"];
export type ClaimMapperRow = Schemas["ClaimMapperRow"];

export function href(page: string, tenant: string, params: Record<string, string> = {}): string {
  const q = new URLSearchParams({ tenant, ...params });
  return `/console/${page}/?${q}`;
}

/** Group id → `parent / child` path. */
export function groupPaths(groups: Group[]): Map<string, string> {
  const byId = new Map(groups.map((g) => [g.id, g]));
  const cache = new Map<string, string>();
  const pathOf = (id: string, depth = 0): string => {
    const hit = cache.get(id);
    if (hit) return hit;
    const g = byId.get(id);
    if (!g) return id;
    const p = g.parent_id && depth < 32 ? `${pathOf(g.parent_id, depth + 1)} / ${g.name}` : g.name;
    cache.set(id, p);
    return p;
  };
  for (const g of groups) pathOf(g.id);
  return cache;
}

export type MapperType = "user_attribute" | "groups" | "roles" | "hardcoded" | "template" | "audience";
export const MAPPER_TYPES: { value: MapperType; label: string; blurb: string }[] = [
  { value: "user_attribute", label: "User attribute", blurb: "Copy a user field or profile attribute into a claim." },
  { value: "groups", label: "Groups", blurb: "Names (or paths) of the user's effective groups." },
  { value: "roles", label: "Roles", blurb: "Names of the user's effective roles." },
  { value: "hardcoded", label: "Fixed value", blurb: "The same value for everyone." },
  { value: "template", label: "Template", blurb: "A Handlebars template over user, tenant, client, roles and groups." },
  { value: "audience", label: "Audience", blurb: "An extra audience on access tokens." },
];

export interface MapperConfig {
  type: MapperType;
  include_in: ("access" | "id" | "userinfo")[];
  claim?: string;
  attribute?: string;
  json_type?: "string" | "number" | "boolean" | "json";
  full_path?: boolean;
  client_id?: string | null;
  value?: unknown;
  template?: string;
  audience?: string;
}

export function defaultMapper(type: MapperType): MapperConfig {
  switch (type) {
    case "user_attribute":
      return { type, include_in: ["id", "userinfo"], attribute: "attributes.department", claim: "department", json_type: "string" };
    case "groups":
      return { type, include_in: ["access", "id"], claim: "groups", full_path: false };
    case "roles":
      return { type, include_in: ["access"], claim: "roles", client_id: null };
    case "hardcoded":
      return { type, include_in: ["id", "userinfo"], claim: "tier", value: "standard" };
    case "template":
      return { type, include_in: ["id"], claim: "display", template: "{{user.username}}" };
    case "audience":
      return { type, include_in: ["access"], audience: "https://api.example.com" };
  }
}
