// Shapes for organizations, their members and their email domains.

import type { Schemas } from "@api/client";

export type Organization = Schemas["Organization"];
export type OrganizationDetail = Schemas["OrganizationDetail"];
export type OrganizationDomain = Schemas["OrganizationDomain"];
export type RoleAssignment = Schemas["RoleAssignment"];

/** The DNS record a domain is proven with. */
export function challengeRecord(domain: OrganizationDomain): string {
  return `_ridm-challenge.${domain.domain}`;
}
