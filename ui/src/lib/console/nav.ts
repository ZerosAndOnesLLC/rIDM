// The console's navigation. Every entry names the permission it needs, so
// the sidebar and the command palette only show what the administrator can
// actually open. Entries are added as their pages land.

import { AppWindow, Building2, FolderTree, KeySquare, LayoutDashboard, Server, Settings2, ShieldCheck, Tags, UsersRound, type LucideIcon } from "lucide-react";

export interface NavItem {
  label: string;
  /** Console path, always with its trailing slash; the tenant is appended as a query parameter. */
  href: string;
  icon: LucideIcon;
  /** `ridm:<resource>:<action>` needed to open the page; none means every administrator. */
  permission?: string;
  /** Second key of the `g` then `<key>` shortcut. */
  key?: string;
  /** Only meaningful for global administrators (signed in through `master`). */
  global?: boolean;
}

export interface NavGroup {
  title: string | null;
  items: NavItem[];
}

export const NAV: NavGroup[] = [
  {
    title: null,
    items: [{ label: "Overview", href: "/console/", icon: LayoutDashboard, key: "o" }],
  },
  {
    title: "Identity",
    items: [
      { label: "Users", href: "/console/users/", icon: UsersRound, permission: "ridm:users:read", key: "u" },
      { label: "Groups", href: "/console/groups/", icon: FolderTree, permission: "ridm:groups:read", key: "g" },
      { label: "Roles", href: "/console/roles/", icon: ShieldCheck, permission: "ridm:roles:read", key: "r" },
    ],
  },
  {
    title: "Applications",
    items: [
      { label: "Clients", href: "/console/clients/", icon: AppWindow, permission: "ridm:clients:read", key: "c" },
      { label: "Resource servers", href: "/console/resource-servers/", icon: Server, permission: "ridm:resource-servers:read", key: "a" },
      { label: "Scopes", href: "/console/scopes/", icon: Tags, permission: "ridm:scopes:read", key: "p" },
      { label: "Claim mappers", href: "/console/claim-mappers/", icon: KeySquare, permission: "ridm:mappers:read", key: "m" },
    ],
  },
  {
    title: "Tenant",
    items: [
      { label: "Tenants", href: "/console/tenants/", icon: Building2, permission: "ridm:tenants:read", key: "t" },
      { label: "Settings", href: "/console/settings/", icon: Settings2, permission: "ridm:tenants:read", key: "s" },
    ],
  },
];

/** Titles of console pages that are not navigation entries. */
export const PAGE_TITLES: Record<string, string> = {
  "/console/playground/": "Playground",
};

export function allNavItems(): NavItem[] {
  return NAV.flatMap((g) => g.items);
}

/** `href` with the current tenant carried along; other parameters are dropped. */
export function consoleHref(href: string, tenant: string | null): string {
  return tenant ? `${href}?tenant=${encodeURIComponent(tenant)}` : href;
}
