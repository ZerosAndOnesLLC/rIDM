"use client";

import { useQuery } from "@tanstack/react-query";
import type { Schemas } from "@api/client";
import type { NavCountKey } from "./nav";
import { useConsole } from "./session";

export type TenantStats = Schemas["TenantStats"];

export interface NavCounts {
  /** How many of each there are, for the sidebar. */
  counts: Partial<Record<NavCountKey, number>>;
  /** Things waiting on the administrator, by sidebar entry ("3 pending"). */
  attention: Partial<Record<NavCountKey, number>>;
  /** Everything that needs attention, for the bell. */
  attentionTotal: number;
}

const NONE: NavCounts = { counts: {}, attention: {}, attentionTotal: 0 };

/**
 * The tenant's statistics: the overview's numbers, and with them the shell's
 * sidebar counts, attention badges and the newest events. One cached call
 * (the server keeps it a minute), shared by key between the shell and the
 * overview, and only for administrators who may read it.
 */
export function useTenantStats(tenant: string | null, days = 30) {
  const { client, can } = useConsole();
  return useQuery({
    queryKey: ["stats", tenant, days],
    enabled: Boolean(tenant) && can("ridm:tenants:read"),
    staleTime: 60_000,
    refetchInterval: 60_000,
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/stats", { params: { path: { slug: tenant! }, query: { days } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
}

/** The sidebar's counts and attention badges, from the tenant statistics. */
export function useNavCounts(tenant: string | null): NavCounts {
  const stats = useTenantStats(tenant);
  const s = stats.data;
  if (!s) return NONE;
  const attention: NavCounts["attention"] = {};
  if (s.attention.open_invitations > 0) attention.users = s.attention.open_invitations;
  if (s.attention.expiring_keys.length > 0) attention.keys = s.attention.expiring_keys.length;
  if (s.attention.dead_deliveries > 0) attention.webhooks = s.attention.dead_deliveries;
  return {
    counts: { users: s.counts.users, groups: s.counts.groups, clients: s.counts.clients, webhooks: s.counts.webhooks, keys: s.counts.keys, idps: s.counts.idps },
    attention,
    attentionTotal: s.attention_total,
  };
}
