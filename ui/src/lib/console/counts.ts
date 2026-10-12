"use client";

import { useQuery } from "@tanstack/react-query";
import type { NavCountKey } from "./nav";
import { useConsole } from "./session";

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
 * The sidebar's counts and attention badges. They ride on the tenant's
 * statistics (one cached call the overview makes too, so the key is shared
 * and the request is not repeated), and only for administrators who may
 * read them.
 */
export function useNavCounts(tenant: string | null): NavCounts {
  const { client, can } = useConsole();
  const stats = useQuery({
    queryKey: ["stats", tenant, 30],
    enabled: Boolean(tenant) && can("ridm:tenants:read"),
    staleTime: 60_000,
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/stats", { params: { path: { slug: tenant! }, query: { days: 30 } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const s = stats.data;
  if (!s) return NONE;
  return { counts: { users: s.users.total }, attention: {}, attentionTotal: 0 };
}
