"use client";

import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useState } from "react";
import { useConsole } from "./session";

/** `value`, settled for `ms` (search boxes that hit the API). */
export function useDebounced(value: string, ms: number): string {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = window.setTimeout(() => setV(value), ms);
    return () => window.clearTimeout(t);
  }, [value, ms]);
  return v;
}

/** The tenant's scopes (small list, cached a minute). */
export function useScopes(tenant: string | null) {
  const { client } = useConsole();
  return useQuery({
    queryKey: ["scopes", tenant],
    enabled: Boolean(tenant),
    staleTime: 60_000,
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/scopes", { params: { path: { slug: tenant! } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
}

/** The tenant's resource servers (audiences). */
export function useResourceServers(tenant: string | null) {
  const { client } = useConsole();
  return useQuery({
    queryKey: ["resource-servers", tenant],
    enabled: Boolean(tenant),
    staleTime: 60_000,
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/resource-servers", { params: { path: { slug: tenant! } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
}

/** Every client of the tenant by id → name, for labels and pickers. Pages
 * through the whole list (no silent cut-off) at the API's largest page, one
 * page after another (each cursor comes from the page before), cached a
 * minute. */
export function useClientNames(tenant: string) {
  const { client } = useConsole();
  return useQuery({
    queryKey: ["clients", tenant, "names"],
    staleTime: 60_000,
    queryFn: async () => {
      const names: Record<string, string> = {};
      let cursor: string | undefined;
      do {
        const { data, error } = await client.GET("/admin/tenants/{slug}/clients", { params: { path: { slug: tenant }, query: { limit: 500, cursor } } });
        if (error) throw new Error(error.detail ?? error.title);
        for (const c of data.items) names[c.id] = c.name;
        cursor = data.next_cursor ?? undefined;
      } while (cursor);
      return names;
    },
  });
}

/**
 * Stable React keys for an editable list whose rows have no id of their own
 * (an index key would hand one row's input state to the next when a row is
 * removed). Rows added at the end get new keys; call `removeKey(i)` together
 * with removing row `i`.
 */
export function useRowKeys(count: number): { keys: number[]; removeKey: (i: number) => void } {
  const [state, setState] = useState(() => ({ keys: Array.from({ length: count }, (_, i) => i), next: count }));
  let keys = state.keys;
  if (keys.length !== count) {
    const added = Math.max(0, count - keys.length);
    keys = added ? [...keys, ...Array.from({ length: added }, (_, i) => state.next + i)] : keys.slice(0, count);
    setState({ keys, next: state.next + added });
  }
  const removeKey = useCallback((i: number) => setState((s) => ({ ...s, keys: s.keys.filter((_, j) => j !== i) })), []);
  return { keys, removeKey };
}
