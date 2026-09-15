"use client";

import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
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
