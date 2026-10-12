"use client";

import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { api, tenantBase } from "@/lib/api";
import type { PublicTenant } from "@/lib/types";
import { applyAppearance, resetAppearance } from "./appearance";

/**
 * Makes the console look like the tenant it administers: loads that tenant's
 * public branding document (cheap, cached by the server for a minute) and
 * applies its appearance while the slug is current.
 */
export function useTenantAppearance(slug: string | null): void {
  const q = useQuery({
    queryKey: ["public-branding", slug],
    enabled: Boolean(slug),
    staleTime: 60_000,
    queryFn: () => api<PublicTenant>(`${tenantBase(slug!)}/branding`),
  });
  const branding = q.data?.branding;
  useEffect(() => {
    if (!slug || !branding) return;
    applyAppearance(document.documentElement, branding, slug);
    return () => resetAppearance(document.documentElement);
  }, [slug, branding]);
}
