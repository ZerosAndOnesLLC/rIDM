"use client";

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, ApiError, tenantBase } from "./api";
import type { PublicTenant } from "./types";

interface TenantState {
  slug: string | null;
  tenant: PublicTenant | null;
  /** `missing` (no ?tenant=), `unknown` (404), `error`, or null while fine. */
  problem: "missing" | "unknown" | "error" | null;
  loading: boolean;
}

const TenantContext = createContext<TenantState | null>(null);

/**
 * Loads the tenant's public branding document and applies its theme:
 * accent and ground colours as CSS variables, favicon, and custom CSS.
 */
export function TenantProvider({ slug, children }: { slug: string | null; children: ReactNode }) {
  const [state, setState] = useState<TenantState>({
    slug,
    tenant: null,
    problem: slug ? null : "missing",
    loading: Boolean(slug),
  });

  useEffect(() => {
    if (!slug) return;
    const ctrl = new AbortController();
    api<PublicTenant>(`${tenantBase(slug)}/branding`, { signal: ctrl.signal })
      .then((tenant) => setState({ slug, tenant, problem: null, loading: false }))
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === "AbortError") return;
        const problem = e instanceof ApiError && e.status === 404 ? "unknown" : "error";
        setState({ slug, tenant: null, problem, loading: false });
      });
    return () => ctrl.abort();
  }, [slug]);

  useEffect(() => {
    const b = state.tenant?.branding;
    if (!b) return;
    const root = document.documentElement;
    if (b.primary_color && isColor(b.primary_color)) root.style.setProperty("--accent", b.primary_color);
    if (b.background_color && isColor(b.background_color)) {
      root.style.setProperty("--ground", b.background_color);
    }
    if (b.favicon_url) {
      let link = document.querySelector<HTMLLinkElement>("link[rel='icon']");
      if (!link) {
        link = document.createElement("link");
        link.rel = "icon";
        document.head.appendChild(link);
      }
      link.href = b.favicon_url;
    }
    let style = document.getElementById("tenant-css") as HTMLStyleElement | null;
    if (b.custom_css) {
      if (!style) {
        style = document.createElement("style");
        style.id = "tenant-css";
        document.head.appendChild(style);
      }
      style.textContent = b.custom_css;
    } else {
      style?.remove();
    }
    if (state.tenant) document.title = state.tenant.display_name;
  }, [state.tenant]);

  return <TenantContext.Provider value={state}>{children}</TenantContext.Provider>;
}

export function useTenant(): TenantState {
  const ctx = useContext(TenantContext);
  if (!ctx) throw new Error("useTenant must be used inside <TenantProvider>");
  return ctx;
}

/** Accept only CSS colour literals, never arbitrary values. */
function isColor(v: string): boolean {
  return /^(#[0-9a-f]{3,8}|(rgb|hsl|oklch|oklab|color)\([^;{}]*\))$/i.test(v.trim());
}
