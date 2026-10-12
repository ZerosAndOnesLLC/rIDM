"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useSyncExternalStore, type ReactNode } from "react";
import { DEFAULT_POLICY, cachedPolicy, effectiveTheme, getPolicy, setPolicy, subscribePolicy, type Policy, type Theme } from "./appearance";

export type { Theme };
const KEY = "ridm.theme";

interface ThemeState {
  /** The person's own choice; "system" when they made none. */
  theme: Theme;
  setTheme: (t: Theme) => void;
  /** The tenant's light/dark policy, which decides whether the choice applies. */
  policy: Policy;
}

const ThemeContext = createContext<ThemeState | null>(null);

// The stored choice is external state: read it through a store so the
// prerendered "system" hydrates cleanly and every tab follows a change.
const listeners = new Set<() => void>();
function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  const onStorage = (e: StorageEvent) => {
    if (e.key === KEY) cb();
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(cb);
    window.removeEventListener("storage", onStorage);
  };
}
function snapshot(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}
const serverSnapshot = (): Theme => "system";

let policyPrimed = false;
function policySnapshot(): Policy {
  if (!policyPrimed) {
    // Before the tenant document arrives, start from what the boot script
    // restored, so the first render does not undo it.
    policyPrimed = true;
    setPolicy(cachedPolicy());
  }
  return getPolicy();
}
const policyServerSnapshot = (): Policy => DEFAULT_POLICY;

/**
 * Light / dark / follow-the-device. The person's choice is kept per browser;
 * the tenant's policy (src/lib/theme/appearance.ts) says whether it applies.
 * The result is `data-theme` on <html>, which only pins `color-scheme`: the
 * stylesheet writes every colour as `light-dark()`, so an absent attribute
 * means the device decides. The root layout restores the attribute before
 * the first paint so there is no flash. Mounted once, in the root layout.
 */
export function ThemeProvider({ children }: { children: ReactNode }) {
  const theme = useSyncExternalStore(subscribe, snapshot, serverSnapshot);
  const policy = useSyncExternalStore(subscribePolicy, policySnapshot, policyServerSnapshot);

  useEffect(() => {
    const eff = effectiveTheme(theme, policy);
    if (eff) document.documentElement.dataset.theme = eff;
    else delete document.documentElement.dataset.theme;
  }, [theme, policy]);

  const setTheme = useCallback((t: Theme) => {
    try {
      if (t === "system") localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, t);
    } catch {
      // Storage blocked: the choice lasts for this page only.
    }
    listeners.forEach((l) => l());
  }, []);

  const value = useMemo(() => ({ theme, setTheme, policy }), [theme, setTheme, policy]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeState {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used inside <ThemeProvider>");
  return ctx;
}
