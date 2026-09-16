"use client";

import { useCallback, useEffect, useMemo, useState, useSyncExternalStore, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createAdminClient, type AdminClient, type Schemas } from "@api/client";
import { API_BASE } from "@/lib/api";
import { SessionStore, type Snapshot } from "@/lib/session-store";
import { consoleAuth, loadSession, logoutUrl, startLogin } from "./auth";
import { hasPermission } from "./permissions";

export type Me = Schemas["Me"];

export type { SessionStatus, Snapshot } from "@/lib/session-store";

export const sessionStore = new SessionStore<Me>(consoleAuth);

/** The typed admin client every console page uses. */
export const adminClient: AdminClient = createAdminClient({
  baseUrl: API_BASE,
  getToken: () => sessionStore.token(),
  onUnauthorized: () => sessionStore.unauthorized(),
});

/**
 * Restores this tab's session and confirms it with `/admin/me`. A session
 * the API rejects (revoked, role removed) drops back to the sign-in card
 * with a notice.
 */
export function ConsoleProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    const restore = async () => {
      const s = loadSession();
      if (s) {
        sessionStore.set(s);
        const { data, response } = await adminClient.GET("/admin/me");
        if (data) {
          sessionStore.identify(data);
        } else if (response.status === 403) {
          sessionStore.end("This account has no administrator permissions.");
        } else if (response.status === 401) {
          sessionStore.end("Your session has ended. Sign in again.");
        } else {
          sessionStore.end("The server could not be reached. Try again.");
        }
      }
      sessionStore.markRestored();
    };
    void restore();
  }, []);

  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: { queries: { retry: 1, staleTime: 15_000, refetchOnWindowFocus: false } },
      }),
  );

  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

export interface ConsoleSession extends Snapshot<Me> {
  client: AdminClient;
  signIn: (tenant: string, returnTo?: string) => Promise<void>;
  signOut: () => void;
  can: (permission: string | undefined) => boolean;
}

export function useConsole(): ConsoleSession {
  const snap = useSyncExternalStore(sessionStore.subscribe, sessionStore.snapshot, sessionStore.serverSnapshot);

  const signIn = useCallback(async (tenant: string, returnTo?: string) => {
    await startLogin(tenant, returnTo ?? `${window.location.pathname}${window.location.search}`);
  }, []);

  const signOut = useCallback(() => {
    const s = sessionStore.current();
    sessionStore.end(null);
    if (s) window.location.assign(logoutUrl(s));
  }, []);

  const me = snap.me;
  const can = useCallback((permission: string | undefined) => hasPermission(me?.permissions ?? [], permission), [me]);

  return useMemo(() => ({ ...snap, client: adminClient, signIn, signOut, can }), [snap, signIn, signOut, can]);
}
