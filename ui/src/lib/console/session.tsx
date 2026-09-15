"use client";

import { useCallback, useEffect, useMemo, useState, useSyncExternalStore, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createAdminClient, type AdminClient, type Schemas } from "@api/client";
import { API_BASE } from "@/lib/api";
import {
  clearSession,
  isExpiring,
  loadSession,
  logoutUrl,
  refreshSession,
  startLogin,
  type StoredSession,
} from "./auth";
import { hasPermission } from "./permissions";

export type Me = Schemas["Me"];

export type SessionStatus = "loading" | "signed_out" | "signed_in";

export interface Snapshot {
  status: SessionStatus;
  session: StoredSession | null;
  /** Who is signed in, once `/admin/me` answered. */
  me: Me | null;
  /** Why the last session ended, shown on the sign-in card. */
  notice: string | null;
}

const LOADING: Snapshot = { status: "loading", session: null, me: null, notice: null };

/**
 * The console's session, outside React: the API client's token getter runs
 * inside fetches, a refresh must be shared by every request that needs one,
 * and components read it through `useSyncExternalStore` so a page that
 * hydrates after the session was restored still matches its server HTML.
 */
class SessionStore {
  private session: StoredSession | null = null;
  private me: Me | null = null;
  private notice: string | null = null;
  private restored = false;
  private snap: Snapshot = LOADING;
  private refreshing: Promise<StoredSession> | null = null;
  private listeners = new Set<() => void>();

  subscribe = (cb: () => void): (() => void) => {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  };

  snapshot = (): Snapshot => this.snap;
  serverSnapshot = (): Snapshot => LOADING;

  private emit() {
    const status: SessionStatus = !this.restored ? "loading" : !this.session ? "signed_out" : this.me ? "signed_in" : "loading";
    this.snap = { status, session: this.session, me: this.session ? this.me : null, notice: this.notice };
    this.listeners.forEach((l) => l());
  }

  current(): StoredSession | null {
    return this.session;
  }

  set(session: StoredSession) {
    this.session = session;
    this.emit();
  }

  identify(me: Me) {
    this.me = me;
    this.emit();
  }

  markRestored() {
    this.restored = true;
    this.emit();
  }

  end(why: string | null) {
    this.session = null;
    this.me = null;
    this.notice = why;
    clearSession();
    this.emit();
  }

  /** A valid access token, refreshing (once, shared) when it is about to expire. */
  async token(): Promise<string | null> {
    const s = this.session;
    if (!s) return null;
    if (!isExpiring(s) || !s.refresh_token) return s.access_token;
    this.refreshing ??= refreshSession(s).finally(() => {
      this.refreshing = null;
    });
    try {
      const next = await this.refreshing;
      this.set(next);
      return next.access_token;
    } catch {
      this.end("Your session has expired. Sign in again.");
      return null;
    }
  }

  /** A 401 despite a fresh-looking token: refresh once, otherwise the session is gone. */
  unauthorized() {
    const s = this.session;
    if (!s) return;
    this.session = { ...s, expires_at: 0 };
    void this.token();
  }
}

export const sessionStore = new SessionStore();

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

export interface ConsoleSession extends Snapshot {
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
