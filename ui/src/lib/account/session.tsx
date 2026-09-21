"use client";

import { useCallback, useEffect, useMemo, useState, useSyncExternalStore, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createAdminClient, type AdminClient, type Problem, type Schemas } from "@api/client";
import { API_BASE } from "@/lib/api";
import { createAuth, type AuthApp, type LoginOptions } from "@/lib/console/auth";
import { SessionStore, type Snapshot } from "@/lib/session-store";

export type AccountMe = Schemas["AccountMe"];

/** The account console signs in through the built-in client every tenant carries. */
export const ACCOUNT_APP: AuthApp = { clientId: "ridm-account-console", base: "/account/", storage: "ridm.account" };
export const accountAuth = createAuth(ACCOUNT_APP);
export const accountStore = new SessionStore<AccountMe>(accountAuth);

/** The typed client every account page uses (the account routes are in the same document as the admin API). */
export const accountClient: AdminClient = createAdminClient({
  baseUrl: API_BASE,
  getToken: () => accountStore.token(),
  onUnauthorized: () => accountStore.unauthorized(),
});

/** Re-read `/account/me` after a change to the identity it shows (email, phone). */
export async function refreshMe(): Promise<void> {
  const s = accountStore.current();
  if (!s) return;
  const { data } = await accountClient.GET("/t/{slug}/account/me", { params: { path: { slug: s.tenant } } });
  if (data) accountStore.identify(data);
}

export const REAUTH_TYPE = "urn:ridm:error:reauthentication-required";
export const MFA_ACR = "urn:ridm:acr:mfa";

/** A security change the API refused until the user signs in again. */
export function needsReauth(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && (error as Problem).type === REAUTH_TYPE);
}

/** Restores this tab's session and confirms it with `/account/me`. */
export function AccountProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    const restore = async () => {
      // Arriving from an impersonation ticket: whoever this tab was signed
      // in as before, it signs in again through the new session.
      if (new URLSearchParams(window.location.search).get("impersonate") === "1") accountAuth.clearSession();
      const s = accountAuth.loadSession();
      if (s) {
        accountStore.set(s);
        const { data, response } = await accountClient.GET("/t/{slug}/account/me", { params: { path: { slug: s.tenant } } });
        if (data) {
          accountStore.identify(data);
        } else if (response.status === 401) {
          accountStore.end("Your session has ended. Sign in again.");
        } else {
          accountStore.end("The server could not be reached. Try again.");
        }
      }
      accountStore.markRestored();
    };
    void restore();
  }, []);

  const [queryClient] = useState(() => new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 10_000, refetchOnWindowFocus: false } } }));
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

export interface AccountSession extends Snapshot<AccountMe> {
  client: AdminClient;
  /** The tenant slug of the session, for the typed routes. */
  slug: string;
  signIn: (tenant: string, returnTo?: string, options?: LoginOptions) => Promise<void>;
  signOut: () => void;
  /** Sign in again (with the second step when `mfa`) and come back to this page. */
  reauth: (mfa: boolean) => Promise<void>;
}

export function useAccount(): AccountSession {
  const snap = useSyncExternalStore(accountStore.subscribe, accountStore.snapshot, accountStore.serverSnapshot);
  const here = () => `${window.location.pathname}${window.location.search}`;

  const signIn = useCallback(async (tenant: string, returnTo?: string, options?: LoginOptions) => {
    await accountAuth.startLogin(tenant, returnTo ?? here(), options);
  }, []);

  const signOut = useCallback(() => {
    const s = accountStore.current();
    accountStore.end(null);
    if (s) window.location.assign(accountAuth.logoutUrl(s));
  }, []);

  const reauth = useCallback(async (mfa: boolean) => {
    const s = accountStore.current();
    if (!s) return;
    await accountAuth.startLogin(s.tenant, here(), { max_age: 0, acr_values: mfa ? MFA_ACR : undefined });
  }, []);

  const slug = snap.session?.tenant ?? "";
  return useMemo(() => ({ ...snap, client: accountClient, slug, signIn, signOut, reauth }), [snap, slug, signIn, signOut, reauth]);
}
