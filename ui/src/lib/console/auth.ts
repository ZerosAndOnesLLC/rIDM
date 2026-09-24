// Sign-in for the bundled consoles: OIDC authorization code with PKCE
// against the tenant the user belongs to, using the built-in public client
// every tenant carries. Tokens live in this tab only (sessionStorage); the
// refresh token is rotated on every use and bound to the browser's SSO
// session, so signing out of the tenant ends console access as well.
//
// The admin console and the account console differ only in their client id,
// pages and storage keys: `createAuth` builds one bundle per console, and
// the named exports below are the admin console's.

import { tenantBase } from "@/lib/api";
import { navigate } from "@/lib/params";

export const CONSOLE_CLIENT_ID = "ridm-admin-console";
export const CONSOLE_SCOPES = "openid profile email";

/** What tells one console's sign-in from another's. */
export interface AuthApp {
  clientId: string;
  /** Path prefix of the console's pages, with slashes (`/console/`). */
  base: string;
  /** Prefix of the storage keys. */
  storage: string;
}

export const CONSOLE_APP: AuthApp = { clientId: CONSOLE_CLIENT_ID, base: "/console/", storage: "ridm.console" };

/** How long before expiry a token is refreshed rather than used. */
const REFRESH_MARGIN_MS = 30_000;

export interface StoredSession {
  tenant: string;
  access_token: string;
  /** Unix ms. */
  expires_at: number;
  refresh_token: string | null;
  id_token: string | null;
}

interface Pending {
  state: string;
  verifier: string;
  tenant: string;
  return_to: string;
}

interface TokenResponse {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
}

export class AuthError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

function storage(kind: "session" | "local"): Storage | null {
  try {
    return kind === "session" ? window.sessionStorage : window.localStorage;
  } catch {
    return null;
  }
}

function readJson<T>(kind: "session" | "local", key: string): T | null {
  try {
    const raw = storage(kind)?.getItem(key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    return null;
  }
}

function writeJson(kind: "session" | "local", key: string, value: unknown) {
  try {
    storage(kind)?.setItem(key, JSON.stringify(value));
  } catch {
    // Private mode or blocked storage: the session simply does not persist.
  }
}

function remove(kind: "session" | "local", key: string) {
  try {
    storage(kind)?.removeItem(key);
  } catch {
    // ignore
  }
}

function base64url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (const b of arr) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomToken(bytes = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function challengeOf(verifier: string): Promise<string> {
  // Browsers only offer Web Crypto on https and localhost.
  if (!globalThis.crypto?.subtle) {
    throw new AuthError("insecure_context", "Signing in needs a secure connection: open the console over https (or on localhost).");
  }
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(digest);
}

export function isExpiring(s: StoredSession, now = Date.now()): boolean {
  return s.expires_at - now < REFRESH_MARGIN_MS;
}

export function isValidSlug(slug: string): boolean {
  return /^[a-z0-9](?:[a-z0-9-]{0,62})$/.test(slug);
}


/** Extra `/authorize` parameters a sign-in may ask for (a step-up, a fresh sign-in). */
export interface LoginOptions {
  prompt?: "login";
  max_age?: number;
  acr_values?: string;
}

export interface AuthApi {
  app: AuthApp;
  home(): string;
  callbackUri(): string;
  loadSession(): StoredSession | null;
  saveSession(s: StoredSession): void;
  clearSession(): void;
  lastTenant(): string | null;
  startLogin(tenant: string, returnTo: string, options?: LoginOptions): Promise<void>;
  completeLogin(params: URLSearchParams): Promise<{ session: StoredSession; returnTo: string }>;
  refreshSession(s: StoredSession): Promise<StoredSession>;
  logoutUrl(s: StoredSession): string;
}

/** The sign-in bundle of one console. */
export function createAuth(app: AuthApp): AuthApi {
  const SESSION_KEY = `${app.storage}.session`;
  const PENDING_KEY = `${app.storage}.pending`;
  const LAST_TENANT_KEY = `${app.storage}.tenant`;
  const home = () => `${window.location.origin}${app.base}`;
  const callbackUri = () => `${window.location.origin}${app.base}callback/`;

  /** Only this console's pages on this origin are valid return targets. */
  function safeReturn(url: string): string {
    try {
      const u = new URL(url, window.location.origin);
      if (u.origin === window.location.origin && u.pathname.startsWith(app.base) && !u.pathname.startsWith(`${app.base}callback`)) {
        return u.pathname + u.search;
      }
    } catch {
      // fall through
    }
    return app.base;
  }

  function fromTokens(tenant: string, t: TokenResponse, previous?: StoredSession): StoredSession {
    return {
      tenant,
      access_token: t.access_token,
      expires_at: Date.now() + Math.max(1, t.expires_in) * 1000,
      refresh_token: t.refresh_token ?? previous?.refresh_token ?? null,
      id_token: t.id_token ?? previous?.id_token ?? null,
    };
  }

  const api: AuthApi = {
    app,
    home,
    callbackUri,
    loadSession() {
      const s = readJson<StoredSession>("session", SESSION_KEY);
      return s && typeof s.access_token === "string" && typeof s.tenant === "string" ? s : null;
    },
    saveSession(s) {
      writeJson("session", SESSION_KEY, s);
    },
    clearSession() {
      remove("session", SESSION_KEY);
    },
    lastTenant() {
      try {
        return storage("local")?.getItem(LAST_TENANT_KEY) ?? null;
      } catch {
        return null;
      }
    },
    /**
     * Send the browser to the tenant's authorization endpoint. `returnTo` is
     * the page to land on afterwards (same origin, this console only).
     */
    async startLogin(tenant, returnTo, options = {}) {
      const slug = tenant.trim().toLowerCase();
      if (!isValidSlug(slug)) throw new AuthError("invalid_tenant", "Enter a valid tenant slug.");
      const verifier = randomToken(48);
      const state = randomToken(16);
      const pending: Pending = { state, verifier, tenant: slug, return_to: safeReturn(returnTo) };
      writeJson("session", PENDING_KEY, pending);
      writeJson("local", LAST_TENANT_KEY, slug);
      const q = new URLSearchParams({
        response_type: "code",
        client_id: app.clientId,
        redirect_uri: callbackUri(),
        scope: CONSOLE_SCOPES,
        state,
        code_challenge: await challengeOf(verifier),
        code_challenge_method: "S256",
      });
      if (options.prompt) q.set("prompt", options.prompt);
      if (options.max_age !== undefined) q.set("max_age", String(options.max_age));
      if (options.acr_values) q.set("acr_values", options.acr_values);
      navigate(`${tenantBase(slug)}/authorize?${q}`);
    },
    /**
     * Finish the code exchange on the callback page. Resolves with the page
     * to return to; throws an `AuthError` the page can show.
     */
    async completeLogin(params) {
      const pending = readJson<Pending>("session", PENDING_KEY);
      remove("session", PENDING_KEY);
      const error = params.get("error");
      if (error) {
        throw new AuthError(error, params.get("error_description") ?? `Sign-in failed (${error}).`);
      }
      const code = params.get("code");
      const state = params.get("state");
      if (!code || !state) throw new AuthError("invalid_callback", "The sign-in response is incomplete.");
      if (!pending || pending.state !== state) {
        throw new AuthError("state_mismatch", "This sign-in response does not belong to this browser tab.");
      }
      const tokens = await tokenRequest(pending.tenant, {
        grant_type: "authorization_code",
        client_id: app.clientId,
        code,
        redirect_uri: callbackUri(),
        code_verifier: pending.verifier,
      });
      const session = fromTokens(pending.tenant, tokens);
      api.saveSession(session);
      return { session, returnTo: pending.return_to };
    },
    /** Rotate the refresh token for a fresh access token. */
    async refreshSession(s) {
      if (!s.refresh_token) throw new AuthError("no_refresh_token", "The session cannot be renewed.");
      const tokens = await tokenRequest(s.tenant, {
        grant_type: "refresh_token",
        client_id: app.clientId,
        refresh_token: s.refresh_token,
      });
      const next = fromTokens(s.tenant, tokens, s);
      api.saveSession(next);
      return next;
    },
    /**
     * RP-initiated logout: with the ID token as hint the tenant ends the
     * browser session without a confirmation page and sends the browser
     * back to the console, which then shows the sign-in card.
     */
    logoutUrl(s) {
      const q = new URLSearchParams({ post_logout_redirect_uri: home(), client_id: app.clientId });
      if (s.id_token) q.set("id_token_hint", s.id_token);
      return `${tenantBase(s.tenant)}/end_session?${q}`;
    },
  };
  return api;
}

async function tokenRequest(tenant: string, form: Record<string, string>): Promise<TokenResponse> {
  let res: Response;
  try {
    res = await fetch(`${tenantBase(tenant)}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams(form),
      cache: "no-store",
    });
  } catch {
    throw new AuthError("network", "Could not reach the server.");
  }
  const body = (await res.json().catch(() => null)) as
    | (TokenResponse & { error?: string; error_description?: string })
    | null;
  if (!res.ok || !body || typeof body.access_token !== "string") {
    const code = body?.error ?? `http_${res.status}`;
    throw new AuthError(code, body?.error_description ?? `The token request failed (${code}).`);
  }
  return body;
}

// The admin console's bundle, under the names its pages have always used.
export const consoleAuth = createAuth(CONSOLE_APP);
export const consoleHome = consoleAuth.home;
export const callbackUri = consoleAuth.callbackUri;
export const loadSession = consoleAuth.loadSession;
export const saveSession = consoleAuth.saveSession;
export const clearSession = consoleAuth.clearSession;
export const lastTenant = consoleAuth.lastTenant;
export const startLogin = consoleAuth.startLogin;
export const completeLogin = consoleAuth.completeLogin;
export const refreshSession = consoleAuth.refreshSession;
export const logoutUrl = consoleAuth.logoutUrl;
