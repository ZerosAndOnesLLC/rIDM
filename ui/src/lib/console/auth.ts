// Sign-in for the admin console: OIDC authorization code with PKCE against
// the tenant the administrator belongs to, using the built-in public client
// every tenant carries. Tokens live in this tab only (sessionStorage); the
// refresh token is rotated on every use and bound to the browser's SSO
// session, so signing out of the tenant ends console access as well.

import { tenantBase } from "@/lib/api";
import { navigate } from "@/lib/params";

export const CONSOLE_CLIENT_ID = "ridm-admin-console";
export const CONSOLE_SCOPES = "openid profile email";

const SESSION_KEY = "ridm.console.session";
const PENDING_KEY = "ridm.console.pending";
const LAST_TENANT_KEY = "ridm.console.tenant";

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

/** The console's own pages, derived from where it is served. */
export function consoleHome(): string {
  return `${window.location.origin}/console/`;
}
export function callbackUri(): string {
  return `${window.location.origin}/console/callback/`;
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

export function loadSession(): StoredSession | null {
  const s = readJson<StoredSession>("session", SESSION_KEY);
  return s && typeof s.access_token === "string" && typeof s.tenant === "string" ? s : null;
}

export function saveSession(s: StoredSession) {
  writeJson("session", SESSION_KEY, s);
}

export function clearSession() {
  remove("session", SESSION_KEY);
}

/** The tenant the administrator last signed in through, offered as the default. */
export function lastTenant(): string | null {
  try {
    return storage("local")?.getItem(LAST_TENANT_KEY) ?? null;
  } catch {
    return null;
  }
}

export function isExpiring(s: StoredSession, now = Date.now()): boolean {
  return s.expires_at - now < REFRESH_MARGIN_MS;
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
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(digest);
}

export function isValidSlug(slug: string): boolean {
  return /^[a-z0-9](?:[a-z0-9-]{0,62})$/.test(slug);
}

/**
 * Send the browser to the tenant's authorization endpoint. `returnTo` is the
 * console page to land on afterwards (same origin only).
 */
export async function startLogin(tenant: string, returnTo: string, prompt?: "login"): Promise<void> {
  const slug = tenant.trim().toLowerCase();
  if (!isValidSlug(slug)) throw new AuthError("invalid_tenant", "Enter a valid tenant slug.");
  const verifier = randomToken(48);
  const state = randomToken(16);
  const pending: Pending = { state, verifier, tenant: slug, return_to: safeReturn(returnTo) };
  writeJson("session", PENDING_KEY, pending);
  writeJson("local", LAST_TENANT_KEY, slug);
  const q = new URLSearchParams({
    response_type: "code",
    client_id: CONSOLE_CLIENT_ID,
    redirect_uri: callbackUri(),
    scope: CONSOLE_SCOPES,
    state,
    code_challenge: await challengeOf(verifier),
    code_challenge_method: "S256",
  });
  if (prompt) q.set("prompt", prompt);
  navigate(`${tenantBase(slug)}/authorize?${q}`);
}

/** Only console pages on this origin are valid return targets. */
function safeReturn(url: string): string {
  try {
    const u = new URL(url, window.location.origin);
    if (u.origin === window.location.origin && u.pathname.startsWith("/console/") && !u.pathname.startsWith("/console/callback")) {
      return u.pathname + u.search;
    }
  } catch {
    // fall through
  }
  return "/console/";
}

/**
 * Finish the code exchange on `/console/callback/`. Resolves with the page to
 * return to; throws an `AuthError` the page can show.
 */
export async function completeLogin(params: URLSearchParams): Promise<{ session: StoredSession; returnTo: string }> {
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
    client_id: CONSOLE_CLIENT_ID,
    code,
    redirect_uri: callbackUri(),
    code_verifier: pending.verifier,
  });
  const session = fromTokens(pending.tenant, tokens);
  saveSession(session);
  return { session, returnTo: pending.return_to };
}

/** Rotate the refresh token for a fresh access token. */
export async function refreshSession(s: StoredSession): Promise<StoredSession> {
  if (!s.refresh_token) throw new AuthError("no_refresh_token", "The session cannot be renewed.");
  const tokens = await tokenRequest(s.tenant, {
    grant_type: "refresh_token",
    client_id: CONSOLE_CLIENT_ID,
    refresh_token: s.refresh_token,
  });
  const next = fromTokens(s.tenant, tokens, s);
  saveSession(next);
  return next;
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

/**
 * RP-initiated logout: with the ID token as hint the tenant ends the browser
 * session without a confirmation page and sends the browser back to the
 * console, which then shows the sign-in card.
 */
export function logoutUrl(s: StoredSession): string {
  const q = new URLSearchParams({
    post_logout_redirect_uri: consoleHome(),
    client_id: CONSOLE_CLIENT_ID,
  });
  if (s.id_token) q.set("id_token_hint", s.id_token);
  return `${tenantBase(s.tenant)}/end_session?${q}`;
}
