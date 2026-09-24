// A playground run. The sign-in happens in a popup, so the console tab keeps
// the run (a pasted client secret included) in memory and nothing is ever
// written to storage; the popup hands the authorization response back with
// postMessage and closes.

import { tenantBase } from "@/lib/api";
import type { AuthMethod } from "./clients";

export interface PlaygroundPending {
  tenant: string;
  /** Database id of the client (for the console) and its public id (for the protocol). */
  id: string;
  client_id: string;
  auth: AuthMethod;
  secret: string | null;
  verifier: string;
  state: string;
  nonce: string;
  scope: string;
  resource: string | null;
}

export interface TokenSet {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
  [k: string]: unknown;
}

export interface PlaygroundResult {
  tenant: string;
  id: string;
  client_id: string;
  auth: AuthMethod;
  secret: string | null;
  tokens: TokenSet;
  userinfo?: unknown;
  at: number;
}

export function redirectUri(): string {
  return `${window.location.origin}/console/playground/`;
}

function base64url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (const b of arr) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomToken(bytes = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function pkceChallenge(verifier: string): Promise<string> {
  // Browsers only offer Web Crypto on https and localhost.
  if (!globalThis.crypto?.subtle) {
    throw new PlaygroundError("insecure_context", "PKCE needs a secure connection: open the console over https (or on localhost).");
  }
  return base64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
}

/** The message type the sign-in popup posts back to the console tab. */
export const CALLBACK_TYPE = "ridm-playground-callback";

/** What the popup found on the redirect URI. */
export interface PlaygroundCallback {
  type: typeof CALLBACK_TYPE;
  code: string | null;
  state: string | null;
  error: string | null;
  error_description: string | null;
}

export function isCallback(data: unknown): data is PlaygroundCallback {
  return typeof data === "object" && data !== null && (data as { type?: unknown }).type === CALLBACK_TYPE;
}

export class PlaygroundError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/** POST to the tenant's token endpoint with the client's authentication method. */
export async function tokenRequest(tenant: string, client_id: string, auth: AuthMethod, secret: string | null, form: Record<string, string>): Promise<TokenSet> {
  const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" };
  const body = new URLSearchParams(form);
  if (auth === "client_secret_basic") {
    if (!secret) throw new PlaygroundError("secret_required", "This client authenticates with a secret; paste it to continue.");
    headers.Authorization = `Basic ${btoa(`${encodeURIComponent(client_id)}:${encodeURIComponent(secret)}`)}`;
  } else if (auth === "client_secret_post") {
    if (!secret) throw new PlaygroundError("secret_required", "This client authenticates with a secret; paste it to continue.");
    body.set("client_id", client_id);
    body.set("client_secret", secret);
  } else if (auth === "private_key_jwt") {
    throw new PlaygroundError("unsupported", "The playground cannot sign private_key_jwt assertions; use a public or secret-based client.");
  } else {
    body.set("client_id", client_id);
  }
  let res: Response;
  try {
    res = await fetch(`${tenantBase(tenant)}/token`, { method: "POST", headers, body, cache: "no-store" });
  } catch {
    throw new PlaygroundError("network", "Could not reach the token endpoint.");
  }
  const json = (await res.json().catch(() => null)) as (TokenSet & { error?: string; error_description?: string }) | null;
  if (!res.ok || !json || typeof json.access_token !== "string") {
    const code = json?.error ?? `http_${res.status}`;
    throw new PlaygroundError(code, json?.error_description ?? `The token endpoint answered ${code}.`);
  }
  return json;
}

export async function userinfoRequest(tenant: string, accessToken: string): Promise<unknown> {
  const res = await fetch(`${tenantBase(tenant)}/userinfo`, { headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" }, cache: "no-store" });
  const json = (await res.json().catch(() => null)) as unknown;
  if (!res.ok) {
    const e = json as { error?: string; error_description?: string } | null;
    throw new PlaygroundError(e?.error ?? `http_${res.status}`, e?.error_description ?? `userinfo answered ${res.status}.`);
  }
  return json;
}

/** Header and claims of a JWS compact token, or null when it is not one. */
export function decodeJwt(token: string): { header: Record<string, unknown>; claims: Record<string, unknown> } | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const dec = (s: string) => JSON.parse(atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(s.length + ((4 - (s.length % 4)) % 4), "="))) as Record<string, unknown>;
    return { header: dec(parts[0]!), claims: dec(parts[1]!) };
  } catch {
    return null;
  }
}
