/**
 * Where the tokens live: in a module variable, which is to say in memory.
 *
 * Not `localStorage`, and not a cookie this app can read. A token in
 * `localStorage` is readable by every script on the origin, so one bad
 * dependency walks off with it and can spend it until it expires. Memory is
 * lost on reload, which is what the silent `prompt=none` sign-in is for.
 */
import { refresh, revoke, type Tokens } from "./oidc";

export type { Tokens };

let current: Tokens | null = null;
const listeners = new Set<(tokens: Tokens | null) => void>();

export function getSession(): Tokens | null {
  return current;
}

export function setSession(tokens: Tokens | null): void {
  current = tokens;
  for (const listener of listeners) listener(current);
}

export function subscribe(listener: (tokens: Tokens | null) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export async function signOutLocally(): Promise<Tokens | null> {
  const ending = current;
  if (ending?.refreshToken) await revoke(ending.refreshToken);
  setSession(null);
  return ending;
}

/**
 * An access token that is good for at least another ten seconds, refreshing it
 * if it is not. A token that passes here and fails at the API a moment later
 * helps nobody.
 */
export async function accessToken(): Promise<string> {
  if (!current) throw new Error("not signed in");
  if (current.expiresAt > Date.now() + 10_000) return current.accessToken;
  if (!current.refreshToken) {
    setSession(null);
    throw new Error("this session has expired — sign in again");
  }
  try {
    // rIDM rotates refresh tokens: what comes back replaces what went in, and
    // presenting the old one again would end the whole family.
    const rotated = await refresh(current.refreshToken);
    setSession(rotated);
    return rotated.accessToken;
  } catch (e) {
    setSession(null);
    throw e;
  }
}
