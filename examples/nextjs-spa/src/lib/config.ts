/** Everything the app is told at build time. */
export const config = {
  /** `https://{host}/t/{tenant}`, the `iss` of every token this app sees. */
  issuer: (process.env.NEXT_PUBLIC_RIDM_ISSUER ?? "").replace(/\/$/, ""),
  clientId: process.env.NEXT_PUBLIC_CLIENT_ID ?? "",
  /** The orders API this app calls. */
  apiUrl: (process.env.NEXT_PUBLIC_API_URL ?? "").replace(/\/$/, ""),
  /** The resource server identifier to ask the token for (RFC 8707). */
  apiAudience: process.env.NEXT_PUBLIC_API_AUDIENCE ?? "",
  /**
   * `offline_access` is what asks for a refresh token. rIDM rotates it on
   * every use, so a public client may hold one.
   */
  scopes: "openid profile email offline_access orders:read orders:write",
} as const;

/** Where rIDM sends the browser back to. Registered on the client in rIDM. */
export function redirectUri(): string {
  return `${window.location.origin}/callback/`;
}

export function postLogoutRedirectUri(): string {
  return `${window.location.origin}/`;
}
