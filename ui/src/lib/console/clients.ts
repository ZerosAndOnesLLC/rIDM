// Shared shapes and vocab for the clients pages.

import type { Schemas } from "@api/client";

export type ClientView = Schemas["ClientView"];
export type RevealView = Schemas["RevealView"];
export type NewClient = Schemas["NewClient"];
export type ClientType = Schemas["ClientType"];
export type AuthMethod = Schemas["TokenEndpointAuthMethod"];

export const CLIENT_TYPES: { value: ClientType; label: string; blurb: string }[] = [
  { value: "spa", label: "Single-page app", blurb: "Runs in the browser. Public, PKCE, no secret." },
  { value: "web", label: "Web application", blurb: "Server-rendered app with a backend that keeps a secret." },
  { value: "native", label: "Native app", blurb: "Mobile or desktop. Public, PKCE, loopback redirects allowed." },
  { value: "machine", label: "Machine to machine", blurb: "A service calling APIs with client credentials. No users." },
  { value: "device", label: "Device", blurb: "Input-constrained device using the device authorization grant." },
];

export const GRANT_LABELS: Record<string, string> = {
  authorization_code: "Authorization code",
  refresh_token: "Refresh token",
  client_credentials: "Client credentials",
  "urn:ietf:params:oauth:grant-type:device_code": "Device code",
  "urn:ietf:params:oauth:grant-type:token-exchange": "Token exchange",
  "urn:openid:params:grant-type:ciba": "Backchannel (CIBA)",
};

export const CIBA_GRANT = "urn:openid:params:grant-type:ciba";
export const ALL_GRANTS = Object.keys(GRANT_LABELS);

/** Scopes every tenant carries; the default `allowed_scopes` of interactive clients. */
export const STANDARD_SCOPES = ["openid", "profile", "email", "phone", "address", "offline_access"];

export const AUTH_METHODS: { value: AuthMethod; label: string }[] = [
  { value: "none", label: "None (public client)" },
  { value: "client_secret_basic", label: "Client secret (HTTP Basic)" },
  { value: "client_secret_post", label: "Client secret (POST body)" },
  { value: "private_key_jwt", label: "Private key JWT" },
];

/** The type-driven defaults the API applies (`services/clients.rs::resolve`). */
export function typeDefaults(type: ClientType): { auth: AuthMethod; grants: string[]; pkce: boolean } {
  switch (type) {
    case "spa":
      return { auth: "none", grants: ["authorization_code", "refresh_token"], pkce: true };
    case "web":
      return { auth: "client_secret_basic", grants: ["authorization_code", "refresh_token"], pkce: true };
    case "native":
      return { auth: "none", grants: ["authorization_code", "refresh_token"], pkce: true };
    case "machine":
      return { auth: "client_secret_basic", grants: ["client_credentials"], pkce: false };
    case "device":
      return { auth: "none", grants: ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"], pkce: true };
    case "saml":
      return { auth: "none", grants: [], pkce: false };
  }
}

export function typeLabel(type: ClientType): string {
  if (type === "saml") return "SAML service provider";
  return CLIENT_TYPES.find((t) => t.value === type)?.label ?? type;
}

export function usesSecret(auth: AuthMethod): boolean {
  return auth === "client_secret_basic" || auth === "client_secret_post";
}

/** A SAML client is edited on the SAML page. */
export function samlHref(tenant: string | null, id: string): string {
  const q = new URLSearchParams({ ...(tenant ? { tenant } : {}), sp: id });
  return `/console/saml/?${q}`;
}

export function clientHref(tenant: string | null, id: string, extra: Record<string, string> = {}): string {
  const q = new URLSearchParams({ ...(tenant ? { tenant } : {}), client: id, ...extra });
  return `/console/clients/?${q}`;
}

export function playgroundHref(tenant: string, id: string): string {
  return `/console/playground/?tenant=${encodeURIComponent(tenant)}&client=${encodeURIComponent(id)}`;
}

export function isValidClientId(v: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(v);
}
