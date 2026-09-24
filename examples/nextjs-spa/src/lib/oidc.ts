/**
 * The protocol, in a browser: discovery, PKCE, the authorization redirect, and
 * the token endpoint.
 *
 * A public client has no secret, so PKCE is what proves that the app spending
 * the code is the app that asked for it (RFC 7636). Everything here runs in the
 * browser; there is no server on this side at all.
 */
import { config, postLogoutRedirectUri, redirectUri } from "./config";

export interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint: string;
  revocation_endpoint?: string;
}

export interface Tokens {
  accessToken: string;
  idToken: string;
  refreshToken?: string;
  /** Milliseconds since the epoch. */
  expiresAt: number;
  claims: IdTokenClaims;
}

export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  nonce?: string;
  sid?: string;
  name?: string;
  email?: string;
  [claim: string]: unknown;
}

const STATE_KEY = "ridm.signin";

let discovered: Promise<Discovery> | null = null;

/** The discovery document, fetched once per page load. */
export function discover(): Promise<Discovery> {
  discovered ??= (async () => {
    const url = `${config.issuer}/.well-known/openid-configuration`;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`discovery at ${url}: HTTP ${response.status}`);
    const document = (await response.json()) as Discovery;
    // The document has to claim the issuer it was fetched from, or someone
    // else is telling us where to send our users (OIDC Discovery §4.3).
    if (document.issuer.replace(/\/$/, "") !== config.issuer) {
      throw new Error(`discovery at ${url} names issuer ${document.issuer}`);
    }
    return document;
  })();
  return discovered;
}

/**
 * Send the browser to rIDM to sign in.
 *
 * `prompt: "none"` asks rIDM to answer without showing anything: if there is
 * still an SSO session the user comes straight back signed in, and if there is
 * not, the callback carries `error=login_required`. That is how this app picks
 * a session back up after a reload without making the user click anything.
 */
export async function beginSignIn(options: { prompt?: "none" } = {}): Promise<void> {
  const { authorization_endpoint } = await discover();
  const state = randomToken();
  const nonce = randomToken();
  const verifier = randomToken();

  // Per tab, and only until the callback: `sessionStorage` is the right shelf
  // for this. The verifier never leaves the browser.
  sessionStorage.setItem(
    STATE_KEY,
    JSON.stringify({ state, nonce, verifier, at: Date.now() }),
  );

  const query = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: redirectUri(),
    scope: config.scopes,
    state,
    nonce,
    code_challenge: await codeChallenge(verifier),
    code_challenge_method: "S256",
    // Which API the access token should be good for (RFC 8707). Without it
    // rIDM falls back to the client's registered audiences plus those of any
    // resource-bound scope requested, and to this client itself only when
    // there are none, in which case the orders API refuses the token.
    resource: config.apiAudience,
  });
  if (options.prompt) query.set("prompt", options.prompt);
  // Leaving the app entirely, for rIDM's own origin — not a route in this app,
  // so the router is not what does it.
  // eslint-disable-next-line @next/next/no-location-assign-relative-destination
  window.location.assign(`${authorization_endpoint}?${query}`);
}

/**
 * Finish a sign-in from the query string the callback page was loaded with.
 * Returns `null` when rIDM answered `login_required` to a silent attempt,
 * which is not an error — it means nobody is signed in.
 */
export async function completeSignIn(search: string): Promise<Tokens | null> {
  const params = new URLSearchParams(search);
  const stored = sessionStorage.getItem(STATE_KEY);
  sessionStorage.removeItem(STATE_KEY);

  const error = params.get("error");
  if (error === "login_required" || error === "interaction_required") return null;
  if (error) {
    throw new Error(`${error}: ${params.get("error_description") ?? ""}`);
  }

  const code = params.get("code");
  const state = params.get("state");
  if (!code || !state) throw new Error("the callback carried no code");
  if (!stored) throw new Error("this sign-in is unknown — start again");

  const pending = JSON.parse(stored) as {
    state: string;
    nonce: string;
    verifier: string;
    at: number;
  };
  // `state` is what ties this callback to a sign-in this app started.
  if (pending.state !== state) throw new Error("the callback answers a different sign-in");
  if (Date.now() - pending.at > 10 * 60 * 1000) {
    throw new Error("this sign-in took too long — start again");
  }

  const tokens = await postToken({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri(),
    code_verifier: pending.verifier,
  });
  // The nonce ties the ID token to the request this app made (OIDC Core
  // §3.1.3.7).
  if (tokens.claims.nonce !== pending.nonce) {
    throw new Error("the ID token does not answer this sign-in");
  }
  return tokens;
}

/** Trade a refresh token for a fresh access token. rIDM rotates it. */
export async function refresh(refreshToken: string): Promise<Tokens> {
  return postToken({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    resource: config.apiAudience,
  });
}

/** Hand a refresh token back at sign-out (RFC 7009). Failure is not fatal. */
export async function revoke(refreshToken: string): Promise<void> {
  const { revocation_endpoint } = await discover();
  if (!revocation_endpoint) return;
  try {
    await fetch(revocation_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        token: refreshToken,
        token_type_hint: "refresh_token",
        client_id: config.clientId,
      }),
    });
  } catch {
    // Signing out locally matters more than telling rIDM about it.
  }
}

/** Where to send the browser to end the SSO session too. */
export async function endSessionUrl(idToken: string): Promise<string> {
  const { end_session_endpoint } = await discover();
  const query = new URLSearchParams({
    id_token_hint: idToken,
    post_logout_redirect_uri: postLogoutRedirectUri(),
    client_id: config.clientId,
  });
  return `${end_session_endpoint}?${query}`;
}

async function postToken(form: Record<string, string>): Promise<Tokens> {
  const { token_endpoint } = await discover();
  const response = await fetch(token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    // A public client has no secret: it identifies itself by `client_id` and
    // proves itself with the PKCE verifier.
    body: new URLSearchParams({ ...form, client_id: config.clientId }),
  });
  const body: unknown = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = body as { error?: string; error_description?: string };
    throw new Error(
      `the token endpoint refused: ${error.error ?? response.status} ${
        error.error_description ?? ""
      }`,
    );
  }
  const token = body as {
    access_token: string;
    id_token?: string;
    refresh_token?: string;
    expires_in?: number;
  };
  if (!token.id_token) throw new Error("the token response carried no ID token");

  const claims = readClaims(token.id_token);
  // The ID token came straight from the token endpoint over TLS, so OIDC Core
  // §3.1.3.7 allows the TLS check to stand in for verifying the signature
  // here. The issuer, the audience and the expiry are still ours to check —
  // and the API this app calls verifies its own token properly.
  if (claims.iss.replace(/\/$/, "") !== config.issuer) {
    throw new Error("the ID token was issued by someone else");
  }
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(config.clientId)) {
    throw new Error("the ID token was issued for another client");
  }
  if (claims.exp * 1000 <= Date.now()) throw new Error("the ID token has expired");

  return {
    accessToken: token.access_token,
    idToken: token.id_token,
    refreshToken: token.refresh_token,
    expiresAt: Date.now() + (token.expires_in ?? 300) * 1000,
    claims,
  };
}

function readClaims(jwt: string): IdTokenClaims {
  const payload = jwt.split(".")[1];
  if (!payload) throw new Error("the ID token is not a JWT");
  const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
  return JSON.parse(
    decodeURIComponent(
      json
        .split("")
        .map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, "0")}`)
        .join(""),
    ),
  ) as IdTokenClaims;
}

/** 32 random bytes, base64url: unguessable-or-nothing, like the rest. */
function randomToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

async function codeChallenge(verifier: string): Promise<string> {
  // Browsers only offer Web Crypto on https and localhost.
  if (!globalThis.crypto?.subtle) {
    throw new Error("Signing in needs a secure connection: serve this app over https (or on localhost).");
  }
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
