// Passkeys in the browser: thin wrappers over @simplewebauthn/browser that
// turn its failures into a small set of codes the pages can translate.

import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
  WebAuthnError,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/browser";
import type { PasskeyCreationOptions, PasskeyRequestOptions } from "./types";

export type PasskeyErrorCode = "cancelled" | "unsupported" | "already_registered" | "failed";

/** A passkey ceremony that did not produce a credential. */
export class PasskeyError extends Error {
  readonly code: PasskeyErrorCode;
  constructor(code: PasskeyErrorCode, cause?: unknown) {
    super(code, { cause });
    this.code = code;
  }
}

/** True when this browser can run a passkey ceremony at all. */
export function passkeysSupported(): boolean {
  return browserSupportsWebAuthn();
}

/**
 * A refusal this soon after the ceremony started came before any prompt
 * could have been shown: the browser has the API but cannot use it here
 * (an app's embedded browser without the app's association with the site,
 * some Android WebViews). A person cancelling takes longer than this.
 */
const NO_PROMPT_MS = 400;

/** What the browser says it can do, where it says (Safari 17.4+, Chrome 133+). */
async function capableHere(): Promise<boolean> {
  const pkc = (globalThis as { PublicKeyCredential?: { getClientCapabilities?: () => Promise<Record<string, boolean | undefined>> } }).PublicKeyCredential;
  if (!pkc?.getClientCapabilities) return true;
  try {
    const caps = await pkc.getClientCapabilities();
    // Neither a passkey on this device nor one on a phone nearby: nothing to offer.
    return caps.passkeyPlatformAuthenticator !== false || caps.hybridTransport !== false;
  } catch {
    return true;
  }
}

function translate(e: unknown, startedAt: number): PasskeyError {
  const refusedAtOnce = performance.now() - startedAt < NO_PROMPT_MS;
  const refused = (name: string) => name === "NotAllowedError" && refusedAtOnce;
  if (e instanceof PasskeyError) return e;
  if (e instanceof WebAuthnError) {
    const cause = e.cause instanceof Error ? e.cause.name : "";
    if (refused(cause)) return new PasskeyError("unsupported", e);
    if (e.code === "ERROR_CEREMONY_ABORTED" || cause === "NotAllowedError" || cause === "AbortError") {
      return new PasskeyError("cancelled", e);
    }
    if (e.code === "ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED" || cause === "InvalidStateError") {
      return new PasskeyError("already_registered", e);
    }
    return new PasskeyError("failed", e);
  }
  if (e instanceof Error && refused(e.name)) return new PasskeyError("unsupported", e);
  if (e instanceof Error && (e.name === "NotAllowedError" || e.name === "AbortError")) {
    return new PasskeyError("cancelled", e);
  }
  return new PasskeyError("failed", e);
}

/** Run `navigator.credentials.create` for the options the API issued. */
export async function createPasskey(options: PasskeyCreationOptions): Promise<RegistrationResponseJSON> {
  if (!passkeysSupported() || !(await capableHere())) throw new PasskeyError("unsupported");
  const startedAt = performance.now();
  try {
    return await startRegistration({ optionsJSON: options.publicKey });
  } catch (e) {
    throw translate(e, startedAt);
  }
}

/** Run `navigator.credentials.get` for the options the API issued. */
export async function assertPasskey(options: PasskeyRequestOptions): Promise<AuthenticationResponseJSON> {
  if (!passkeysSupported() || !(await capableHere())) throw new PasskeyError("unsupported");
  const startedAt = performance.now();
  try {
    return await startAuthentication({ optionsJSON: options.publicKey });
  } catch (e) {
    throw translate(e, startedAt);
  }
}
