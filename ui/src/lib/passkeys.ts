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

function translate(e: unknown): PasskeyError {
  if (e instanceof PasskeyError) return e;
  if (e instanceof WebAuthnError) {
    const cause = e.cause instanceof Error ? e.cause.name : "";
    if (e.code === "ERROR_CEREMONY_ABORTED" || cause === "NotAllowedError" || cause === "AbortError") {
      return new PasskeyError("cancelled", e);
    }
    if (e.code === "ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED" || cause === "InvalidStateError") {
      return new PasskeyError("already_registered", e);
    }
    return new PasskeyError("failed", e);
  }
  if (e instanceof Error && (e.name === "NotAllowedError" || e.name === "AbortError")) {
    return new PasskeyError("cancelled", e);
  }
  return new PasskeyError("failed", e);
}

/** Run `navigator.credentials.create` for the options the API issued. */
export async function createPasskey(options: PasskeyCreationOptions): Promise<RegistrationResponseJSON> {
  if (!passkeysSupported()) throw new PasskeyError("unsupported");
  try {
    return await startRegistration({ optionsJSON: options.publicKey });
  } catch (e) {
    throw translate(e);
  }
}

/** Run `navigator.credentials.get` for the options the API issued. */
export async function assertPasskey(options: PasskeyRequestOptions): Promise<AuthenticationResponseJSON> {
  if (!passkeysSupported()) throw new PasskeyError("unsupported");
  try {
    return await startAuthentication({ optionsJSON: options.publicKey });
  } catch (e) {
    throw translate(e);
  }
}
