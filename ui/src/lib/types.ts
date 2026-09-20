// Shapes returned by the rIDM API that the end-user pages consume.

import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser";

export type FlowStage =
  | "authenticate"
  | "register"
  | "verify_email"
  | "password_change"
  | "mfa"
  | "profile"
  | "terms"
  | "organization"
  | "consent"
  | "done";

export type Method = "password" | "magic_link" | "email_otp" | "sms_otp" | "passkey";

export interface PublicClient {
  client_id: string;
  name: string;
  logo_uri: string | null;
  client_uri: string | null;
  tos_uri: string | null;
  policy_uri: string | null;
}

export interface ScopeInfo {
  name: string;
  description: string | null;
}

export type AttributeType =
  | "string"
  | "number"
  | "boolean"
  | "email"
  | "url"
  | "phone"
  | "date"
  | "enum"
  | "json";

export interface AttributeDef {
  name: string;
  type: AttributeType;
  label: string | null;
  description: string | null;
  required: boolean;
  multivalued: boolean;
  validation: {
    min_length: number | null;
    max_length: number | null;
    pattern: string | null;
    min: number | null;
    max: number | null;
    values: string[];
  };
  order: number;
}

export interface CaptchaChallenge {
  provider: "turnstile" | "h_captcha" | "hcaptcha" | "disabled";
  site_key: string;
}

export interface PublicFlow {
  id: string;
  stage: FlowStage;
  csrf: string;
  expires_at: string;
  client: PublicClient;
  methods: Method[];
  login_hint: string | null;
  ui_locales: string[];
  locale: string;
  dir: "ltr" | "rtl";
  locales: string[];
  pending_scopes: ScopeInfo[];
  missing_attributes: AttributeDef[];
  terms_url: string | null;
  privacy_url: string | null;
  user: { username: string; email: string | null } | null;
  attempts: number;
  captcha: CaptchaChallenge | null;
  /** Present at the `mfa` stage. */
  mfa: MfaInfo | null;
  /** Offered at the `organization` stage. */
  organizations: PublicOrganization[];
  /** Present once the stage is `done`. */
  finish_url?: string;
  /** Upstream providers offered as "Continue with …" buttons. */
  identity_providers: PublicIdp[];
}

export interface PublicOrganization {
  id: string;
  slug: string;
  display_name: string;
}

export interface PublicIdp {
  alias: string;
  display_name: string;
  preset: string | null;
}

export type Factor = "totp" | "webauthn" | "email_otp" | "sms_otp";

export interface MfaInfo {
  /** Enrolled factor kinds. */
  factors: Factor[];
  /** Factor kinds the tenant offers for enrolment. */
  methods: Factor[];
  /** No factor yet: the user must enrol one now. */
  enroll: boolean;
  /** Unused recovery codes remain. */
  recovery_codes: boolean;
  /** The phone an SMS enrolment would use (masked); null asks for one. */
  phone: string | null;
}

/** Answer of `mfa/{email|sms}/enroll` and `/send`: where the code went (masked). */
export interface OtpSent {
  sent: boolean;
  destination: string;
}

/** Answer of `mfa/totp/enroll`. */
export interface TotpEnrolment {
  secret: string;
  otpauth_uri: string;
  issuer: string;
  account: string;
  digits: number;
  period: number;
}

/**
 * Answer of `mfa/totp/confirm` and of `mfa/passkey/register/finish` when the
 * factor is the user's first: the codes are shown once, then the flow goes on.
 */
export interface MfaEnrolled {
  recovery_codes: string[];
  flow: PublicFlow;
}

/** Answer of `mfa/passkey/register`: what `navigator.credentials.create` needs. */
export interface PasskeyCreationOptions {
  publicKey: PublicKeyCredentialCreationOptionsJSON;
}

/** Answer of `passkey/start` and `mfa/passkey/start`: what `navigator.credentials.get` needs. */
export interface PasskeyRequestOptions {
  publicKey: PublicKeyCredentialRequestOptionsJSON;
  mediation?: "conditional" | "optional" | "required" | "silent";
}

export interface BrandingLink {
  label: string;
  url: string;
}

export interface PublicTenant {
  slug: string;
  display_name: string;
  branding: {
    logo_url: string | null;
    favicon_url: string | null;
    primary_color: string | null;
    background_color: string | null;
    support_url: string | null;
    custom_css: string | null;
    links: BrandingLink[];
  };
  locale: { default: string; supported: string[] };
  methods: Method[];
  registration: { enabled: boolean; terms_url: string | null; privacy_url: string | null };
}

export interface LogoutView {
  id: string;
  csrf: string;
  client: { client_id: string; name: string; logo_uri: string | null } | null;
  signed_in: boolean;
  returns_to_client: boolean;
  locale: string;
  dir: "ltr" | "rtl";
}

export interface PublicInvitation {
  email: string;
  tenant: string;
  invited_by: string | null;
  expires_at: string;
}

/** RFC 9457 problem document produced by the API. */
export interface Problem {
  type: string;
  title: string;
  status: number;
  detail?: string | null;
  errors?: { field: string; message: string }[] | null;
}
