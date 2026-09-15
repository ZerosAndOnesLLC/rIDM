import { API, TENANT, clearTenantCache, mailpit, registerVerifiedUser, saveState, sql, t } from "./helpers";

const UI_PORT = Number(process.env.E2E_UI_PORT ?? 3110);
const UI = process.env.E2E_UI_URL ?? `http://localhost:${UI_PORT}`;

/** Tenant, client and one verified user; everything else the specs create themselves. */
export default async function globalSetup() {
  const settings = {
    dcr: { mode: "open" },
    auth: { password: true, magic_link: true, email_otp: true, sms_otp: false, passkey: false },
    registration: {
      enabled: true,
      require_email_verification: true,
      require_terms: true,
      terms_url: "https://example.com/terms",
      privacy_url: "https://example.com/privacy",
    },
    locale: { default: "en", supported: ["en"] },
    notifications: { new_device: false, password_changed: true, mfa_changed: true, email_changed: true },
  };
  sql(`UPDATE tenants SET settings = settings || '${JSON.stringify(settings)}'::jsonb WHERE slug = '${TENANT}'`);
  clearTenantCache();
  await mailpit.clear();

  const reg = await fetch(`${API}${t("/register")}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "E2E App",
      redirect_uris: [`${UI}/callback/`],
      post_logout_redirect_uris: [`${UI}/callback/`],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    }),
  });
  if (!reg.ok) throw new Error(`client registration failed: ${reg.status} ${await reg.text()}`);
  const client_id = ((await reg.json()) as { client_id: string }).client_id;

  // A verified user, created through the registration flow like a real one.
  const { email, password } = await registerVerifiedUser(client_id, UI);

  saveState({ ui: UI, client_id, email, password });
}
