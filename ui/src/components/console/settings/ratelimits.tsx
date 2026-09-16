"use client";

import { Field, NumberInput, Section, Toggle } from "@/components/console/form";
import { useSettingsEditor } from "./context";

/**
 * Request ceilings on the OAuth and sign-in endpoints. Each limit counts
 * requests per window; 0 switches that limit off. The deployment's own
 * per-address ceiling applies on top and is not editable here.
 */
export function RateLimitsSection() {
  const { draft, editable, update } = useSettingsEditor();
  const r = draft.settings.rate_limits;
  const num = (key: keyof typeof r, label: string, hint: string, min = 0, max?: number) => (
    <Field key={key} label={label} hint={hint}>
      {(id, by) => (
        <NumberInput id={id} describedBy={by} value={r[key] as number} min={min} max={max} onValue={(v) => v !== null && update({ rate_limits: { [key]: v } })} unit={key === "window_secs" ? "s" : "per window"} />
      )}
    </Field>
  );
  return (
    <Section id="ratelimits" title="Rate limits" description="Request ceilings on the OAuth and sign-in endpoints, counted per window and shared by every node. 0 switches a limit off; refused requests get 429 with Retry-After.">
      <div className="flex flex-col gap-1 sm:col-span-2">
        <Toggle label="Enforce rate limits" hint="The deployment-wide per-address ceiling stays on regardless." checked={r.enabled} disabled={!editable} onChange={(v) => update({ rate_limits: { enabled: v } })} />
      </div>
      {num("window_secs", "Window", "Length of the counting window.", 1, 3600)}
      {num("token_per_ip", "Token endpoints per address", "/token, /introspect, /revoke, /userinfo and /device_authorization from one client address.")}
      {num("token_per_client", "Token endpoints per client", "The same endpoints for one authenticated client, counted before its secret is checked.")}
      {num("authorize_per_ip", "Authorization per address", "/authorize, /par and dynamic client registration from one address.")}
      {num("flows_per_ip", "Sign-in flow per address", "Sign-in, registration, recovery, verification, invitation, device and brokering steps from one address.")}
      {num("tenant_total", "Whole tenant", "Every limited endpoint together, across all addresses.")}
    </Section>
  );
}
