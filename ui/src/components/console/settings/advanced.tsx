"use client";

import { Field, NumberInput, Section, SelectInput, TagsInput, Toggle } from "@/components/console/form";
import { GRANTS, RSA_BITS, SIGNING_ALGS } from "@/lib/console/settings";
import { useSettingsEditor } from "./context";

export function AdvancedSection() {
  const { draft, editable, update } = useSettingsEditor();
  const { keys, discovery, dcr, audit } = draft.settings;
  const toggleGrant = (g: string, on: boolean) => {
    const next = on ? [...dcr.allowed_grants, g] : dcr.allowed_grants.filter((x) => x !== g);
    update({ dcr: { allowed_grants: next } });
  };
  return (
    <Section id="advanced" title="Keys, discovery & audit" description="Signing key lifecycle, issuer discovery, dynamic client registration and audit retention.">
      <Field label="Algorithm for new keys">
        {(id) => (
          <SelectInput id={id} value={keys.default_alg} disabled={!editable} onChange={(e) => update({ keys: { default_alg: e.target.value as (typeof SIGNING_ALGS)[number] } })}>
            {SIGNING_ALGS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </SelectInput>
        )}
      </Field>
      <Field label="RSA key size">
        {(id) => (
          <SelectInput id={id} value={keys.rsa_bits} disabled={!editable} onChange={(e) => update({ keys: { rsa_bits: e.target.value as (typeof RSA_BITS)[number]["value"] } })}>
            {RSA_BITS.map((b) => (
              <option key={b.value} value={b.value}>
                {b.label}
              </option>
            ))}
          </SelectInput>
        )}
      </Field>
      <Field label="Rotate the active key every" hint="0 = only on demand.">
        {(id, by) => <NumberInput id={id} describedBy={by} value={keys.rotation_interval_days} min={0} onValue={(v) => v !== null && update({ keys: { rotation_interval_days: v } })} unit="days" />}
      </Field>
      <Field label="Keep a retired key published for" hint="So tokens it signed still verify.">
        {(id, by) => <NumberInput id={id} describedBy={by} value={keys.retire_overlap_hours} min={0} onValue={(v) => v !== null && update({ keys: { retire_overlap_hours: v } })} unit="hours" />}
      </Field>

      <Field label="WebFinger email domains" hint="acct:user@domain resolves to this tenant's issuer." wide>
        {(id, by) => (
          <TagsInput id={id} describedBy={by} value={discovery.email_domains} onChange={(v) => update({ discovery: { email_domains: v } })} placeholder="example.com" normalize={(s) => s.trim().toLowerCase()} />
        )}
      </Field>

      <Field label="Dynamic client registration" hint="RFC 7591 at /t/{slug}/register.">
        {(id, by) => (
          <SelectInput id={id} aria-describedby={by} value={dcr.mode} disabled={!editable} onChange={(e) => update({ dcr: { mode: e.target.value as typeof dcr.mode } })}>
            <option value="disabled">Disabled</option>
            <option value="open">Open (rate limited)</option>
            <option value="initial_access_token">Requires an initial access token</option>
          </SelectInput>
        )}
      </Field>
      <fieldset className="flex flex-col gap-1.5">
        <legend className="mb-1.5 text-[0.8125rem] font-medium text-ink">Grants a registered client may request</legend>
        {GRANTS.map((g) => (
          <label key={g.value} className="flex items-center gap-2 text-[0.875rem] text-ink">
            <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={dcr.allowed_grants.includes(g.value)} disabled={!editable} onChange={(e) => toggleGrant(g.value, e.target.checked)} />
            {g.label}
          </label>
        ))}
      </fieldset>
      <Toggle
        label="Registered confidential clients must use PKCE"
        hint="Public clients always must. Off matches the OpenID Connect basic profile, whose clients authenticate with a secret and send no code challenge."
        checked={dcr.require_pkce}
        disabled={!editable}
        onChange={(v) => update({ dcr: { require_pkce: v } })}
      />

      <Field label="Audit retention" hint="Days to keep audit rows; 0 keeps them forever.">
        {(id, by) => <NumberInput id={id} describedBy={by} value={audit.retention_days} min={0} onValue={(v) => v !== null && update({ audit: { retention_days: v } })} unit="days" />}
      </Field>
    </Section>
  );
}
