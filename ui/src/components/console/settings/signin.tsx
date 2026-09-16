"use client";

import { Field, Section, SelectInput, TagsInput, TextInput, Toggle } from "@/components/console/form";
import { isHttpUrl } from "@/lib/console/settings";
import { useSettingsEditor } from "./context";

type MfaMode = "off" | "optional" | "required" | "required_for_admins" | "required_for_roles";

export function SignInSection() {
  const { draft, editable, update } = useSettingsEditor();
  const { auth, mfa, mfa_methods, registration } = draft.settings;
  const mfaRoles = mfa.mode === "required_for_roles" ? mfa.roles : [];
  const setMfa = (mode: MfaMode, roles = mfaRoles) => update({ mfa: mode === "required_for_roles" ? { mode, roles } : { mode } });
  const urlError = (v: string | null | undefined) => (v && !isHttpUrl(v) ? "Enter an http(s) URL." : null);

  return (
    <Section id="signin" title="Sign-in" description="First factors, second-factor policy and self-registration.">
      <div className="flex flex-col gap-1 sm:col-span-2">
        <h3 className="text-[0.8125rem] font-medium text-ink">Methods</h3>
        <Toggle label="Password" checked={auth.password} disabled={!editable} onChange={(v) => update({ auth: { password: v } })} />
        <Toggle label="Magic link" hint="A sign-in link by email." checked={auth.magic_link} disabled={!editable} onChange={(v) => update({ auth: { magic_link: v } })} />
        <Toggle label="Email code" checked={auth.email_otp} disabled={!editable} onChange={(v) => update({ auth: { email_otp: v } })} />
        <Toggle label="SMS code" hint="Needs an SMS provider under Messaging." checked={auth.sms_otp} disabled={!editable} onChange={(v) => update({ auth: { sms_otp: v } })} />
        <Toggle label="Passkeys" hint="Passwordless sign-in with a device passkey or security key; also offered as a second step." checked={auth.passkey} disabled={!editable} onChange={(v) => update({ auth: { passkey: v } })} />
      </div>

      <div className="flex flex-col gap-1 sm:col-span-2">
        <h3 className="text-[0.8125rem] font-medium text-ink">Second-step methods</h3>
        <Toggle label="Authenticator app" hint="Time-based codes from an app (TOTP)." checked={mfa_methods.totp} disabled={!editable} onChange={(v) => update({ mfa_methods: { totp: v } })} />
        <Toggle label="Email code" hint="A one-time code to the account's email address." checked={mfa_methods.email_otp} disabled={!editable} onChange={(v) => update({ mfa_methods: { email_otp: v } })} />
        <Toggle label="SMS code" hint="A one-time code to a verified phone number; needs an SMS provider under Messaging." checked={mfa_methods.sms_otp} disabled={!editable} onChange={(v) => update({ mfa_methods: { sms_otp: v } })} />
      </div>

      <Field label="Two-step verification" hint="Required asks everyone (enrolling a second step on first sign-in); optional asks users who enrolled one. Role-based modes arrive with 7.4.">
        {(id, by) => (
          <SelectInput id={id} aria-describedby={by} value={mfa.mode} disabled={!editable} onChange={(e) => setMfa(e.target.value as MfaMode)}>
            <option value="off">Off</option>
            <option value="optional">Optional</option>
            <option value="required">Required for everyone</option>
            <option value="required_for_admins">Required for administrators</option>
            <option value="required_for_roles">Required for roles…</option>
          </SelectInput>
        )}
      </Field>
      {mfa.mode === "required_for_roles" && (
        <Field label="Roles that require it" hint="Role names; Enter adds one.">
          {(id, by) => <TagsInput id={id} describedBy={by} value={mfaRoles} onChange={(roles) => setMfa("required_for_roles", roles)} placeholder="finance, admins" />}
        </Field>
      )}

      <div className="flex flex-col gap-1 sm:col-span-2">
        <h3 className="text-[0.8125rem] font-medium text-ink">Self-registration</h3>
        <Toggle label="Allow people to create accounts" checked={registration.enabled} disabled={!editable} onChange={(v) => update({ registration: { enabled: v } })} />
        <Toggle label="Require email verification" checked={registration.require_email_verification} disabled={!editable} onChange={(v) => update({ registration: { require_email_verification: v } })} />
        <Toggle label="Require accepting the terms" checked={registration.require_terms} disabled={!editable} onChange={(v) => update({ registration: { require_terms: v } })} />
        <Toggle label="CAPTCHA on registration" checked={registration.captcha} disabled={!editable} onChange={(v) => update({ registration: { captcha: v } })} />
      </div>
      <Field label="Terms of service URL" error={urlError(registration.terms_url)}>
        {(id, by) => (
          <TextInput id={id} aria-describedby={by} type="url" value={registration.terms_url ?? ""} disabled={!editable} onChange={(e) => update({ registration: { terms_url: e.target.value || null } })} />
        )}
      </Field>
      <Field label="Privacy policy URL" error={urlError(registration.privacy_url)}>
        {(id, by) => (
          <TextInput id={id} aria-describedby={by} type="url" value={registration.privacy_url ?? ""} disabled={!editable} onChange={(e) => update({ registration: { privacy_url: e.target.value || null } })} />
        )}
      </Field>
      <Field label="Allowed email domains" hint="Only these domains may register; empty means any." wide>
        {(id, by) => (
          <TagsInput
            id={id}
            describedBy={by}
            value={registration.allowed_email_domains}
            onChange={(v) => update({ registration: { allowed_email_domains: v } })}
            placeholder="example.com"
            normalize={(s) => s.trim().toLowerCase().replace(/^@/, "")}
          />
        )}
      </Field>
    </Section>
  );
}
