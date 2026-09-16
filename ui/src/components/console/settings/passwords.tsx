"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Field, NumberInput, Section, SelectInput, TextInput, Toggle } from "@/components/console/form";
import { Badge, Button } from "@/components/console/ui";
import { useConsole } from "@/lib/console/session";
import { useSettingsEditor } from "./context";

export function PasswordsSection() {
  const { draft, editable, update } = useSettingsEditor();
  const { password, lockout, captcha } = draft.settings;
  return (
    <Section id="passwords" title="Passwords & lockout" description="Password rules, brute-force protection and when a CAPTCHA is demanded.">
      <Field label="Minimum length">
        {(id, by) => <NumberInput id={id} describedBy={by} value={password.min_length} min={1} max={password.max_length} onValue={(v) => v !== null && update({ password: { min_length: v } })} unit="chars" />}
      </Field>
      <Field label="Maximum length">
        {(id, by) => <NumberInput id={id} describedBy={by} value={password.max_length} min={password.min_length} max={1024} onValue={(v) => v !== null && update({ password: { max_length: v } })} unit="chars" />}
      </Field>
      <div className="flex flex-col gap-1 sm:col-span-2">
        <Toggle label="Require an uppercase letter" checked={password.require_uppercase} disabled={!editable} onChange={(v) => update({ password: { require_uppercase: v } })} />
        <Toggle label="Require a lowercase letter" checked={password.require_lowercase} disabled={!editable} onChange={(v) => update({ password: { require_lowercase: v } })} />
        <Toggle label="Require a digit" checked={password.require_digit} disabled={!editable} onChange={(v) => update({ password: { require_digit: v } })} />
        <Toggle label="Require a symbol" checked={password.require_symbol} disabled={!editable} onChange={(v) => update({ password: { require_symbol: v } })} />
        <Toggle label="Reject breached passwords" hint="Refuses passwords found in breach corpora (Have I Been Pwned range API, k-anonymity: only five hex digits of the SHA-1 leave the server). Needs the deployment to allow the lookup; an outage lets passwords through." checked={password.check_breached} disabled={!editable} onChange={(v) => update({ password: { check_breached: v } })} />
      </div>
      <Field label="Password history" hint="A new password must differ from this many previous ones (0 = off).">
        {(id, by) => <NumberInput id={id} describedBy={by} value={password.history} min={0} max={100} onValue={(v) => v !== null && update({ password: { history: v } })} />}
      </Field>
      <Field label="Maximum age" hint="Days until a password must be changed; empty = never.">
        {(id, by) => <NumberInput id={id} describedBy={by} value={password.max_age_days ?? null} min={1} nullable onValue={(v) => update({ password: { max_age_days: v } })} unit="days" />}
      </Field>

      <div className="sm:col-span-2">
        <h3 className="text-[0.8125rem] font-medium text-ink">Lockout</h3>
      </div>
      <Field label="Failures before a user is locked" hint="Consecutive failed sign-ins (0 = never lock).">
        {(id, by) => <NumberInput id={id} describedBy={by} value={lockout.max_failures} min={0} onValue={(v) => v !== null && update({ lockout: { max_failures: v } })} />}
      </Field>
      <Field label="Lock duration">
        {(id, by) => <NumberInput id={id} describedBy={by} value={lockout.lock_minutes} min={1} onValue={(v) => v !== null && update({ lockout: { lock_minutes: v } })} unit="min" />}
      </Field>
      <Field label="Failures per IP before throttling" hint="0 = off.">
        {(id, by) => <NumberInput id={id} describedBy={by} value={lockout.ip_max_failures} min={0} onValue={(v) => v !== null && update({ lockout: { ip_max_failures: v } })} />}
      </Field>
      <Field label="IP window">
        {(id, by) => <NumberInput id={id} describedBy={by} value={lockout.ip_window_minutes} min={1} onValue={(v) => v !== null && update({ lockout: { ip_window_minutes: v } })} unit="min" />}
      </Field>

      <div className="sm:col-span-2">
        <h3 className="text-[0.8125rem] font-medium text-ink">CAPTCHA</h3>
      </div>
      <Field label="Demand a challenge after" hint="Failed attempts in one flow (0 = never).">
        {(id, by) => <NumberInput id={id} describedBy={by} value={captcha.after_failures} min={0} onValue={(v) => v !== null && update({ captcha: { after_failures: v } })} unit="failures" />}
      </Field>
      <div className="flex items-end">
        <div className="w-full">
          <Toggle label="Challenge on registration" checked={captcha.on_registration} disabled={!editable} onChange={(v) => update({ captcha: { on_registration: v } })} />
        </div>
      </div>
      <CaptchaProvider slug={draft.slug} editable={editable} />
    </Section>
  );
}

type Provider = "turnstile" | "h_captcha";

/**
 * The CAPTCHA provider is stored encrypted behind its own endpoint. It saves
 * itself as soon as a site key and a secret are both present; the secret is
 * never read back.
 */
function CaptchaProvider({ slug, editable }: { slug: string; editable: boolean }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["tenant", slug, "captcha"],
    queryFn: async () => {
      const { data, response, error } = await client.GET("/admin/tenants/{slug}/captcha", { params: { path: { slug } } });
      if (response.status === 404) return null;
      if (error) throw new Error(error.detail ?? error.title);
      return data ?? null;
    },
  });
  const [provider, setProvider] = useState<Provider>("turnstile");
  const [siteKey, setSiteKey] = useState("");
  const [secret, setSecret] = useState("");
  const [verifyUrl, setVerifyUrl] = useState("");
  const [seeded, setSeeded] = useState(false);
  if (q.data !== undefined && !seeded) {
    setSeeded(true);
    if (q.data) {
      setProvider(q.data.provider);
      setSiteKey(q.data.site_key);
      setVerifyUrl(q.data.verify_url ?? "");
    }
  }
  const save = useMutation({
    mutationFn: async () => {
      const { error } = await client.PUT("/admin/tenants/{slug}/captcha", {
        params: { path: { slug } },
        body: { provider, site_key: siteKey.trim(), secret: secret.trim(), verify_url: verifyUrl.trim() || null },
      });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      setSecret("");
      void qc.invalidateQueries({ queryKey: ["tenant", slug, "captcha"] });
    },
  });
  const remove = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/captcha", { params: { path: { slug } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      setSiteKey("");
      setSecret("");
      setVerifyUrl("");
      void qc.invalidateQueries({ queryKey: ["tenant", slug, "captcha"] });
    },
  });
  const complete = siteKey.trim() !== "" && secret.trim() !== "";
  const configured = Boolean(q.data);

  return (
    <div className="grid gap-5 sm:col-span-2 sm:grid-cols-2">
      <div className="flex items-center gap-2 sm:col-span-2">
        <h4 className="text-[0.8125rem] font-medium text-ink">Provider</h4>
        {configured ? <Badge tone="ok">Configured</Badge> : <Badge>Not configured</Badge>}
        {(save.isError || remove.isError) && (
          <span role="alert" className="text-[0.8125rem] text-danger">
            {(save.error ?? remove.error)?.message}
          </span>
        )}
      </div>
      <Field label="Service">
        {(id) => (
          <SelectInput id={id} value={provider} disabled={!editable} onChange={(e) => setProvider(e.target.value as Provider)}>
            <option value="turnstile">Cloudflare Turnstile</option>
            <option value="h_captcha">hCaptcha</option>
          </SelectInput>
        )}
      </Field>
      <Field label="Site key">
        {(id) => <TextInput id={id} value={siteKey} disabled={!editable} onChange={(e) => setSiteKey(e.target.value)} spellCheck={false} />}
      </Field>
      <Field label="Secret" hint={configured ? "A secret is stored; enter a new one to replace it. Saved as soon as both keys are filled." : "Saved as soon as both keys are filled."}>
        {(id, by) => (
          <TextInput
            id={id}
            aria-describedby={by}
            type="password"
            autoComplete="off"
            value={secret}
            disabled={!editable}
            onChange={(e) => setSecret(e.target.value)}
            onBlur={() => complete && !save.isPending && save.mutate()}
          />
        )}
      </Field>
      <Field label="Verification URL" hint="Optional override for self-hosted proxies.">
        {(id, by) => <TextInput id={id} aria-describedby={by} type="url" value={verifyUrl} disabled={!editable} onChange={(e) => setVerifyUrl(e.target.value)} onBlur={() => complete && !save.isPending && save.mutate()} />}
      </Field>
      {editable && (
        <div className="flex gap-2 sm:col-span-2">
          <Button variant="primary" disabled={!complete || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save provider"}
          </Button>
          {configured && (
            <Button variant="danger" disabled={remove.isPending} onClick={() => remove.mutate()}>
              Remove provider
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
