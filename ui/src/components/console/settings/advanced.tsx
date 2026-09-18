"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { useState } from "react";
import { Field, NumberInput, Section, SelectInput, TagsInput, TextInput, Toggle } from "@/components/console/form";
import { Badge, Button } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatDate } from "@/i18n";
import type { InitialAccessToken } from "@/lib/console/ops";
import { useConsole } from "@/lib/console/session";
import { GRANTS, RSA_BITS, SIGNING_ALGS } from "@/lib/console/settings";
import { ErrorLine } from "../access/common";
import { RevealModal, type Revealed } from "../clients/reveal";
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
      {dcr.mode === "initial_access_token" && <InitialAccessTokens slug={draft.slug} />}
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

/**
 * Initial access tokens (RFC 7591 §1.2): what `/register` demands in this
 * mode. Each is shown once when issued, with an optional expiry and budget
 * of registrations, and can be revoked.
 */
function InitialAccessTokens({ slug }: { slug: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const editable = can("ridm:clients:write");
  const tokens = useQuery({
    queryKey: ["dcr-tokens", slug],
    enabled: can("ridm:clients:read"),
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/dcr/initial-access-tokens", { params: { path: { slug } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [description, setDescription] = useState("");
  const [hours, setHours] = useState<number | null>(24);
  const [uses, setUses] = useState<number | null>(1);
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const invalidate = () => void qc.invalidateQueries({ queryKey: ["dcr-tokens", slug] });
  const issue = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/dcr/initial-access-tokens", {
        params: { path: { slug } },
        body: { description: description.trim() || null, expires_in_secs: hours === null ? null : hours * 3600, max_uses: uses },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (t) => {
      setDescription("");
      invalidate();
      setRevealed({ title: "Initial access token issued", description: "Registering software sends it as its bearer token to the registration endpoint; it is shown only now.", values: [{ label: "Initial access token", value: t.token }] });
    },
  });
  const revoke = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/dcr/initial-access-tokens/{token}", { params: { path: { slug, token: id } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: invalidate,
  });
  const state = (t: InitialAccessToken): { label: string; tone: "neutral" | "danger" | "ok" } => {
    if (t.revoked_at) return { label: "revoked", tone: "neutral" };
    if (t.expires_at && new Date(t.expires_at) < new Date()) return { label: "expired", tone: "danger" };
    if (t.max_uses != null && t.uses >= t.max_uses) return { label: "used up", tone: "neutral" };
    return { label: "active", tone: "ok" };
  };
  if (!can("ridm:clients:read")) return null;
  return (
    <div className="flex flex-col gap-3 sm:col-span-2">
      <h3 className="text-[0.8125rem] font-medium text-ink">Initial access tokens</h3>
      <RevealModal revealed={revealed} onClose={() => setRevealed(null)} />
      <ErrorLine error={issue.error ?? revoke.error} />
      {editable && (
        <form
          className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_8rem_8rem_auto] sm:items-end"
          onSubmit={(e) => {
            e.preventDefault();
            issue.mutate();
          }}
        >
          <label className="flex flex-col gap-1 text-[0.8125rem] text-muted">
            Description
            <TextInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="CI pipeline" maxLength={200} />
          </label>
          <label className="flex flex-col gap-1 text-[0.8125rem] text-muted">
            Expires in
            <NumberInput id="dcr-token-hours" value={hours} min={1} nullable onValue={setHours} unit="h" />
          </label>
          <label className="flex flex-col gap-1 text-[0.8125rem] text-muted">
            Registrations
            <NumberInput id="dcr-token-uses" value={uses} min={1} nullable onValue={setUses} />
          </label>
          <Button type="submit" disabled={issue.isPending}>
            <Plus className="size-4" aria-hidden /> Issue token
          </Button>
        </form>
      )}
      {tokens.isPending ? (
        <Spinner label="Loading…" />
      ) : tokens.isError ? (
        <ErrorLine error={tokens.error} />
      ) : tokens.data.length === 0 ? (
        <p className="text-[0.875rem] text-muted">No initial access tokens yet; registration is closed until one is issued.</p>
      ) : (
        <ul className="divide-y divide-line">
          {tokens.data.map((t) => {
            const s = state(t);
            return (
              <li key={t.id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-[0.875rem]">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-ink">{t.description ?? "Untitled"}</span>
                  <Badge tone={s.tone}>{s.label}</Badge>
                  <span className="text-[0.8125rem] text-muted">
                    {t.uses} of {t.max_uses ?? "unlimited"} used · created {formatDate("en", t.created_at)}
                    {t.expires_at ? ` · expires ${formatDate("en", t.expires_at)}` : " · no expiry"}
                  </span>
                </div>
                {editable && !t.revoked_at && (
                  <Button className="min-h-8 px-2.5 text-[0.8125rem]" disabled={revoke.isPending} onClick={() => revoke.mutate(t.id)}>
                    Revoke
                  </Button>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
